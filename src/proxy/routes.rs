use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::audit::{AuditEvent, AuditLogger};
use crate::auth::TokenManager;
use crate::gmail::client::GmailClient;
use crate::scrub::content::ContentScrubber;
use crate::scrub::labels::LabelFilter;
use crate::scrub::query::{parse_query, validate_query};

pub struct PollerStatus {
    pub connected: bool,
    pub last_message_received: Option<String>,
    pub last_message_delivered: Option<String>,
    pub consecutive_errors: u32,
}

pub struct WatchStatus {
    pub active: bool,
    pub expiration: Option<String>,
    pub last_history_id: Option<u64>,
}

pub struct AppState {
    pub gmail: Arc<GmailClient>,
    pub label_filter: Arc<LabelFilter>,
    pub scrubber: Arc<ContentScrubber>,
    pub audit: Arc<AuditLogger>,
    pub allowed_operators: Vec<String>,
    pub blocked_label: String,
    pub max_query_depth: usize,
    pub search_concurrency: usize,
    pub poller_status: Arc<RwLock<PollerStatus>>,
    pub token_manager: Arc<TokenManager>,
    pub watch_status: Arc<RwLock<WatchStatus>>,
}

#[derive(Deserialize)]
pub struct SearchParams {
    pub q: Option<String>,
    pub max: Option<u32>,
    pub page_token: Option<String>,
}

pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/search", axum::routing::get(search_handler))
        .route("/message/{id}", axum::routing::get(get_message_handler))
        .route("/thread/{id}", axum::routing::get(get_thread_handler))
        .route("/health", axum::routing::get(health_handler))
        .with_state(state)
}

async fn search_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let raw_query = match params.q {
        Some(q) if !q.trim().is_empty() => q,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Missing required query parameter 'q'",
                    "hint": "Provide a search query using the 'q' parameter"
                })),
            ));
        }
    };

    let max = params.max.unwrap_or(20).min(100);
    let page_token = params.page_token.as_deref();

    // Parse
    let ast = match parse_query(&raw_query) {
        Ok(ast) => ast,
        Err(e) => {
            state.audit.log(AuditEvent::QueryRejected {
                raw_query: raw_query.clone(),
                error: e.message.clone(),
                hint: e.hint.clone(),
            });
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": e.message,
                    "hint": e.hint,
                    "query": e.query
                })),
            ));
        }
    };

    // Validate
    let allowed_ops: Vec<&str> = state.allowed_operators.iter().map(|s| s.as_str()).collect();
    if let Err(e) = validate_query(&ast, &allowed_ops, &state.blocked_label, state.max_query_depth)
    {
        state.audit.log(AuditEvent::QueryRejected {
            raw_query: raw_query.clone(),
            error: e.message.clone(),
            hint: e.hint.clone(),
        });
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": e.message,
                "hint": e.hint,
                "query": raw_query
            })),
        ));
    }

    // Reconstruct with label exclusion
    let secured_query = state.label_filter.secure_query_string(&ast);

    // Search Gmail
    let search_result = state
        .gmail
        .search(&secured_query, max, page_token)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Gmail search failed: {e}")})),
            )
        })?;

    let refs = search_result.messages.unwrap_or_default();

    // Fetch messages concurrently
    let ids: Vec<String> = refs.iter().map(|r| r.id.clone()).collect();
    let fetched: Vec<_> = stream::iter(ids)
        .map(|id| {
            let gmail = &state.gmail;
            async move { gmail.get_message(&id).await }
        })
        .buffer_unordered(state.search_concurrency)
        .collect()
        .await;

    // Filter and scrub
    let mut messages = Vec::new();
    for result in fetched {
        let msg = match result {
            Ok(m) => m,
            Err(_) => continue,
        };

        let labels = msg.label_ids.clone().unwrap_or_default();
        if state.label_filter.is_message_blocked(&labels) {
            continue;
        }

        let from = msg.header("From").unwrap_or("");
        if state.scrubber.check_sender(from).is_blocked() {
            continue;
        }

        let body = msg.extract_text_body().unwrap_or_default();
        let scrubbed = state.scrubber.scrub_body(&body);
        messages.push(msg.to_sanitized(scrubbed));
    }

    let message_ids: Vec<String> = messages.iter().map(|m| m.id.clone()).collect();

    state.audit.log(AuditEvent::Search {
        raw_query: raw_query.clone(),
        parsed_query: secured_query,
        result_count: messages.len(),
        message_ids,
        page_token_used: params.page_token.clone(),
        has_next_page: search_result.next_page_token.is_some(),
    });

    Ok(Json(serde_json::json!({
        "messages": messages,
        "next_page_token": search_result.next_page_token,
        "result_size_estimate": search_result.result_size_estimate
    })))
}

async fn get_message_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let msg = state.gmail.get_message(&id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to fetch message: {e}")})),
        )
    })?;

    let labels = msg.label_ids.clone().unwrap_or_default();
    let from = msg.header("From").unwrap_or("").to_string();
    let subject = msg.header("Subject").unwrap_or("").to_string();

    if state.label_filter.is_message_blocked(&labels) {
        state.audit.log(AuditEvent::GetMessage {
            message_id: id,
            from,
            subject,
            blocked: true,
            block_reason: Some("Blocked label".into()),
        });
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Message not found"})),
        ));
    }

    if state.scrubber.check_sender(&from).is_blocked() {
        state.audit.log(AuditEvent::GetMessage {
            message_id: id,
            from,
            subject,
            blocked: true,
            block_reason: Some("Blocked sender".into()),
        });
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Message not found"})),
        ));
    }

    let body = msg.extract_text_body().unwrap_or_default();
    let scrubbed = state.scrubber.scrub_body(&body);
    let sanitized = msg.to_sanitized(scrubbed);

    state.audit.log(AuditEvent::GetMessage {
        message_id: id,
        from,
        subject,
        blocked: false,
        block_reason: None,
    });

    Ok(Json(serde_json::to_value(sanitized).unwrap()))
}

async fn get_thread_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let thread = state.gmail.get_thread(&id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to fetch thread: {e}")})),
        )
    })?;

    let all_messages = thread.messages.unwrap_or_default();
    let total_count = all_messages.len();
    let mut blocked_count = 0;
    let mut sanitized_messages = Vec::new();

    for msg in &all_messages {
        let labels = msg.label_ids.clone().unwrap_or_default();
        if state.label_filter.is_message_blocked(&labels) {
            blocked_count += 1;
            continue;
        }

        let from = msg.header("From").unwrap_or("");
        if state.scrubber.check_sender(from).is_blocked() {
            blocked_count += 1;
            continue;
        }

        let body = msg.extract_text_body().unwrap_or_default();
        let scrubbed = state.scrubber.scrub_body(&body);
        sanitized_messages.push(msg.to_sanitized(scrubbed));
    }

    state.audit.log(AuditEvent::GetThread {
        thread_id: id.clone(),
        message_count: total_count,
        returned_count: sanitized_messages.len(),
        blocked_count,
    });

    Ok(Json(serde_json::json!({
        "thread_id": id,
        "messages": sanitized_messages
    })))
}

async fn health_handler(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let watch = {
        let ws = state.watch_status.read().await;
        serde_json::json!({
            "active": ws.active,
            "expiration": ws.expiration,
            "last_history_id": ws.last_history_id
        })
    };

    let token = serde_json::json!({
        "valid": state.token_manager.is_valid().await,
        "expires_in_secs": state.token_manager.expires_in_secs().await
    });

    let poller = {
        let ps = state.poller_status.read().await;
        serde_json::json!({
            "connected": ps.connected,
            "last_message_received": ps.last_message_received,
            "last_message_delivered": ps.last_message_delivered,
            "consecutive_errors": ps.consecutive_errors
        })
    };

    Json(serde_json::json!({
        "status": "ok",
        "watch": watch,
        "token": token,
        "poller": poller
    }))
}
