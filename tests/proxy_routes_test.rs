use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use std::sync::Arc;
use tokio::sync::RwLock;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use gmail_proxy::auth::TokenManager;
use gmail_proxy::gmail::client::GmailClient;
use gmail_proxy::scrub::labels::LabelFilter;
use gmail_proxy::scrub::content::ContentScrubber;
use gmail_proxy::audit::AuditLogger;
use gmail_proxy::proxy::routes::*;

async fn setup_test_app() -> (axum::Router, MockServer) {
    let mock_server = MockServer::start().await;
    let audit_dir = tempfile::TempDir::new().unwrap();

    // Mock token endpoint
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token", "expires_in": 3599, "token_type": "Bearer"
        })))
        .mount(&mock_server).await;

    // Mock Gmail search
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messages": [{"id": "msg1", "threadId": "t1"}],
            "resultSizeEstimate": 1
        })))
        .mount(&mock_server).await;

    // Mock Gmail get message (normal message)
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg1", "threadId": "t1", "labelIds": ["INBOX"],
            "snippet": "Hello",
            "payload": {
                "mimeType": "text/plain",
                "body": {"data": "SGVsbG8gV29ybGQ"},
                "headers": [
                    {"name": "From", "value": "alice@example.com"},
                    {"name": "To", "value": "bob@gmail.com"},
                    {"name": "Subject", "value": "Test"},
                    {"name": "Date", "value": "2026-03-14T10:00:00Z"}
                ]
            }
        })))
        .mount(&mock_server).await;

    // Mock Gmail get thread
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/threads/t1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "t1",
            "messages": [{
                "id": "msg1", "threadId": "t1", "labelIds": ["INBOX"],
                "snippet": "Hello",
                "payload": {
                    "mimeType": "text/plain",
                    "body": {"data": "SGVsbG8"},
                    "headers": [
                        {"name": "From", "value": "alice@example.com"},
                        {"name": "To", "value": "bob@gmail.com"},
                        {"name": "Subject", "value": "Test"},
                        {"name": "Date", "value": "2026-03-14T10:00:00Z"}
                    ]
                }
            }]
        })))
        .mount(&mock_server).await;

    let token_manager = Arc::new(TokenManager::new(
        "cid".into(), "csecret".into(), "refresh".into(),
        format!("{}/token", mock_server.uri()),
    ));
    let gmail = GmailClient::new(
        token_manager.clone(),
        format!("{}/gmail/v1/users/me", mock_server.uri()),
    );
    let label_filter = LabelFilter::new("Label_42".into(), "agent-blocked".into());
    let scrubber = ContentScrubber::new(vec![], vec![], vec![], false);
    let audit = AuditLogger::new(audit_dir.path()).unwrap();

    let state = Arc::new(AppState {
        gmail,
        label_filter,
        scrubber,
        audit,
        allowed_operators: vec!["from".into(), "to".into(), "subject".into(), "has".into(), "is".into(), "newer_than".into()],
        blocked_label: "agent-blocked".into(),
        max_query_depth: 10,
        search_concurrency: 5,
        poller_status: Arc::new(RwLock::new(PollerStatus {
            connected: true,
            last_message_received: Some("2026-03-14T15:30:02Z".into()),
            last_message_delivered: Some("2026-03-14T15:28:12Z".into()),
            consecutive_errors: 0,
        })),
        token_manager,
        watch_status: Arc::new(RwLock::new(WatchStatus {
            active: true,
            expiration: Some("2026-03-20T10:00:00Z".into()),
            last_history_id: Some(12345678),
        })),
    });

    // Leak the tempdir so it doesn't get cleaned up during the test
    let _ = Box::leak(Box::new(audit_dir));

    (build_router(state), mock_server)
}

#[tokio::test]
async fn test_search_basic() {
    let (app, _mock) = setup_test_app().await;
    let response = app
        .oneshot(Request::builder().uri("/search?q=from:alice&max=5").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["messages"].is_array());
}

#[tokio::test]
async fn test_search_invalid_query() {
    let (app, _mock) = setup_test_app().await;
    let response = app
        .oneshot(Request::builder().uri("/search?q=(unclosed").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].is_string());
    assert!(json["hint"].is_string());
}

#[tokio::test]
async fn test_search_blocked_label_query() {
    let (app, _mock) = setup_test_app().await;
    let response = app
        .oneshot(Request::builder().uri("/search?q=label:agent-blocked").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_search_missing_query() {
    let (app, _mock) = setup_test_app().await;
    let response = app
        .oneshot(Request::builder().uri("/search").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_message() {
    let (app, _mock) = setup_test_app().await;
    let response = app
        .oneshot(Request::builder().uri("/message/msg1").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], "msg1");
    assert!(json["body_text"].is_string());
    assert!(json.get("body_html").is_none());
}

#[tokio::test]
async fn test_get_thread() {
    let (app, _mock) = setup_test_app().await;
    let response = app
        .oneshot(Request::builder().uri("/thread/t1").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["thread_id"], "t1");
    assert!(json["messages"].is_array());
}

#[tokio::test]
async fn test_health() {
    let (app, _mock) = setup_test_app().await;
    let response = app
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["watch"].is_object());
    assert!(json["token"].is_object());
    assert!(json["poller"].is_object());
}
