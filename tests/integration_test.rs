use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use regex::Regex;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use gmail_proxy::audit::AuditLogger;
use gmail_proxy::auth::TokenManager;
use gmail_proxy::gmail::client::GmailClient;
use gmail_proxy::proxy::routes::*;
use gmail_proxy::scrub::content::ContentScrubber;
use gmail_proxy::scrub::labels::LabelFilter;

fn b64(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s)
}

fn make_message_json(
    id: &str,
    thread_id: &str,
    from: &str,
    subject: &str,
    body_text: &str,
    label_ids: Vec<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "threadId": thread_id,
        "labelIds": label_ids,
        "snippet": &body_text[..body_text.len().min(50)],
        "payload": {
            "mimeType": "text/plain",
            "body": {"data": b64(body_text)},
            "headers": [
                {"name": "From", "value": from},
                {"name": "To", "value": "user@gmail.com"},
                {"name": "Subject", "value": subject},
                {"name": "Date", "value": "2026-03-14T10:00:00Z"}
            ]
        }
    })
}

/// Build a full app with real scrubbing pipeline (OTP patterns, URL patterns,
/// blocked senders, strip_links=true).
async fn setup_integration_app(mock_server: &MockServer) -> (axum::Router, tempfile::TempDir) {
    let audit_dir = tempfile::TempDir::new().unwrap();

    // Mock token endpoint
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test-token",
                "expires_in": 3599,
                "token_type": "Bearer"
            })),
        )
        .mount(mock_server)
        .await;

    let token_manager = Arc::new(TokenManager::new(
        "cid".into(),
        "csecret".into(),
        "refresh".into(),
        format!("{}/token", mock_server.uri()),
    ));
    let gmail = Arc::new(GmailClient::new(
        token_manager.clone(),
        format!("{}/gmail/v1/users/me", mock_server.uri()),
    ));
    let label_filter = Arc::new(LabelFilter::new(
        "Label_42".into(),
        "agent-blocked".into(),
    ));

    // Real scrubber with OTP patterns, blocked senders, and strip_links=true
    let otp_patterns = vec![
        Regex::new(r"\b\d{6}\b").unwrap(), // 6-digit OTP codes
    ];
    let url_strip_patterns = vec![
        Regex::new(r"https?://\S+/reset\?\S+").unwrap(), // password reset links
    ];
    let blocked_sender_patterns = vec![
        Regex::new(r"noreply@accounts\.google\.com").unwrap(),
    ];
    let scrubber = Arc::new(ContentScrubber::new(
        otp_patterns,
        url_strip_patterns,
        blocked_sender_patterns,
        true, // strip_links
    ));
    let audit = Arc::new(AuditLogger::new(audit_dir.path()).unwrap());

    let state = Arc::new(AppState {
        gmail,
        label_filter,
        scrubber,
        audit,
        allowed_operators: vec![
            "from".into(),
            "to".into(),
            "subject".into(),
            "has".into(),
            "is".into(),
            "newer_than".into(),
        ],
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

    (build_router(state), audit_dir)
}

// -------------------------------------------------------------------------
// Test 1: Full search pipeline with OTP scrubbing
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_full_search_pipeline_with_otp_scrubbing() {
    let mock_server = MockServer::start().await;

    // Mock search -> returns one message
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [{"id": "msg-otp", "threadId": "t1"}],
                "resultSizeEstimate": 1
            })),
        )
        .mount(&mock_server)
        .await;

    // Mock get message - body contains a 6-digit OTP
    let body_with_otp = "Your verification code is 482917. Do not share this code.";
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg-otp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            make_message_json("msg-otp", "t1", "support@example.com", "Your code", body_with_otp, vec!["INBOX"]),
        ))
        .mount(&mock_server)
        .await;

    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/search?q=from:support&max=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify response structure
    assert!(json["messages"].is_array());
    assert!(json.get("result_size_estimate").is_some());

    let messages = json["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);

    let msg = &messages[0];
    assert_eq!(msg["id"], "msg-otp");
    assert_eq!(msg["thread_id"], "t1");
    assert_eq!(msg["from"], "support@example.com");
    assert_eq!(msg["subject"], "Your code");

    // OTP should be redacted
    let body_text = msg["body_text"].as_str().unwrap();
    assert!(
        body_text.contains("[REDACTED]"),
        "OTP should be redacted, got: {body_text}"
    );
    assert!(
        !body_text.contains("482917"),
        "Raw OTP should not appear in output"
    );

    // No body_html field
    assert!(msg.get("body_html").is_none(), "body_html should not exist");
}

// -------------------------------------------------------------------------
// Test 2: Blocked sender is suppressed from search results
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_blocked_sender_suppressed_in_search() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [{"id": "msg-blocked-sender", "threadId": "t2"}],
                "resultSizeEstimate": 1
            })),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg-blocked-sender"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_message_json(
            "msg-blocked-sender",
            "t2",
            "noreply@accounts.google.com",
            "Security alert",
            "Someone signed into your account.",
            vec!["INBOX"],
        )))
        .mount(&mock_server)
        .await;

    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/search?q=from:noreply&max=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Message from blocked sender should be filtered out
    let messages = json["messages"].as_array().unwrap();
    assert_eq!(
        messages.len(),
        0,
        "Blocked sender messages should not appear in results"
    );
}

// -------------------------------------------------------------------------
// Test 3: Blocked label message returns 404 on direct fetch
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_blocked_label_message_returns_404() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg-blocked-label"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_message_json(
            "msg-blocked-label",
            "t3",
            "someone@example.com",
            "Blocked",
            "This is blocked.",
            vec!["INBOX", "Label_42"], // Label_42 is the blocked label ID
        )))
        .mount(&mock_server)
        .await;

    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/message/msg-blocked-label")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].is_string());
}

// -------------------------------------------------------------------------
// Test 4: Link stripping works
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_link_stripping() {
    let mock_server = MockServer::start().await;

    let body_with_links =
        "Check out https://example.com/page and https://test.org/link for details.";

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg-links"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_message_json(
            "msg-links",
            "t4",
            "friend@example.com",
            "Links",
            body_with_links,
            vec!["INBOX"],
        )))
        .mount(&mock_server)
        .await;

    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/message/msg-links")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let body_text = json["body_text"].as_str().unwrap();
    assert!(
        body_text.contains("[link removed]"),
        "URLs should be replaced with [link removed], got: {body_text}"
    );
    assert!(
        !body_text.contains("https://example.com"),
        "Raw URLs should not appear"
    );
    assert!(
        !body_text.contains("https://test.org"),
        "Raw URLs should not appear"
    );

    // No body_html
    assert!(json.get("body_html").is_none());
}

// -------------------------------------------------------------------------
// Test 5: Query validation - blocked label query returns 400
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_query_validation_blocked_label() {
    let mock_server = MockServer::start().await;
    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/search?q=label:agent-blocked")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["error"].is_string(), "Error field should be present");
    assert!(json["hint"].is_string(), "Hint field should be present");
}

// -------------------------------------------------------------------------
// Test 6: Thread with mixed messages - filtering works
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_thread_with_mixed_messages() {
    let mock_server = MockServer::start().await;

    let thread_json = serde_json::json!({
        "id": "thread-mixed",
        "messages": [
            // Normal message
            make_message_json(
                "msg-normal", "thread-mixed",
                "alice@example.com", "Hello",
                "This is a normal message.",
                vec!["INBOX"],
            ),
            // Blocked sender message
            make_message_json(
                "msg-blocked-s", "thread-mixed",
                "noreply@accounts.google.com", "Security",
                "Security alert from Google.",
                vec!["INBOX"],
            ),
            // Blocked label message
            make_message_json(
                "msg-blocked-l", "thread-mixed",
                "bob@example.com", "Blocked label",
                "This has a blocked label.",
                vec!["INBOX", "Label_42"],
            ),
        ]
    });

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/threads/thread-mixed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(thread_json))
        .mount(&mock_server)
        .await;

    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/thread/thread-mixed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["thread_id"], "thread-mixed");

    let messages = json["messages"].as_array().unwrap();
    // Only the normal message should remain
    assert_eq!(
        messages.len(),
        1,
        "Only the normal message should pass filters, got {} messages",
        messages.len()
    );
    assert_eq!(messages[0]["id"], "msg-normal");
    assert_eq!(messages[0]["from"], "alice@example.com");

    // Verify no body_html on the surviving message
    assert!(messages[0].get("body_html").is_none());
}

// -------------------------------------------------------------------------
// Test 7: OTP + link stripping combined in search results
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_otp_and_link_stripping_combined() {
    let mock_server = MockServer::start().await;

    let body_text = "Your code is 753219. Reset at https://example.com/reset?token=abc123 or visit https://help.example.com/faq for help.";

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [{"id": "msg-combo", "threadId": "t5"}],
                "resultSizeEstimate": 1
            })),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg-combo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_message_json(
            "msg-combo",
            "t5",
            "alerts@service.com",
            "Code and links",
            body_text,
            vec!["INBOX"],
        )))
        .mount(&mock_server)
        .await;

    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/search?q=from:alerts&max=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let messages = json["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);

    let scrubbed = messages[0]["body_text"].as_str().unwrap();

    // OTP redacted
    assert!(
        !scrubbed.contains("753219"),
        "OTP should be redacted"
    );
    assert!(
        scrubbed.contains("[REDACTED]"),
        "Should contain [REDACTED] for OTP"
    );

    // Reset URL specifically matched by url_strip_patterns -> [REDACTED]
    assert!(
        !scrubbed.contains("token=abc123"),
        "Reset token URL should be redacted"
    );

    // General URLs stripped
    assert!(
        !scrubbed.contains("https://help.example.com"),
        "General URLs should be stripped"
    );
    assert!(
        scrubbed.contains("[link removed]"),
        "General URLs should become [link removed]"
    );
}

// -------------------------------------------------------------------------
// Test 8: Audit log is written for search
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_audit_log_written() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [],
                "resultSizeEstimate": 0
            })),
        )
        .mount(&mock_server)
        .await;

    let (app, audit_dir) = setup_integration_app(&mock_server).await;

    let _response = app
        .oneshot(
            Request::builder()
                .uri("/search?q=from:test&max=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Give the async audit writer a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Check that an audit log file was created
    let entries: Vec<_> = std::fs::read_dir(audit_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();

    assert!(
        !entries.is_empty(),
        "Audit log directory should contain at least one file"
    );

    // Read the first audit log file and verify it contains search event
    let log_content = std::fs::read_to_string(entries[0].path()).unwrap();
    assert!(
        log_content.contains("Search"),
        "Audit log should contain a Search event"
    );
    assert!(
        log_content.contains("from:test"),
        "Audit log should contain the raw query"
    );
}

// -------------------------------------------------------------------------
// Test 9: Missing query parameter returns 400
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_missing_query_returns_400() {
    let mock_server = MockServer::start().await;
    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/search")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].is_string());
    assert!(json["hint"].is_string());
}

// -------------------------------------------------------------------------
// Test 10: Blocked sender returns 404 on direct message fetch
// -------------------------------------------------------------------------
#[tokio::test]
async fn test_blocked_sender_direct_fetch_returns_404() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg-google"))
        .respond_with(ResponseTemplate::new(200).set_body_json(make_message_json(
            "msg-google",
            "t-google",
            "noreply@accounts.google.com",
            "Alert",
            "Your account was accessed.",
            vec!["INBOX"],
        )))
        .mount(&mock_server)
        .await;

    let (app, _audit_dir) = setup_integration_app(&mock_server).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/message/msg-google")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "Message not found");
}
