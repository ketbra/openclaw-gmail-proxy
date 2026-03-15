use gmail_proxy::auth::TokenManager;
use gmail_proxy::gmail::client::GmailClient;
use gmail_proxy::gmail::watch::WatchManager;
use gmail_proxy::proxy::routes::WatchStatus;
use std::sync::Arc;
use tokio::sync::RwLock;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup() -> (MockServer, Arc<GmailClient>, Arc<RwLock<WatchStatus>>) {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token", "expires_in": 3599, "token_type": "Bearer"
        })))
        .mount(&mock_server)
        .await;

    let token_manager = Arc::new(TokenManager::new(
        "cid".into(),
        "csecret".into(),
        "refresh".into(),
        format!("{}/token", mock_server.uri()),
    ));
    let gmail = Arc::new(GmailClient::new(
        token_manager,
        format!("{}/gmail/v1/users/me", mock_server.uri()),
    ));
    let status = Arc::new(RwLock::new(WatchStatus {
        active: false,
        expiration: None,
        last_history_id: None,
    }));

    (mock_server, gmail, status)
}

#[tokio::test]
async fn test_watch_registration() {
    let (mock_server, gmail, status) = setup().await;

    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/watch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "historyId": "12345",
            "expiration": "1742400000000"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let _wm = WatchManager::start(
        gmail,
        "projects/test/topics/test".into(),
        vec!["INBOX".into()],
        518400,
        status.clone(),
    )
    .await
    .unwrap();

    let s = status.read().await;
    assert!(s.active);
    assert!(s.last_history_id.is_some());
}

#[tokio::test]
async fn test_watch_provides_initial_history_id() {
    let (mock_server, gmail, status) = setup().await;

    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/watch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "historyId": "67890",
            "expiration": "1742400000000"
        })))
        .mount(&mock_server)
        .await;

    let wm = WatchManager::start(
        gmail,
        "projects/test/topics/test".into(),
        vec!["INBOX".into()],
        518400,
        status.clone(),
    )
    .await
    .unwrap();

    assert_eq!(wm.initial_history_id(), Some(67890));
}

#[tokio::test]
async fn test_watch_registration_failure() {
    let (mock_server, gmail, status) = setup().await;

    Mock::given(method("POST"))
        .and(path("/gmail/v1/users/me/watch"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {"message": "Pub/Sub permissions not configured"}
        })))
        .mount(&mock_server)
        .await;

    let result = WatchManager::start(
        gmail,
        "projects/test/topics/test".into(),
        vec!["INBOX".into()],
        518400,
        status,
    )
    .await;

    assert!(result.is_err());
}
