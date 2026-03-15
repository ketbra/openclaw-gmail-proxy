use base64::Engine;
use gmail_proxy::auth::TokenManager;
use gmail_proxy::poller::processor::Processor;
use gmail_proxy::poller::pubsub::PubSubClient;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_pubsub_pull_with_messages() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "expires_in": 3599,
                "token_type": "Bearer"
            })),
        )
        .mount(&mock_server)
        .await;

    let notification_data = base64::engine::general_purpose::STANDARD.encode(
        r#"{"emailAddress":"test@gmail.com","historyId":99999}"#,
    );

    Mock::given(method("POST"))
        .and(path("/v1/projects/test/subscriptions/test-sub:pull"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "receivedMessages": [{
                    "ackId": "ack1",
                    "message": {
                        "data": notification_data,
                        "messageId": "pubsub-1",
                        "publishTime": "2026-03-14T15:30:00Z"
                    }
                }]
            })),
        )
        .mount(&mock_server)
        .await;

    let token_manager = Arc::new(TokenManager::new(
        "cid".into(),
        "csecret".into(),
        "refresh".into(),
        format!("{}/token", mock_server.uri()),
    ));
    let client = PubSubClient::new(
        token_manager,
        "projects/test/subscriptions/test-sub",
        mock_server.uri(),
    );

    let messages = client.pull().await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].ack_id, "ack1");
}

#[tokio::test]
async fn test_pubsub_pull_empty() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "expires_in": 3599,
                "token_type": "Bearer"
            })),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/projects/test/subscriptions/test-sub:pull"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&mock_server)
        .await;

    let token_manager = Arc::new(TokenManager::new(
        "cid".into(),
        "csecret".into(),
        "refresh".into(),
        format!("{}/token", mock_server.uri()),
    ));
    let client = PubSubClient::new(
        token_manager,
        "projects/test/subscriptions/test-sub",
        mock_server.uri(),
    );

    let messages = client.pull().await.unwrap();
    assert!(messages.is_empty());
}

#[tokio::test]
async fn test_pubsub_acknowledge() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok",
                "expires_in": 3599,
                "token_type": "Bearer"
            })),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/test/subscriptions/test-sub:acknowledge",
        ))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_manager = Arc::new(TokenManager::new(
        "cid".into(),
        "csecret".into(),
        "refresh".into(),
        format!("{}/token", mock_server.uri()),
    ));
    let client = PubSubClient::new(
        token_manager,
        "projects/test/subscriptions/test-sub",
        mock_server.uri(),
    );

    client
        .acknowledge(vec!["ack1".into(), "ack2".into()])
        .await
        .unwrap();
}

#[tokio::test]
async fn test_state_persistence() {
    let dir = tempfile::TempDir::new().unwrap();
    let state_path = dir.path().join("state.json");

    Processor::save_state(&state_path, 12345).unwrap();

    let loaded = Processor::load_state(&state_path).unwrap();
    assert_eq!(loaded, Some(12345));
}

#[tokio::test]
async fn test_state_missing_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let state_path = dir.path().join("nonexistent.json");

    let loaded = Processor::load_state(&state_path).unwrap();
    assert_eq!(loaded, None);
}
