use gmail_proxy::auth::TokenManager;
use gmail_proxy::gmail::client::GmailClient;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup() -> (MockServer, GmailClient) {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 3599,
            "token_type": "Bearer"
        })))
        .mount(&mock_server)
        .await;

    let token_url = format!("{}/token", mock_server.uri());
    let token_manager = Arc::new(TokenManager::new(
        "cid".into(),
        "csecret".into(),
        "refresh".into(),
        token_url,
    ));
    let gmail_base = format!("{}/gmail/v1/users/me", mock_server.uri());
    let client = GmailClient::new(token_manager, gmail_base);

    (mock_server, client)
}

#[tokio::test]
async fn test_search_messages() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messages": [
                {"id": "msg1", "threadId": "t1"},
                {"id": "msg2", "threadId": "t2"}
            ],
            "resultSizeEstimate": 2
        })))
        .mount(&mock_server)
        .await;

    let result = client.search("from:alice", 20, None).await.unwrap();
    assert_eq!(result.messages.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn test_get_message() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg1",
            "threadId": "t1",
            "labelIds": ["INBOX"],
            "snippet": "Hello there",
            "payload": {
                "mimeType": "text/plain",
                "body": {"data": "SGVsbG8gdGhlcmU"},
                "headers": [
                    {"name": "From", "value": "alice@example.com"},
                    {"name": "Subject", "value": "Test"}
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let msg = client.get_message("msg1").await.unwrap();
    assert_eq!(msg.id, "msg1");
    assert_eq!(msg.header("From"), Some("alice@example.com"));
}

#[tokio::test]
async fn test_get_thread() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/threads/t1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "t1",
            "messages": [
                {
                    "id": "msg1", "threadId": "t1",
                    "payload": {"mimeType": "text/plain", "body": {"data": "Zmlyc3Q"}}
                },
                {
                    "id": "msg2", "threadId": "t1",
                    "payload": {"mimeType": "text/plain", "body": {"data": "c2Vjb25k"}}
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let thread = client.get_thread("t1").await.unwrap();
    assert_eq!(thread.messages.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_labels() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "labels": [
                {"id": "INBOX", "name": "INBOX"},
                {"id": "Label_42", "name": "agent-blocked"}
            ]
        })))
        .mount(&mock_server)
        .await;

    let labels = client.list_labels().await.unwrap();
    let blocked = labels
        .labels
        .unwrap()
        .into_iter()
        .find(|l| l.name == "agent-blocked");
    assert!(blocked.is_some());
    assert_eq!(blocked.unwrap().id, "Label_42");
}

#[tokio::test]
async fn test_history_list() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "history": [
                {"messagesAdded": [{"message": {"id": "msg3", "threadId": "t3"}}]},
                {"messagesAdded": [{"message": {"id": "msg4", "threadId": "t4"}}]}
            ],
            "historyId": "99999"
        })))
        .mount(&mock_server)
        .await;

    let history = client.history(12345).await.unwrap();
    assert!(history.history.is_some());
    assert_eq!(history.history.as_ref().unwrap().len(), 2);
}
