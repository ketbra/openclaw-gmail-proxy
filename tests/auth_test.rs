use gmail_proxy::auth::TokenManager;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_token_refresh() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new-access-token",
            "expires_in": 3599,
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_url = format!("{}/token", mock_server.uri());
    let manager = TokenManager::new(
        "client-id".into(),
        "client-secret".into(),
        "refresh-token".into(),
        token_url,
    );

    let token = manager.get_token().await.unwrap();
    assert_eq!(token, "new-access-token");
}

#[tokio::test]
async fn test_token_cached_until_expiry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "cached-token",
            "expires_in": 3599,
            "token_type": "Bearer"
        })))
        .expect(1) // Only called once
        .mount(&mock_server)
        .await;

    let token_url = format!("{}/token", mock_server.uri());
    let manager = TokenManager::new(
        "client-id".into(),
        "client-secret".into(),
        "refresh-token".into(),
        token_url,
    );

    let t1 = manager.get_token().await.unwrap();
    let t2 = manager.get_token().await.unwrap();
    assert_eq!(t1, "cached-token");
    assert_eq!(t2, "cached-token");
}

#[tokio::test]
async fn test_token_refresh_failure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_grant"
        })))
        .mount(&mock_server)
        .await;

    let token_url = format!("{}/token", mock_server.uri());
    let manager = TokenManager::new(
        "client-id".into(),
        "client-secret".into(),
        "bad-refresh-token".into(),
        token_url,
    );

    let result = manager.get_token().await;
    assert!(result.is_err());
}
