use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::auth::TokenManager;
use crate::gmail::types::{PubSubPullResponse, ReceivedMessage};

pub struct PubSubClient {
    http_client: reqwest::Client,
    token_manager: Arc<TokenManager>,
    pull_url: String,
    ack_url: String,
}

impl PubSubClient {
    pub fn new(
        token_manager: Arc<TokenManager>,
        subscription: &str,
        base_url: String,
    ) -> Self {
        let pull_url = format!("{}/v1/{}:pull", base_url, subscription);
        let ack_url = format!("{}/v1/{}:acknowledge", base_url, subscription);
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(45))
            .build()
            .expect("failed to build HTTP client");

        Self {
            http_client,
            token_manager,
            pull_url,
            ack_url,
        }
    }

    pub async fn pull(&self) -> Result<Vec<ReceivedMessage>> {
        let token = self.token_manager.get_token().await?;

        let resp = self
            .http_client
            .post(&self.pull_url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({"maxMessages": 10}))
            .send()
            .await
            .context("Pub/Sub pull request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Pub/Sub pull failed with status {}: {}", status, text);
        }

        let body: PubSubPullResponse = resp.json().await.context("failed to deserialize pull response")?;
        Ok(body.received_messages.unwrap_or_default())
    }

    pub async fn acknowledge(&self, ack_ids: Vec<String>) -> Result<()> {
        let token = self.token_manager.get_token().await?;

        let resp = self
            .http_client
            .post(&self.ack_url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({"ackIds": ack_ids}))
            .send()
            .await
            .context("Pub/Sub acknowledge request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Pub/Sub acknowledge failed with status {}: {}", status, text);
        }

        Ok(())
    }
}
