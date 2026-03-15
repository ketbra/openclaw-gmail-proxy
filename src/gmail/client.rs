use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::auth::TokenManager;
use crate::gmail::types::*;

pub struct GmailClient {
    http_client: reqwest::Client,
    token_manager: Arc<TokenManager>,
    base_url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WatchRequestBody<'a> {
    topic_name: &'a str,
    label_ids: &'a [String],
    label_filter_behavior: &'a str,
}

impl GmailClient {
    pub fn new(token_manager: Arc<TokenManager>, base_url: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            token_manager,
            base_url,
        }
    }

    async fn auth_header_value(&self) -> Result<String> {
        let token = self.token_manager.get_token().await?;
        Ok(format!("Bearer {}", token))
    }

    pub async fn search(
        &self,
        query: &str,
        max_results: u32,
        page_token: Option<&str>,
    ) -> Result<MessageListResponse> {
        let auth = self.auth_header_value().await?;
        let mut request = self
            .http_client
            .get(format!("{}/messages", self.base_url))
            .header("Authorization", &auth)
            .query(&[("q", query), ("maxResults", &max_results.to_string())]);

        if let Some(pt) = page_token {
            request = request.query(&[("pageToken", pt)]);
        }

        let resp = request.send().await.context("search request failed")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("search failed with status {}: {}", status, text);
        }
        resp.json().await.context("failed to deserialize search response")
    }

    pub async fn get_message(&self, id: &str) -> Result<Message> {
        let auth = self.auth_header_value().await?;
        let resp = self
            .http_client
            .get(format!("{}/messages/{}", self.base_url, id))
            .header("Authorization", &auth)
            .query(&[("format", "full")])
            .send()
            .await
            .context("get_message request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("get_message failed with status {}: {}", status, text);
        }
        resp.json().await.context("failed to deserialize message")
    }

    pub async fn get_thread(&self, id: &str) -> Result<ThreadResponse> {
        let auth = self.auth_header_value().await?;
        let resp = self
            .http_client
            .get(format!("{}/threads/{}", self.base_url, id))
            .header("Authorization", &auth)
            .query(&[("format", "full")])
            .send()
            .await
            .context("get_thread request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("get_thread failed with status {}: {}", status, text);
        }
        resp.json().await.context("failed to deserialize thread")
    }

    pub async fn list_labels(&self) -> Result<LabelListResponse> {
        let auth = self.auth_header_value().await?;
        let resp = self
            .http_client
            .get(format!("{}/labels", self.base_url))
            .header("Authorization", &auth)
            .send()
            .await
            .context("list_labels request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("list_labels failed with status {}: {}", status, text);
        }
        resp.json().await.context("failed to deserialize labels")
    }

    pub async fn watch_start(
        &self,
        topic: &str,
        label_ids: &[String],
    ) -> Result<WatchResponse> {
        let auth = self.auth_header_value().await?;
        let body = WatchRequestBody {
            topic_name: topic,
            label_ids,
            label_filter_behavior: "INCLUDE",
        };
        let resp = self
            .http_client
            .post(format!("{}/watch", self.base_url))
            .header("Authorization", &auth)
            .json(&body)
            .send()
            .await
            .context("watch_start request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("watch_start failed with status {}: {}", status, text);
        }
        resp.json().await.context("failed to deserialize watch response")
    }

    pub async fn watch_stop(&self) -> Result<()> {
        let auth = self.auth_header_value().await?;
        let resp = self
            .http_client
            .post(format!("{}/stop", self.base_url))
            .header("Authorization", &auth)
            .send()
            .await
            .context("watch_stop request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("watch_stop failed with status {}: {}", status, text);
        }
        Ok(())
    }

    pub async fn history(&self, start_history_id: u64) -> Result<HistoryResponse> {
        let auth = self.auth_header_value().await?;
        let resp = self
            .http_client
            .get(format!("{}/history", self.base_url))
            .header("Authorization", &auth)
            .query(&[
                ("startHistoryId", &start_history_id.to_string()),
                ("historyTypes", &"messageAdded".to_string()),
            ])
            .send()
            .await
            .context("history request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("history failed with status {}: {}", status, text);
        }
        resp.json().await.context("failed to deserialize history response")
    }
}
