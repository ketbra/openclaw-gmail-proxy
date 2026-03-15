use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::RwLock;

use crate::audit::{AuditLogger, AuditEvent};
use crate::gmail::client::GmailClient;
use crate::gmail::types::{GmailNotification, ReceivedMessage, SanitizedMessage};
use crate::proxy::routes::PollerStatus;
use crate::scrub::content::ContentScrubber;
use crate::scrub::labels::LabelFilter;

pub struct Processor {
    gmail: Arc<GmailClient>,
    label_filter: Arc<LabelFilter>,
    scrubber: Arc<ContentScrubber>,
    audit: Arc<AuditLogger>,
    hook_url: String,
    hook_token: String,
    http_client: reqwest::Client,
    state_path: PathBuf,
    last_history_id: Arc<RwLock<u64>>,
    poller_status: Arc<RwLock<PollerStatus>>,
}

impl Processor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gmail: Arc<GmailClient>,
        label_filter: Arc<LabelFilter>,
        scrubber: Arc<ContentScrubber>,
        audit: Arc<AuditLogger>,
        hook_url: String,
        hook_token: String,
        state_path: PathBuf,
        initial_history_id: u64,
        poller_status: Arc<RwLock<PollerStatus>>,
    ) -> Self {
        Self {
            gmail,
            label_filter,
            scrubber,
            audit,
            hook_url,
            hook_token,
            http_client: reqwest::Client::new(),
            state_path,
            last_history_id: Arc::new(RwLock::new(initial_history_id)),
            poller_status,
        }
    }

    pub async fn process_notifications(&self, messages: Vec<ReceivedMessage>) -> Result<()> {
        // Decode notifications and extract historyIds
        let mut max_history_id: u64 = 0;
        for msg in &messages {
            if let Some(data) = &msg.message.data {
                let decoded = STANDARD
                    .decode(data)
                    .context("failed to decode base64 notification data")?;
                let notification: GmailNotification = serde_json::from_slice(&decoded)
                    .context("failed to parse Gmail notification")?;
                if notification.history_id > max_history_id {
                    max_history_id = notification.history_id;
                }
            }
        }

        let current = { *self.last_history_id.read().await };

        if max_history_id <= current {
            return Ok(());
        }

        // Fetch history since last known id
        let history_resp = self.gmail.history(current).await?;

        // Deduplicate message IDs from history records
        let mut seen_ids = HashSet::new();
        let mut unique_ids = Vec::new();
        if let Some(records) = &history_resp.history {
            for record in records {
                if let Some(added) = &record.messages_added {
                    for ma in added {
                        if seen_ids.insert(ma.message.id.clone()) {
                            unique_ids.push(ma.message.id.clone());
                        }
                    }
                }
            }
        }

        // Fetch, filter, scrub each message
        let mut passing_messages = Vec::new();
        let mut suppressed_ids = Vec::new();

        for id in &unique_ids {
            let msg = match self.gmail.get_message(id).await {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("Failed to fetch message {}: {}", id, e);
                    continue;
                }
            };

            let labels = msg.label_ids.clone().unwrap_or_default();
            if self.label_filter.is_message_blocked(&labels) {
                suppressed_ids.push(id.clone());
                continue;
            }

            let from = msg.header("From").unwrap_or("");
            if self.scrubber.check_sender(from).is_blocked() {
                suppressed_ids.push(id.clone());
                continue;
            }

            let body = msg.extract_text_body().unwrap_or_default();
            let scrubbed = self.scrubber.scrub_body(&body);
            passing_messages.push(msg.to_sanitized(scrubbed));
        }

        // Forward passing messages to OpenClaw
        let delivered_count = passing_messages.len();
        if !passing_messages.is_empty() {
            self.forward_to_openclaw(&passing_messages).await?;
        }

        // Update last_history_id and persist
        {
            let mut guard = self.last_history_id.write().await;
            *guard = max_history_id;
        }
        Self::save_state(&self.state_path, max_history_id)?;

        // Update poller status timestamps
        {
            let now = chrono::Utc::now().to_rfc3339();
            let mut ps = self.poller_status.write().await;
            ps.connected = true;
            ps.last_message_received = Some(now.clone());
            if delivered_count > 0 {
                ps.last_message_delivered = Some(now);
            }
            ps.consecutive_errors = 0;
        }

        // Audit log
        self.audit.log(AuditEvent::PollProcessed {
            history_id: max_history_id,
            new_message_count: unique_ids.len(),
            delivered_count,
            suppressed_count: suppressed_ids.len(),
            suppressed_ids,
        });

        Ok(())
    }

    pub async fn forward_to_openclaw(&self, messages: &[SanitizedMessage]) -> Result<()> {
        let resp = self
            .http_client
            .post(&self.hook_url)
            .header("Authorization", format!("Bearer {}", self.hook_token))
            .json(&serde_json::json!({"messages": messages}))
            .send()
            .await
            .context("failed to forward messages to OpenClaw")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("OpenClaw hook returned status {}: {}", status, text);
        }

        Ok(())
    }

    pub fn save_state(path: &Path, history_id: u64) -> Result<()> {
        let tmp_path = path.with_extension("json.tmp");
        let data = serde_json::json!({"last_history_id": history_id});
        std::fs::write(&tmp_path, serde_json::to_string_pretty(&data)?)
            .context("failed to write state temp file")?;
        std::fs::rename(&tmp_path, path).context("failed to rename state file")?;
        Ok(())
    }

    pub fn load_state(path: &Path) -> Result<Option<u64>> {
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(path).context("failed to read state file")?;
        let parsed: serde_json::Value =
            serde_json::from_str(&content).context("failed to parse state file")?;
        let history_id = parsed
            .get("last_history_id")
            .and_then(|v| v.as_u64());
        Ok(history_id)
    }
}
