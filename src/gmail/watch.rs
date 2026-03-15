use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::warn;

use crate::gmail::client::GmailClient;
use crate::proxy::routes::WatchStatus;

pub struct WatchManager {
    gmail: Arc<GmailClient>,
    topic: String,
    label_ids: Vec<String>,
    renew_interval_secs: u64,
    status: Arc<RwLock<WatchStatus>>,
    initial_history_id: Option<u64>,
}

impl WatchManager {
    pub async fn start(
        gmail: Arc<GmailClient>,
        topic: String,
        label_ids: Vec<String>,
        renew_interval_secs: u64,
        status: Arc<RwLock<WatchStatus>>,
    ) -> Result<Self> {
        let resp = gmail.watch_start(&topic, &label_ids).await?;

        let history_id: u64 = resp.history_id.parse()?;

        {
            let mut s = status.write().await;
            s.active = true;
            s.expiration = Some(resp.expiration);
            s.last_history_id = Some(history_id);
        }

        Ok(Self {
            gmail,
            topic,
            label_ids,
            renew_interval_secs,
            status,
            initial_history_id: Some(history_id),
        })
    }

    pub fn initial_history_id(&self) -> Option<u64> {
        self.initial_history_id
    }

    pub async fn run_renewal_loop(self) -> ! {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(self.renew_interval_secs)).await;

            match self.gmail.watch_start(&self.topic, &self.label_ids).await {
                Ok(resp) => {
                    let history_id: u64 = match resp.history_id.parse() {
                        Ok(id) => id,
                        Err(e) => {
                            warn!("failed to parse history_id from watch renewal: {e}");
                            continue;
                        }
                    };
                    let mut s = self.status.write().await;
                    s.active = true;
                    s.expiration = Some(resp.expiration);
                    s.last_history_id = Some(history_id);
                }
                Err(e) => {
                    warn!("watch renewal failed: {e}");
                }
            }
        }
    }
}
