use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

#[derive(Serialize)]
pub struct AuditRecord {
    pub timestamp: String,
    pub request_id: String,
    pub event: AuditEvent,
    pub duration_ms: u64,
}

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum AuditEvent {
    Search {
        raw_query: String,
        parsed_query: String,
        result_count: usize,
        message_ids: Vec<String>,
        page_token_used: Option<String>,
        has_next_page: bool,
    },
    GetMessage {
        message_id: String,
        from: String,
        subject: String,
        blocked: bool,
        block_reason: Option<String>,
    },
    GetThread {
        thread_id: String,
        message_count: usize,
        returned_count: usize,
        blocked_count: usize,
    },
    PollProcessed {
        history_id: u64,
        new_message_count: usize,
        delivered_count: usize,
        suppressed_count: usize,
        suppressed_ids: Vec<String>,
    },
    QueryRejected {
        raw_query: String,
        error: String,
        hint: String,
    },
}

pub struct AuditLogger {
    sender: mpsc::UnboundedSender<AuditRecord>,
}

impl AuditLogger {
    pub fn new(log_dir: &Path) -> anyhow::Result<Self> {
        let log_dir = PathBuf::from(log_dir);
        std::fs::create_dir_all(&log_dir)?;

        let (sender, mut receiver) = mpsc::unbounded_channel::<AuditRecord>();

        tokio::spawn(async move {
            while let Some(record) = receiver.recv().await {
                let date = chrono::Local::now().format("%Y-%m-%d").to_string();
                let file_path = log_dir.join(format!("audit-{date}.jsonl"));

                let line = match serde_json::to_string(&record) {
                    Ok(json) => json,
                    Err(e) => {
                        tracing::error!("Failed to serialize audit record: {e}");
                        continue;
                    }
                };

                let result = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&file_path)
                    .and_then(|mut file| {
                        writeln!(file, "{line}")?;
                        file.flush()
                    });

                if let Err(e) = result {
                    tracing::error!("Failed to write audit log to {}: {e}", file_path.display());
                }
            }
        });

        Ok(Self { sender })
    }

    pub fn log(&self, event: AuditEvent) {
        let record = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: uuid::Uuid::new_v4().to_string(),
            event,
            duration_ms: 0,
        };
        let _ = self.sender.send(record);
    }

    pub fn log_with_duration(&self, event: AuditEvent, duration_ms: u64) {
        let record = AuditRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: uuid::Uuid::new_v4().to_string(),
            event,
            duration_ms,
        };
        let _ = self.sender.send(record);
    }
}
