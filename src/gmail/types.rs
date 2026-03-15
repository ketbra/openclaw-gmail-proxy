use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Gmail API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageListResponse {
    pub messages: Option<Vec<MessageRef>>,
    pub next_page_token: Option<String>,
    pub result_size_estimate: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRef {
    pub id: String,
    pub thread_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub id: String,
    pub thread_id: String,
    pub label_ids: Option<Vec<String>>,
    pub snippet: Option<String>,
    pub payload: Option<MessagePart>,
    pub internal_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePart {
    pub mime_type: Option<String>,
    pub headers: Option<Vec<Header>>,
    pub body: Option<MessagePartBody>,
    pub parts: Option<Vec<MessagePart>>,
}

#[derive(Debug, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct MessagePartBody {
    pub data: Option<String>,
    pub size: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadResponse {
    pub id: String,
    pub messages: Option<Vec<Message>>,
}

#[derive(Debug, Deserialize)]
pub struct LabelListResponse {
    pub labels: Option<Vec<Label>>,
}

#[derive(Debug, Deserialize)]
pub struct Label {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchResponse {
    pub history_id: String,
    pub expiration: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryResponse {
    pub history: Option<Vec<HistoryRecord>>,
    pub history_id: Option<String>,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRecord {
    pub messages_added: Option<Vec<MessageAdded>>,
}

#[derive(Debug, Deserialize)]
pub struct MessageAdded {
    pub message: MessageRef,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PubSubPullResponse {
    pub received_messages: Option<Vec<ReceivedMessage>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedMessage {
    pub ack_id: String,
    pub message: PubSubMessage,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PubSubMessage {
    pub data: Option<String>,
    pub message_id: String,
    pub publish_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailNotification {
    pub email_address: String,
    pub history_id: u64,
}

// ---------------------------------------------------------------------------
// Sanitized output type
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Clone)]
pub struct SanitizedMessage {
    pub id: String,
    pub thread_id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub snippet: String,
    pub body_text: String,
    pub labels: Vec<String>,
    pub has_attachments: bool,
}

// ---------------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------------

impl Message {
    /// Extract plain text body from MIME parts recursively.
    /// Walks the tree preferring text/plain over text/html.
    /// Decodes base64url data (RFC 4648 section 5).
    pub fn extract_text_body(&self) -> Option<String> {
        let payload = self.payload.as_ref()?;
        Self::extract_text_from_part(payload)
    }

    fn extract_text_from_part(part: &MessagePart) -> Option<String> {
        let mime = part.mime_type.as_deref().unwrap_or("");

        if mime == "text/plain" {
            if let Some(body) = &part.body {
                if let Some(data) = &body.data {
                    return Self::decode_base64url(data);
                }
            }
            return None;
        }

        if mime.starts_with("multipart/") {
            if let Some(parts) = &part.parts {
                // First pass: look for text/plain (or nested multipart containing it)
                for sub in parts {
                    let sub_mime = sub.mime_type.as_deref().unwrap_or("");
                    if sub_mime == "text/plain" || sub_mime.starts_with("multipart/") {
                        if let Some(text) = Self::extract_text_from_part(sub) {
                            return Some(text);
                        }
                    }
                }
                // Second pass: fall back to text/html
                for sub in parts {
                    let sub_mime = sub.mime_type.as_deref().unwrap_or("");
                    if sub_mime == "text/html" {
                        if let Some(body) = &sub.body {
                            if let Some(data) = &body.data {
                                return Self::decode_base64url(data);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn decode_base64url(data: &str) -> Option<String> {
        // Gmail uses URL-safe base64, sometimes with padding, sometimes without.
        // Try with padding first, then without.
        URL_SAFE
            .decode(data)
            .or_else(|_| URL_SAFE_NO_PAD.decode(data))
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    /// Extract header value by name (case-insensitive lookup).
    pub fn header(&self, name: &str) -> Option<&str> {
        let payload = self.payload.as_ref()?;
        let headers = payload.headers.as_ref()?;
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    /// Check if the message has attachments.
    pub fn has_attachments(&self) -> bool {
        match &self.payload {
            Some(payload) => Self::part_has_attachments(payload),
            None => false,
        }
    }

    fn part_has_attachments(part: &MessagePart) -> bool {
        let mime = part.mime_type.as_deref().unwrap_or("");

        // Check Content-Disposition header for "attachment"
        if let Some(headers) = &part.headers {
            for h in headers {
                if h.name.eq_ignore_ascii_case("Content-Disposition")
                    && h.value.to_lowercase().contains("attachment")
                {
                    return true;
                }
            }
        }

        // Non-text, non-multipart part with a filename is an attachment
        if !mime.starts_with("text/") && !mime.starts_with("multipart/") && !mime.is_empty() {
            if let Some(headers) = &part.headers {
                for h in headers {
                    if h.value.to_lowercase().contains("filename") {
                        return true;
                    }
                }
            }
        }

        // Recurse into sub-parts
        if let Some(parts) = &part.parts {
            for sub in parts {
                if Self::part_has_attachments(sub) {
                    return true;
                }
            }
        }

        false
    }

    /// Convert to SanitizedMessage using a pre-scrubbed body text.
    pub fn to_sanitized(&self, scrubbed_body: String) -> SanitizedMessage {
        SanitizedMessage {
            id: self.id.clone(),
            thread_id: self.thread_id.clone(),
            from: self.header("From").unwrap_or("").to_string(),
            to: self.header("To").unwrap_or("").to_string(),
            subject: self.header("Subject").unwrap_or("").to_string(),
            date: self.header("Date").unwrap_or("").to_string(),
            snippet: self.snippet.clone().unwrap_or_default(),
            body_text: scrubbed_body,
            labels: self.label_ids.clone().unwrap_or_default(),
            has_attachments: self.has_attachments(),
        }
    }
}
