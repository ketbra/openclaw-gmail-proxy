use gmail_proxy::gmail::types::Message;

#[test]
fn test_extract_text_body_simple() {
    let msg: Message = serde_json::from_str(r#"{
        "id": "abc",
        "threadId": "def",
        "labelIds": ["INBOX"],
        "payload": {
            "mimeType": "text/plain",
            "body": { "data": "SGVsbG8gV29ybGQ" },
            "headers": [
                {"name": "From", "value": "alice@example.com"},
                {"name": "Subject", "value": "Test"}
            ]
        }
    }"#).unwrap();
    assert_eq!(msg.extract_text_body().unwrap(), "Hello World");
}

#[test]
fn test_extract_text_body_multipart() {
    let msg: Message = serde_json::from_str(r#"{
        "id": "abc",
        "threadId": "def",
        "payload": {
            "mimeType": "multipart/alternative",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": { "data": "UGxhaW4gdGV4dA" }
                },
                {
                    "mimeType": "text/html",
                    "body": { "data": "PGI-SFRNTDwvYj4" }
                }
            ]
        }
    }"#).unwrap();
    assert_eq!(msg.extract_text_body().unwrap(), "Plain text");
}

#[test]
fn test_extract_text_body_nested_multipart() {
    let msg: Message = serde_json::from_str(r#"{
        "id": "abc",
        "threadId": "def",
        "payload": {
            "mimeType": "multipart/mixed",
            "parts": [
                {
                    "mimeType": "multipart/alternative",
                    "parts": [
                        {
                            "mimeType": "text/plain",
                            "body": { "data": "TmVzdGVk" }
                        }
                    ]
                },
                {
                    "mimeType": "application/pdf",
                    "body": { "size": 12345 },
                    "headers": [{"name": "Content-Disposition", "value": "attachment; filename=\"doc.pdf\""}]
                }
            ]
        }
    }"#).unwrap();
    assert_eq!(msg.extract_text_body().unwrap(), "Nested");
    assert!(msg.has_attachments());
}

#[test]
fn test_header_extraction() {
    let msg: Message = serde_json::from_str(r#"{
        "id": "abc",
        "threadId": "def",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": "alice@example.com"},
                {"name": "To", "value": "bob@example.com"},
                {"name": "Subject", "value": "Hello"},
                {"name": "Date", "value": "Mon, 14 Mar 2026 10:30:00 +0000"}
            ],
            "body": { "data": "dGVzdA" }
        }
    }"#).unwrap();
    assert_eq!(msg.header("From"), Some("alice@example.com"));
    assert_eq!(msg.header("from"), Some("alice@example.com"));
    assert_eq!(msg.header("Subject"), Some("Hello"));
    assert_eq!(msg.header("X-Missing"), None);
}

#[test]
fn test_to_sanitized() {
    let msg: Message = serde_json::from_str(r#"{
        "id": "msg1",
        "threadId": "t1",
        "labelIds": ["INBOX", "CATEGORY_UPDATES"],
        "snippet": "Hello there...",
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": "alice@example.com"},
                {"name": "To", "value": "bob@example.com"},
                {"name": "Subject", "value": "Test Subject"},
                {"name": "Date", "value": "2026-03-14T10:30:00Z"}
            ],
            "body": { "data": "dGVzdA" }
        }
    }"#).unwrap();
    let sanitized = msg.to_sanitized("scrubbed body text".into());
    assert_eq!(sanitized.id, "msg1");
    assert_eq!(sanitized.thread_id, "t1");
    assert_eq!(sanitized.from, "alice@example.com");
    assert_eq!(sanitized.to, "bob@example.com");
    assert_eq!(sanitized.subject, "Test Subject");
    assert_eq!(sanitized.body_text, "scrubbed body text");
    assert_eq!(sanitized.labels, vec!["INBOX", "CATEGORY_UPDATES"]);
    assert!(!sanitized.has_attachments);
}

#[test]
fn test_no_payload_returns_none() {
    let msg: Message = serde_json::from_str(r#"{
        "id": "abc",
        "threadId": "def"
    }"#).unwrap();
    assert!(msg.extract_text_body().is_none());
}
