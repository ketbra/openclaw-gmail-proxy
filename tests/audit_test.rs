use gmail_proxy::audit::{AuditEvent, AuditLogger};
use tempfile::TempDir;

#[tokio::test]
async fn test_audit_log_search_event() {
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path()).unwrap();

    logger.log(AuditEvent::Search {
        raw_query: "from:alice".into(),
        parsed_query: "(from:alice) -label:agent-blocked".into(),
        result_count: 5,
        message_ids: vec!["m1".into(), "m2".into()],
        page_token_used: None,
        has_next_page: false,
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "Should have one audit file");

    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    let record: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(record["event"]["type"], "Search");
    assert_eq!(record["event"]["raw_query"], "from:alice");
    assert!(record["timestamp"].is_string());
    assert!(record["request_id"].is_string());
}

#[tokio::test]
async fn test_audit_log_get_message_event() {
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path()).unwrap();

    logger.log(AuditEvent::GetMessage {
        message_id: "msg1".into(),
        from: "alice@example.com".into(),
        subject: "Test Subject".into(),
        blocked: false,
        block_reason: None,
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    let record: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(record["event"]["type"], "GetMessage");
    assert_eq!(record["event"]["message_id"], "msg1");
    assert!(!content.contains("body_text"));
}

#[tokio::test]
async fn test_audit_log_with_duration() {
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path()).unwrap();

    logger.log_with_duration(
        AuditEvent::Search {
            raw_query: "test".into(),
            parsed_query: "(test) -label:agent-blocked".into(),
            result_count: 0,
            message_ids: vec![],
            page_token_used: None,
            has_next_page: false,
        },
        42,
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    let record: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(record["duration_ms"], 42);
}

#[tokio::test]
async fn test_audit_log_query_rejected() {
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path()).unwrap();

    logger.log(AuditEvent::QueryRejected {
        raw_query: "label:agent-blocked".into(),
        error: "query_validation_error".into(),
        hint: "This label is used for security filtering".into(),
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    let record: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(record["event"]["type"], "QueryRejected");
}
