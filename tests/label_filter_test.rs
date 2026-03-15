use gmail_proxy::scrub::labels::LabelFilter;
use gmail_proxy::scrub::query::parse_query;

#[test]
fn test_message_with_blocked_label_is_blocked() {
    let filter = LabelFilter::new("Label_42".into(), "agent-blocked".into());
    let labels = vec!["INBOX".into(), "Label_42".into()];
    assert!(filter.is_message_blocked(&labels));
}

#[test]
fn test_message_without_blocked_label_passes() {
    let filter = LabelFilter::new("Label_42".into(), "agent-blocked".into());
    let labels = vec!["INBOX".into(), "CATEGORY_UPDATES".into()];
    assert!(!filter.is_message_blocked(&labels));
}

#[test]
fn test_empty_labels_passes() {
    let filter = LabelFilter::new("Label_42".into(), "agent-blocked".into());
    let empty: Vec<String> = vec![];
    assert!(!filter.is_message_blocked(&empty));
}

#[test]
fn test_secure_query_wrapping() {
    let filter = LabelFilter::new("Label_42".into(), "agent-blocked".into());
    let node = parse_query("from:alice").unwrap();
    let secured = filter.secure_query_string(&node);
    assert!(secured.contains("-label:agent-blocked"));
    assert!(secured.starts_with("("));
}

#[test]
fn test_accessors() {
    let filter = LabelFilter::new("Label_42".into(), "agent-blocked".into());
    assert_eq!(filter.blocked_label_id(), "Label_42");
    assert_eq!(filter.blocked_label_name(), "agent-blocked");
}
