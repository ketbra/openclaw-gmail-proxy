use gmail_proxy::config::load_config;
use std::fs;
use tempfile::TempDir;

fn valid_config_toml() -> &'static str {
    r#"
[auth]
client_id = "test-client-id"
client_secret = "test-client-secret"
secrets_file = "secrets.toml"

[gmail]
account = "user@example.com"
pubsub_topic = "projects/myproject/topics/gmail"
pubsub_subscription = "projects/myproject/subscriptions/gmail"
watch_labels = ["INBOX"]
watch_renew_secs = 86400

[scrub]
blocked_label = "BLOCKED"
strip_links = true
otp_patterns = ["\\b\\d{6}\\b"]
blocked_sender_patterns = ["spam@example\\.com"]
url_strip_patterns = ["https?://tracking\\.example\\.com/.*"]
allowed_operators = ["from", "to", "subject"]

[proxy]
bind = "127.0.0.1:8080"
search_fetch_concurrency = 4

[openclaw]
hook_url = "https://openclaw.example.com/hook"

[audit]
log_dir = "audit_logs"
state_dir = "state"
"#
}

fn valid_secrets_toml() -> &'static str {
    r#"
refresh_token = "test-refresh-token"
openclaw_hook_token = "test-hook-token"
"#
}

#[test]
fn test_load_valid_config() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let secrets_path = dir.path().join("secrets.toml");

    fs::write(&config_path, valid_config_toml()).unwrap();
    fs::write(&secrets_path, valid_secrets_toml()).unwrap();

    let config = load_config(&config_path, true).expect("should load valid config");

    assert_eq!(config.auth.client_id, "test-client-id");
    assert_eq!(config.auth.client_secret, "test-client-secret");
    assert_eq!(config.auth.secrets_file, "secrets.toml");
    assert_eq!(config.gmail.account, "user@example.com");
    assert_eq!(config.gmail.pubsub_topic, "projects/myproject/topics/gmail");
    assert_eq!(config.gmail.watch_labels, vec!["INBOX"]);
    assert_eq!(config.gmail.watch_renew_secs, 86400);
    assert!(config.scrub.strip_links);
    assert_eq!(config.scrub.blocked_label, "BLOCKED");
    assert_eq!(config.scrub.otp_patterns, vec!["\\b\\d{6}\\b"]);
    assert_eq!(config.scrub.allowed_operators, vec!["from", "to", "subject"]);
    assert_eq!(config.proxy.bind, "127.0.0.1:8080");
    assert_eq!(config.proxy.search_fetch_concurrency, 4);
    assert_eq!(config.openclaw.hook_url, "https://openclaw.example.com/hook");
    assert_eq!(config.audit.log_dir, "audit_logs");
    assert_eq!(config.secrets.refresh_token, "test-refresh-token");
    assert_eq!(config.secrets.openclaw_hook_token, "test-hook-token");
}

#[test]
fn test_missing_secrets_file() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    // Write config that references a secrets file that doesn't exist
    fs::write(&config_path, valid_config_toml()).unwrap();

    let err = load_config(&config_path, true).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.to_lowercase().contains("secrets"),
        "error should mention 'secrets', got: {}",
        msg
    );
}

#[test]
fn test_missing_required_field() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let secrets_path = dir.path().join("secrets.toml");

    // Config missing [gmail] section
    let incomplete_config = r#"
[auth]
client_id = "id"
client_secret = "secret"
secrets_file = "secrets.toml"

[scrub]
blocked_label = "BLOCKED"
strip_links = false
otp_patterns = []
blocked_sender_patterns = []
url_strip_patterns = []
allowed_operators = []

[proxy]
bind = "127.0.0.1:8080"
search_fetch_concurrency = 2

[openclaw]
hook_url = "https://example.com/hook"

[audit]
log_dir = "logs"
state_dir = "state"
"#;

    fs::write(&config_path, incomplete_config).unwrap();
    fs::write(&secrets_path, valid_secrets_toml()).unwrap();

    let err = load_config(&config_path, true).unwrap_err();
    let msg = format!("{:#}", err);
    // toml deserialization error should mention the missing field
    assert!(
        msg.contains("gmail"),
        "error should mention missing 'gmail' section, got: {}",
        msg
    );
}

#[test]
fn test_invalid_otp_regex() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let secrets_path = dir.path().join("secrets.toml");

    let config_with_bad_regex = r#"
[auth]
client_id = "id"
client_secret = "secret"
secrets_file = "secrets.toml"

[gmail]
account = "user@example.com"
pubsub_topic = "projects/p/topics/t"
pubsub_subscription = "projects/p/subscriptions/s"
watch_labels = ["INBOX"]
watch_renew_secs = 3600

[scrub]
blocked_label = "BLOCKED"
strip_links = false
otp_patterns = ["[invalid regex"]
blocked_sender_patterns = []
url_strip_patterns = []
allowed_operators = []

[proxy]
bind = "127.0.0.1:8080"
search_fetch_concurrency = 2

[openclaw]
hook_url = "https://example.com/hook"

[audit]
log_dir = "logs"
state_dir = "state"
"#;

    fs::write(&config_path, config_with_bad_regex).unwrap();
    fs::write(&secrets_path, valid_secrets_toml()).unwrap();

    let err = load_config(&config_path, true).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.to_lowercase().contains("regex") || msg.to_lowercase().contains("pattern"),
        "error should mention 'regex' or 'pattern', got: {}",
        msg
    );
}
