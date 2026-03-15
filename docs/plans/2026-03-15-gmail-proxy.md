# Gmail Proxy for OpenClaw — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a single Rust binary that provides secure, read-only, content-scrubbed Gmail access for AI agents via a local HTTP API.

**Architecture:** Axum HTTP server on localhost exposes search/message/thread/health endpoints. Gmail queries are parsed into an AST, validated against an operator allowlist, and reconstructed with a label exclusion. A background Pub/Sub long-poll loop fetches new messages and forwards them to OpenClaw after scrubbing. OAuth token refresh runs in a background loop. All state is shared via `Arc<AppState>`.

**Tech Stack:** Rust, Axum 0.8, Tokio, reqwest, serde, clap 4, regex, tracing, chrono, base64, toml, anyhow

---

## Task 1: Project Scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `src/config.rs`
- Create: `skill/SKILL.md`

**Step 1: Initialize Cargo project with all dependencies**

Create `Cargo.toml`:

```toml
[package]
name = "gmail-proxy"
version = "0.1.0"
edition = "2024"

[dependencies]
axum = "0.8"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
regex = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
tracing-appender = "0.2"
chrono = { version = "0.4", features = ["serde"] }
toml = "0.8"
clap = { version = "4", features = ["derive"] }
open = "5"
anyhow = "1"
rand = "0.9"
uuid = { version = "1", features = ["v4"] }
futures = "0.3"

[dev-dependencies]
wiremock = "0.6"
tempfile = "3"
```

**Step 2: Create minimal `src/main.rs`**

```rust
mod config;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "gmail-proxy", about = "Secure Gmail proxy for OpenClaw")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install binary and service configuration
    Install {
        /// System-level install (requires sudo)
        #[arg(long)]
        system: bool,
        /// Service user name
        #[arg(long, default_value = "gmail-proxy")]
        service_user: String,
    },
    /// Interactive OAuth setup (opens browser)
    Setup {
        /// Path to config file
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// Path to Google client_secret JSON
        #[arg(long)]
        client_json: Option<std::path::PathBuf>,
        /// Service user to chown secrets to
        #[arg(long)]
        service_user: Option<String>,
    },
    /// Run the proxy server
    Serve {
        /// Path to config file
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Install OpenClaw skill file
    InstallSkill {
        /// Path to OpenClaw workspace
        #[arg(long)]
        workspace: Option<std::path::PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Install { system, service_user } => {
            eprintln!("install: not yet implemented");
        }
        Command::Setup { config, client_json, service_user } => {
            eprintln!("setup: not yet implemented");
        }
        Command::Serve { config } => {
            eprintln!("serve: not yet implemented");
        }
        Command::InstallSkill { workspace } => {
            eprintln!("install-skill: not yet implemented");
        }
    }
    Ok(())
}
```

**Step 3: Create `skill/SKILL.md`**

Write the SKILL.md content provided by the user (the full OpenClaw skill definition for agents to use the proxy). This file is embedded in the binary via `include_str!`.

**Step 4: Build and verify**

Run: `cargo build`
Expected: Compiles successfully

Run: `cargo run -- --help`
Expected: Shows subcommands: install, setup, serve, install-skill

**Step 5: Commit**

```
feat: project scaffold with CLI parsing and dependencies
```

---

## Task 2: Config Loading (`src/config.rs`)

**Files:**
- Create: `src/config.rs`
- Create: `tests/config_test.rs`

**Step 1: Write failing tests for config loading**

Create `tests/config_test.rs`:

```rust
use gmail_proxy::config::{load_config, Config, ConfigError};
use std::io::Write;
use tempfile::TempDir;

#[test]
fn test_load_valid_config() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let secrets_path = dir.path().join("secrets.toml");

    std::fs::write(&config_path, r#"
[auth]
client_id = "123.apps.googleusercontent.com"
client_secret = "GOCSPX-secret"
secrets_file = "secrets.toml"

[gmail]
account = "test@gmail.com"
pubsub_topic = "projects/test/topics/gmail-watch"
pubsub_subscription = "projects/test/subscriptions/gmail-proxy-pull"
watch_labels = ["INBOX"]
watch_renew_secs = 518400

[scrub]
blocked_label = "agent-blocked"
strip_links = true
otp_patterns = ["\\b\\d{4,8}\\b"]
blocked_sender_patterns = ["(?i)noreply@.*\\.google\\.com"]
url_strip_patterns = ["(?i)https?://[^\\s]*/reset[^\\s]*"]
allowed_operators = ["from", "to", "subject"]

[proxy]
bind = "127.0.0.1:8780"
search_fetch_concurrency = 10

[openclaw]
hook_url = "http://127.0.0.1:18789/hooks/gmail"

[audit]
log_dir = "/tmp/gmail-proxy-test-audit"
"#).unwrap();

    std::fs::write(&secrets_path, r#"
refresh_token = "1//0eXyz"
openclaw_hook_token = "hook-token-123"
"#).unwrap();

    // On test platforms, skip permission check
    let config = load_config(&config_path, true).unwrap();
    assert_eq!(config.auth.client_id, "123.apps.googleusercontent.com");
    assert_eq!(config.gmail.account, "test@gmail.com");
    assert_eq!(config.scrub.blocked_label, "agent-blocked");
    assert_eq!(config.secrets.refresh_token, "1//0eXyz");
    assert_eq!(config.proxy.bind, "127.0.0.1:8780");
}

#[test]
fn test_missing_secrets_file() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");

    std::fs::write(&config_path, r#"
[auth]
client_id = "x"
client_secret = "x"
secrets_file = "nonexistent.toml"

[gmail]
account = "test@gmail.com"
pubsub_topic = "projects/test/topics/t"
pubsub_subscription = "projects/test/subscriptions/s"
watch_labels = ["INBOX"]
watch_renew_secs = 518400

[scrub]
blocked_label = "agent-blocked"
strip_links = true
otp_patterns = []
blocked_sender_patterns = []
url_strip_patterns = []
allowed_operators = ["from"]

[proxy]
bind = "127.0.0.1:8780"
search_fetch_concurrency = 10

[openclaw]
hook_url = "http://127.0.0.1:18789/hooks/gmail"

[audit]
log_dir = "/tmp/test-audit"
"#).unwrap();

    let result = load_config(&config_path, true);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("secrets"), "Error should mention secrets file: {err}");
}

#[test]
fn test_missing_required_field() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    // Missing [gmail] section entirely
    std::fs::write(&config_path, r#"
[auth]
client_id = "x"
client_secret = "x"
secrets_file = "secrets.toml"
"#).unwrap();

    let result = load_config(&config_path, true);
    assert!(result.is_err());
}

#[test]
fn test_invalid_otp_regex() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("config.toml");
    let secrets_path = dir.path().join("secrets.toml");

    std::fs::write(&config_path, r#"
[auth]
client_id = "x"
client_secret = "x"
secrets_file = "secrets.toml"

[gmail]
account = "test@gmail.com"
pubsub_topic = "projects/test/topics/t"
pubsub_subscription = "projects/test/subscriptions/s"
watch_labels = ["INBOX"]
watch_renew_secs = 518400

[scrub]
blocked_label = "agent-blocked"
strip_links = true
otp_patterns = ["[invalid regex"]
blocked_sender_patterns = []
url_strip_patterns = []
allowed_operators = ["from"]

[proxy]
bind = "127.0.0.1:8780"
search_fetch_concurrency = 10

[openclaw]
hook_url = "http://127.0.0.1:18789/hooks/gmail"

[audit]
log_dir = "/tmp/test-audit"
"#).unwrap();

    std::fs::write(&secrets_path, r#"
refresh_token = "tok"
openclaw_hook_token = "hook"
"#).unwrap();

    let result = load_config(&config_path, true);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("regex") || err.contains("pattern"), "Should mention bad regex: {err}");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test config_test`
Expected: FAIL — module `config` doesn't export anything yet

**Step 3: Implement `src/config.rs`**

The config module needs:
- `Config` struct with all sections (`AuthConfig`, `GmailConfig`, `ScrubConfig`, `ProxyConfig`, `OpenClawConfig`, `AuditConfig`)
- `Secrets` struct (refresh_token, openclaw_hook_token)
- `load_config(path, skip_permission_check) -> Result<Config>` that:
  1. Reads and deserializes `config.toml`
  2. Resolves `secrets_file` relative to the config directory
  3. Optionally checks that secrets file has 0600 permissions (skip in tests)
  4. Reads and deserializes `secrets.toml`
  5. Validates all regex patterns compile
  6. Returns combined `Config` with `secrets` field
- `Paths` struct: `config`, `secrets`, `state`, `audit_dir`
- `resolve_paths(config_path) -> Paths` that derives all paths from the config file location and config values
- `ConfigError` enum or use `anyhow`

Key implementation details:
- Use `toml::from_str` for deserialization
- Secrets permission check: `std::fs::metadata().permissions().mode() & 0o077 == 0` on Unix
- All regex patterns should be compiled at load time and stored as `Vec<regex::Regex>` (separate `CompiledConfig` or just compile in a post-processing step)
- Make the module public in `main.rs` with `pub mod config;` and add `#[path]` or `lib.rs` as needed

Add `src/lib.rs` to expose modules for integration tests:
```rust
pub mod config;
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --test config_test`
Expected: All 4 tests pass

**Step 5: Commit**

```
feat: config loading with secrets resolution, permission checks, and regex validation
```

---

## Task 3: Query Parser — AST Types and Basic Parsing (`src/scrub/query.rs`)

**Files:**
- Create: `src/scrub/mod.rs`
- Create: `src/scrub/query.rs`
- Create: `tests/query_test.rs`

This is the security-critical module. Build it incrementally with tests at every step.

**Step 1: Write failing tests for basic query parsing**

Create `tests/query_test.rs` with initial tests:

```rust
use gmail_proxy::scrub::query::{parse_query, QueryNode};

#[test]
fn test_parse_single_word() {
    let node = parse_query("hello").unwrap();
    assert_eq!(node, QueryNode::Term("hello".into()));
}

#[test]
fn test_parse_two_words_implicit_and() {
    let node = parse_query("hello world").unwrap();
    match node {
        QueryNode::And(children) => {
            assert_eq!(children.len(), 2);
            assert_eq!(children[0], QueryNode::Term("hello".into()));
            assert_eq!(children[1], QueryNode::Term("world".into()));
        }
        other => panic!("Expected And, got {other:?}"),
    }
}

#[test]
fn test_parse_quoted_string() {
    let node = parse_query(r#""hello world""#).unwrap();
    assert_eq!(node, QueryNode::Quoted("hello world".into()));
}

#[test]
fn test_parse_operator() {
    let node = parse_query("from:alice").unwrap();
    match node {
        QueryNode::Operator { key, value, negated } => {
            assert_eq!(key, "from");
            assert_eq!(value, "alice");
            assert!(!negated);
        }
        other => panic!("Expected Operator, got {other:?}"),
    }
}

#[test]
fn test_parse_negated_operator() {
    let node = parse_query("-from:bob").unwrap();
    match node {
        QueryNode::Operator { key, value, negated } => {
            assert_eq!(key, "from");
            assert_eq!(value, "bob");
            assert!(negated);
        }
        other => panic!("Expected negated Operator, got {other:?}"),
    }
}

#[test]
fn test_parse_operator_quoted_value() {
    let node = parse_query(r#"subject:"hello world""#).unwrap();
    match node {
        QueryNode::Operator { key, value, negated } => {
            assert_eq!(key, "subject");
            assert_eq!(value, "hello world");
            assert!(!negated);
        }
        other => panic!("Expected Operator, got {other:?}"),
    }
}

#[test]
fn test_parse_or_expression() {
    let node = parse_query("from:alice OR from:bob").unwrap();
    match node {
        QueryNode::Or(children) => {
            assert_eq!(children.len(), 2);
        }
        other => panic!("Expected Or, got {other:?}"),
    }
}

#[test]
fn test_parse_group_parens() {
    let node = parse_query("(from:alice OR from:bob) subject:meeting").unwrap();
    match node {
        QueryNode::And(children) => {
            assert_eq!(children.len(), 2);
            match &children[0] {
                QueryNode::Group(inner) => match inner.as_ref() {
                    QueryNode::Or(_) => {}
                    other => panic!("Expected Or inside group, got {other:?}"),
                },
                other => panic!("Expected Group, got {other:?}"),
            }
        }
        other => panic!("Expected And, got {other:?}"),
    }
}

#[test]
fn test_parse_negated_term() {
    let node = parse_query("-spam").unwrap();
    match node {
        QueryNode::Not(inner) => {
            assert_eq!(*inner, QueryNode::Term("spam".into()));
        }
        other => panic!("Expected Not, got {other:?}"),
    }
}

#[test]
fn test_parse_curly_brace_group() {
    let node = parse_query("{from:alice from:bob}").unwrap();
    match node {
        QueryNode::Group(inner) => match inner.as_ref() {
            QueryNode::And(_) => {}
            other => panic!("Expected And inside group, got {other:?}"),
        },
        other => panic!("Expected Group, got {other:?}"),
    }
}

#[test]
fn test_parse_empty_query() {
    let result = parse_query("");
    assert!(result.is_err());
}

#[test]
fn test_unmatched_open_paren() {
    let result = parse_query("(from:alice");
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("Unmatched"), "Error should mention unmatched: {err}");
}

#[test]
fn test_unmatched_close_paren() {
    let result = parse_query("from:alice)");
    assert!(result.is_err());
}

#[test]
fn test_empty_group() {
    let result = parse_query("()");
    assert!(result.is_err());
}

#[test]
fn test_dangling_or() {
    let result = parse_query("from:alice OR");
    assert!(result.is_err());
}

#[test]
fn test_operator_missing_value() {
    let result = parse_query("from:");
    assert!(result.is_err());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test query_test`
Expected: FAIL — module doesn't exist

**Step 3: Create module structure and AST types**

Create `src/scrub/mod.rs`:
```rust
pub mod query;
pub mod content;
pub mod labels;
```

Add to `src/lib.rs`:
```rust
pub mod config;
pub mod scrub;
```

Create `src/scrub/query.rs` with:
- `QueryNode` enum (And, Or, Not, Group, Operator, Term, Quoted) — derive `Debug, Clone, PartialEq`
- `QueryError` struct (error, message, hint, position, query) — derive `Serialize`
- `parse_query(input: &str) -> Result<QueryNode, QueryError>` — hand-written recursive descent parser

Parser implementation:
- Tokenizer: split input into tokens (words, quoted strings, operators with `:`, parens, braces, `OR`, `-`)
- Parser functions: `parse_expr_list()` → `parse_or_expr()` → `parse_term()`
- `parse_term`: handles `-` prefix (negation), `(` / `{` (groups), quoted strings, operators (`key:value`), bare words
- `parse_or_expr`: if next token is `OR`, consume and parse right side, collect into `Or` node
- `parse_expr_list`: collect terms with implicit AND, if only one child return it unwrapped
- Track position for error reporting
- `QueryNode::Term` and `QueryNode::Quoted` are leaf nodes
- For `Operator`, parse `key:value` where value can be a quoted string or a bare word (up to next whitespace/paren)

Create stub files for `src/scrub/content.rs` and `src/scrub/labels.rs` (empty `// TODO` for now so the module compiles).

**Step 4: Run tests to verify they pass**

Run: `cargo test --test query_test`
Expected: All 16 tests pass

**Step 5: Commit**

```
feat: Gmail query parser with AST types and recursive descent parsing
```

---

## Task 4: Query Validation and Reconstruction (`src/scrub/query.rs`)

**Files:**
- Modify: `src/scrub/query.rs`
- Modify: `tests/query_test.rs`

**Step 1: Write failing tests for validation and reconstruction**

Add to `tests/query_test.rs`:

```rust
use gmail_proxy::scrub::query::{validate_query, reconstruct_query, reconstruct_with_label_exclusion};

// --- Validation tests ---

#[test]
fn test_validate_rejects_blocked_label() {
    let node = parse_query("label:agent-blocked").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("security filtering") || err.contains("blocked"),
        "Should mention security: {err}");
}

#[test]
fn test_validate_rejects_blocked_label_case_insensitive() {
    let node = parse_query("label:Agent-Blocked").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_negated_blocked_label() {
    // Even -label:agent-blocked is rejected — user shouldn't reference it at all
    let node = parse_query("-label:agent-blocked").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_disallowed_operator() {
    let node = parse_query("filename:secret.pdf").unwrap();
    let allowed = vec!["from", "to", "subject"]; // filename not in list
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("filename") || err.contains("supported"),
        "Should mention unsupported operator: {err}");
}

#[test]
fn test_validate_allows_valid_operator() {
    let node = parse_query("from:alice").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_ok());
}

#[test]
fn test_validate_rejects_is_draft() {
    let node = parse_query("is:draft").unwrap();
    let allowed = vec!["from", "to", "subject", "is"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_in_anywhere() {
    let node = parse_query("in:anywhere").unwrap();
    let allowed = vec!["from", "to", "subject", "in"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_in_trash() {
    let node = parse_query("in:trash").unwrap();
    let allowed = vec!["from", "to", "subject", "in"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_in_spam() {
    let node = parse_query("in:spam").unwrap();
    let allowed = vec!["from", "to", "subject", "in"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_rejects_excessive_depth() {
    // Build deeply nested query
    let deep = "(((((((((((from:alice)))))))))))";
    let node = parse_query(deep).unwrap();
    let allowed = vec!["from"];
    let result = validate_query(&node, &allowed, "agent-blocked", 5);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("depth") || err.contains("nesting"),
        "Should mention depth: {err}");
}

#[test]
fn test_validate_blocked_label_nested_in_or() {
    let node = parse_query("from:alice OR label:agent-blocked").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_validate_blocked_label_nested_in_group() {
    let node = parse_query("(label:agent-blocked from:alice)").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

// --- Reconstruction tests ---

#[test]
fn test_reconstruct_simple_term() {
    let node = parse_query("hello").unwrap();
    assert_eq!(reconstruct_query(&node), "hello");
}

#[test]
fn test_reconstruct_operator() {
    let node = parse_query("from:alice").unwrap();
    assert_eq!(reconstruct_query(&node), "from:alice");
}

#[test]
fn test_reconstruct_quoted() {
    let node = parse_query(r#""hello world""#).unwrap();
    assert_eq!(reconstruct_query(&node), r#""hello world""#);
}

#[test]
fn test_reconstruct_negated() {
    let node = parse_query("-from:bob").unwrap();
    assert_eq!(reconstruct_query(&node), "-from:bob");
}

#[test]
fn test_reconstruct_or() {
    let node = parse_query("from:alice OR from:bob").unwrap();
    assert_eq!(reconstruct_query(&node), "from:alice OR from:bob");
}

#[test]
fn test_reconstruct_group() {
    let node = parse_query("(from:alice OR from:bob) subject:meeting").unwrap();
    let result = reconstruct_query(&node);
    assert!(result.contains("(from:alice OR from:bob)"));
    assert!(result.contains("subject:meeting"));
}

#[test]
fn test_reconstruct_with_label_exclusion() {
    let node = parse_query("from:alice").unwrap();
    let result = reconstruct_with_label_exclusion(&node, "agent-blocked");
    assert_eq!(result, "(from:alice) -label:agent-blocked");
}

#[test]
fn test_reconstruct_complex_with_label_exclusion() {
    let node = parse_query("from:alice OR from:bob").unwrap();
    let result = reconstruct_with_label_exclusion(&node, "agent-blocked");
    assert_eq!(result, "(from:alice OR from:bob) -label:agent-blocked");
}

// --- Length limit ---

#[test]
fn test_rejects_query_over_length_limit() {
    let long_query = "a ".repeat(600); // ~1200 chars
    let result = parse_query(&long_query);
    assert!(result.is_err());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test query_test`
Expected: FAIL — `validate_query`, `reconstruct_query`, `reconstruct_with_label_exclusion` don't exist

**Step 3: Implement validation and reconstruction**

Add to `src/scrub/query.rs`:

`validate_query(node, allowed_operators, blocked_label, max_depth) -> Result<(), QueryError>`:
- Recursively walk the AST
- Track depth, reject if > `max_depth`
- For `Operator` nodes:
  - If `key` is `label` (case-insensitive) and `value` matches `blocked_label` (case-insensitive): reject
  - If `key` is `is` and `value` is `draft`: reject
  - If `key` is `in` and `value` is `anywhere`, `trash`, or `spam`: reject
  - If `key` (case-insensitive) is not in `allowed_operators` and not `label`/`is`/`in`: reject
  - Note: `label` is always blocked (not in allowed_operators), `is` and `in` are allowed except for specific values
- For all compound nodes (And, Or, Not, Group): recurse into children

`reconstruct_query(node) -> String`:
- `Term(s)` → `s`
- `Quoted(s)` → `"s"`
- `Operator { key, value, negated }` → if value contains spaces: `[-]key:"value"`, else `[-]key:value`
- `Not(inner)` → `-{reconstruct(inner)}`
- `Group(inner)` → `({reconstruct(inner)})`
- `And(children)` → join with ` `
- `Or(children)` → join with ` OR `

`reconstruct_with_label_exclusion(node, label) -> String`:
- `({reconstruct(node)}) -label:{label}`

Also add length limit check at the top of `parse_query`: reject queries over 1000 characters.

**Step 4: Run tests to verify they pass**

Run: `cargo test --test query_test`
Expected: All tests pass (original 16 + new ~20)

**Step 5: Commit**

```
feat: query validation (operator allowlist, blocked labels, depth limits) and AST reconstruction
```

---

## Task 5: Query Parser Edge Cases (Security Hardening)

**Files:**
- Modify: `tests/query_test.rs`
- Modify: `src/scrub/query.rs` (if any tests reveal bugs)

**Step 1: Add edge case tests**

Add to `tests/query_test.rs`:

```rust
// --- Security edge cases ---

#[test]
fn test_or_precedence_does_not_bypass_filter() {
    // Even with OR tricks, the label exclusion is structural
    let node = parse_query("from:alice OR from:bob").unwrap();
    let allowed = vec!["from"];
    validate_query(&node, &allowed, "agent-blocked", 10).unwrap();
    let result = reconstruct_with_label_exclusion(&node, "agent-blocked");
    // The exclusion must be outside the OR group
    assert!(result.starts_with("("), "User query should be grouped: {result}");
    assert!(result.ends_with("-label:agent-blocked"), "Exclusion at end: {result}");
}

#[test]
fn test_double_negation_blocked_label() {
    // --label:agent-blocked — still references the blocked label
    // Parser should handle double negation; validator should still reject
    let result = parse_query("--label:agent-blocked");
    // Either parse error or validation error is acceptable
    if let Ok(node) = result {
        let allowed = vec!["from"];
        let validation = validate_query(&node, &allowed, "agent-blocked", 10);
        assert!(validation.is_err(), "Double negation of blocked label must be rejected");
    }
    // Parse error is also fine
}

#[test]
fn test_blocked_label_with_different_case() {
    for label_form in &["Agent-Blocked", "AGENT-BLOCKED", "agent-BLOCKED", "aGeNt-bLoCkEd"] {
        let query = format!("label:{}", label_form);
        let node = parse_query(&query).unwrap();
        let allowed = vec!["from"];
        let result = validate_query(&node, &allowed, "agent-blocked", 10);
        assert!(result.is_err(), "Should reject label:{label_form}");
    }
}

#[test]
fn test_nested_groups_with_or() {
    let node = parse_query("((from:alice OR to:bob) (subject:meeting OR subject:call))").unwrap();
    let allowed = vec!["from", "to", "subject"];
    validate_query(&node, &allowed, "agent-blocked", 10).unwrap();
    let result = reconstruct_with_label_exclusion(&node, "agent-blocked");
    assert!(result.contains("-label:agent-blocked"));
}

#[test]
fn test_curly_braces_treated_as_group() {
    let node = parse_query("{from:alice from:bob}").unwrap();
    let allowed = vec!["from"];
    validate_query(&node, &allowed, "agent-blocked", 10).unwrap();
    let result = reconstruct_query(&node);
    // Curly braces reconstructed as parens (Gmail treats them similarly)
    assert!(result.contains("(") || result.contains("{"));
}

#[test]
fn test_unicode_in_quoted_string() {
    let node = parse_query(r#""日本語のメール""#).unwrap();
    assert_eq!(node, QueryNode::Quoted("日本語のメール".into()));
}

#[test]
fn test_adjacent_operators_implicit_and() {
    let node = parse_query("from:alice to:bob subject:lunch").unwrap();
    match node {
        QueryNode::And(children) => assert_eq!(children.len(), 3),
        other => panic!("Expected And with 3 children, got {other:?}"),
    }
}

#[test]
fn test_mixed_terms_and_operators() {
    let node = parse_query("invoice from:alice").unwrap();
    match node {
        QueryNode::And(children) => {
            assert_eq!(children.len(), 2);
            assert_eq!(children[0], QueryNode::Term("invoice".into()));
        }
        other => panic!("Expected And, got {other:?}"),
    }
}

#[test]
fn test_multiple_or_chains() {
    let node = parse_query("a OR b OR c").unwrap();
    match node {
        QueryNode::Or(children) => assert_eq!(children.len(), 3),
        other => panic!("Expected Or with 3 children, got {other:?}"),
    }
}

#[test]
fn test_or_with_group() {
    let node = parse_query("(a b) OR (c d)").unwrap();
    match node {
        QueryNode::Or(children) => assert_eq!(children.len(), 2),
        other => panic!("Expected Or, got {other:?}"),
    }
}

#[test]
fn test_only_whitespace_query() {
    let result = parse_query("   ");
    assert!(result.is_err());
}

#[test]
fn test_label_operator_always_rejected() {
    // Even a non-blocked label should be rejected (label: not in allowed_operators)
    let node = parse_query("label:important").unwrap();
    let allowed = vec!["from", "to", "subject"];
    let result = validate_query(&node, &allowed, "agent-blocked", 10);
    assert!(result.is_err());
}

#[test]
fn test_reconstruct_roundtrip() {
    let queries = vec![
        "from:alice",
        r#"subject:"hello world""#,
        "from:alice OR from:bob",
        "(from:alice OR from:bob) subject:meeting",
        "-from:noreply",
        "invoice has:attachment newer_than:7d",
    ];
    for q in queries {
        let node = parse_query(q).unwrap();
        let reconstructed = reconstruct_query(&node);
        let reparsed = parse_query(&reconstructed).unwrap();
        assert_eq!(node, reparsed, "Roundtrip failed for: {q}");
    }
}
```

**Step 2: Run all query tests**

Run: `cargo test --test query_test`
Expected: All tests pass. If any fail, fix the parser/validator.

**Step 3: Fix any issues found**

Address any edge case failures. Common issues:
- OR precedence: make sure `a b OR c d` parses as `a (b OR c) d` or define clear precedence
- Double negation handling
- Whitespace-only queries

**Step 4: Commit**

```
test: comprehensive query parser edge cases for security hardening
```

---

## Task 6: Content Scrubber (`src/scrub/content.rs`)

**Files:**
- Create: `src/scrub/content.rs`
- Create: `tests/content_scrub_test.rs`

**Step 1: Write failing tests**

Create `tests/content_scrub_test.rs`:

```rust
use gmail_proxy::scrub::content::ContentScrubber;
use regex::Regex;

fn test_scrubber() -> ContentScrubber {
    ContentScrubber::new(
        vec![
            Regex::new(r"\b\d{4,8}\b").unwrap(),
            Regex::new(r"(?i)verification code[:\s]+\S+").unwrap(),
            Regex::new(r"(?i)(one.time|temporary|security)\s+(code|password|pin)").unwrap(),
        ],
        vec![
            Regex::new(r"(?i)https?://[^\s]*/(reset|verify|confirm|auth|signin|login|activate)[^\s]*").unwrap(),
        ],
        vec![
            Regex::new(r"(?i)noreply@.*\.google\.com").unwrap(),
            Regex::new(r"(?i)no-reply@accounts\.google\.com").unwrap(),
            Regex::new(r"(?i)security@").unwrap(),
        ],
        true, // strip_links
    )
}

fn scrubber_no_strip_links() -> ContentScrubber {
    ContentScrubber::new(
        vec![Regex::new(r"\b\d{4,8}\b").unwrap()],
        vec![
            Regex::new(r"(?i)https?://[^\s]*/(reset|verify|confirm|auth)[^\s]*").unwrap(),
        ],
        vec![Regex::new(r"(?i)noreply@.*\.google\.com").unwrap()],
        false, // strip_links = false
    )
}

// --- Blocked sender tests ---

#[test]
fn test_blocked_sender_suppresses_message() {
    let scrubber = test_scrubber();
    let result = scrubber.check_sender("noreply@accounts.google.com");
    assert!(result.is_blocked());
}

#[test]
fn test_blocked_sender_security_at() {
    let scrubber = test_scrubber();
    assert!(scrubber.check_sender("security@example.com").is_blocked());
}

#[test]
fn test_allowed_sender() {
    let scrubber = test_scrubber();
    assert!(!scrubber.check_sender("alice@example.com").is_blocked());
}

#[test]
fn test_blocked_sender_case_insensitive() {
    let scrubber = test_scrubber();
    assert!(scrubber.check_sender("NoReply@Accounts.Google.Com").is_blocked());
}

// --- OTP pattern redaction ---

#[test]
fn test_redact_otp_code() {
    let scrubber = test_scrubber();
    let body = "Your code is 123456 please enter it.";
    let result = scrubber.scrub_body(body);
    assert!(!result.contains("123456"), "OTP should be redacted: {result}");
    assert!(result.contains("[REDACTED]"));
    assert!(result.contains("please enter it"));
}

#[test]
fn test_redact_verification_code() {
    let scrubber = test_scrubber();
    let body = "Your verification code: ABC123XYZ";
    let result = scrubber.scrub_body(body);
    assert!(!result.contains("ABC123XYZ"), "Code should be redacted: {result}");
}

#[test]
fn test_redact_one_time_password() {
    let scrubber = test_scrubber();
    let body = "Use this one-time password to log in.";
    let result = scrubber.scrub_body(body);
    assert!(result.contains("[REDACTED]"));
}

#[test]
fn test_no_false_positive_on_year() {
    // 4-digit numbers that look like years will get redacted too — this is by design
    // The otp_patterns from config are user-controlled, so this is expected behavior
    let scrubber = test_scrubber();
    let body = "Meeting scheduled for 2026.";
    let result = scrubber.scrub_body(body);
    // With \b\d{4,8}\b pattern, "2026" matches — this is expected
    assert!(result.contains("[REDACTED]"));
}

// --- URL redaction ---

#[test]
fn test_redact_auth_url() {
    let scrubber = scrubber_no_strip_links();
    let body = "Click here: https://example.com/auth/callback?token=abc123 to verify.";
    let result = scrubber.scrub_body(body);
    assert!(!result.contains("token=abc123"), "Auth URL should be redacted: {result}");
    assert!(result.contains("[REDACTED]"));
}

#[test]
fn test_redact_reset_url() {
    let scrubber = scrubber_no_strip_links();
    let body = "Reset your password: https://accounts.google.com/reset/pwd?id=xyz";
    let result = scrubber.scrub_body(body);
    assert!(!result.contains("id=xyz"), "Reset URL should be redacted: {result}");
}

#[test]
fn test_safe_url_preserved_when_strip_links_false() {
    let scrubber = scrubber_no_strip_links();
    let body = "Check out https://example.com/blog/article for details.";
    let result = scrubber.scrub_body(body);
    assert!(result.contains("https://example.com/blog/article"),
        "Safe URL should be preserved: {result}");
}

// --- strip_links = true ---

#[test]
fn test_strip_all_links_when_enabled() {
    let scrubber = test_scrubber();
    let body = "Visit https://example.com/blog/article for details.";
    let result = scrubber.scrub_body(body);
    assert!(!result.contains("https://"), "All links should be stripped: {result}");
    assert!(result.contains("[link removed]"));
}

#[test]
fn test_strip_http_links_too() {
    let scrubber = test_scrubber();
    let body = "Go to http://example.com for info.";
    let result = scrubber.scrub_body(body);
    assert!(!result.contains("http://"), "HTTP links should be stripped: {result}");
}

// --- Precedence: blocked sender > inline redaction ---

#[test]
fn test_scrub_pipeline_order() {
    let scrubber = test_scrubber();
    // Blocked sender — entire message suppressed, no need for body scrubbing
    assert!(scrubber.check_sender("noreply@mail.google.com").is_blocked());
    // Normal sender — body gets scrubbed
    assert!(!scrubber.check_sender("friend@example.com").is_blocked());
    let body = "Your code is 654321";
    let result = scrubber.scrub_body(body);
    assert!(result.contains("[REDACTED]"));
}

// --- Multiple patterns in one body ---

#[test]
fn test_multiple_redactions_in_one_body() {
    let scrubber = test_scrubber();
    let body = "Code: 123456. Also try https://evil.com/reset/pw?t=abc for recovery.";
    let result = scrubber.scrub_body(body);
    assert!(!result.contains("123456"), "OTP not redacted: {result}");
    assert!(!result.contains("evil.com"), "URL not redacted: {result}");
}

#[test]
fn test_clean_body_unchanged() {
    let scrubber = scrubber_no_strip_links();
    let body = "Hi Alice, the meeting is at noon. See you there.";
    let result = scrubber.scrub_body(body);
    assert_eq!(result, body);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test content_scrub_test`
Expected: FAIL

**Step 3: Implement `src/scrub/content.rs`**

```rust
pub struct ContentScrubber {
    otp_patterns: Vec<Regex>,
    url_strip_patterns: Vec<Regex>,
    blocked_sender_patterns: Vec<Regex>,
    strip_links: bool,
}

pub struct SenderCheckResult {
    pub blocked: bool,
    pub reason: Option<String>,
}

impl SenderCheckResult {
    pub fn is_blocked(&self) -> bool { self.blocked }
}
```

Methods:
- `new(otp_patterns, url_strip_patterns, blocked_sender_patterns, strip_links) -> Self`
- `check_sender(from: &str) -> SenderCheckResult` — check against blocked_sender_patterns
- `scrub_body(body: &str) -> String` — apply redactions in order:
  1. Replace OTP pattern matches with `[REDACTED]`
  2. Replace auth/reset URL matches with `[REDACTED]`
  3. If `strip_links`, replace all remaining `https?://\S+` with `[link removed]`

**Step 4: Run tests to verify they pass**

Run: `cargo test --test content_scrub_test`
Expected: All tests pass

**Step 5: Commit**

```
feat: content scrubber with sender blocking, OTP/URL redaction, and link stripping
```

---

## Task 7: Label Filter (`src/scrub/labels.rs`)

**Files:**
- Create: `src/scrub/labels.rs`
- Create: `tests/label_filter_test.rs`

**Step 1: Write failing tests**

Create `tests/label_filter_test.rs`:

```rust
use gmail_proxy::scrub::labels::LabelFilter;

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
    assert!(!filter.is_message_blocked(&[]));
}

#[test]
fn test_secure_query_wrapping() {
    let filter = LabelFilter::new("Label_42".into(), "agent-blocked".into());
    // Use the query parser to build a node, then have the filter add exclusion
    use gmail_proxy::scrub::query::parse_query;
    let node = parse_query("from:alice").unwrap();
    let secured = filter.secure_query_string(&node);
    assert!(secured.contains("-label:agent-blocked"));
    assert!(secured.starts_with("("));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test label_filter_test`
Expected: FAIL

**Step 3: Implement `src/scrub/labels.rs`**

```rust
pub struct LabelFilter {
    blocked_label_id: String,
    blocked_label_name: String,
}
```

Methods:
- `new(blocked_label_id, blocked_label_name) -> Self`
- `is_message_blocked(label_ids: &[String]) -> bool` — check if blocked_label_id is in the list
- `secure_query_string(node: &QueryNode) -> String` — call `reconstruct_with_label_exclusion` with `blocked_label_name`

**Step 4: Run tests to verify they pass**

Run: `cargo test --test label_filter_test`
Expected: All tests pass

**Step 5: Commit**

```
feat: label filter for message-level blocking and query security wrapping
```

---

## Task 8: Gmail Types (`src/gmail/types.rs`)

**Files:**
- Create: `src/gmail/mod.rs`
- Create: `src/gmail/types.rs`

**Step 1: Implement Gmail API serde types**

No tests needed for pure data types — they'll be tested through the client tests.

Create `src/gmail/mod.rs`:
```rust
pub mod types;
pub mod client;
pub mod watch;
```

Create `src/gmail/types.rs` with serde structs:

```rust
// Gmail API response types
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

// Sanitized output types (what the proxy API returns)
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

// Token refresh response
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

// Pub/Sub types
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
```

Also add a helper function for extracting text body from a `Message`:

```rust
impl Message {
    /// Extract plain text body from MIME parts, recursively walking the tree.
    /// Prefers text/plain. Decodes base64url data.
    pub fn extract_text_body(&self) -> Option<String> { ... }

    /// Extract header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> { ... }

    /// Check if message has attachments (any part with a filename).
    pub fn has_attachments(&self) -> bool { ... }

    /// Convert to SanitizedMessage with scrubbed body text.
    pub fn to_sanitized(&self, scrubbed_body: String) -> SanitizedMessage { ... }
}
```

**Step 2: Add a test for MIME body extraction**

Add `tests/gmail_types_test.rs`:

```rust
use gmail_proxy::gmail::types::Message;

#[test]
fn test_extract_text_body_simple() {
    // Build a Message with text/plain body
    let msg = serde_json::from_str::<Message>(r#"{
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
    // Multipart with text/plain and text/html — should prefer text/plain
    let msg = serde_json::from_str::<Message>(r#"{
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
    // multipart/mixed containing multipart/alternative containing text/plain
    let msg = serde_json::from_str::<Message>(r#"{
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
    let msg = serde_json::from_str::<Message>(r#"{
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
    assert_eq!(msg.header("from"), Some("alice@example.com")); // case-insensitive
    assert_eq!(msg.header("Subject"), Some("Hello"));
    assert_eq!(msg.header("X-Missing"), None);
}
```

**Step 3: Run tests**

Run: `cargo test --test gmail_types_test`
Expected: All pass

**Step 4: Commit**

```
feat: Gmail API serde types with MIME body extraction and sanitized output types
```

---

## Task 9: Auth Token Manager (`src/auth.rs`)

**Files:**
- Create: `src/auth.rs`
- Create: `tests/auth_test.rs`

**Step 1: Write failing tests**

Create `tests/auth_test.rs`:

```rust
use gmail_proxy::auth::TokenManager;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

#[tokio::test]
async fn test_token_refresh() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new-access-token",
            "expires_in": 3599,
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let token_url = format!("{}/token", mock_server.uri());
    let manager = TokenManager::new(
        "client-id".into(),
        "client-secret".into(),
        "refresh-token".into(),
        token_url,
    );

    let token = manager.get_token().await.unwrap();
    assert_eq!(token, "new-access-token");
}

#[tokio::test]
async fn test_token_cached_until_expiry() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "cached-token",
            "expires_in": 3599,
            "token_type": "Bearer"
        })))
        .expect(1) // Only called once despite two get_token() calls
        .mount(&mock_server)
        .await;

    let token_url = format!("{}/token", mock_server.uri());
    let manager = TokenManager::new(
        "client-id".into(),
        "client-secret".into(),
        "refresh-token".into(),
        token_url,
    );

    let t1 = manager.get_token().await.unwrap();
    let t2 = manager.get_token().await.unwrap();
    assert_eq!(t1, "cached-token");
    assert_eq!(t2, "cached-token");
}

#[tokio::test]
async fn test_token_refresh_failure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_grant"
        })))
        .mount(&mock_server)
        .await;

    let token_url = format!("{}/token", mock_server.uri());
    let manager = TokenManager::new(
        "client-id".into(),
        "client-secret".into(),
        "bad-refresh-token".into(),
        token_url,
    );

    let result = manager.get_token().await;
    assert!(result.is_err());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test auth_test`
Expected: FAIL

**Step 3: Implement `src/auth.rs`**

`TokenManager` struct:
- Holds `client_id`, `client_secret`, `refresh_token`, `token_url` (configurable for testing)
- Cached token + expiry in `Arc<RwLock<Option<(String, Instant)>>>`
- `get_token() -> Result<String>`: check cache, if expired or missing, call refresh endpoint
- `refresh()`: POST to token URL with `grant_type=refresh_token`, parse `TokenResponse`
- Cache with 5-minute safety margin (refresh 5 mins before actual expiry)
- `expires_in_secs() -> Option<u64>`: for health endpoint
- `is_valid() -> bool`: for health endpoint
- Default `token_url`: `https://oauth2.googleapis.com/token`

**Step 4: Run tests**

Run: `cargo test --test auth_test`
Expected: All pass

**Step 5: Commit**

```
feat: OAuth token manager with background refresh and caching
```

---

## Task 10: Gmail Client (`src/gmail/client.rs`)

**Files:**
- Create: `src/gmail/client.rs`
- Create: `tests/gmail_client_test.rs`

**Step 1: Write failing tests**

Create `tests/gmail_client_test.rs`:

```rust
use gmail_proxy::gmail::client::GmailClient;
use gmail_proxy::auth::TokenManager;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, query_param};

async fn setup() -> (MockServer, GmailClient) {
    let mock_server = MockServer::start().await;

    // Mock token endpoint
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "test-token",
            "expires_in": 3599,
            "token_type": "Bearer"
        })))
        .mount(&mock_server)
        .await;

    let token_url = format!("{}/token", mock_server.uri());
    let token_manager = TokenManager::new(
        "cid".into(), "csecret".into(), "refresh".into(), token_url,
    );
    let gmail_base = format!("{}/gmail/v1/users/me", mock_server.uri());
    let client = GmailClient::new(token_manager, gmail_base);

    (mock_server, client)
}

#[tokio::test]
async fn test_search_messages() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(query_param("q", "from:alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "messages": [
                {"id": "msg1", "threadId": "t1"},
                {"id": "msg2", "threadId": "t2"}
            ],
            "resultSizeEstimate": 2
        })))
        .mount(&mock_server)
        .await;

    let result = client.search("from:alice", 20, None).await.unwrap();
    assert_eq!(result.messages.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn test_get_message() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/msg1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg1",
            "threadId": "t1",
            "labelIds": ["INBOX"],
            "snippet": "Hello there",
            "payload": {
                "mimeType": "text/plain",
                "body": {"data": "SGVsbG8gdGhlcmU"},
                "headers": [
                    {"name": "From", "value": "alice@example.com"},
                    {"name": "Subject", "value": "Test"}
                ]
            }
        })))
        .mount(&mock_server)
        .await;

    let msg = client.get_message("msg1").await.unwrap();
    assert_eq!(msg.id, "msg1");
    assert_eq!(msg.header("From"), Some("alice@example.com"));
}

#[tokio::test]
async fn test_get_thread() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/threads/t1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "t1",
            "messages": [
                {
                    "id": "msg1", "threadId": "t1",
                    "payload": {"mimeType": "text/plain", "body": {"data": "Zmlyc3Q"}}
                },
                {
                    "id": "msg2", "threadId": "t1",
                    "payload": {"mimeType": "text/plain", "body": {"data": "c2Vjb25k"}}
                }
            ]
        })))
        .mount(&mock_server)
        .await;

    let thread = client.get_thread("t1").await.unwrap();
    assert_eq!(thread.messages.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_labels() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/labels"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "labels": [
                {"id": "INBOX", "name": "INBOX"},
                {"id": "Label_42", "name": "agent-blocked"}
            ]
        })))
        .mount(&mock_server)
        .await;

    let labels = client.list_labels().await.unwrap();
    let blocked = labels.labels.unwrap().into_iter().find(|l| l.name == "agent-blocked");
    assert!(blocked.is_some());
    assert_eq!(blocked.unwrap().id, "Label_42");
}

#[tokio::test]
async fn test_history_list() {
    let (mock_server, client) = setup().await;

    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/history"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "history": [
                {"messagesAdded": [{"message": {"id": "msg3", "threadId": "t3"}}]},
                {"messagesAdded": [{"message": {"id": "msg4", "threadId": "t4"}}]}
            ],
            "historyId": "99999"
        })))
        .mount(&mock_server)
        .await;

    let history = client.history(12345).await.unwrap();
    assert!(history.history.is_some());
    assert_eq!(history.history.as_ref().unwrap().len(), 2);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test gmail_client_test`
Expected: FAIL

**Step 3: Implement `src/gmail/client.rs`**

`GmailClient` struct:
- Holds `reqwest::Client`, `TokenManager` (in Arc), `base_url` (configurable for testing, default `https://gmail.googleapis.com/gmail/v1/users/me`)
- All methods take `&self`, use `self.token_manager.get_token().await?` for auth header
- Methods:
  - `search(query, max_results, page_token) -> Result<MessageListResponse>`
  - `get_message(id) -> Result<Message>`
  - `get_thread(id) -> Result<ThreadResponse>`
  - `list_labels() -> Result<LabelListResponse>`
  - `watch_start(topic, label_ids) -> Result<WatchResponse>`
  - `watch_stop() -> Result<()>`
  - `history(start_history_id) -> Result<HistoryResponse>`

**Step 4: Run tests**

Run: `cargo test --test gmail_client_test`
Expected: All pass

**Step 5: Commit**

```
feat: Gmail API client with mocked tests for search, message, thread, labels, and history
```

---

## Task 11: Audit Logging (`src/audit.rs`)

**Files:**
- Create: `src/audit.rs`
- Create: `tests/audit_test.rs`

**Step 1: Write failing tests**

Create `tests/audit_test.rs`:

```rust
use gmail_proxy::audit::{AuditLogger, AuditEvent};
use tempfile::TempDir;
use std::io::BufRead;

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
    }).await;

    // Read the audit log file
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1);

    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    let record: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(record["event"]["type"], "Search");
    assert_eq!(record["event"]["raw_query"], "from:alice");
    assert!(record["timestamp"].is_string());
    assert!(record["request_id"].is_string());
}

#[tokio::test]
async fn test_audit_log_does_not_contain_secrets() {
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path()).unwrap();

    logger.log(AuditEvent::GetMessage {
        message_id: "msg1".into(),
        from: "alice@example.com".into(),
        subject: "Token: abc123secret".into(),
        blocked: false,
        block_reason: None,
    }).await;

    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap()
        .filter_map(|e| e.ok())
        .collect();
    let content = std::fs::read_to_string(entries[0].path()).unwrap();
    // Should log subject (metadata is OK) but never message body
    assert!(content.contains("Token: abc123secret")); // subject is metadata, OK to log
    assert!(!content.contains("body")); // No body field in GetMessage event
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test audit_test`
Expected: FAIL

**Step 3: Implement `src/audit.rs`**

- `AuditLogger` struct: holds a `tokio::sync::mpsc::Sender<AuditRecord>` for background writing
- Background task: receives records, serializes to JSON, appends to daily-rotated file (`audit-YYYY-MM-DD.jsonl`)
- `AuditRecord` struct: `timestamp` (ISO 8601), `request_id` (UUID), `event` (AuditEvent), `duration_ms` (u64)
- `AuditEvent` enum as specified in project.md (Search, GetMessage, GetThread, PollProcessed, QueryRejected)
- `log(event)` method: creates record with timestamp + UUID, sends to background writer
- `log_with_duration(event, duration)` method: same but with measured duration
- File rotation: use `chrono::Local::now().format("audit-%Y-%m-%d.jsonl")`

**Step 4: Run tests**

Run: `cargo test --test audit_test`
Expected: All pass

**Step 5: Commit**

```
feat: structured audit logging with daily rotation and async background writing
```

---

## Task 12: Proxy API Routes (`src/proxy/routes.rs`)

**Files:**
- Create: `src/proxy/mod.rs`
- Create: `src/proxy/routes.rs`
- Create: `tests/proxy_routes_test.rs`

**Step 1: Write failing tests**

Create `tests/proxy_routes_test.rs`:

```rust
use axum::http::StatusCode;
use axum::body::Body;
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

// Test helper: build test app with mocked Gmail backend
// This will need a helper that sets up wiremock + creates the full Axum app
// with real scrubbing pipeline but mocked Gmail API

#[tokio::test]
async fn test_search_basic() {
    let (app, _mock) = setup_test_app().await;

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/search?q=from:alice&max=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["messages"].is_array());
}

#[tokio::test]
async fn test_search_invalid_query() {
    let (app, _mock) = setup_test_app().await;

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/search?q=(unclosed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].is_string());
    assert!(json["hint"].is_string());
}

#[tokio::test]
async fn test_search_blocked_label_query() {
    let (app, _mock) = setup_test_app().await;

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/search?q=label:agent-blocked")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_message() {
    let (app, _mock) = setup_test_app().await;

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/message/msg1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], "msg1");
    assert!(json["body_text"].is_string());
    // Verify no body_html field
    assert!(json.get("body_html").is_none());
}

#[tokio::test]
async fn test_get_message_blocked_returns_404() {
    // Mock a message that has the blocked label
    let (app, _mock) = setup_test_app_with_blocked_message().await;

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/message/blocked-msg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_thread() {
    let (app, _mock) = setup_test_app().await;

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/thread/t1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["thread_id"], "t1");
    assert!(json["messages"].is_array());
}

#[tokio::test]
async fn test_health() {
    let (app, _mock) = setup_test_app().await;

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["status"].is_string());
}

// Helper functions that create test app with wiremock backends
// These will be implemented in the test file, creating:
// - A wiremock MockServer for Gmail API
// - A TokenManager pointing at the mock
// - A GmailClient pointing at the mock
// - LabelFilter, ContentScrubber with test config
// - AuditLogger with tempdir
// - The full Axum Router with all state
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --test proxy_routes_test`
Expected: FAIL

**Step 3: Implement proxy routes**

Create `src/proxy/mod.rs`:
```rust
pub mod routes;
```

Create `src/proxy/routes.rs`:

Define `AppState`:
```rust
pub struct AppState {
    pub gmail: GmailClient,
    pub label_filter: LabelFilter,
    pub scrubber: ContentScrubber,
    pub audit: AuditLogger,
    pub allowed_operators: Vec<String>,
    pub blocked_label: String,
    pub max_depth: usize,
    pub search_concurrency: usize,
    pub poller_status: Arc<RwLock<PollerStatus>>,
    pub token_manager: Arc<TokenManager>,
    pub watch_status: Arc<RwLock<WatchStatus>>,
}
```

Routes:
- `GET /search` — parse query params (`q`, `max`, `page_token`), parse query into AST, validate, reconstruct with label exclusion, call Gmail search, fetch messages concurrently with `buffer_unordered`, filter blocked labels, scrub content, return `SanitizedMessage` array + pagination. Audit log the search.
- `GET /message/:id` — fetch message, check label filter (404 if blocked), check sender (404 if blocked), scrub body, return `SanitizedMessage`. Audit log.
- `GET /thread/:id` — fetch thread, filter out blocked messages, scrub remaining, return thread with filtered messages. Audit log.
- `GET /health` — return health JSON with watch, token, poller status.

Create `build_router(state: Arc<AppState>) -> Router` function.

Implement the `setup_test_app` helper in the test file using wiremock.

**Step 4: Run tests**

Run: `cargo test --test proxy_routes_test`
Expected: All pass

**Step 5: Commit**

```
feat: Axum proxy routes for search, message, thread, and health endpoints
```

---

## Task 13: Watch Manager (`src/gmail/watch.rs`)

**Files:**
- Create: `src/gmail/watch.rs`
- Create: `tests/watch_test.rs`

**Step 1: Write failing tests**

```rust
use gmail_proxy::gmail::watch::WatchManager;
// Test that WatchManager:
// - Calls watch_start on creation
// - Stores the returned history_id and expiration
// - Schedules renewal before expiration
// Use wiremock to mock the watch endpoint

#[tokio::test]
async fn test_watch_registration() {
    // Mock Gmail watch endpoint returning historyId + expiration
    // Verify WatchManager stores the state correctly
}

#[tokio::test]
async fn test_watch_provides_initial_history_id() {
    // After registration, initial_history_id() should return the value from watch response
}
```

**Step 2: Implement `src/gmail/watch.rs`**

`WatchManager`:
- `start(gmail: &GmailClient, topic, label_ids, renew_interval) -> Result<Self>`
- Calls `gmail.watch_start()`, stores history_id + expiration in `Arc<RwLock<WatchStatus>>`
- `run_renewal_loop(self) -> JoinHandle<()>` — tokio task that sleeps until renewal time, re-registers watch
- `WatchStatus { active, expiration, last_history_id }`

**Step 3: Run tests, commit**

```
feat: Gmail watch manager with auto-renewal loop
```

---

## Task 14: Pub/Sub Poller (`src/poller/`)

**Files:**
- Create: `src/poller/mod.rs`
- Create: `src/poller/pubsub.rs`
- Create: `src/poller/processor.rs`
- Create: `tests/poller_test.rs`

**Step 1: Write failing tests**

Test the poller components:
- `PubSubClient::pull()` — mock the Pub/Sub REST API, verify it decodes base64 data, extracts history IDs
- `PubSubClient::acknowledge()` — verify it sends ack IDs
- `Processor::process_history()` — mock Gmail history endpoint, verify deduplication, scrubbing, forwarding
- Test exponential backoff behavior on errors

**Step 2: Implement poller**

`src/poller/pubsub.rs`:
- `PubSubClient` struct: holds `reqwest::Client` (with 45s timeout), `TokenManager`, `subscription` URL
- `pull() -> Result<Vec<ReceivedMessage>>` — POST to `:pull`, return messages or empty vec on timeout
- `acknowledge(ack_ids) -> Result<()>` — POST to `:acknowledge`

`src/poller/processor.rs`:
- `Processor` struct: holds `GmailClient`, `LabelFilter`, `ContentScrubber`, `AuditLogger`, openclaw hook URL + token
- `process_notifications(messages) -> Result<()>`:
  1. Decode base64 data from each Pub/Sub message → extract historyId
  2. Take max historyId
  3. If > last_known: call history.list, deduplicate message IDs
  4. For each message: fetch, check labels, check sender, scrub
  5. Forward passing messages to OpenClaw hook (POST with Bearer token)
  6. Update and persist last_known_history_id (atomic write to state.json)
  7. Audit log

`src/poller/mod.rs`:
- `run_poller(pubsub, processor, state) -> JoinHandle<()>` — the main long-poll loop with backoff

**Step 3: State persistence**

- `save_state(path, history_id) -> Result<()>` — write to `.tmp` file then rename (atomic)
- `load_state(path) -> Result<Option<u64>>` — read history_id from state.json

**Step 4: Run tests, commit**

```
feat: Pub/Sub long-poll poller with history processing and OpenClaw forwarding
```

---

## Task 15: Serve Subcommand (Wire Everything Together)

**Files:**
- Modify: `src/main.rs`

**Step 1: Implement `serve` subcommand**

Wire up the full startup sequence:

```rust
async fn serve(config_path: Option<PathBuf>) -> Result<()> {
    // 1. Resolve config path (default: ~/.config/gmail-proxy/config.toml)
    // 2. Load config + secrets (validates permissions)
    // 3. Initialize tracing (stderr for operational logs)
    // 4. Initialize audit logger
    // 5. Create TokenManager, force initial refresh to validate credentials
    // 6. Create GmailClient
    // 7. Resolve label names to IDs (list_labels, find "agent-blocked")
    //    — exit with error if not found
    // 8. Build ContentScrubber from compiled config regexes
    // 9. Build LabelFilter with resolved label ID
    // 10. Load or initialize state (last_history_id)
    // 11. Register Gmail watch, get initial history_id if no state
    // 12. Start watch renewal loop
    // 13. Start Pub/Sub poller
    // 14. Build AppState, create router
    // 15. Start Axum server on bind address
    // 16. Wait for SIGTERM/SIGINT, graceful shutdown
}
```

Use `tokio::select!` to run server + poller + watch renewal concurrently.
Use `tokio::signal` for graceful shutdown.

**Step 2: Test manually**

Run: `cargo build`
Run: `cargo run -- serve --help`
Expected: Shows serve options

**Step 3: Commit**

```
feat: serve subcommand wiring all components together with graceful shutdown
```

---

## Task 16: Install Subcommand

**Files:**
- Modify: `src/main.rs`
- Create: `src/install.rs`

**Step 1: Implement install logic**

Two modes: user-level (default) and system-level (`--system`).

User-level:
- Copy binary to `~/.local/bin/gmail-proxy`
- Create `~/.config/gmail-proxy/` with template `config.toml`
- Create `~/.local/share/gmail-proxy/` for state + audit
- macOS: write `~/Library/LaunchAgents/com.gmail-proxy.plist`
- Linux: write `~/.config/systemd/user/gmail-proxy.service`

System-level:
- Copy binary to `/usr/local/bin/gmail-proxy`
- Create service user (macOS: `_gmailproxy`, Linux: `gmail-proxy`)
- Create config/state/log directories with correct ownership
- Install service file (macOS: launchd plist, Linux: systemd unit with hardening)

Both modes:
- Idempotent: re-running updates binary + service file, doesn't touch existing config/secrets
- Template `config.toml` has placeholder values with comments
- Print next steps after install

**Step 2: Test**

Run: `cargo run -- install --help`
Expected: Shows install options

**Step 3: Commit**

```
feat: install subcommand with user-level and system-level modes
```

---

## Task 17: Setup Subcommand (OAuth Flow)

**Files:**
- Modify: `src/main.rs`
- Modify: `src/auth.rs`

**Step 1: Implement OAuth setup flow**

Add to `src/auth.rs`:
- `run_oauth_setup(config, client_json_path, service_user) -> Result<()>`
- Parse `client_secret_*.json` if provided → write client_id/client_secret to config.toml
- Spin up ephemeral Axum listener on `127.0.0.1:{random_port}` with a single callback route
- Open browser to Google consent screen with scopes `gmail.readonly` + `pubsub`
- Catch redirect, extract auth code
- Exchange code for tokens (POST to token endpoint)
- Generate random `openclaw_hook_token`
- Write `secrets.toml`
- Optional: `sudo chown` to service user, or print command for user to run
- Print summary

**Step 2: Test manually**

This requires a real browser + Google account — can't automate in CI.
Test that the CLI accepts the flags and prints the expected prompts.

**Step 3: Commit**

```
feat: interactive OAuth setup with ephemeral callback server
```

---

## Task 18: Install-Skill Subcommand

**Files:**
- Modify: `src/main.rs`

**Step 1: Implement install-skill**

```rust
const SKILL_CONTENT: &str = include_str!("../skill/SKILL.md");

fn install_skill(workspace: Option<PathBuf>) -> Result<()> {
    let workspace = workspace
        .or_else(|| find_workspace())  // check ~/.openclaw/workspace, $OPENCLAW_WORKSPACE, cwd
        .unwrap_or_else(|| {
            // No workspace found — print to stdout
            println!("{SKILL_CONTENT}");
            std::process::exit(0);
        });

    let skill_dir = workspace.join("skills").join("gmail-proxy");
    std::fs::create_dir_all(&skill_dir)?;
    std::fs::write(skill_dir.join("SKILL.md"), SKILL_CONTENT)?;
    eprintln!("Skill installed to {}", skill_dir.display());
    Ok(())
}
```

**Step 2: Test**

Run: `cargo run -- install-skill`
Expected: Prints skill content to stdout (no workspace found)

**Step 3: Commit**

```
feat: install-skill subcommand with embedded SKILL.md
```

---

## Task 19: Integration Smoke Test

**Files:**
- Create: `tests/integration_test.rs`

**Step 1: Write end-to-end test with mocked Gmail**

Full integration test:
1. Start wiremock server mocking all Gmail endpoints
2. Create temp config + secrets files
3. Build the full AppState
4. Build the Axum router
5. Send requests through the router (using tower's `ServiceExt::oneshot`)
6. Verify:
   - Search query goes through AST parsing → validation → reconstruction
   - Blocked messages are filtered out
   - Content scrubbing happens (OTPs redacted, links stripped)
   - Audit log entries are written
   - Health endpoint returns valid status

**Step 2: Run**

Run: `cargo test --test integration_test`
Expected: All pass

**Step 3: Commit**

```
test: end-to-end integration test with mocked Gmail backend
```

---

## Task 20: Final Polish

**Files:**
- Modify: various

**Step 1: Add tracing initialization to serve**

Configure `tracing-subscriber`:
- stderr: human-readable for dev, JSON for production (controlled by env var)
- `RUST_LOG` env var for level filtering
- Default: `info` for gmail_proxy, `warn` for dependencies

**Step 2: Add error context with anyhow**

Review all `?` operators — add `.context("meaningful message")` where errors would be confusing.

**Step 3: Clippy + fmt**

Run: `cargo clippy -- -D warnings`
Run: `cargo fmt --check`
Fix any issues.

**Step 4: Final commit**

```
chore: tracing setup, error context, clippy/fmt cleanup
```

---

## Summary

| Task | Module | Priority | Est. Complexity |
|------|--------|----------|----------------|
| 1 | Scaffold | Setup | Low |
| 2 | Config | Foundation | Medium |
| 3 | Query parser (basic) | Security-critical | High |
| 4 | Query validation/reconstruction | Security-critical | High |
| 5 | Query edge cases | Security-critical | Medium |
| 6 | Content scrubber | High priority | Medium |
| 7 | Label filter | High priority | Low |
| 8 | Gmail types | Foundation | Medium |
| 9 | Auth token manager | Foundation | Medium |
| 10 | Gmail client | Core | Medium |
| 11 | Audit logging | Core | Medium |
| 12 | Proxy routes | Core | High |
| 13 | Watch manager | Core | Medium |
| 14 | Pub/Sub poller | Core | High |
| 15 | Serve (wire up) | Integration | Medium |
| 16 | Install subcommand | CLI | Medium |
| 17 | Setup (OAuth) | CLI | High |
| 18 | Install-skill | CLI | Low |
| 19 | Integration test | Testing | Medium |
| 20 | Polish | Cleanup | Low |

After Task 12, you have a working proxy you can curl with a manually-provided token. Tasks 13-14 add push notifications. Tasks 16-18 add CLI convenience.
