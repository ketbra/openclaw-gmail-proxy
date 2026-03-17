use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub secrets_file: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GmailConfig {
    pub account: String,
    pub pubsub_topic: String,
    pub pubsub_subscription: String,
    pub watch_labels: Vec<String>,
    pub watch_renew_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScrubConfig {
    pub blocked_label: String,
    pub strip_links: bool,
    pub otp_patterns: Vec<String>,
    pub blocked_sender_patterns: Vec<String>,
    pub url_strip_patterns: Vec<String>,
    pub allowed_operators: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    pub socket_path: String,
    pub search_fetch_concurrency: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OpenClawConfig {
    pub hook_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    pub log_dir: String,
    pub state_dir: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Secrets {
    pub refresh_token: String,
    pub openclaw_hook_token: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConfigFile {
    pub auth: AuthConfig,
    pub gmail: GmailConfig,
    pub scrub: ScrubConfig,
    pub proxy: ProxyConfig,
    pub openclaw: OpenClawConfig,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub auth: AuthConfig,
    pub gmail: GmailConfig,
    pub scrub: ScrubConfig,
    pub proxy: ProxyConfig,
    pub openclaw: OpenClawConfig,
    pub audit: AuditConfig,
    pub secrets: Secrets,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub config: PathBuf,
    pub secrets: PathBuf,
    pub state: PathBuf,
    pub audit_dir: PathBuf,
}

/// Validate that all regex patterns in the config compile successfully.
pub fn validate_patterns(config: &ConfigFile) -> Result<()> {
    for (i, pat) in config.scrub.otp_patterns.iter().enumerate() {
        regex::Regex::new(pat)
            .with_context(|| format!("invalid regex in otp_patterns[{}]: {}", i, pat))?;
    }
    for (i, pat) in config.scrub.blocked_sender_patterns.iter().enumerate() {
        regex::Regex::new(pat)
            .with_context(|| format!("invalid regex in blocked_sender_patterns[{}]: {}", i, pat))?;
    }
    for (i, pat) in config.scrub.url_strip_patterns.iter().enumerate() {
        regex::Regex::new(pat)
            .with_context(|| format!("invalid regex in url_strip_patterns[{}]: {}", i, pat))?;
    }
    Ok(())
}

/// Load configuration from the given TOML file path.
///
/// If `skip_permission_check` is false, the secrets file must have 0600
/// permissions on Unix.
pub fn load_config(path: &Path, skip_permission_check: bool) -> Result<Config> {
    let config_text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    let config_file: ConfigFile = toml::from_str(&config_text)
        .with_context(|| format!("failed to parse config file: {}", path.display()))?;

    validate_patterns(&config_file).context("config pattern validation failed")?;

    // Resolve secrets_file relative to config file's parent directory
    let config_dir = path.parent().unwrap_or(Path::new("."));
    let secrets_path = config_dir.join(&config_file.auth.secrets_file);

    if !skip_permission_check {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&secrets_path)
                .with_context(|| format!("failed to stat secrets file: {}", secrets_path.display()))?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                anyhow::bail!(
                    "secrets file {} has permissions {:04o}, expected 0600",
                    secrets_path.display(),
                    mode
                );
            }
        }
    }

    let secrets_text = std::fs::read_to_string(&secrets_path)
        .with_context(|| format!("failed to read secrets file: {}", secrets_path.display()))?;

    let secrets: Secrets = toml::from_str(&secrets_text)
        .with_context(|| format!("failed to parse secrets file: {}", secrets_path.display()))?;

    Ok(Config {
        auth: config_file.auth,
        gmail: config_file.gmail,
        scrub: config_file.scrub,
        proxy: config_file.proxy,
        openclaw: config_file.openclaw,
        audit: config_file.audit,
        secrets,
    })
}

/// Derive all relevant paths from the config file path and loaded config values.
pub fn resolve_paths(config_path: &Path, config: &Config) -> Paths {
    let config_dir = config_path.parent().unwrap_or(Path::new("."));
    Paths {
        config: config_path.to_path_buf(),
        secrets: config_dir.join(&config.auth.secrets_file),
        state: PathBuf::from(&config.audit.state_dir).join("state.json"),
        audit_dir: PathBuf::from(&config.audit.log_dir),
    }
}
