use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::Instant;
use anyhow::{Context, Result, anyhow};

use crate::gmail::types::TokenResponse;

/// Response from the OAuth token exchange endpoint (includes refresh_token).
#[derive(Debug, serde::Deserialize)]
struct OAuthTokenResponse {
    refresh_token: Option<String>,
    #[allow(dead_code)]
    access_token: String,
    #[allow(dead_code)]
    expires_in: u64,
}

pub struct TokenManager {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    token_url: String,
    http_client: reqwest::Client,
    cached: Arc<RwLock<Option<CachedToken>>>,
}

struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

/// Safety margin: refresh tokens 5 minutes before they actually expire.
const SAFETY_MARGIN_SECS: u64 = 5 * 60;

impl TokenManager {
    pub fn new(
        client_id: String,
        client_secret: String,
        refresh_token: String,
        token_url: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            refresh_token,
            token_url,
            http_client: reqwest::Client::new(),
            cached: Arc::new(RwLock::new(None)),
        }
    }

    /// Return a valid access token, refreshing if necessary.
    pub async fn get_token(&self) -> Result<String> {
        // Check cache first
        {
            let guard = self.cached.read().await;
            if let Some(cached) = guard.as_ref() {
                if Instant::now() < cached.expires_at {
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // Cache miss or expired — refresh
        self.refresh().await
    }

    async fn refresh(&self) -> Result<String> {
        let body = format!(
            "grant_type=refresh_token&client_id={}&client_secret={}&refresh_token={}",
            self.client_id, self.client_secret, self.refresh_token,
        );

        let resp = self
            .http_client
            .post(&self.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Token refresh failed with status {}: {}",
                status,
                text
            ));
        }

        let token_resp: TokenResponse = resp.json().await?;

        let expires_at = if token_resp.expires_in > SAFETY_MARGIN_SECS {
            Instant::now()
                + std::time::Duration::from_secs(token_resp.expires_in - SAFETY_MARGIN_SECS)
        } else {
            // Token expires sooner than the safety margin; use it but mark as
            // expiring immediately so we re-fetch next time.
            Instant::now()
        };

        let access_token = token_resp.access_token.clone();

        {
            let mut guard = self.cached.write().await;
            *guard = Some(CachedToken {
                access_token: access_token.clone(),
                expires_at,
            });
        }

        Ok(access_token)
    }

    /// Remaining seconds until the cached token expires, if any.
    /// Intended for the health endpoint.
    pub async fn expires_in_secs(&self) -> Option<u64> {
        let guard = self.cached.read().await;
        guard.as_ref().map(|c| {
            let now = Instant::now();
            if c.expires_at > now {
                (c.expires_at - now).as_secs()
            } else {
                0
            }
        })
    }

    /// Whether the cached token is present and not yet expired.
    pub async fn is_valid(&self) -> bool {
        let guard = self.cached.read().await;
        match guard.as_ref() {
            Some(cached) => Instant::now() < cached.expires_at,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// OAuth setup flow
// ---------------------------------------------------------------------------

/// Google client_secret JSON structure (the file you download from Google Cloud Console).
#[derive(Debug, serde::Deserialize)]
struct GoogleClientSecretFile {
    installed: Option<GoogleClientCreds>,
    web: Option<GoogleClientCreds>,
}

#[derive(Debug, serde::Deserialize)]
struct GoogleClientCreds {
    client_id: String,
    client_secret: String,
}

/// Run the interactive OAuth setup flow.
///
/// This function:
/// 1. Optionally reads a Google client_secret JSON to extract credentials
/// 2. Starts an ephemeral local HTTP server
/// 3. Opens the browser for OAuth consent
/// 4. Exchanges the authorization code for a refresh token
/// 5. Writes secrets.toml
pub async fn run_oauth_setup(
    config_path: Option<PathBuf>,
    client_json: Option<PathBuf>,
    service_user: Option<String>,
) -> Result<()> {
    // Resolve config path
    let config_path = config_path.unwrap_or_else(|| {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gmail-proxy")
            .join("config.toml")
    });

    if !config_path.exists() {
        anyhow::bail!(
            "Config file not found at {}. Run 'gmail-proxy install' first.",
            config_path.display()
        );
    }

    let config_dir = config_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    // Read current config
    let config_text = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read {}", config_path.display()))?;

    let client_id: String;
    let client_secret: String;

    // Step 1: If --client-json provided, extract credentials and update config
    if let Some(json_path) = client_json {
        let json_text = std::fs::read_to_string(&json_path)
            .with_context(|| format!("failed to read {}", json_path.display()))?;
        let parsed: GoogleClientSecretFile = serde_json::from_str(&json_text)
            .context("failed to parse client_secret JSON")?;

        let creds = parsed
            .installed
            .or(parsed.web)
            .context("client_secret JSON has neither 'installed' nor 'web' key")?;

        client_id = creds.client_id;
        client_secret = creds.client_secret;

        // Update config.toml with the new credentials
        let updated = config_text
            .lines()
            .map(|line| {
                let trimmed = line.trim_start();
                if trimmed.starts_with("client_id") && trimmed.contains('=') {
                    format!(
                        "client_id = \"{}\"",
                        client_id
                    )
                } else if trimmed.starts_with("client_secret") && trimmed.contains('=') {
                    format!(
                        "client_secret = \"{}\"",
                        client_secret
                    )
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        std::fs::write(&config_path, &updated)
            .with_context(|| format!("failed to update {}", config_path.display()))?;
        println!("Updated client_id and client_secret in {}", config_path.display());
    } else {
        // Parse existing config for client_id and client_secret
        let parsed: toml::Value = toml::from_str(&config_text)
            .context("failed to parse config.toml")?;

        client_id = parsed
            .get("auth")
            .and_then(|a| a.get("client_id"))
            .and_then(|v| v.as_str())
            .context("client_id not found in config.toml")?
            .to_string();
        client_secret = parsed
            .get("auth")
            .and_then(|a| a.get("client_secret"))
            .and_then(|v| v.as_str())
            .context("client_secret not found in config.toml")?
            .to_string();

        if client_id.contains("YOUR_CLIENT_ID") || client_secret.contains("YOUR_CLIENT_SECRET") {
            anyhow::bail!(
                "config.toml still has placeholder credentials. \
                 Either edit them manually or use --client-json to import from Google's JSON file."
            );
        }
    }

    // Step 2: Spin up ephemeral Axum listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}");

    // Channel to receive the authorization code
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let callback_handler = {
        let tx = tx.clone();
        move |axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>| {
            let tx = tx.clone();
            async move {
                if let Some(code) = params.get("code") {
                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send(code.clone());
                    }
                    axum::response::Html(
                        "<html><body><h1>Authorization successful!</h1>\
                         <p>You can close this tab and return to the terminal.</p></body></html>"
                            .to_string(),
                    )
                } else {
                    let error = params
                        .get("error")
                        .cloned()
                        .unwrap_or_else(|| "unknown error".into());
                    axum::response::Html(format!(
                        "<html><body><h1>Authorization failed</h1><p>{error}</p></body></html>"
                    ))
                }
            }
        }
    };

    let app = axum::Router::new().route("/", axum::routing::get(callback_handler));

    // Step 3: Build OAuth URL
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
         client_id={}&\
         redirect_uri={}&\
         response_type=code&\
         scope=https://www.googleapis.com/auth/gmail.readonly%20https://www.googleapis.com/auth/pubsub&\
         access_type=offline&\
         prompt=consent",
        urlencoding(&client_id),
        urlencoding(&redirect_uri),
    );

    println!("\nOpening browser for Google OAuth consent...");
    println!("If the browser doesn't open, visit this URL manually:\n");
    println!("  {auth_url}\n");

    // Step 4: Open browser
    if let Err(e) = open::that(&auth_url) {
        eprintln!("Warning: could not open browser: {e}");
    }

    // Run the server until we get the code
    let server = axum::serve(listener, app);
    let code = tokio::select! {
        result = server => {
            result.context("callback server error")?;
            anyhow::bail!("callback server exited unexpectedly");
        }
        code = rx => {
            code.context("failed to receive authorization code")?
        }
    };

    println!("Received authorization code. Exchanging for tokens...");

    // Step 6: Exchange code for tokens
    let http = reqwest::Client::new();
    let token_body = format!(
        "grant_type=authorization_code&code={}&client_id={}&client_secret={}&redirect_uri={}",
        urlencoding(&code),
        urlencoding(&client_id),
        urlencoding(&client_secret),
        urlencoding(&redirect_uri),
    );

    let resp = http
        .post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(token_body)
        .send()
        .await
        .context("failed to exchange authorization code")?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Token exchange failed with status {status}: {text}");
    }

    let token_resp: OAuthTokenResponse = resp.json().await.context("failed to parse token response")?;

    let refresh_token = token_resp
        .refresh_token
        .context("No refresh_token in response. Try revoking access at https://myaccount.google.com/permissions and re-running setup.")?;

    // Step 7: Generate random openclaw_hook_token
    use rand::Rng;
    let mut rng = rand::rng();
    let hook_token_bytes: [u8; 32] = rng.random();
    let hook_token: String = hook_token_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Step 8: Write secrets.toml
    let secrets_path = config_dir.join("secrets.toml");
    let secrets_content = format!(
        "refresh_token = \"{refresh_token}\"\nopenclaw_hook_token = \"{hook_token}\"\n"
    );
    std::fs::write(&secrets_path, &secrets_content)
        .with_context(|| format!("failed to write {}", secrets_path.display()))?;

    // Set permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secrets_path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("Wrote {}", secrets_path.display());

    // Step 9: If --service-user, chown
    if let Some(user) = service_user {
        let chown_result = std::process::Command::new("sudo")
            .args([
                "chown",
                &format!("{user}:{user}"),
                &secrets_path.display().to_string(),
            ])
            .status();

        match chown_result {
            Ok(s) if s.success() => {
                println!("Set ownership of secrets.toml to {user}");
            }
            _ => {
                eprintln!("Could not chown secrets.toml. Run manually:");
                eprintln!("  sudo chown {user}:{user} {}", secrets_path.display());
                eprintln!("  chmod 0600 {}", secrets_path.display());
            }
        }
    }

    // Step 10: Print summary
    println!("\nSetup complete!");
    println!("  Config:  {}", config_path.display());
    println!("  Secrets: {}", secrets_path.display());
    println!("\nNext steps:");
    println!("  1. Verify your config.toml settings (Gmail account, Pub/Sub topic, etc.)");
    println!("  2. Create the '{}' label in Gmail if it doesn't exist", "agent-blocked");
    println!("  3. Start the proxy: gmail-proxy serve");

    Ok(())
}

/// Simple percent-encoding for URL query parameters.
fn urlencoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    result
}
