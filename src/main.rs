use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use gmail_proxy::audit::AuditLogger;
use gmail_proxy::auth::{TokenManager, run_oauth_setup};
use gmail_proxy::config;
use gmail_proxy::gmail::client::GmailClient;
use gmail_proxy::gmail::watch::WatchManager;
use gmail_proxy::install;
use gmail_proxy::poller::processor::Processor;
use gmail_proxy::poller::pubsub::PubSubClient;
use gmail_proxy::proxy::routes::{
    build_router, AppState, PollerStatus, WatchStatus,
};
use gmail_proxy::scrub::content::ContentScrubber;
use gmail_proxy::scrub::labels::LabelFilter;

#[derive(Parser)]
#[command(name = "gmail-proxy", about = "Secure Gmail proxy for OpenClaw")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Install binary and service configuration (requires sudo)
    Install {
        /// Service user that runs the proxy (e.g. _gmail_proxy)
        #[arg(long)]
        service_user: String,
        /// User that runs OpenClaw (needs socket access)
        #[arg(long)]
        openclaw_user: String,
    },
    /// Interactive OAuth setup and OpenClaw integration
    Setup {
        /// Path to config file
        #[arg(long, default_value = "/etc/gmail-proxy/config.toml")]
        config: PathBuf,
        /// Path to Google client_secret JSON
        #[arg(long)]
        client_json: Option<PathBuf>,
        /// Service user that owns secrets
        #[arg(long)]
        service_user: String,
        /// User that runs OpenClaw
        #[arg(long)]
        openclaw_user: String,
        /// Path to openclaw.json (default: ~openclaw_user/.openclaw/openclaw.json)
        #[arg(long)]
        openclaw_config: Option<PathBuf>,
    },
    /// Run the proxy server
    Serve {
        /// Path to config file
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Install {
            service_user,
            openclaw_user,
        } => {
            install::run_install(&service_user, &openclaw_user)?;
        }
        Command::Setup {
            config,
            client_json,
            service_user,
            openclaw_user,
            openclaw_config,
        } => {
            run_oauth_setup(config, client_json, &service_user, &openclaw_user, openclaw_config).await?;
        }
        Command::Serve { config } => {
            serve(config).await?;
        }
    }
    Ok(())
}

async fn serve(config_path: Option<PathBuf>) -> anyhow::Result<()> {
    // 1. Resolve config path
    let config_path = config_path.unwrap_or_else(|| {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gmail-proxy")
            .join("config.toml")
    });

    // 2. Load config + secrets
    let config = config::load_config(&config_path, false)?;
    let paths = config::resolve_paths(&config_path, &config);

    // 3. Initialize tracing (stderr)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gmail_proxy=info,warn".parse().unwrap()),
        )
        .init();

    tracing::info!("Starting gmail-proxy for {}", config.gmail.account);

    // 4. Initialize audit logger
    let audit = Arc::new(AuditLogger::new(Path::new(&config.audit.log_dir))?);

    // 5. Create TokenManager, validate credentials
    let token_manager = Arc::new(TokenManager::new(
        config.auth.client_id.clone(),
        config.auth.client_secret.clone(),
        config.secrets.refresh_token.clone(),
        "https://oauth2.googleapis.com/token".into(),
    ));
    token_manager
        .get_token()
        .await
        .context("Initial token refresh failed — check your OAuth credentials")?;
    tracing::info!("OAuth token valid");

    // 6. Create Gmail client
    let gmail = Arc::new(GmailClient::new(
        token_manager.clone(),
        "https://gmail.googleapis.com/gmail/v1/users/me".into(),
    ));

    // 7. Resolve label names to IDs
    let labels = gmail
        .list_labels()
        .await
        .context("Failed to list Gmail labels")?;
    let blocked_label = labels
        .labels
        .unwrap_or_default()
        .into_iter()
        .find(|l| l.name.eq_ignore_ascii_case(&config.scrub.blocked_label))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Label '{}' not found in Gmail. Create it at mail.google.com before starting the proxy.",
                config.scrub.blocked_label
            )
        })?;
    tracing::info!(
        "Resolved label '{}' to ID '{}'",
        blocked_label.name,
        blocked_label.id
    );

    // 8. Build ContentScrubber from compiled config regexes
    let scrubber = Arc::new(ContentScrubber::new(
        config
            .scrub
            .otp_patterns
            .iter()
            .map(|p| regex::Regex::new(p).unwrap())
            .collect(),
        config
            .scrub
            .url_strip_patterns
            .iter()
            .map(|p| regex::Regex::new(p).unwrap())
            .collect(),
        config
            .scrub
            .blocked_sender_patterns
            .iter()
            .map(|p| regex::Regex::new(p).unwrap())
            .collect(),
        config.scrub.strip_links,
    ));

    // 9. Build LabelFilter
    let label_filter = Arc::new(LabelFilter::new(
        blocked_label.id.clone(),
        config.scrub.blocked_label.clone(),
    ));

    // 10. Load or initialize state
    let last_history_id_from_state = Processor::load_state(&paths.state)?;

    // 11. Shared status objects
    let watch_status = Arc::new(RwLock::new(WatchStatus {
        active: false,
        expiration: None,
        last_history_id: None,
    }));
    let poller_status = Arc::new(RwLock::new(PollerStatus {
        connected: false,
        last_message_received: None,
        last_message_delivered: None,
        consecutive_errors: 0,
    }));

    // 12. Register Gmail watch
    let watch = WatchManager::start(
        gmail.clone(),
        config.gmail.pubsub_topic.clone(),
        config.gmail.watch_labels.clone(),
        config.gmail.watch_renew_secs,
        watch_status.clone(),
    )
    .await
    .context("Failed to register Gmail watch")?;

    let initial_history_id = last_history_id_from_state
        .unwrap_or_else(|| watch.initial_history_id().unwrap_or(0));

    tracing::info!("Starting from history ID {}", initial_history_id);

    // 13. Create processor and Pub/Sub client
    let processor = Processor::new(
        gmail.clone(),
        label_filter.clone(),
        scrubber.clone(),
        audit.clone(),
        config.openclaw.hook_url.clone(),
        config.secrets.openclaw_hook_token.clone(),
        paths.state.clone(),
        initial_history_id,
        poller_status.clone(),
    );

    let pubsub = PubSubClient::new(
        token_manager.clone(),
        &config.gmail.pubsub_subscription,
        "https://pubsub.googleapis.com".into(),
    );

    // 14. Build AppState and router
    let state = Arc::new(AppState {
        gmail: gmail.clone(),
        label_filter: label_filter.clone(),
        scrubber: scrubber.clone(),
        audit: audit.clone(),
        allowed_operators: config.scrub.allowed_operators.clone(),
        blocked_label: config.scrub.blocked_label.clone(),
        max_query_depth: 10,
        search_concurrency: config.proxy.search_fetch_concurrency,
        poller_status: poller_status.clone(),
        token_manager: token_manager.clone(),
        watch_status: watch_status.clone(),
    });

    let app = build_router(state);

    let socket_path = std::path::Path::new(&config.proxy.socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .context(format!("Failed to create socket directory {}", parent.display()))?;
    }
    // Remove stale socket file from previous run
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .context("Failed to remove stale socket file")?;
    }

    let listener = tokio::net::UnixListener::bind(socket_path)
        .context(format!("Failed to bind Unix socket at {}", socket_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            socket_path,
            std::fs::Permissions::from_mode(0o660),
        ).context("Failed to set socket permissions to 0660")?;
        tracing::info!("Socket permissions set to 0660");
    }

    tracing::info!("Proxy API listening on {}", socket_path.display());

    // 15. Run everything concurrently with graceful shutdown
    let server = axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal());

    tokio::select! {
        result = server => {
            result.context("Server error")?;
        }
        _ = gmail_proxy::poller::run_poller(pubsub, processor) => {
            // Poller runs forever, only exits on error
        }
        _ = watch.run_renewal_loop() => {
            // Watch renewal runs forever
        }
    }

    tracing::info!("Shutting down");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C handler");
    tracing::info!("Received shutdown signal");
}
