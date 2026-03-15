use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tokio::sync::RwLock;

use gmail_proxy::audit::AuditLogger;
use gmail_proxy::auth::TokenManager;
use gmail_proxy::config;
use gmail_proxy::gmail::client::GmailClient;
use gmail_proxy::gmail::watch::WatchManager;
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
        config: Option<PathBuf>,
        /// Path to Google client_secret JSON
        #[arg(long)]
        client_json: Option<PathBuf>,
        /// Service user to chown secrets to
        #[arg(long)]
        service_user: Option<String>,
    },
    /// Run the proxy server
    Serve {
        /// Path to config file
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Install OpenClaw skill file
    InstallSkill {
        /// Path to OpenClaw workspace
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Install {
            system: _,
            service_user: _,
        } => {
            eprintln!("install: not yet implemented");
        }
        Command::Setup {
            config: _,
            client_json: _,
            service_user: _,
        } => {
            eprintln!("setup: not yet implemented");
        }
        Command::Serve { config } => {
            serve(config).await?;
        }
        Command::InstallSkill { workspace: _ } => {
            eprintln!("install-skill: not yet implemented");
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
    let listener = tokio::net::TcpListener::bind(&config.proxy.bind)
        .await
        .context(format!("Failed to bind to {}", config.proxy.bind))?;
    tracing::info!("Proxy API listening on {}", config.proxy.bind);

    // 15. Run everything concurrently with graceful shutdown
    let server = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal());

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
