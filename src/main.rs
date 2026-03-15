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
        Command::Install { system: _, service_user: _ } => {
            eprintln!("install: not yet implemented");
        }
        Command::Setup { config: _, client_json: _, service_user: _ } => {
            eprintln!("setup: not yet implemented");
        }
        Command::Serve { config: _ } => {
            eprintln!("serve: not yet implemented");
        }
        Command::InstallSkill { workspace: _ } => {
            eprintln!("install-skill: not yet implemented");
        }
    }
    Ok(())
}
