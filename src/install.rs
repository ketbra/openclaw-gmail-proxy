use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Template config.toml content with a placeholder for the log directory.
const TEMPLATE_CONFIG: &str = r#"# Gmail Proxy Configuration
# Edit this file, then run: gmail-proxy setup

[auth]
client_id = "YOUR_CLIENT_ID.apps.googleusercontent.com"
client_secret = "YOUR_CLIENT_SECRET"
secrets_file = "secrets.toml"

[gmail]
account = "you@gmail.com"
pubsub_topic = "projects/YOUR_PROJECT/topics/gmail-watch"
pubsub_subscription = "projects/YOUR_PROJECT/subscriptions/gmail-proxy-pull"
watch_labels = ["INBOX"]
watch_renew_secs = 518400

[scrub]
blocked_label = "agent-blocked"
strip_links = true
otp_patterns = [
  "\\b\\d{4,8}\\b",
  "(?i)verification code[:\\s]+\\S+",
  "(?i)(one.time|temporary|security)\\s+(code|password|pin)",
]
blocked_sender_patterns = [
  "(?i)noreply@.*\\.google\\.com",
  "(?i)no-reply@accounts\\.google\\.com",
  "(?i)security@",
]
url_strip_patterns = [
  "(?i)https?://[^\\s]*/(reset|verify|confirm|auth|signin|login|activate)[^\\s]*",
]
allowed_operators = [
  "from", "to", "cc", "bcc", "subject",
  "has", "is", "in", "filename", "list", "deliveredto",
  "newer_than", "older_than", "after", "before",
  "category", "size", "larger", "smaller",
  "rfc822msgid",
]

[proxy]
bind = "127.0.0.1:8780"
search_fetch_concurrency = 10

[openclaw]
hook_url = "http://127.0.0.1:18789/hooks/gmail"

[audit]
log_dir = "LOG_DIR_PLACEHOLDER"
"#;

const USER_SYSTEMD_UNIT: &str = r#"[Unit]
Description=Gmail Proxy for OpenClaw
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%h/.local/bin/gmail-proxy serve --config %h/.config/gmail-proxy/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#;

const SYSTEM_SYSTEMD_UNIT: &str = r#"[Unit]
Description=Gmail Proxy for OpenClaw
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=SERVICE_USER
Group=SERVICE_USER
ExecStart=/usr/local/bin/gmail-proxy serve --config /etc/gmail-proxy/config.toml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/gmail-proxy /var/log/gmail-proxy
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
SystemCallFilter=@system-service
SystemCallArchitectures=native
ReadOnlyPaths=/etc/gmail-proxy/config.toml

[Install]
WantedBy=multi-user.target
"#;

const LAUNCHAGENT_PLIST_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.gmail-proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>HOME/.local/bin/gmail-proxy</string>
        <string>serve</string>
        <string>--config</string>
        <string>CONFIG_DIR/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>DATA_DIR/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>DATA_DIR/stderr.log</string>
</dict>
</plist>
"#;

const LAUNCHDAEMON_PLIST_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.gmail-proxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/gmail-proxy</string>
        <string>serve</string>
        <string>--config</string>
        <string>/etc/gmail-proxy/config.toml</string>
    </array>
    <key>UserName</key>
    <string>SERVICE_USER</string>
    <key>GroupName</key>
    <string>SERVICE_USER</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/gmail-proxy/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/gmail-proxy/stderr.log</string>
</dict>
</plist>
"#;

/// Run the install subcommand.
pub fn run_install(system: bool, service_user: &str) -> Result<()> {
    if system {
        run_system_install(service_user)
    } else {
        run_user_install()
    }
}

fn current_exe_path() -> Result<PathBuf> {
    std::env::current_exe().context("failed to determine current executable path")
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().context("could not determine home directory")
}

fn copy_binary(dest: &Path) -> Result<()> {
    let src = current_exe_path()?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    std::fs::copy(&src, dest)
        .with_context(|| format!("failed to copy binary to {}", dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755))?;
    }
    println!("  Binary installed to {}", dest.display());
    Ok(())
}

fn write_if_not_exists(path: &Path, content: &str, description: &str) -> Result<()> {
    if path.exists() {
        println!("  {} already exists, skipping", description);
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("  Created {}", path.display());
    Ok(())
}

fn write_always(path: &Path, content: &str, description: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("  Installed {}", description);
    Ok(())
}

fn run_user_install() -> Result<()> {
    let home = home_dir()?;

    println!("Installing gmail-proxy (user-level)...\n");

    // 1. Copy binary
    let bin_path = home.join(".local/bin/gmail-proxy");
    copy_binary(&bin_path)?;

    // 2. Resolve platform-native directories
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| home.join(".config"))
        .join("gmail-proxy");
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| home.join(".local/share"))
        .join("gmail-proxy");

    // On macOS these resolve to:
    //   config: ~/Library/Application Support/gmail-proxy/
    //   data:   ~/Library/Application Support/gmail-proxy/
    // On Linux (XDG):
    //   config: ~/.config/gmail-proxy/
    //   data:   ~/.local/share/gmail-proxy/

    std::fs::create_dir_all(&config_dir)?;
    println!("  Created {}", config_dir.display());

    std::fs::create_dir_all(&data_dir)?;
    println!("  Created {}", data_dir.display());

    let config_content = TEMPLATE_CONFIG.replace("LOG_DIR_PLACEHOLDER", &data_dir.display().to_string());
    let config_path = config_dir.join("config.toml");
    write_if_not_exists(&config_path, &config_content, "config.toml")?;

    // 3. Platform-specific service file
    if cfg!(target_os = "macos") {
        let plist_dir = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&plist_dir)?;
        let plist_path = plist_dir.join("com.gmail-proxy.plist");
        let home_str = home.display().to_string();
        let config_dir_str = config_dir.display().to_string();
        let data_dir_str = data_dir.display().to_string();
        let plist_content = LAUNCHAGENT_PLIST_TEMPLATE
            .replace("HOME", &home_str)
            .replace("CONFIG_DIR", &config_dir_str)
            .replace("DATA_DIR", &data_dir_str);
        write_always(&plist_path, &plist_content, "LaunchAgent plist")?;
    } else {
        // Linux: user-level systemd
        let systemd_dir = home.join(".config/systemd/user");
        std::fs::create_dir_all(&systemd_dir)?;
        let unit_path = systemd_dir.join("gmail-proxy.service");
        write_always(&unit_path, USER_SYSTEMD_UNIT, "systemd user unit")?;
    }

    // 4. Check if ~/.local/bin is in PATH
    let bin_dir = home.join(".local/bin");
    let bin_dir_str = bin_dir.display().to_string();
    let in_path = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|p| p == bin_dir_str || p == "~/.local/bin" || p == "$HOME/.local/bin");

    println!("\nInstallation complete!");

    if !in_path {
        let shell_rc = if cfg!(target_os = "macos") {
            "~/.zshrc"
        } else if std::env::var("SHELL").unwrap_or_default().contains("zsh") {
            "~/.zshrc"
        } else {
            "~/.bashrc"
        };

        println!();
        println!("  Note: {} is not in your PATH. Add it with:", bin_dir.display());
        println!("    echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> {shell_rc}");
        println!();
        println!("  Then either restart your shell or run:");
        println!("    source {shell_rc}");
    }

    println!("\nNext steps:");
    println!("  1. Edit {}", config_path.display());
    println!("  2. Run: gmail-proxy setup");
    if cfg!(target_os = "macos") {
        println!("  3. Start: launchctl load ~/Library/LaunchAgents/com.gmail-proxy.plist");
    } else {
        println!("  3. Enable service: systemctl --user enable --now gmail-proxy");
    }

    Ok(())
}

fn run_system_install(service_user: &str) -> Result<()> {
    println!("Installing gmail-proxy (system-level)...\n");

    // Check for root
    #[cfg(unix)]
    {
        if !nix_is_root() {
            anyhow::bail!("System-level install requires root. Run with sudo.");
        }
    }

    // 1. Copy binary
    let bin_path = Path::new("/usr/local/bin/gmail-proxy");
    copy_binary(bin_path)?;

    // 2. Create service user
    create_service_user(service_user)?;

    // 3. Create directories
    if cfg!(target_os = "macos") {
        let config_dir = Path::new("/etc/gmail-proxy");
        std::fs::create_dir_all(config_dir)?;
        let state_dir = Path::new("/var/lib/gmail-proxy");
        std::fs::create_dir_all(state_dir)?;
        let log_dir = Path::new("/var/log/gmail-proxy");
        std::fs::create_dir_all(log_dir)?;

        // Config file
        let config_content = TEMPLATE_CONFIG.replace("LOG_DIR_PLACEHOLDER", "/var/log/gmail-proxy");
        write_if_not_exists(&config_dir.join("config.toml"), &config_content, "config.toml")?;

        // Set ownership on state/log dirs
        chown_dir(state_dir, service_user);
        chown_dir(log_dir, service_user);

        // LaunchDaemon plist
        let plist_path = Path::new("/Library/LaunchDaemons/com.gmail-proxy.plist");
        let plist_content = LAUNCHDAEMON_PLIST_TEMPLATE.replace("SERVICE_USER", service_user);
        write_always(plist_path, &plist_content, "LaunchDaemon plist")?;
    } else {
        // Linux
        let config_dir = Path::new("/etc/gmail-proxy");
        std::fs::create_dir_all(config_dir)?;
        let state_dir = Path::new("/var/lib/gmail-proxy");
        std::fs::create_dir_all(state_dir)?;
        let log_dir = Path::new("/var/log/gmail-proxy");
        std::fs::create_dir_all(log_dir)?;

        let config_content = TEMPLATE_CONFIG.replace("LOG_DIR_PLACEHOLDER", "/var/log/gmail-proxy");
        write_if_not_exists(&config_dir.join("config.toml"), &config_content, "config.toml")?;

        chown_dir(state_dir, service_user);
        chown_dir(log_dir, service_user);

        // systemd unit
        let unit_content = SYSTEM_SYSTEMD_UNIT.replace("SERVICE_USER", service_user);
        let unit_path = Path::new("/etc/systemd/system/gmail-proxy.service");
        write_always(unit_path, &unit_content, "systemd unit")?;
        println!("  Run: systemctl daemon-reload");
    }

    println!("\nSystem-level installation complete!");
    println!("\nNext steps:");
    println!("  1. Edit /etc/gmail-proxy/config.toml");
    println!("  2. Run: gmail-proxy setup --config /etc/gmail-proxy/config.toml --service-user {}", service_user);
    println!("  3. Start the service (do NOT start until setup is complete)");

    Ok(())
}

fn nix_is_root() -> bool {
    // Check if running as root by trying to read a root-only indicator.
    // On Unix, we use the `id -u` command to get the effective UID.
    std::process::Command::new("id")
        .args(["-u"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

fn create_service_user(service_user: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        // macOS: use dscl to check/create
        let check = std::process::Command::new("dscl")
            .args([".", "-read", &format!("/Users/{service_user}")])
            .output();
        match check {
            Ok(output) if output.status.success() => {
                println!("  Service user '{service_user}' already exists");
            }
            _ => {
                println!("  Creating service user '{service_user}' via dscl...");
                // Find next available UID in the service range
                let result = std::process::Command::new("dscl")
                    .args([
                        ".", "-create", &format!("/Users/{service_user}"),
                    ])
                    .status();
                match result {
                    Ok(s) if s.success() => {
                        // Set shell to nologin
                        let _ = std::process::Command::new("dscl")
                            .args([".", "-create", &format!("/Users/{service_user}"), "UserShell", "/usr/bin/false"])
                            .status();
                        let _ = std::process::Command::new("dscl")
                            .args([".", "-create", &format!("/Users/{service_user}"), "RealName", "Gmail Proxy Service"])
                            .status();
                        println!("  Created service user '{service_user}'");
                    }
                    _ => {
                        eprintln!("  Warning: failed to create service user '{service_user}'");
                        eprintln!("  You may need to create it manually");
                    }
                }
            }
        }
    } else {
        // Linux: useradd
        let check = std::process::Command::new("id")
            .arg(service_user)
            .output();
        match check {
            Ok(output) if output.status.success() => {
                println!("  Service user '{service_user}' already exists");
            }
            _ => {
                println!("  Creating service user '{service_user}'...");
                let result = std::process::Command::new("useradd")
                    .args([
                        "--system",
                        "--no-create-home",
                        "--shell", "/usr/sbin/nologin",
                        service_user,
                    ])
                    .status();
                match result {
                    Ok(s) if s.success() => {
                        println!("  Created service user '{service_user}'");
                    }
                    _ => {
                        eprintln!("  Warning: failed to create service user '{service_user}'");
                        eprintln!("  You may need to create it manually with:");
                        eprintln!("    useradd --system --no-create-home --shell /usr/sbin/nologin {service_user}");
                    }
                }
            }
        }
    }
    Ok(())
}

fn chown_dir(path: &Path, user: &str) {
    let status = std::process::Command::new("chown")
        .args(["-R", &format!("{user}:{user}"), &path.display().to_string()])
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("  Set ownership of {} to {user}", path.display());
        }
        _ => {
            eprintln!("  Warning: could not chown {}. Run manually:", path.display());
            eprintln!("    chown -R {user}:{user} {}", path.display());
        }
    }
}
