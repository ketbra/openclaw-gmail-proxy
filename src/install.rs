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
socket_path = "/var/run/gmail-proxy/proxy.sock"
search_fetch_concurrency = 10

[openclaw]
hook_url = "http://127.0.0.1:18789/hooks/gmail-proxy"

[audit]
log_dir = "/var/log/gmail-proxy"
state_dir = "/var/lib/gmail-proxy"
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
ReadWritePaths=/var/lib/gmail-proxy /var/log/gmail-proxy /var/run/gmail-proxy
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
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

/// Run the install subcommand. Requires root.
pub fn run_install(service_user: &str, openclaw_user: &str) -> Result<()> {
    println!("Installing gmail-proxy (system-level)...\n");

    // 1. Check for root
    #[cfg(unix)]
    {
        if !nix_is_root() {
            anyhow::bail!("Install requires root. Run with sudo.");
        }
    }

    // 2. Copy binary
    let bin_path = Path::new("/usr/local/bin/gmail-proxy");
    copy_binary(bin_path)?;

    // 3. Create service user + matching group
    create_service_user(service_user)?;

    // 4. Add openclaw_user to service user's group
    add_user_to_group(openclaw_user, service_user)?;

    // 5. Create directories
    let config_dir = Path::new("/etc/gmail-proxy");
    std::fs::create_dir_all(config_dir)?;
    println!("  Created {}", config_dir.display());

    let state_dir = Path::new("/var/lib/gmail-proxy");
    std::fs::create_dir_all(state_dir)?;
    chown_dir(state_dir, service_user);
    set_dir_mode(state_dir, "0700");

    let log_dir = Path::new("/var/log/gmail-proxy");
    std::fs::create_dir_all(log_dir)?;
    chown_dir(log_dir, service_user);
    set_dir_mode(log_dir, "0700");

    setup_socket_dir(service_user)?;

    // 6. Write template config.toml (if not exists)
    let config_path = config_dir.join("config.toml");
    write_if_not_exists(&config_path, TEMPLATE_CONFIG, "config.toml")?;

    // 7. Install service file
    if cfg!(target_os = "macos") {
        let plist_path = Path::new("/Library/LaunchDaemons/com.gmail-proxy.plist");
        let plist_content = LAUNCHDAEMON_PLIST_TEMPLATE.replace("SERVICE_USER", service_user);
        write_always(plist_path, &plist_content, "LaunchDaemon plist")?;
    } else {
        let unit_content = SYSTEM_SYSTEMD_UNIT.replace("SERVICE_USER", service_user);
        let unit_path = Path::new("/etc/systemd/system/gmail-proxy.service");
        write_always(unit_path, &unit_content, "systemd unit")?;
        println!("  Run: systemctl daemon-reload");
    }

    // 8. Print next steps
    println!("\nInstallation complete!");
    println!("\nNext steps:");
    println!("  1. Edit /etc/gmail-proxy/config.toml");
    println!(
        "  2. Run: gmail-proxy setup --service-user {service_user} --openclaw-user {openclaw_user} --client-json /path/to/client_secret.json"
    );
    println!("  3. Start the service:");
    if cfg!(target_os = "macos") {
        println!("     macOS: sudo launchctl load /Library/LaunchDaemons/com.gmail-proxy.plist");
    } else {
        println!("     Linux: sudo systemctl enable --now gmail-proxy");
    }

    Ok(())
}

fn current_exe_path() -> Result<PathBuf> {
    std::env::current_exe().context("failed to determine current executable path")
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

fn nix_is_root() -> bool {
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
        let check = std::process::Command::new("dscl")
            .args([".", "-read", &format!("/Users/{service_user}")])
            .output();
        match check {
            Ok(output) if output.status.success() => {
                println!("  Service user '{service_user}' already exists");
            }
            _ => {
                println!("  Creating service user '{service_user}' via dscl...");

                let uid = find_available_macos_id();
                let uid_str = uid.to_string();
                let user_path = format!("/Users/{service_user}");
                let group_path = format!("/Groups/{service_user}");

                let cmds: Vec<(&str, Vec<&str>)> = vec![
                    ("dscl", vec![".", "-create", &group_path]),
                    (
                        "dscl",
                        vec![".", "-create", &group_path, "PrimaryGroupID", &uid_str],
                    ),
                    (
                        "dscl",
                        vec![
                            ".",
                            "-create",
                            &group_path,
                            "RealName",
                            "Gmail Proxy Service",
                        ],
                    ),
                    ("dscl", vec![".", "-create", &group_path, "Password", "*"]),
                    ("dscl", vec![".", "-create", &user_path]),
                    (
                        "dscl",
                        vec![".", "-create", &user_path, "UniqueID", &uid_str],
                    ),
                    (
                        "dscl",
                        vec![".", "-create", &user_path, "PrimaryGroupID", &uid_str],
                    ),
                    (
                        "dscl",
                        vec![".", "-create", &user_path, "UserShell", "/usr/bin/false"],
                    ),
                    (
                        "dscl",
                        vec![
                            ".",
                            "-create",
                            &user_path,
                            "RealName",
                            "Gmail Proxy Service",
                        ],
                    ),
                    (
                        "dscl",
                        vec![
                            ".",
                            "-create",
                            &user_path,
                            "NFSHomeDirectory",
                            "/var/empty",
                        ],
                    ),
                    ("dscl", vec![".", "-create", &user_path, "Password", "*"]),
                ];

                let mut ok = true;
                for (cmd, args) in &cmds {
                    let result = std::process::Command::new(cmd).args(args).status();
                    if !matches!(result, Ok(s) if s.success()) {
                        ok = false;
                        break;
                    }
                }

                if ok {
                    println!(
                        "  Created service user and group '{service_user}' (UID/GID {uid})"
                    );
                } else {
                    eprintln!(
                        "  Warning: failed to fully create service user '{service_user}'"
                    );
                    eprintln!(
                        "  You may need to create it manually via System Settings or dscl"
                    );
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
                        "--shell",
                        "/usr/sbin/nologin",
                        service_user,
                    ])
                    .status();
                match result {
                    Ok(s) if s.success() => {
                        println!("  Created service user '{service_user}'");
                    }
                    _ => {
                        eprintln!(
                            "  Warning: failed to create service user '{service_user}'"
                        );
                        eprintln!("  You may need to create it manually with:");
                        eprintln!("    useradd --system --no-create-home --shell /usr/sbin/nologin {service_user}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Add a user to a group so they can access the socket directory.
fn add_user_to_group(user: &str, group: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        let status = std::process::Command::new("dseditgroup")
            .args(["-o", "edit", "-a", user, "-t", "user", group])
            .status();
        match status {
            Ok(s) if s.success() => {
                println!("  Added '{user}' to group '{group}'");
            }
            _ => {
                eprintln!(
                    "  Warning: could not add '{user}' to group '{group}'. Run manually:"
                );
                eprintln!("    sudo dseditgroup -o edit -a {user} -t user {group}");
            }
        }
    } else {
        let status = std::process::Command::new("usermod")
            .args(["-aG", group, user])
            .status();
        match status {
            Ok(s) if s.success() => {
                println!("  Added '{user}' to group '{group}'");
            }
            _ => {
                eprintln!(
                    "  Warning: could not add '{user}' to group '{group}'. Run manually:"
                );
                eprintln!("    sudo usermod -aG {group} {user}");
            }
        }
    }
    Ok(())
}

/// Create the socket directory with setgid bit so the socket inherits the service group.
fn setup_socket_dir(service_user: &str) -> Result<()> {
    let socket_dir = Path::new("/var/run/gmail-proxy");
    std::fs::create_dir_all(socket_dir)?;
    chown_dir(socket_dir, service_user);
    // Set mode 2750 (setgid + rwxr-x---)
    let status = std::process::Command::new("chmod")
        .args(["2750", &socket_dir.display().to_string()])
        .status();
    match status {
        Ok(s) if s.success() => println!("  Set socket directory mode to 2750 (setgid)"),
        _ => {
            eprintln!("  Warning: could not set socket directory mode. Run manually:");
            eprintln!("    chmod 2750 {}", socket_dir.display());
        }
    }
    Ok(())
}

/// Find an available UID/GID in the 400-499 range for macOS service accounts.
fn find_available_macos_id() -> u32 {
    for id in 400..500 {
        let uid_check = std::process::Command::new("dscl")
            .args([".", "-search", "/Users", "UniqueID", &id.to_string()])
            .output();
        let uid_taken = uid_check
            .as_ref()
            .map(|o| !o.stdout.is_empty() && o.stdout != b"\n")
            .unwrap_or(false);

        let gid_check = std::process::Command::new("dscl")
            .args([
                ".",
                "-search",
                "/Groups",
                "PrimaryGroupID",
                &id.to_string(),
            ])
            .output();
        let gid_taken = gid_check
            .as_ref()
            .map(|o| !o.stdout.is_empty() && o.stdout != b"\n")
            .unwrap_or(false);

        if !uid_taken && !gid_taken {
            return id;
        }
    }
    450
}

fn chown_dir(path: &Path, user: &str) {
    let ownership = format!("{user}:{user}");
    let status = std::process::Command::new("chown")
        .args(["-R", &ownership, &path.display().to_string()])
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("  Set ownership of {} to {user}", path.display());
        }
        _ => {
            eprintln!(
                "  Warning: could not chown {}. Run manually:",
                path.display()
            );
            eprintln!("    chown -R {ownership} {}", path.display());
        }
    }
}

fn set_dir_mode(path: &Path, mode: &str) {
    let status = std::process::Command::new("chmod")
        .args([mode, &path.display().to_string()])
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("  Set mode of {} to {mode}", path.display());
        }
        _ => {
            eprintln!(
                "  Warning: could not chmod {}. Run manually:",
                path.display()
            );
            eprintln!("    chmod {mode} {}", path.display());
        }
    }
}
