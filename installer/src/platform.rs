//! Cross-platform preflight, hardware, toolchain, and edge-case discovery.

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightWarning {
    pub code: String,
    pub severity: String, // "info" | "warning" | "critical"
    pub title_ru: String,
    pub title_en: String,
    pub detail_ru: String,
    pub detail_en: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledComponent {
    pub kind: String,
    pub path: String,
    pub version: Option<String>,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExistingInstalls {
    pub client_paths: Vec<InstalledComponent>,
    pub host_paths: Vec<InstalledComponent>,
    pub systemd_units: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoCheckoutInfo {
    pub root: String,
    pub has_moonlight_qt: bool,
    pub has_sunshine: bool,
    pub has_mac_client_builder: bool,
    pub has_linux_client_builder: bool,
    pub has_linux_builder: bool,
    pub has_windows_builder: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosPreflight {
    pub homebrew_prefix: Option<String>,
    pub xcode_clt_installed: bool,
    pub qmake6_path: Option<String>,
    pub macdeployqt_path: Option<String>,
    pub local_signing_identities_count: usize,
    pub signing_config_exists: bool,
    pub free_disk_mb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxPreflight {
    pub distro_pretty_name: Option<String>,
    pub package_manager: String,
    pub systemd_user_reachable: bool,
    pub linger_enabled: Option<bool>,
    pub display_server: String,
    pub render_devices: Vec<String>,
    pub uinput_exists: bool,
    pub uinput_rw: bool,
    pub pipewire_version: Option<String>,
    pub wireplumber_version: Option<String>,
    pub firewall_backend: String,
    pub picom_glx_detected: bool,
    pub docker_available: bool,
    pub free_disk_mb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsPreflight {
    pub powershell_path: Option<String>,
    pub winget_available: bool,
    pub localappdata_set: bool,
    pub is_admin: bool,
    pub firewall_service_running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub os: String,
    pub arch: String,
    pub os_version: String,
    pub hostname: String,
    pub is_rosetta2: bool,
    pub is_headless: bool,
    pub has_browser_opener: bool,
    pub ssh_available: bool,
    pub ssh_version: Option<String>,
    pub pq_ssh_supported: bool,
    pub ssh_public_keys: Vec<String>,
    pub cargo_available: bool,
    pub rustc_version: Option<String>,
    pub repo_checkout: Option<RepoCheckoutInfo>,
    pub existing_installs: ExistingInstalls,
    pub macos: Option<MacosPreflight>,
    pub linux: Option<LinuxPreflight>,
    pub windows: Option<WindowsPreflight>,
    pub warnings: Vec<PreflightWarning>,
}

/// Normalizes Rust `env::consts::OS` to installer platform strings.
pub fn current_os() -> &'static str {
    env::consts::OS
}

/// Normalizes Rust `env::consts::ARCH` to standard release arch strings.
pub fn current_arch() -> &'static str {
    match env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => other,
    }
}

/// Attempts to locate the enclosing `secure-desktop-stream` repository root.
pub fn detect_repo_root(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if looks_like_sds_repo(p) {
            return fs::canonicalize(p).ok().or_else(|| Some(p.to_path_buf()));
        }
        return None;
    }
    let mut candidates = Vec::new();
    if let Ok(cwd) = env::current_dir() {
        let mut cur: Option<&Path> = Some(cwd.as_path());
        while let Some(dir) = cur {
            candidates.push(dir.to_path_buf());
            cur = dir.parent();
        }
    }
    if let Ok(exe) = env::current_exe() {
        let mut cur = exe.parent();
        while let Some(dir) = cur {
            candidates.push(dir.to_path_buf());
            cur = dir.parent();
        }
    }
    for cand in candidates {
        if looks_like_sds_repo(&cand) {
            return fs::canonicalize(&cand).ok().or(Some(cand));
        }
    }
    None
}

fn looks_like_sds_repo(dir: &Path) -> bool {
    dir.join("FORKS.md").is_file() && dir.join("tools").is_dir() && dir.join("installer").is_dir()
}

fn inspect_repo_checkout(root: &Path) -> RepoCheckoutInfo {
    RepoCheckoutInfo {
        root: root.display().to_string(),
        has_moonlight_qt: root.join("moonlight-qt/moonlight-qt.pro").is_file(),
        has_sunshine: root.join("sunshine/CMakeLists.txt").is_file(),
        has_mac_client_builder: root.join("tools/build-client-mac.sh").is_file(),
        has_linux_client_builder: root.join("tools/build-client-linux.sh").is_file(),
        has_linux_builder: root.join("tools/builder-sunshine-linux.sh").is_file(),
        has_windows_builder: root
            .join("tools/builder-sunshine-windows/build-sunshine-windows.sh")
            .is_file(),
    }
}

/// Runs a short diagnostic command with a hard timeout; never hangs preflight.
pub(crate) fn run_cmd_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Option<(bool, String, String)> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().ok()?;
                return Some((
                    output.status.success(),
                    String::from_utf8_lossy(&output.stdout).to_string(),
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}

pub(crate) fn command_exists(name: &str) -> Option<String> {
    #[cfg(windows)]
    {
        if let Some((true, out, _)) = run_cmd_timeout("where", &[name], Duration::from_secs(2)) {
            let line = out.lines().next().map(str::trim).unwrap_or("");
            if !line.is_empty() {
                return Some(line.to_string());
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        if let Ok(path_var) = env::var("PATH") {
            for dir in env::split_paths(&path_var) {
                let candidate = dir.join(name);
                if is_executable_file(&candidate) {
                    return Some(candidate.display().to_string());
                }
            }
        }
        None
    }
}

#[cfg(not(windows))]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        return meta.is_file() && (meta.permissions().mode() & 0o111) != 0;
    }
    false
}

fn user_home() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn detect_ssh_pub_keys(home: Option<&Path>) -> Vec<String> {
    let mut keys = Vec::new();
    let Some(h) = home else {
        return keys;
    };
    let ssh_dir = h.join(".ssh");
    if let Ok(entries) = fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("pub") {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    keys.push(name.to_string());
                }
            }
        }
    }
    keys.sort();
    keys
}

fn free_disk_mb_df(path: &Path) -> Option<u64> {
    #[cfg(not(windows))]
    {
        let target = path.to_str()?;
        let (ok, out, _) = run_cmd_timeout("df", &["-Pk", target], Duration::from_secs(2))?;
        if !ok {
            return None;
        }
        let line = out.lines().nth(1)?;
        let cols: Vec<&str> = line.split_whitespace().collect();
        let avail_kb: u64 = cols.get(3)?.parse().ok()?;
        Some(avail_kb / 1024)
    }
    #[cfg(windows)]
    {
        let _ = path;
        None
    }
}

fn detect_existing_installs(home: Option<&Path>, os: &str) -> ExistingInstalls {
    let mut client_paths = Vec::new();
    let mut host_paths = Vec::new();
    let mut systemd_units = Vec::new();

    if os == "macos" {
        let mut candidates = vec![
            PathBuf::from("/Applications/Moonlight Secure Desktop.app"),
            PathBuf::from("/Applications/Moonlight.app"),
        ];
        if let Some(h) = home {
            candidates.push(h.join("Applications/Moonlight Secure Desktop.app"));
            candidates.push(h.join("Applications/Moonlight.app"));
        }
        for app in candidates {
            if app.exists() {
                let (version, commit) = read_macos_bundle_meta(&app);
                client_paths.push(InstalledComponent {
                    kind: "moonlight-macos".to_string(),
                    path: app.display().to_string(),
                    version,
                    commit,
                });
            }
        }
    } else if os == "linux" {
        if let Some(h) = home {
            let client_bin = h.join(".local/bin/moonlight-sds");
            if client_bin.exists() {
                client_paths.push(InstalledComponent {
                    kind: "moonlight-linux".to_string(),
                    path: client_bin.display().to_string(),
                    version: None,
                    commit: None,
                });
            }
            let client_dir = h.join(".local/share/sds-client/app");
            if client_dir.exists() {
                client_paths.push(InstalledComponent {
                    kind: "moonlight-linux-dir".to_string(),
                    path: client_dir.display().to_string(),
                    version: None,
                    commit: None,
                });
            }
        }
        if let Ok(entries) = fs::read_dir("/opt") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("secure-desktop-stream") {
                    let bin = entry.path().join("sunshine");
                    if bin.exists() {
                        host_paths.push(InstalledComponent {
                            kind: "sunshine-linux".to_string(),
                            path: bin.display().to_string(),
                            version: None,
                            commit: None,
                        });
                    }
                }
            }
        }
        if let Some((true, out, _)) = run_cmd_timeout(
            "systemctl",
            &[
                "--user",
                "list-unit-files",
                "sds-*",
                "--no-legend",
                "--no-pager",
            ],
            Duration::from_secs(2),
        ) {
            for line in out.lines() {
                if let Some(unit) = line.split_whitespace().next() {
                    if unit.starts_with("sds-") {
                        systemd_units.push(unit.to_string());
                    }
                }
            }
        }
    } else if os == "windows" {
        if let Ok(local) = env::var("LOCALAPPDATA") {
            let base = PathBuf::from(local).join("Programs/SecureDesktopStream");
            let client_exe = base.join("Client/current/Moonlight.exe");
            if client_exe.exists() {
                client_paths.push(InstalledComponent {
                    kind: "moonlight-windows".to_string(),
                    path: client_exe.display().to_string(),
                    version: None,
                    commit: None,
                });
            }
            let host_exe = base.join("Sunshine/current/sunshine.exe");
            if host_exe.exists() {
                host_paths.push(InstalledComponent {
                    kind: "sunshine-windows".to_string(),
                    path: host_exe.display().to_string(),
                    version: None,
                    commit: None,
                });
            }
        }
    }

    ExistingInstalls {
        client_paths,
        host_paths,
        systemd_units,
    }
}

fn read_macos_bundle_meta(app: &Path) -> (Option<String>, Option<String>) {
    let mut commit = None;
    let build_json = app.join("Contents/Resources/sds-build.json");
    if let Ok(raw) = fs::read_to_string(&build_json) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            commit = val
                .get("client_commit")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);
        }
    }
    let version = run_cmd_timeout(
        "/usr/bin/plutil",
        &[
            "-extract",
            "CFBundleShortVersionString",
            "raw",
            "-o",
            "-",
            &app.join("Contents/Info.plist").display().to_string(),
        ],
        Duration::from_secs(2),
    )
    .and_then(|(ok, out, _)| {
        let s = out.trim().to_string();
        if ok && !s.is_empty() {
            Some(s)
        } else {
            None
        }
    });
    (version, commit)
}

fn collect_macos(home: Option<&Path>) -> MacosPreflight {
    let homebrew_prefix = if Path::new("/opt/homebrew/bin/brew").exists() {
        Some("/opt/homebrew".to_string())
    } else if Path::new("/usr/local/bin/brew").exists() {
        Some("/usr/local".to_string())
    } else {
        None
    };
    let xcode_clt_installed =
        run_cmd_timeout("/usr/bin/xcode-select", &["-p"], Duration::from_secs(2))
            .is_some_and(|(ok, _, _)| ok);

    let qmake6_path = ["/opt/homebrew/bin/qmake6", "/usr/local/bin/qmake6"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .map(ToString::to_string)
        .or_else(|| command_exists("qmake6"));
    let macdeployqt_path = [
        "/opt/homebrew/bin/macdeployqt",
        "/usr/local/bin/macdeployqt",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists())
    .map(ToString::to_string)
    .or_else(|| command_exists("macdeployqt"));

    let local_signing_identities_count = run_cmd_timeout(
        "/usr/bin/security",
        &["find-identity", "-v", "-p", "codesigning"],
        Duration::from_secs(3),
    )
    .map(|(ok, out, _)| {
        if !ok {
            return 0;
        }
        out.lines()
            .filter(|line| line.contains("Local Signing"))
            .count()
    })
    .unwrap_or(0);

    let signing_config_exists = home
        .map(|h| {
            h.join("Library/Application Support/SecureDesktopStream/code-signing.json")
                .exists()
        })
        .unwrap_or(false);

    let free_disk_mb = home.and_then(free_disk_mb_df);

    MacosPreflight {
        homebrew_prefix,
        xcode_clt_installed,
        qmake6_path,
        macdeployqt_path,
        local_signing_identities_count,
        signing_config_exists,
        free_disk_mb,
    }
}

fn collect_linux(home: Option<&Path>) -> LinuxPreflight {
    let distro_pretty_name = fs::read_to_string("/etc/os-release").ok().and_then(|txt| {
        txt.lines()
            .find_map(|line| line.strip_prefix("PRETTY_NAME="))
            .map(|v| v.trim_matches('"').to_string())
    });

    let systemd_user_reachable = run_cmd_timeout(
        "systemctl",
        &["--user", "is-system-running"],
        Duration::from_secs(2),
    )
    .is_some_and(|(_, out, _)| {
        matches!(
            out.trim(),
            "running" | "degraded" | "starting" | "initializing" | "maintenance"
        )
    });

    let user_name = env::var("USER").unwrap_or_default();
    let linger_enabled = if !user_name.is_empty() {
        run_cmd_timeout(
            "loginctl",
            &["show-user", &user_name, "-p", "Linger", "--value"],
            Duration::from_secs(2),
        )
        .and_then(|(ok, out, _)| {
            if !ok {
                return None;
            }
            match out.trim() {
                "yes" => Some(true),
                "no" => Some(false),
                _ => None,
            }
        })
    } else {
        None
    };

    let display_server = if env::var_os("WAYLAND_DISPLAY").is_some() {
        "wayland".to_string()
    } else if env::var_os("DISPLAY").is_some() {
        "x11".to_string()
    } else {
        "headless".to_string()
    };

    let mut render_devices = Vec::new();
    if let Ok(entries) = fs::read_dir("/dev/dri") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("renderD") {
                render_devices.push(entry.path().display().to_string());
            }
        }
    }
    render_devices.sort();

    let uinput_path = Path::new("/dev/uinput");
    let uinput_exists = uinput_path.exists();
    let uinput_rw = uinput_exists
        && fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(uinput_path)
            .is_ok();

    let pipewire_version = run_cmd_timeout("pipewire", &["--version"], Duration::from_secs(2))
        .and_then(|(ok, out, _)| {
            if ok {
                out.lines().last().map(|l| l.trim().to_string())
            } else {
                None
            }
        });
    let wireplumber_version =
        run_cmd_timeout("wireplumber", &["--version"], Duration::from_secs(2)).and_then(
            |(ok, out, _)| {
                if ok {
                    out.lines().last().map(|l| l.trim().to_string())
                } else {
                    None
                }
            },
        );

    let package_manager = if command_exists("apt-get").is_some() {
        "apt".to_string()
    } else if command_exists("dnf").is_some() {
        "dnf".to_string()
    } else if command_exists("pacman").is_some() {
        "pacman".to_string()
    } else if command_exists("zypper").is_some() {
        "zypper".to_string()
    } else {
        "unknown".to_string()
    };

    let firewall_backend = if command_exists("ufw").is_some() {
        "ufw".to_string()
    } else if command_exists("firewall-cmd").is_some() {
        "firewalld".to_string()
    } else if command_exists("nft").is_some() {
        "nftables".to_string()
    } else {
        "none".to_string()
    };

    let picom_glx_detected = home
        .map(|h| {
            [
                h.join(".config/picom.conf"),
                h.join(".config/picom/picom.conf"),
            ]
            .into_iter()
            .filter_map(|p| fs::read_to_string(p).ok())
            .any(|txt| {
                txt.lines().any(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with('#')
                        && trimmed.contains("backend")
                        && trimmed.contains("glx")
                })
            })
        })
        .unwrap_or(false);

    let docker_available = command_exists("docker").is_some();
    let free_disk_mb = home.and_then(free_disk_mb_df);

    LinuxPreflight {
        distro_pretty_name,
        package_manager,
        systemd_user_reachable,
        linger_enabled,
        display_server,
        render_devices,
        uinput_exists,
        uinput_rw,
        pipewire_version,
        wireplumber_version,
        firewall_backend,
        picom_glx_detected,
        docker_available,
        free_disk_mb,
    }
}

fn collect_windows() -> WindowsPreflight {
    let powershell_path = command_exists("pwsh").or_else(|| command_exists("powershell"));
    let winget_available = command_exists("winget").is_some();
    let localappdata_set = env::var_os("LOCALAPPDATA").is_some();
    let is_admin = powershell_path
        .as_deref()
        .and_then(|ps| {
            run_cmd_timeout(
                ps,
                &[
                    "-NoProfile",
                    "-Command",
                    "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
                ],
                Duration::from_secs(3),
            )
        })
        .is_some_and(|(ok, out, _)| ok && out.trim().eq_ignore_ascii_case("true"));
    let firewall_service_running = powershell_path
        .as_deref()
        .and_then(|ps| {
            run_cmd_timeout(
                ps,
                &[
                    "-NoProfile",
                    "-Command",
                    "(Get-Service mpssvc -ErrorAction SilentlyContinue).Status",
                ],
                Duration::from_secs(3),
            )
        })
        .is_some_and(|(ok, out, _)| ok && out.trim().eq_ignore_ascii_case("Running"));

    WindowsPreflight {
        powershell_path,
        winget_available,
        localappdata_set,
        is_admin,
        firewall_service_running,
    }
}

/// Collects a full diagnostic & capability report for the current machine.
pub fn collect_preflight(explicit_repo_root: Option<&Path>) -> PreflightReport {
    let os = current_os().to_string();
    let arch = current_arch().to_string();
    let home = user_home();

    let os_version = match os.as_str() {
        "macos" => run_cmd_timeout("sw_vers", &["-productVersion"], Duration::from_secs(2))
            .filter(|(ok, _, _)| *ok)
            .map(|(_, out, _)| out.trim().to_string())
            .unwrap_or_else(|| "macOS".to_string()),
        "linux" => run_cmd_timeout("uname", &["-r"], Duration::from_secs(2))
            .filter(|(ok, _, _)| *ok)
            .map(|(_, out, _)| out.trim().to_string())
            .unwrap_or_else(|| "Linux".to_string()),
        _ => env::consts::OS.to_string(),
    };

    let hostname = run_cmd_timeout("hostname", &[], Duration::from_secs(2))
        .filter(|(ok, _, _)| *ok)
        .map(|(_, out, _)| out.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let is_rosetta2 = os == "macos"
        && run_cmd_timeout(
            "/usr/sbin/sysctl",
            &["-n", "sysctl.proc_translated"],
            Duration::from_secs(2),
        )
        .is_some_and(|(ok, out, _)| ok && out.trim() == "1");

    let is_headless = os == "linux"
        && ((env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none())
            || env::var_os("SSH_CONNECTION").is_some());

    let has_browser_opener = match os.as_str() {
        "macos" => Path::new("/usr/bin/open").exists(),
        "linux" => command_exists("xdg-open").is_some(),
        "windows" => true,
        _ => false,
    };

    let ssh_available = command_exists("ssh").is_some();
    let ssh_version = if ssh_available {
        run_cmd_timeout("ssh", &["-V"], Duration::from_secs(2)).and_then(|(_, out, err)| {
            let line = err.lines().chain(out.lines()).next()?.trim().to_string();
            if line.is_empty() {
                None
            } else {
                Some(line)
            }
        })
    } else {
        None
    };
    let pq_ssh_supported = ssh_available
        && run_cmd_timeout("ssh", &["-Q", "kex"], Duration::from_secs(2)).is_some_and(
            |(ok, out, _)| ok && out.lines().any(|l| l.trim() == "mlkem768x25519-sha256"),
        );

    let ssh_public_keys = detect_ssh_pub_keys(home.as_deref());
    let cargo_available = command_exists("cargo").is_some();
    let rustc_version = run_cmd_timeout("rustc", &["--version"], Duration::from_secs(2))
        .filter(|(ok, _, _)| *ok)
        .map(|(_, out, _)| out.trim().to_string());

    let repo_checkout = detect_repo_root(explicit_repo_root).map(|r| inspect_repo_checkout(&r));
    let existing_installs = detect_existing_installs(home.as_deref(), &os);

    let macos = if os == "macos" {
        Some(collect_macos(home.as_deref()))
    } else {
        None
    };
    let linux = if os == "linux" {
        Some(collect_linux(home.as_deref()))
    } else {
        None
    };
    let windows = if os == "windows" {
        Some(collect_windows())
    } else {
        None
    };

    let mut warnings = Vec::new();
    if is_rosetta2 {
        warnings.push(PreflightWarning {
            code: "macos_rosetta2".into(),
            severity: "warning".into(),
            title_ru: "Запуск под трансляцией Rosetta 2".into(),
            title_en: "Running under Rosetta 2 translation".into(),
            detail_ru: "На Apple Silicon рекомендуется нативный arm64-процесс и arm64 Homebrew (/opt/homebrew).".into(),
            detail_en: "On Apple Silicon, use native arm64 execution and /opt/homebrew.".into(),
        });
    }
    if ssh_available && !pq_ssh_supported {
        warnings.push(PreflightWarning {
            code: "ssh_no_pq_kex".into(),
            severity: "warning".into(),
            title_ru: "OpenSSH не поддерживает mlkem768x25519-sha256".into(),
            title_en: "OpenSSH lacks mlkem768x25519-sha256".into(),
            detail_ru: "Обновите OpenSSH до >= 9.9/10.0 или временно снимите требование строгого PQ SSH при деплое.".into(),
            detail_en: "Upgrade OpenSSH to >= 9.9/10.0 or uncheck strict PQ SSH enforcement for legacy hosts.".into(),
        });
    }
    if os == "macos" {
        warnings.push(PreflightWarning {
            code: "unsigned_macos_notice".into(),
            severity: "info".into(),
            title_ru: "Неподписанные/ad-hoc сборки macOS".into(),
            title_en: "Unsigned / ad-hoc macOS builds".into(),
            detail_ru: "Без Apple Developer ID снятие карантина выполняется только по явному выбору (--allow-unnotarized), глобальный Gatekeeper не отключается.".into(),
            detail_en: "Without Apple Developer ID, quarantine removal requires explicit opt-in; global Gatekeeper remains enabled.".into(),
        });
    }
    if let Some(ref m) = macos {
        if m.free_disk_mb.is_some_and(|mb| mb < 2048) {
            warnings.push(PreflightWarning {
                code: "low_disk_space".into(),
                severity: "warning".into(),
                title_ru: "Мало свободного места на диске (< 2 ГБ)".into(),
                title_en: "Low free disk space (< 2 GiB)".into(),
                detail_ru: "Сборка клиента из исходников требует минимум 2 ГБ свободного места.".into(),
                detail_en: "Building the Mac client from source requires at least 2 GiB free space.".into(),
            });
        }
    }
    if let Some(ref l) = linux {
        if l.linger_enabled == Some(false) {
            warnings.push(PreflightWarning {
                code: "linux_linger_disabled".into(),
                severity: "warning".into(),
                title_ru: "systemd linger выключен для текущего пользователя".into(),
                title_en: "systemd user lingering is disabled".into(),
                detail_ru: "Без `loginctl enable-linger` виртуальный стол и Sunshine не запустятся автоматически после перезагрузки без входа в консоль.".into(),
                detail_en: "Without `loginctl enable-linger`, headless host services will not start at boot.".into(),
            });
        }
        if l.display_server == "wayland" {
            warnings.push(PreflightWarning {
                code: "linux_wayland_detected".into(),
                severity: "info".into(),
                title_ru: "Обнаружена сессия Wayland".into(),
                title_en: "Wayland session detected".into(),
                detail_ru: "Для автономного удалённого стола без блокировки экрана используйте профиль «Linux Virtual X11» (Xvfb/Xorg dummy + LXQt).".into(),
                detail_en: "For unattended headless streaming, use the 'Linux Virtual X11' profile.".into(),
            });
        }
        if l.firewall_backend == "none" {
            warnings.push(PreflightWarning {
                code: "linux_no_firewall".into(),
                severity: "warning".into(),
                title_ru: "Не обнаружен ufw/firewalld/nft".into(),
                title_en: "No ufw/firewalld/nft firewall tool found".into(),
                detail_ru: "Для изоляции портов 47984/48010/47989 от лишних хостов установите ufw или nftables.".into(),
                detail_en: "Install ufw or nftables to restrict streaming ports to the controller IP.".into(),
            });
        }
        if l.picom_glx_detected {
            warnings.push(PreflightWarning {
                code: "linux_picom_glx".into(),
                severity: "warning".into(),
                title_ru: "Обнаружен picom с backend = \"glx\"".into(),
                title_en: "Detected picom configured with backend = \"glx\"".into(),
                detail_ru: "При захвате X11 (x11grab) и полноэкранном видео в браузере picom glx может вызывать зависание кадра; используйте backend = \"xrender\".".into(),
                detail_en: "With Sunshine x11grab and fullscreen browser video, picom glx can freeze frames; switch to backend = \"xrender\".".into(),
            });
        }
    }
    if os == "windows" {
        warnings.push(PreflightWarning {
            code: "unsigned_windows_notice".into(),
            severity: "info".into(),
            title_ru: "Неподписанные сборки Windows (SmartScreen / MOTW)".into(),
            title_en: "Unsigned Windows builds (SmartScreen / MOTW)".into(),
            detail_ru: "Без Authenticode-подписи `Unblock-File` применяется только после проверки SHA-256 и явного подтверждения, без отключения SmartScreen/Defender.".into(),
            detail_en: "Without Authenticode, Unblock-File runs only after SHA-256 verification and explicit opt-in; SmartScreen stays enabled.".into(),
        });
    }

    PreflightReport {
        os,
        arch,
        os_version,
        hostname,
        is_rosetta2,
        is_headless,
        has_browser_opener,
        ssh_available,
        ssh_version,
        pq_ssh_supported,
        ssh_public_keys,
        cargo_available,
        rustc_version,
        repo_checkout,
        existing_installs,
        macos,
        linux,
        windows,
        warnings,
    }
}
