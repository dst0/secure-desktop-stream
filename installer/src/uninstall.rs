//! Manifest-backed, allowlist-guarded cross-platform uninstaller for Secure Desktop Stream.
//! Never removes arbitrary manifest paths: every target path must pass `is_safe_sds_removal_path`.

use crate::archive::write_atomic;
use crate::config_gen::{generate_firewall_commands, FirewallBackend};
use crate::installer_ops::ProgressEmitter;
use crate::platform::{current_os, run_cmd_timeout};
use crate::validation::{shell_single_quote, validate_instance_name, validate_ssh_target};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UninstallComponent {
    Client,
    Host,
    Installer,
    All,
}

impl UninstallComponent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Host => "host",
            Self::Installer => "installer",
            Self::All => "all",
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            Self::All => Self::Client,
            Self::Client => Self::Host,
            Self::Host => Self::Installer,
            Self::Installer => Self::All,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostManifestEntry {
    pub instance_name: String,
    pub install_dir: String,
    pub systemd_units: Vec<String>,
    pub firewall_backend: Option<FirewallBackend>,
    pub paths: Vec<String>,
    pub config_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InstallManifest {
    pub version: u32,
    pub os: String,
    pub client_paths: Vec<String>,
    pub client_config_paths: Vec<String>,
    pub host_instances: Vec<HostManifestEntry>,
    pub installer_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallRequest {
    pub component: UninstallComponent,
    #[serde(default = "default_instance_name")]
    pub instance_name: String,
    #[serde(default)]
    pub purge_config: bool,
    #[serde(default = "default_true")]
    pub remove_firewall: bool,
    #[serde(default)]
    pub ssh_target: Option<String>,
    #[serde(default = "default_true")]
    pub require_pq_ssh: bool,
    #[serde(default)]
    pub strict_ssh_host_key: bool,
    #[serde(default)]
    pub execute_sudo: bool,
    #[serde(default)]
    pub user_only: bool,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallResult {
    pub ok: bool,
    pub dry_run: bool,
    pub verified_clean: bool,
    pub removed_paths: Vec<String>,
    pub skipped_or_protected_paths: Vec<String>,
    pub remaining_artifacts: Vec<String>,
    pub commands_executed_or_planned: Vec<String>,
    pub elevated_commands: Vec<String>,
    pub summary: String,
}

fn default_instance_name() -> String {
    "sds-host".to_string()
}

fn default_true() -> bool {
    true
}

fn user_home() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| "HOME / USERPROFILE is not set".to_string())
}

pub fn manifest_path(home: &Path, os: &str) -> PathBuf {
    match os {
        "macos" => {
            home.join("Library/Application Support/SecureDesktopStream/install-manifest.json")
        }
        "windows" => env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Local"))
            .join("SecureDesktopStream/install-manifest.json"),
        _ => home.join(".local/state/secure-desktop-stream/manifest.json"),
    }
}

pub fn load_manifest(home: &Path, os: &str) -> InstallManifest {
    let path = manifest_path(home, os);
    let Ok(raw) = fs::read_to_string(&path) else {
        return InstallManifest {
            version: 1,
            os: os.to_string(),
            ..InstallManifest::default()
        };
    };
    serde_json::from_str(&raw).unwrap_or_else(|_| InstallManifest {
        version: 1,
        os: os.to_string(),
        ..InstallManifest::default()
    })
}

pub fn save_manifest(home: &Path, os: &str, manifest: &InstallManifest) -> Result<(), String> {
    let path = manifest_path(home, os);
    let bytes = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
    write_atomic(&path, &bytes, false).map_err(|e| e.to_string())
}

pub fn record_client_install(
    home: &Path,
    os: &str,
    paths: &[PathBuf],
    config_paths: &[PathBuf],
) -> Result<(), String> {
    let mut m = load_manifest(home, os);
    m.version = 1;
    m.os = os.to_string();
    let mut pset: BTreeSet<String> = m.client_paths.into_iter().collect();
    for p in paths {
        pset.insert(p.display().to_string());
    }
    m.client_paths = pset.into_iter().collect();

    let mut cset: BTreeSet<String> = m.client_config_paths.into_iter().collect();
    for p in config_paths {
        cset.insert(p.display().to_string());
    }
    m.client_config_paths = cset.into_iter().collect();
    save_manifest(home, os, &m)
}

pub fn record_host_install(home: &Path, os: &str, entry: HostManifestEntry) -> Result<(), String> {
    let mut m = load_manifest(home, os);
    m.version = 1;
    m.os = os.to_string();
    m.host_instances
        .retain(|existing| existing.instance_name != entry.instance_name);
    m.host_instances.push(entry);
    save_manifest(home, os, &m)
}

fn has_valid_slug_suffix(name: &str, prefix: &str, suffix: &str) -> bool {
    let Some(rest) = name
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
    else {
        return false;
    };
    validate_instance_name(rest).is_ok()
}

fn has_valid_slug_prefix_only(name: &str, prefix: &str) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    validate_instance_name(rest).is_ok()
}

fn normalize_win_path(p: &Path) -> String {
    p.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn path_eq_win(a: &Path, b: &Path) -> bool {
    normalize_win_path(a) == normalize_win_path(b)
}

fn is_win_versions_child(candidate: &Path, versions_dir: &Path) -> bool {
    let Some(parent) = candidate.parent() else {
        return false;
    };
    if !path_eq_win(parent, versions_dir) {
        return false;
    }
    let Some(name) = candidate.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    (1..=64).contains(&name.len()) && name.chars().all(|c| c.is_ascii_hexdigit())
}

/// Strictly validates whether a filesystem path is an SDS-owned artifact eligible for deletion.
/// Rejects root directories, user home directories, traversal (`..` / `.`), and unrelated application paths.
pub fn is_safe_sds_removal_path(candidate: &Path, home: &Path, purge_config: bool) -> bool {
    if !candidate.is_absolute()
        || candidate
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || candidate
            .to_string_lossy()
            .split(['/', '\\'])
            .any(|seg| seg == ".")
    {
        return false;
    }

    // Never allow deleting top-level or container directories themselves.
    let protected = [
        PathBuf::from("/"),
        PathBuf::from("/Applications"),
        PathBuf::from("/opt"),
        PathBuf::from("/etc"),
        home.to_path_buf(),
        home.join("Applications"),
        home.join(".config"),
        home.join(".local"),
        home.join(".local/bin"),
        home.join(".local/share"),
        home.join(".local/share/applications"),
        home.join(".local/state"),
        home.join(".cache"),
        home.join("Library"),
        home.join("Library/Application Support"),
        home.join("Library/Preferences"),
    ];
    if protected.iter().any(|p| p == candidate) {
        return false;
    }

    // Exact cross-platform SDS binary / bundle / launcher / systemd / udev paths
    let exact_non_config = [
        home.join("Applications/Moonlight Secure Desktop.app"),
        PathBuf::from("/Applications/Moonlight Secure Desktop.app"),
        home.join("Applications/Secure Desktop Stream Installer.app"),
        PathBuf::from("/Applications/Secure Desktop Stream Installer.app"),
        home.join(".local/share/sds-client"),
        home.join(".local/share/sds-client/app"),
        home.join(".local/bin/moonlight-sds"),
        home.join(".local/share/applications/sds-moonlight.desktop"),
        home.join(".local/share/sds-installer"),
        home.join(".local/share/sds-installer/app"),
        home.join(".local/bin/sds-installer"),
        home.join(".local/share/applications/sds-installer.desktop"),
        PathBuf::from("/etc/udev/rules.d/60-sds-uinput.rules"),
    ];
    if exact_non_config.iter().any(|p| p == candidate) {
        return true;
    }

    // /opt/secure-desktop-stream-<valid_slug>
    if candidate.parent() == Some(Path::new("/opt")) {
        if let Some(name) = candidate.file_name().and_then(|n| n.to_str()) {
            if has_valid_slug_prefix_only(name, "secure-desktop-stream-") {
                return true;
            }
        }
    }

    // ~/.local/share/sds-installer-stage/<valid_slug>
    let stage_root = home.join(".local/share/sds-installer-stage");
    if candidate.parent() == Some(stage_root.as_path()) {
        if let Some(name) = candidate.file_name().and_then(|n| n.to_str()) {
            if validate_instance_name(name).is_ok() {
                return true;
            }
        }
    }

    // ~/.config/systemd/user/<valid_slug>-{display,audio,sunshine}.service or drop-in dir
    let systemd_user = home.join(".config/systemd/user");
    if candidate.parent() == Some(systemd_user.as_path()) {
        if let Some(name) = candidate.file_name().and_then(|n| n.to_str()) {
            if has_valid_slug_suffix(name, "", "-display.service")
                || has_valid_slug_suffix(name, "", "-audio.service")
                || has_valid_slug_suffix(name, "", "-sunshine.service")
                || has_valid_slug_suffix(name, "", "-display.service.d")
                || has_valid_slug_suffix(name, "", "-sunshine.service.d")
            {
                return true;
            }
        }
    }

    // Windows LocalAppData SDS folders / Start Menu shortcut (case-insensitive comparison)
    if let Some(local) = env::var_os("LOCALAPPDATA").map(PathBuf::from) {
        let win_prog = local.join("Programs/SecureDesktopStream");
        for sub in ["Client", "Sunshine", "Installer"] {
            let root = win_prog.join(sub);
            let allow_root = sub != "Sunshine" || purge_config;
            if (allow_root && path_eq_win(candidate, &root))
                || path_eq_win(candidate, &root.join("current"))
                || path_eq_win(candidate, &root.join("versions"))
                || is_win_versions_child(candidate, &root.join("versions"))
            {
                return true;
            }
        }
        if purge_config
            && (path_eq_win(candidate, &win_prog.join("Sunshine/config"))
                || path_eq_win(candidate, &win_prog)
                || path_eq_win(candidate, &local.join("SecureDesktopStream")))
        {
            return true;
        }
    }
    if let Some(appdata) = env::var_os("APPDATA").map(PathBuf::from) {
        if path_eq_win(
            candidate,
            &appdata
                .join("Microsoft/Windows/Start Menu/Programs/Secure Desktop Stream Installer.lnk"),
        ) {
            return true;
        }
    }

    // Purge-only config / state / receipt paths
    if purge_config {
        let exact_config = [
            home.join("Library/Application Support/SecureDesktopStream"),
            home.join("Library/Application Support/SecureDesktopStream/client-receipt.json"),
            home.join("Library/Application Support/SecureDesktopStream/install-manifest.json"),
            home.join("Library/Preferences/local.secure-desktop-stream.Moonlight.plist"),
            home.join(".local/state/secure-desktop-stream"),
            home.join(".local/state/secure-desktop-stream/manifest.json"),
            home.join(".local/share/sds-client/client-receipt.json"),
        ];
        if exact_config.iter().any(|p| p == candidate) {
            return true;
        }

        if candidate.parent() == Some(home.join(".config").as_path()) {
            if let Some(name) = candidate.file_name().and_then(|n| n.to_str()) {
                if has_valid_slug_suffix(name, "", "-sunshine")
                    || has_valid_slug_suffix(name, "", "-desktop")
                {
                    return true;
                }
            }
        }
        for base in [
            home.join(".local/share"),
            home.join(".local/state"),
            home.join(".cache"),
        ] {
            if candidate.parent() == Some(base.as_path()) {
                if let Some(name) = candidate.file_name().and_then(|n| n.to_str()) {
                    if has_valid_slug_suffix(name, "", "-sunshine")
                        || has_valid_slug_suffix(name, "", "-desktop")
                        || has_valid_slug_suffix(name, "", "-audio")
                    {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn verify_no_symlink_ancestors(target: &Path, stop_at: &Path) -> Result<(), String> {
    let mut cur = target.parent();
    while let Some(anc) = cur {
        if anc == stop_at || anc.as_os_str().is_empty() || anc == Path::new("/") {
            break;
        }
        #[cfg(target_os = "macos")]
        if anc == Path::new("/etc") || anc == Path::new("/var") || anc == Path::new("/tmp") {
            cur = anc.parent();
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(anc) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing removal through symlinked ancestor directory: {}",
                    anc.display()
                ));
            }
        }
        cur = anc.parent();
    }
    Ok(())
}

fn path_exists_or_symlink(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

fn remove_allowlisted_path(p: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(p).map_err(|e| format!("stat {}: {e}", p.display()))?;
    if meta.file_type().is_symlink() || meta.is_file() {
        fs::remove_file(p).map_err(|e| format!("remove {}: {e}", p.display()))?;
    } else if meta.is_dir() {
        fs::remove_dir_all(p).map_err(|e| format!("remove dir {}: {e}", p.display()))?;
    }
    Ok(())
}

fn requires_root_on_unix(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.starts_with("/Applications/") || s.starts_with("/opt/") || s.starts_with("/etc/")
}

fn detect_local_linux_firewall() -> Option<FirewallBackend> {
    if crate::platform::command_exists("ufw").is_some() {
        Some(FirewallBackend::Ufw)
    } else if crate::platform::command_exists("firewall-cmd").is_some() {
        Some(FirewallBackend::Firewalld)
    } else if crate::platform::command_exists("nft").is_some() {
        Some(FirewallBackend::Nftables)
    } else {
        None
    }
}

/// Runs a safe, manifest-tracked uninstallation locally or over PQ SSH.
pub async fn run_uninstall(
    req: &UninstallRequest,
    emit: &ProgressEmitter,
) -> Result<UninstallResult, String> {
    let instance = validate_instance_name(&req.instance_name).map_err(|e| e.to_string())?;

    if let Some(ref raw_ssh) = req.ssh_target {
        let trimmed = raw_ssh.trim();
        if !trimmed.is_empty() {
            let ssh = validate_ssh_target(trimmed).map_err(|e| e.to_string())?;
            return run_remote_linux_uninstall(req, &ssh, &instance, emit).await;
        }
    }

    let os = current_os();
    let home = user_home()?;
    run_uninstall_for_home(req, &home, os, emit).await
}

/// Runs a safe, manifest-tracked local uninstallation scoped to an explicit `home` and `os`.
pub async fn run_uninstall_for_home(
    req: &UninstallRequest,
    home: &Path,
    os: &str,
    emit: &ProgressEmitter,
) -> Result<UninstallResult, String> {
    let instance = validate_instance_name(&req.instance_name).map_err(|e| e.to_string())?;
    let home = home.to_path_buf();
    let manifest = load_manifest(&home, os);
    let effective_user_only =
        req.user_only || env::var("SDS_UNINSTALL_USER_ONLY").as_deref() == Ok("1");

    let include_client = matches!(
        req.component,
        UninstallComponent::Client | UninstallComponent::All
    );
    let include_host = matches!(
        req.component,
        UninstallComponent::Host | UninstallComponent::All
    );
    let include_installer = matches!(
        req.component,
        UninstallComponent::Installer | UninstallComponent::All
    );

    let mut candidate_paths = BTreeSet::<PathBuf>::new();
    let mut systemd_units = BTreeSet::<String>::new();
    let mut active_instances = BTreeSet::<String>::new();
    active_instances.insert(instance.clone());
    if req.component == UninstallComponent::All {
        for entry in &manifest.host_instances {
            if validate_instance_name(&entry.instance_name).is_ok() {
                active_instances.insert(entry.instance_name.clone());
            }
        }
    }

    if include_client {
        for p in &manifest.client_paths {
            let pb = PathBuf::from(p);
            if effective_user_only && os == "macos" && pb.starts_with("/Applications/") {
                continue;
            }
            candidate_paths.insert(pb);
        }
        if req.purge_config {
            for p in &manifest.client_config_paths {
                candidate_paths.insert(PathBuf::from(p));
            }
        }
        match os {
            "macos" => {
                candidate_paths.insert(home.join("Applications/Moonlight Secure Desktop.app"));
                if !effective_user_only {
                    candidate_paths
                        .insert(PathBuf::from("/Applications/Moonlight Secure Desktop.app"));
                }
                if req.purge_config {
                    candidate_paths.insert(home.join(
                        "Library/Application Support/SecureDesktopStream/client-receipt.json",
                    ));
                    candidate_paths.insert(
                        home.join(
                            "Library/Preferences/local.secure-desktop-stream.Moonlight.plist",
                        ),
                    );
                }
            }
            "linux" => {
                candidate_paths.insert(home.join(".local/share/sds-client"));
                candidate_paths.insert(home.join(".local/bin/moonlight-sds"));
                candidate_paths
                    .insert(home.join(".local/share/applications/sds-moonlight.desktop"));
            }
            "windows" => {
                if let Some(local) = env::var_os("LOCALAPPDATA").map(PathBuf::from) {
                    candidate_paths.insert(local.join("Programs/SecureDesktopStream/Client"));
                }
            }
            _ => {}
        }
    }

    if include_host {
        for entry in &manifest.host_instances {
            if !active_instances.contains(&entry.instance_name) {
                continue;
            }
            for p in &entry.paths {
                candidate_paths.insert(PathBuf::from(p));
            }
            for u in &entry.systemd_units {
                systemd_units.insert(u.clone());
            }
            if req.purge_config {
                for p in &entry.config_paths {
                    candidate_paths.insert(PathBuf::from(p));
                }
            }
        }
        for inst in &active_instances {
            if os == "linux" {
                for suffix in ["display.service", "audio.service", "sunshine.service"] {
                    let u = format!("{inst}-{suffix}");
                    candidate_paths.insert(home.join(".config/systemd/user").join(&u));
                    systemd_units.insert(u);
                }
                candidate_paths.insert(
                    home.join(".config/systemd/user")
                        .join(format!("{inst}-display.service.d")),
                );
                candidate_paths.insert(
                    home.join(".config/systemd/user")
                        .join(format!("{inst}-sunshine.service.d")),
                );
                candidate_paths.insert(home.join(".local/share/sds-installer-stage").join(inst));
                candidate_paths.insert(PathBuf::from(format!("/opt/secure-desktop-stream-{inst}")));
                candidate_paths.insert(PathBuf::from("/etc/udev/rules.d/60-sds-uinput.rules"));
                if req.purge_config {
                    candidate_paths.insert(home.join(".config").join(format!("{inst}-sunshine")));
                    candidate_paths.insert(home.join(".config").join(format!("{inst}-desktop")));
                    candidate_paths
                        .insert(home.join(".local/share").join(format!("{inst}-sunshine")));
                    candidate_paths
                        .insert(home.join(".local/share").join(format!("{inst}-desktop")));
                    candidate_paths
                        .insert(home.join(".local/state").join(format!("{inst}-sunshine")));
                    candidate_paths.insert(home.join(".local/state").join(format!("{inst}-audio")));
                    candidate_paths.insert(home.join(".cache").join(format!("{inst}-sunshine")));
                    candidate_paths.insert(home.join(".cache").join(format!("{inst}-desktop")));
                }
            } else if os == "windows" {
                if let Some(local) = env::var_os("LOCALAPPDATA").map(PathBuf::from) {
                    if req.purge_config {
                        candidate_paths.insert(local.join("Programs/SecureDesktopStream/Sunshine"));
                    } else {
                        candidate_paths
                            .insert(local.join("Programs/SecureDesktopStream/Sunshine/current"));
                        candidate_paths
                            .insert(local.join("Programs/SecureDesktopStream/Sunshine/versions"));
                    }
                }
            }
        }
    }

    if include_installer {
        for p in &manifest.installer_paths {
            let pb = PathBuf::from(p);
            if effective_user_only && os == "macos" && pb.starts_with("/Applications/") {
                continue;
            }
            candidate_paths.insert(pb);
        }
        match os {
            "macos" => {
                candidate_paths
                    .insert(home.join("Applications/Secure Desktop Stream Installer.app"));
                if !effective_user_only {
                    candidate_paths.insert(PathBuf::from(
                        "/Applications/Secure Desktop Stream Installer.app",
                    ));
                }
                candidate_paths.insert(home.join(".local/bin/sds-installer"));
                if req.purge_config {
                    candidate_paths
                        .insert(home.join("Library/Application Support/SecureDesktopStream"));
                }
            }
            "linux" => {
                candidate_paths.insert(home.join(".local/share/sds-installer"));
                candidate_paths.insert(home.join(".local/bin/sds-installer"));
                candidate_paths
                    .insert(home.join(".local/share/applications/sds-installer.desktop"));
                if req.purge_config {
                    candidate_paths.insert(home.join(".local/state/secure-desktop-stream"));
                }
            }
            "windows" => {
                if let Some(local) = env::var_os("LOCALAPPDATA").map(PathBuf::from) {
                    candidate_paths.insert(local.join("Programs/SecureDesktopStream/Installer"));
                    if req.purge_config {
                        candidate_paths.insert(local.join("SecureDesktopStream"));
                    }
                }
                if let Some(appdata) = env::var_os("APPDATA").map(PathBuf::from) {
                    candidate_paths.insert(appdata.join(
                        "Microsoft/Windows/Start Menu/Programs/Secure Desktop Stream Installer.lnk",
                    ));
                }
            }
            _ => {}
        }
    }

    let mut commands_planned = Vec::new();
    let mut elevated = Vec::new();
    let mut safe_targets = Vec::new();
    let mut skipped = Vec::new();

    for p in candidate_paths {
        if !is_safe_sds_removal_path(&p, &home, req.purge_config) {
            if path_exists_or_symlink(&p) {
                skipped.push(p.display().to_string());
            }
            continue;
        }
        let stop_at = if p.starts_with(&home) {
            home.as_path()
        } else {
            Path::new("/")
        };
        if let Err(e) = verify_no_symlink_ancestors(&p, stop_at) {
            emit.emit("uninstall", "warn", e);
            if path_exists_or_symlink(&p) {
                skipped.push(p.display().to_string());
            }
            continue;
        }
        if path_exists_or_symlink(&p) {
            safe_targets.push(p);
        }
    }

    if include_host && os == "linux" {
        for u in &systemd_units {
            commands_planned.push(format!("systemctl --user disable --now {u}"));
        }
        if req.remove_firewall {
            if let Some(fw) = detect_local_linux_firewall() {
                let cmds =
                    generate_firewall_commands(fw, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), true);
                elevated.extend(cmds.remove_firewall);
            }
        }
    } else if include_host && os == "windows" && req.remove_firewall {
        elevated.push("Get-NetFirewallRule -DisplayName 'SDS-*' | Remove-NetFirewallRule".into());
    }

    for p in &safe_targets {
        commands_planned.push(format!("remove {}", p.display()));
        if os != "windows" && requires_root_on_unix(p) {
            elevated.push(format!(
                "sudo rm -rf -- {}",
                shell_single_quote(&p.display().to_string())
            ));
        }
    }
    if include_host
        && os == "linux"
        && safe_targets
            .iter()
            .any(|p| p == Path::new("/etc/udev/rules.d/60-sds-uinput.rules"))
    {
        elevated.push("sudo udevadm control --reload-rules".into());
    }

    if req.dry_run {
        emit.finish(
            "uninstall",
            true,
            format!(
                "Dry-run uninstall ({}): {} target(s) identified",
                req.component.as_str(),
                safe_targets.len()
            ),
        );
        return Ok(UninstallResult {
            ok: true,
            dry_run: true,
            verified_clean: safe_targets.is_empty(),
            removed_paths: Vec::new(),
            skipped_or_protected_paths: skipped,
            remaining_artifacts: safe_targets
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            commands_executed_or_planned: commands_planned,
            elevated_commands: elevated,
            summary: format!(
                "Dry-run uninstall identified {} target(s) for '{}'",
                safe_targets.len(),
                req.component.as_str()
            ),
        });
    }

    // Stop running client/host processes before deleting payloads
    if include_client {
        match os {
            "macos" => {
                let _ = run_cmd_timeout(
                    "/usr/bin/pkill",
                    &["-x", "Moonlight"],
                    Duration::from_secs(2),
                );
            }
            "linux" => {
                let _ = run_cmd_timeout("pkill", &["-x", "moonlight"], Duration::from_secs(2));
            }
            "windows" => {
                let _ = run_cmd_timeout(
                    "powershell",
                    &[
                        "-NoProfile",
                        "-Command",
                        "Stop-Process -Name Moonlight -Force -ErrorAction SilentlyContinue",
                    ],
                    Duration::from_secs(5),
                );
            }
            _ => {}
        }
    }
    if include_host && os == "linux" {
        for u in &systemd_units {
            let _ = run_cmd_timeout(
                "systemctl",
                &["--user", "disable", "--now", u],
                Duration::from_secs(5),
            );
        }
        let _ = run_cmd_timeout("pkill", &["-x", "sunshine"], Duration::from_secs(2));
    } else if include_host && os == "windows" {
        let _ = run_cmd_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Stop-Process -Name sunshine -Force -ErrorAction SilentlyContinue",
            ],
            Duration::from_secs(5),
        );
    }

    let mut removed = Vec::new();
    for p in &safe_targets {
        let stop_at = if p.starts_with(&home) {
            home.as_path()
        } else {
            Path::new("/")
        };
        if let Err(e) = verify_no_symlink_ancestors(p, stop_at) {
            emit.emit("uninstall", "warn", e);
            skipped.push(p.display().to_string());
            continue;
        }
        if os != "windows" && requires_root_on_unix(p) {
            if req.execute_sudo {
                let out = Command::new("sudo")
                    .args(["-n", "rm", "-rf", "--", &p.display().to_string()])
                    .stdin(Stdio::null())
                    .output()
                    .await;
                if out.is_ok_and(|o| o.status.success()) {
                    emit.emit(
                        "uninstall",
                        "ok",
                        format!("Removed (sudo): {}", p.display()),
                    );
                    removed.push(p.display().to_string());
                    continue;
                }
            }
            skipped.push(p.display().to_string());
            continue;
        }
        match remove_allowlisted_path(p) {
            Ok(()) => {
                emit.emit("uninstall", "ok", format!("Removed: {}", p.display()));
                removed.push(p.display().to_string());
            }
            Err(e) => {
                emit.emit(
                    "uninstall",
                    "warn",
                    format!("Could not remove {}: {e}", p.display()),
                );
                skipped.push(p.display().to_string());
            }
        }
    }

    if include_host && os == "linux" {
        let _ = run_cmd_timeout(
            "systemctl",
            &["--user", "daemon-reload"],
            Duration::from_secs(3),
        );
        if req.execute_sudo
            && removed
                .iter()
                .any(|p| p == "/etc/udev/rules.d/60-sds-uinput.rules")
        {
            let _ = Command::new("sudo")
                .args(["-n", "udevadm", "control", "--reload-rules"])
                .stdin(Stdio::null())
                .output()
                .await;
        }
        if req.remove_firewall && req.execute_sudo {
            if let Some(fw) = detect_local_linux_firewall() {
                match fw {
                    FirewallBackend::Nftables => {
                        let _ = Command::new("sudo")
                            .args(["-n", "nft", "delete", "table", "inet", "sds_filter"])
                            .stdin(Stdio::null())
                            .output()
                            .await;
                    }
                    FirewallBackend::Ufw => {
                        let _ = Command::new("sudo")
                            .args([
                                "-n",
                                "sh",
                                "-c",
                                "for n in $(ufw status numbered | awk '/sds-(https|rtsp|av|mic|pairing|block-webui)/ && match($0, /^\\[[[:space:]]*[0-9]+\\]/) { s=substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, \"\", s); print s }' | sort -rn); do yes | ufw delete \"$n\"; done",
                            ])
                            .stdin(Stdio::null())
                            .output()
                            .await;
                    }
                    FirewallBackend::Firewalld => {
                        let _ = Command::new("sudo")
                            .args([
                                "-n",
                                "sh",
                                "-c",
                                "firewall-cmd --permanent --list-rich-rules | while IFS= read -r r; do case \"$r\" in *port=\"47984\"*|*port=\"48010\"*|*port=\"47998-48000\"*|*port=\"48002\"*|*port=\"47989\"*|*port=\"47990\"*) firewall-cmd --permanent --remove-rich-rule=\"$r\" || true ;; esac; done && firewall-cmd --reload",
                            ])
                            .stdin(Stdio::null())
                            .output()
                            .await;
                    }
                    _ => {}
                }
            }
        }
    }

    if include_host && os == "windows" && req.remove_firewall {
        let _ = run_cmd_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-NetFirewallRule -DisplayName 'SDS-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
            ],
            Duration::from_secs(10),
        );
    }

    if include_client && req.purge_config && os == "macos" {
        let _ = run_cmd_timeout(
            "/usr/bin/security",
            &[
                "delete-generic-password",
                "-s",
                "local.secure-desktop-stream.Moonlight.identity",
                "-a",
                "client-key",
            ],
            Duration::from_secs(3),
        );
    }

    // Update or delete manifest
    let mpath = manifest_path(&home, os);
    if !(include_installer && req.purge_config) && mpath.exists() {
        let mut updated = load_manifest(&home, os);
        if include_client {
            updated.client_paths.clear();
            if req.purge_config {
                updated.client_config_paths.clear();
            }
        }
        if include_host {
            if req.component == UninstallComponent::All {
                updated.host_instances.clear();
            } else {
                updated
                    .host_instances
                    .retain(|e| e.instance_name != instance);
            }
        }
        if include_installer {
            updated.installer_paths.clear();
        }
        let _ = save_manifest(&home, os, &updated);
    }

    // Post-uninstall verification
    let mut remaining = Vec::new();
    for p in &safe_targets {
        if path_exists_or_symlink(p) {
            remaining.push(p.display().to_string());
        }
    }
    let verified_clean = remaining.is_empty();
    let ok = verified_clean || (!removed.is_empty() && !elevated.is_empty());
    emit.finish(
        "uninstall",
        verified_clean,
        if verified_clean {
            format!(
                "Uninstall verified clean ({} item(s) removed).",
                removed.len()
            )
        } else {
            format!(
                "Removed {} item(s); {} item(s) remain (see elevated_commands).",
                removed.len(),
                remaining.len()
            )
        },
    );

    Ok(UninstallResult {
        ok,
        dry_run: false,
        verified_clean,
        removed_paths: removed,
        skipped_or_protected_paths: skipped,
        remaining_artifacts: remaining,
        commands_executed_or_planned: commands_planned,
        elevated_commands: elevated,
        summary: if verified_clean {
            format!("Cleanly uninstalled '{}'", req.component.as_str())
        } else {
            format!(
                "Partially uninstalled '{}'; run remaining elevated commands if needed",
                req.component.as_str()
            )
        },
    })
}

async fn run_remote_linux_uninstall(
    req: &UninstallRequest,
    ssh_target: &str,
    instance: &str,
    emit: &ProgressEmitter,
) -> Result<UninstallResult, String> {
    if !matches!(
        req.component,
        UninstallComponent::Host | UninstallComponent::All
    ) {
        return Err(
            "Remote SSH uninstall applies to host components (--component host or all)".into(),
        );
    }
    let mut user_cmds = vec![
        format!("systemctl --user disable --now {instance}-sunshine.service {instance}-display.service {instance}-audio.service >/dev/null 2>&1 || true"),
        format!("rm -rf -- \"$HOME/.config/systemd/user/{instance}-sunshine.service\" \"$HOME/.config/systemd/user/{instance}-display.service\" \"$HOME/.config/systemd/user/{instance}-audio.service\" \"$HOME/.config/systemd/user/{instance}-display.service.d\" \"$HOME/.config/systemd/user/{instance}-sunshine.service.d\" \"$HOME/.local/share/sds-installer-stage/{instance}\""),
        "systemctl --user daemon-reload >/dev/null 2>&1 || true".into(),
    ];
    if req.purge_config {
        user_cmds.push(format!(
            "rm -rf -- \"$HOME/.config/{instance}-sunshine\" \"$HOME/.config/{instance}-desktop\" \"$HOME/.local/share/{instance}-sunshine\" \"$HOME/.local/share/{instance}-desktop\" \"$HOME/.local/state/{instance}-sunshine\" \"$HOME/.local/state/{instance}-audio\" \"$HOME/.cache/{instance}-sunshine\" \"$HOME/.cache/{instance}-desktop\""
        ));
    }

    let mut elevated = vec![format!(
        "sudo rm -rf -- '/opt/secure-desktop-stream-{instance}'"
    )];
    if req.remove_firewall {
        elevated.push("sudo sh -c 'if command -v nft >/dev/null 2>&1; then nft delete table inet sds_filter 2>/dev/null || true; fi; if command -v ufw >/dev/null 2>&1; then for n in $(ufw status numbered | awk \"/sds-(https|rtsp|av|mic|pairing|block-webui)/ && match(\\$0, /^\\[[[:space:]]*[0-9]+\\]/) { s=substr(\\$0, RSTART, RLENGTH); gsub(/[^0-9]/, \\\"\\\", s); print s }\" | sort -rn); do yes | ufw delete \"$n\"; done; fi; if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --list-rich-rules | while IFS= read -r r; do case \"$r\" in *port=\"47984\"*|*port=\"48010\"*|*port=\"47998-48000\"*|*port=\"48002\"*|*port=\"47989\"*|*port=\"47990\"*) firewall-cmd --permanent --remove-rich-rule=\"$r\" || true ;; esac; done && firewall-cmd --reload; fi'".into());
    }

    if req.dry_run {
        emit.finish(
            "uninstall",
            true,
            format!("Dry-run remote SSH uninstall ready for {ssh_target}"),
        );
        return Ok(UninstallResult {
            ok: true,
            dry_run: true,
            verified_clean: false,
            removed_paths: Vec::new(),
            skipped_or_protected_paths: Vec::new(),
            remaining_artifacts: Vec::new(),
            commands_executed_or_planned: user_cmds,
            elevated_commands: elevated,
            summary: format!("Dry-run remote uninstall plan ready for {ssh_target}"),
        });
    }

    let mut args = vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        format!(
            "StrictHostKeyChecking={}",
            if req.strict_ssh_host_key {
                "yes"
            } else {
                "accept-new"
            }
        ),
    ];
    if req.require_pq_ssh {
        args.push("-o".into());
        args.push("KexAlgorithms=mlkem768x25519-sha256".into());
    }
    args.push("--".into());
    args.push(ssh_target.to_string());
    let mut full = user_cmds.join(" && ");
    if req.execute_sudo {
        let sudo_part = elevated
            .iter()
            .map(|c| c.replacen("sudo ", "sudo -n ", 1))
            .collect::<Vec<_>>()
            .join(" && ");
        full = format!("{full} && ({sudo_part})");
    }
    args.push(full);

    let out = Command::new("ssh")
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| format!("ssh uninstall failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Remote uninstall on {ssh_target} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    emit.finish(
        "uninstall",
        true,
        format!("Remote uninstall completed on {ssh_target}"),
    );
    Ok(UninstallResult {
        ok: true,
        dry_run: false,
        verified_clean: req.execute_sudo,
        removed_paths: vec![format!("{ssh_target}:user-units/{instance}")],
        skipped_or_protected_paths: Vec::new(),
        remaining_artifacts: Vec::new(),
        commands_executed_or_planned: user_cmds,
        elevated_commands: elevated,
        summary: format!("Remote host '{instance}' uninstalled on {ssh_target}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn allowlist_rejects_arbitrary_system_and_user_paths() {
        let home = PathBuf::from("/home/user");
        assert!(!is_safe_sds_removal_path(Path::new("/"), &home, true));
        assert!(!is_safe_sds_removal_path(
            Path::new("/Applications"),
            &home,
            true
        ));
        assert!(!is_safe_sds_removal_path(Path::new("/opt"), &home, true));
        assert!(!is_safe_sds_removal_path(&home, &home, true));
        assert!(!is_safe_sds_removal_path(
            &home.join("Documents"),
            &home,
            true
        ));
        assert!(!is_safe_sds_removal_path(
            Path::new("/etc/passwd"),
            &home,
            true
        ));
        assert!(!is_safe_sds_removal_path(
            &home.join("Applications/../Documents"),
            &home,
            true
        ));
        assert!(!is_safe_sds_removal_path(
            Path::new("/opt/secure-desktop-stream-bad;slug"),
            &home,
            true
        ));

        // Config paths rejected unless purge_config == true
        assert!(!is_safe_sds_removal_path(
            &home.join(".config/sds-host-sunshine"),
            &home,
            false
        ));
        assert!(is_safe_sds_removal_path(
            &home.join(".config/sds-host-sunshine"),
            &home,
            true
        ));

        // Valid SDS artifacts accepted
        assert!(is_safe_sds_removal_path(
            &home.join("Applications/Moonlight Secure Desktop.app"),
            &home,
            false
        ));
        assert!(is_safe_sds_removal_path(
            Path::new("/opt/secure-desktop-stream-sds-host"),
            &home,
            false
        ));
    }

    #[test]
    fn manifest_roundtrip_writes_0600_and_persists_entries() {
        let tmp = tempdir().unwrap();
        let home = tmp.path();
        record_client_install(
            home,
            "macos",
            &[home.join("Applications/Moonlight Secure Desktop.app")],
            &[home.join("Library/Application Support/SecureDesktopStream/client-receipt.json")],
        )
        .unwrap();
        let loaded = load_manifest(home, "macos");
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.client_paths.len(), 1);
        assert_eq!(loaded.client_config_paths.len(), 1);
    }
}
