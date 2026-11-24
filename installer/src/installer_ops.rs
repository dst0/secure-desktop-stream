//! Execution engine for client installs, local host setup, remote PQ-SSH fleet deployment,
//! and guided pairing + firewall lockdown over loopback PQ TLS 1.3.

use crate::archive::{
    compute_file_sha256, detect_archive_kind, download_https_verified, extract_tar_gz_safe,
    extract_zip_safe, inspect_binary_header, verify_archive_file, write_atomic, ArchiveKind,
    BinaryFormat, ExtractionLimits, InstallReceipt, MAX_ARCHIVE_BYTES,
};
use crate::config_gen::{generate_host_bundle, HostConfigParams, HostProfileKind};
use crate::deps::{
    check_dependencies, install_missing_dependencies, DependencyCheckRequest,
    DependencyInstallRequest, DependencyRole,
};
use crate::platform::{current_arch, current_os, detect_repo_root, run_cmd_timeout};
use crate::probe::{
    probe_host, sha256_der_hex, HostProbeReport, HostProbeRequest, HostProbeVerdict,
    SshFingerprintStatus,
};
use crate::uninstall::{record_client_install, record_host_install, HostManifestEntry};
use crate::validation::{
    constant_time_hex_eq, shell_single_quote, validate_https_url, validate_ip_or_host,
    validate_ipv4_or_ipv6_literal, validate_pin, validate_sha256_hex, validate_signing_identity,
    validate_ssh_target,
};
use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::broadcast;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub timestamp_unix: u64,
    pub step: String,
    pub level: String, // "info" | "warn" | "error" | "ok"
    pub message: String,
    pub done: bool,
    pub ok: Option<bool>,
}

#[derive(Clone)]
pub struct ProgressEmitter {
    tx: Option<broadcast::Sender<ProgressEvent>>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl ProgressEmitter {
    pub fn new(tx: Option<broadcast::Sender<ProgressEvent>>) -> Self {
        Self {
            tx,
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn emit(&self, step: &str, level: &str, message: impl Into<String>) {
        let msg = message.into();
        let line = format!("[{level}] [{step}] {msg}");
        if let Ok(mut guard) = self.logs.lock() {
            guard.push(line);
        }
        if let Some(ref tx) = self.tx {
            let _ = tx.send(ProgressEvent {
                timestamp_unix: now_unix(),
                step: step.to_string(),
                level: level.to_string(),
                message: msg,
                done: false,
                ok: None,
            });
        }
    }

    pub fn finish(&self, step: &str, ok: bool, message: impl Into<String>) {
        let msg = message.into();
        let level = if ok { "ok" } else { "error" };
        let line = format!("[{level}] [{step}] {msg}");
        if let Ok(mut guard) = self.logs.lock() {
            guard.push(line);
        }
        if let Some(ref tx) = self.tx {
            let _ = tx.send(ProgressEvent {
                timestamp_unix: now_unix(),
                step: step.to_string(),
                level: level.to_string(),
                message: msg,
                done: true,
                ok: Some(ok),
            });
        }
    }

    pub fn snapshot_logs(&self) -> Vec<String> {
        self.logs.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub ok: bool,
    pub dry_run: bool,
    pub summary: String,
    pub installed_path: Option<String>,
    pub commands_executed_or_planned: Vec<String>,
    pub elevated_commands: Vec<String>,
    pub logs: Vec<String>,
    pub probe_report: Option<HostProbeReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ClientSource {
    FromSource {
        #[serde(default)]
        repo_root: Option<String>,
    },
    Archive {
        path: String,
        sha256: String,
    },
    ReleaseUrl {
        url: String,
        sha256: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallScope {
    User,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInstallRequest {
    pub source: ClientSource,
    #[serde(default = "default_user_scope")]
    pub scope: InstallScope,
    #[serde(default)]
    pub allow_unnotarized: bool,
    #[serde(default)]
    pub local_signing_identity: Option<String>,
    #[serde(default)]
    pub auto_deps: bool,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_user_scope() -> InstallScope {
    InstallScope::User
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHostInstallRequest {
    pub config: HostConfigParams,
    #[serde(default)]
    pub archive_path: Option<String>,
    #[serde(default)]
    pub archive_sha256: Option<String>,
    #[serde(default)]
    pub from_source: bool,
    #[serde(default)]
    pub repo_root: Option<String>,
    #[serde(default)]
    pub auto_deps: bool,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDeployRequest {
    pub ssh_target: String,
    pub host_ip: String,
    #[serde(default = "default_true")]
    pub require_pq_ssh: bool,
    #[serde(default)]
    pub strict_ssh_host_key: bool,
    pub config: HostConfigParams,
    #[serde(default)]
    pub archive_path: Option<String>,
    #[serde(default)]
    pub archive_sha256: Option<String>,
    #[serde(default)]
    pub execute_sudo: bool,
    #[serde(default)]
    pub auto_deps: bool,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPairingRequest {
    pub host: String,
    pub ssh_target: String,
    pub controller_ip: String,
    #[serde(default = "default_true")]
    pub require_pq_ssh: bool,
    #[serde(default)]
    pub strict_ssh_host_key: bool,
    #[serde(default)]
    pub execute_sudo_firewall: bool,
    #[serde(default)]
    pub ssh_cert_path: Option<String>,
    #[serde(default = "default_firewall_backend")]
    pub firewall_backend: crate::config_gen::FirewallBackend,
    #[serde(default)]
    pub dry_run: bool,
}

fn default_firewall_backend() -> crate::config_gen::FirewallBackend {
    crate::config_gen::FirewallBackend::Auto
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPairingResponse {
    pub session_id: String,
    pub host: String,
    pub local_tunnel_port: u16,
    pub cert_sha256_hex: String,
    pub open_firewall_commands: Vec<String>,
    pub firewall_opened_automatically: bool,
    pub dry_run: bool,
    pub pending_pairings: Vec<PendingPairingEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPairingEntry {
    pub id: String,
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPairingPinRequest {
    pub session_id: String,
    pub pin: String,
    pub client_name: String,
    #[serde(default)]
    pub pairing_id: Option<String>,
    pub admin_user: String,
    pub admin_pass: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPairingPinResponse {
    pub paired: bool,
    pub client_uuid: Option<String>,
    pub applied_permissions: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosePairingRequest {
    pub session_id: String,
    #[serde(default)]
    pub execute_sudo_firewall: bool,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosePairingResponse {
    pub closed: bool,
    pub close_firewall_commands: Vec<String>,
    pub firewall_closed_automatically: bool,
    pub post_lockdown_probe: Option<HostProbeReport>,
}

struct ActivePairingSession {
    host: String,
    ssh_target: String,
    require_pq_ssh: bool,
    strict_ssh_host_key: bool,
    local_port: u16,
    cert_sha256_hex: String,
    open_cmds: Vec<String>,
    close_cmds: Vec<String>,
    tunnel_child: Option<Child>,
}

impl Drop for ActivePairingSession {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.tunnel_child {
            let _ = child.start_kill();
        }
    }
}

#[derive(Clone, Default)]
pub struct PairingManager {
    sessions: Arc<Mutex<HashMap<String, ActivePairingSession>>>,
}

impl PairingManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn shutdown_all(&self) {
        if let Ok(mut guard) = self.sessions.lock() {
            for (_, mut session) in guard.drain() {
                if let Some(ref mut child) = session.tunnel_child {
                    let _ = child.start_kill();
                }
            }
        }
    }
}

fn user_home() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| "HOME / USERPROFILE is not set".to_string())
}

fn expand_tilde(hint: &str, home: &Path) -> PathBuf {
    if let Some(rest) = hint.strip_prefix("~/") {
        home.join(rest)
    } else if hint == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(hint)
    }
}

fn set_dir_private(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("create dir {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod 0700 {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Installs or builds the Moonlight Secure Desktop client cleanly on macOS, Linux, or Windows.
pub async fn install_client(
    req: &ClientInstallRequest,
    emit: &ProgressEmitter,
) -> Result<ActionResult, String> {
    let os = current_os();
    let arch = current_arch();
    let home = user_home()?;
    let mut planned = Vec::new();
    let mut elevated = Vec::new();
    let dep_role = if matches!(req.source, ClientSource::FromSource { .. }) {
        DependencyRole::ClientBuild
    } else {
        DependencyRole::Client
    };

    let validated_signing_id = match req.local_signing_identity.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            Some(validate_signing_identity(raw).map_err(|e| e.to_string())?)
        }
        _ => None,
    };

    match &req.source {
        ClientSource::Archive { path, sha256 } => {
            let expected = validate_sha256_hex(sha256).map_err(|e| e.to_string())?;
            planned.push(format!("verify SHA-256 ({expected}) of archive {path}"));
            if !req.dry_run {
                verify_archive_file(Path::new(path), &expected, MAX_ARCHIVE_BYTES)
                    .map_err(|e| e.to_string())?;
            }
        }
        ClientSource::ReleaseUrl { url, sha256 } => {
            let valid_url = validate_https_url(url).map_err(|e| e.to_string())?;
            let expected = validate_sha256_hex(sha256).map_err(|e| e.to_string())?;
            planned.push(format!("curl --proto =https --tlsv1.2 {valid_url}"));
            planned.push(format!("verify SHA-256 == {expected}"));
        }
        ClientSource::FromSource { repo_root } => {
            let explicit = repo_root.as_deref().map(Path::new);
            let root = detect_repo_root(explicit).ok_or_else(|| {
                "Could not find secure-desktop-stream repository root for --from-source".to_string()
            })?;
            if os == "macos" {
                planned.push(format!(
                    "bash {}/tools/build-client-mac.sh {}/moonlight-qt",
                    root.display(),
                    root.display()
                ));
            } else if os == "linux" {
                planned.push(format!(
                    "bash {}/tools/build-client-linux.sh {}/moonlight-qt",
                    root.display(),
                    root.display()
                ));
            } else {
                planned.push(format!("build moonlight-qt from {}", root.display()));
            }
        }
    }

    if req.auto_deps {
        let can_sudo = os != "linux"
            || run_cmd_timeout("sudo", &["-n", "true"], Duration::from_secs(2))
                .is_some_and(|o| o.0);
        let dep_res = install_missing_dependencies(
            &DependencyInstallRequest {
                role: dep_role,
                ssh_target: None,
                require_pq_ssh: true,
                strict_ssh_host_key: false,
                include_optional: false,
                execute_sudo: !req.dry_run && can_sudo,
                dry_run: req.dry_run,
            },
            emit,
        )
        .await?;
        planned.extend(dep_res.commands_executed_or_planned.iter().cloned());
        elevated.extend(dep_res.elevated_commands.iter().cloned());
        if !req.dry_run && !dep_res.ok {
            let msg = if !dep_res.elevated_commands.is_empty() {
                format!(
                    "Missing required system packages for client ({}): run: {}",
                    dep_role.as_str(),
                    dep_res.elevated_commands.join(" && ")
                )
            } else {
                dep_res.summary
            };
            emit.finish("install-client", false, msg.clone());
            return Err(msg);
        }
    } else if !req.dry_run {
        if let Ok(rep) = check_dependencies(&DependencyCheckRequest {
            role: dep_role,
            ssh_target: None,
            require_pq_ssh: true,
            strict_ssh_host_key: false,
        })
        .await
        {
            if !rep.all_satisfied {
                let msg = format!(
                    "Missing dependencies for {}: {} (pass --auto-deps or run: sds-installer deps install --role {})",
                    dep_role.as_str(),
                    rep.missing_required.join(", "),
                    dep_role.as_str()
                );
                if matches!(req.source, ClientSource::FromSource { .. }) {
                    emit.finish("install-client", false, msg.clone());
                    return Err(msg);
                }
                emit.emit("install-client", "warn", msg);
            }
        }
    }

    let destination = match (os, req.scope) {
        ("macos", InstallScope::System) => {
            PathBuf::from("/Applications/Moonlight Secure Desktop.app")
        }
        ("macos", InstallScope::User) => home.join("Applications/Moonlight Secure Desktop.app"),
        ("linux", _) => home.join(".local/share/sds-client/app"),
        ("windows", _) => {
            let local =
                env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA is not set".to_string())?;
            PathBuf::from(local).join(r"Programs\SecureDesktopStream\Client")
        }
        _ => return Err(format!("Unsupported client OS: {os}")),
    };

    if os == "macos" {
        if let Some(ref id) = validated_signing_id {
            planned.push(format!(
                "codesign --force --options runtime -s {id} <staged.app>"
            ));
        }
        if req.allow_unnotarized {
            planned.push("xattr -dr com.apple.quarantine <staged.app> (explicit opt-in)".into());
        }
        planned.push(format!("atomic swap into {}", destination.display()));
    } else if os == "linux" {
        planned.push(format!("atomic swap into {}", destination.display()));
        planned.push("symlink ~/.local/bin/moonlight-sds and write desktop entry".into());
    } else if os == "windows" {
        planned.push(format!(
            "install versioned directory + junction under {}",
            destination.display()
        ));
        if req.allow_unnotarized {
            planned.push("Unblock-File on verified binaries (explicit opt-in)".into());
        }
    }

    if req.dry_run {
        emit.finish(
            "install-client",
            true,
            format!(
                "Dry-run validated for {os}/{arch} -> {}",
                destination.display()
            ),
        );
        return Ok(ActionResult {
            ok: true,
            dry_run: true,
            summary: format!("Dry-run plan ready for {os}/{arch}"),
            installed_path: Some(destination.display().to_string()),
            commands_executed_or_planned: planned,
            elevated_commands: elevated,
            logs: emit.snapshot_logs(),
            probe_report: None,
        });
    }

    let work = tempfile::Builder::new()
        .prefix("sds-client-inst-")
        .tempdir()
        .map_err(|e| format!("create temp dir: {e}"))?;

    // Resolve the payload source into either an extracted directory or a built macOS .app bundle.
    let (staged_source_path, archive_digest) = match &req.source {
        ClientSource::Archive { path, sha256 } => {
            let src_path = PathBuf::from(path);
            let digest = validate_sha256_hex(sha256).map_err(|e| e.to_string())?;
            emit.emit(
                "install-client",
                "info",
                format!("Verifying archive {}", src_path.display()),
            );
            verify_archive_file(&src_path, &digest, MAX_ARCHIVE_BYTES)
                .map_err(|e| e.to_string())?;
            let unpacked = work.path().join("unpacked");
            extract_any_client_archive(&src_path, &unpacked, os == "macos")?;
            (unpacked, digest)
        }
        ClientSource::ReleaseUrl { url, sha256 } => {
            let digest = validate_sha256_hex(sha256).map_err(|e| e.to_string())?;
            let dl = work.path().join("client-release.archive");
            emit.emit("install-client", "info", format!("Downloading {url}"));
            download_https_verified(url, &dl, &digest, MAX_ARCHIVE_BYTES)
                .await
                .map_err(|e| e.to_string())?;
            let unpacked = work.path().join("unpacked");
            extract_any_client_archive(&dl, &unpacked, os == "macos")?;
            (unpacked, digest)
        }
        ClientSource::FromSource { repo_root } => {
            let explicit = repo_root.as_deref().map(Path::new);
            let root = detect_repo_root(explicit).ok_or_else(|| {
                "Could not find secure-desktop-stream repository root".to_string()
            })?;
            let mq_src = root.join("moonlight-qt");
            if !mq_src.join("moonlight-qt.pro").is_file() {
                return Err(
                    "moonlight-qt submodule checkout missing (moonlight-qt/moonlight-qt.pro)"
                        .into(),
                );
            }
            if os == "macos" {
                let builder = root.join("tools/build-client-mac.sh");
                if !builder.is_file() {
                    return Err("tools/build-client-mac.sh missing".into());
                }
                emit.emit(
                    "install-client",
                    "info",
                    "Building Moonlight Secure Desktop.app from source (tools/build-client-mac.sh)...",
                );
                run_streaming_command(
                    "bash",
                    &[
                        builder.to_str().ok_or("non-utf8 path")?,
                        mq_src.to_str().ok_or("non-utf8 path")?,
                    ],
                    Some(&root),
                    emit,
                    "build-client-mac",
                )
                .await?;
                let built_app = root.join("build/moonlight-qt/app/Moonlight.app");
                if !built_app.is_dir() {
                    return Err(format!(
                        "Expected built bundle not found at {}",
                        built_app.display()
                    ));
                }
                let digest = compute_file_sha256(&built_app.join("Contents/MacOS/Moonlight"))
                    .map_err(|e| e.to_string())?;
                (built_app, digest)
            } else if os == "linux" {
                let builder = root.join("tools/build-client-linux.sh");
                if !builder.is_file() {
                    return Err("tools/build-client-linux.sh missing".into());
                }
                emit.emit(
                    "install-client",
                    "info",
                    "Building Moonlight Secure Desktop for Linux from source (tools/build-client-linux.sh)...",
                );
                run_streaming_command(
                    "bash",
                    &[
                        builder.to_str().ok_or("non-utf8 path")?,
                        mq_src.to_str().ok_or("non-utf8 path")?,
                    ],
                    Some(&root),
                    emit,
                    "build-client-linux",
                )
                .await?;
                let built_dir = root.join("build/moonlight-qt/app");
                let bin = if built_dir.join("moonlight").is_file() {
                    built_dir.join("moonlight")
                } else if built_dir.join("Moonlight").is_file() {
                    built_dir.join("Moonlight")
                } else {
                    return Err(format!(
                        "Expected Linux client binary not found in {}",
                        built_dir.display()
                    ));
                };
                let digest = compute_file_sha256(&bin).map_err(|e| e.to_string())?;
                (built_dir, digest)
            } else {
                return Err(
                    "From-source client build is automated for macOS and Linux; on Windows pass a verified --archive."
                        .into(),
                );
            }
        }
    };

    let installed = match os {
        "macos" => {
            let source_app = locate_macos_app(&staged_source_path)?;
            let installed_path = install_macos_client_bundle(
                &source_app,
                &destination,
                validated_signing_id.as_deref(),
                req.allow_unnotarized,
                &archive_digest,
                &home,
                emit,
            )?;
            let _ = record_client_install(
                &home,
                os,
                std::slice::from_ref(&installed_path),
                &[
                    home.join(
                        "Library/Application Support/SecureDesktopStream/client-receipt.json",
                    ),
                    home.join("Library/Preferences/local.secure-desktop-stream.Moonlight.plist"),
                ],
            );
            installed_path
        }
        "linux" => {
            let installed_path = install_linux_client_dir(
                &staged_source_path,
                &destination,
                &archive_digest,
                &home,
                emit,
            )?;
            let _ = record_client_install(
                &home,
                os,
                &[
                    installed_path.clone(),
                    home.join(".local/share/sds-client"),
                    home.join(".local/bin/moonlight-sds"),
                    home.join(".local/share/applications/sds-moonlight.desktop"),
                ],
                &[home.join(".local/share/sds-client/client-receipt.json")],
            );
            installed_path
        }
        "windows" => {
            let installed_path = install_windows_client_dir(
                &staged_source_path,
                &destination,
                &archive_digest,
                req.allow_unnotarized,
                emit,
            )?;
            let _ = record_client_install(
                &home,
                os,
                &[destination.clone(), installed_path.clone()],
                &[],
            );
            installed_path
        }
        _ => return Err(format!("Unsupported OS: {os}")),
    };

    emit.finish(
        "install-client",
        true,
        format!("Client installed at {}", installed.display()),
    );
    Ok(ActionResult {
        ok: true,
        dry_run: false,
        summary: format!("Installed client at {}", installed.display()),
        installed_path: Some(installed.display().to_string()),
        commands_executed_or_planned: planned,
        elevated_commands: elevated,
        logs: emit.snapshot_logs(),
        probe_report: None,
    })
}

fn extract_any_client_archive(
    archive: &Path,
    dest: &Path,
    allow_bundle_symlinks: bool,
) -> Result<(), String> {
    let limits = ExtractionLimits {
        allow_bundle_internal_symlinks: allow_bundle_symlinks,
        ..ExtractionLimits::default()
    };
    match detect_archive_kind(archive).map_err(|e| e.to_string())? {
        ArchiveKind::TarGz => {
            extract_tar_gz_safe(archive, dest, limits).map_err(|e| e.to_string())?;
        }
        ArchiveKind::Zip => {
            extract_zip_safe(archive, dest, limits).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn update_windows_junction(link: &Path, target: &Path) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let link_esc = link.display().to_string().replace('\'', "''");
        let target_esc = target.display().to_string().replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference = 'Stop'; \
             $l = '{link_esc}'; $t = '{target_esc}'; \
             if (Test-Path -LiteralPath $l) {{ [System.IO.Directory]::Delete($l, $false) }}; \
             New-Item -ItemType Junction -Path $l -Target $t | Out-Null"
        );
        let (ok, _, err) = run_cmd_timeout(
            "powershell",
            &["-NoProfile", "-Command", &script],
            Duration::from_secs(15),
        )
        .ok_or_else(|| "PowerShell timed out updating Windows junction".to_string())?;
        if !ok {
            return Err(format!("Failed updating Windows current junction: {err}"));
        }
        Ok(link.to_path_buf())
    }
    #[cfg(not(windows))]
    {
        let _ = link;
        Ok(target.to_path_buf())
    }
}

fn find_binary_recursive(dir: &Path, names: &[&str]) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_file() {
            if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                if names.contains(&fname) {
                    return Some(path);
                }
            }
        } else if meta.is_dir() {
            if let Some(found) = find_binary_recursive(&path, names) {
                return Some(found);
            }
        }
    }
    None
}

fn locate_macos_app(root: &Path) -> Result<PathBuf, String> {
    if root.extension().and_then(|e| e.to_str()) == Some("app") && root.is_dir() {
        return Ok(root.to_path_buf());
    }
    for name in ["Moonlight Secure Desktop.app", "Moonlight.app"] {
        let cand = root.join(name);
        if cand.is_dir() {
            return Ok(cand);
        }
    }
    Err(format!(
        "No Moonlight.app or Moonlight Secure Desktop.app found under {}",
        root.display()
    ))
}

fn install_macos_client_bundle(
    source_app: &Path,
    destination: &Path,
    signing_identity: Option<&str>,
    allow_unnotarized: bool,
    archive_digest: &str,
    home: &Path,
    emit: &ProgressEmitter,
) -> Result<PathBuf, String> {
    let dest_parent = destination
        .parent()
        .ok_or_else(|| "destination has no parent".to_string())?;
    fs::create_dir_all(dest_parent)
        .map_err(|e| format!("create {}: {e}", dest_parent.display()))?;

    if let Ok(meta) = fs::symlink_metadata(destination) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing to replace symlink at {}",
                destination.display()
            ));
        }
    }
    if run_cmd_timeout(
        "/usr/bin/pgrep",
        &["-x", "Moonlight"],
        Duration::from_secs(2),
    )
    .is_some_and(|(ok, _, _)| ok)
    {
        return Err("Quit Moonlight before installing an update; nothing modified.".into());
    }

    // Verify source bundle Info.plist and Mach-O binary before staging
    let info_plist = source_app.join("Contents/Info.plist");
    let (_, bundle_id, _) = run_cmd_timeout(
        "/usr/bin/plutil",
        &[
            "-extract",
            "CFBundleIdentifier",
            "raw",
            "-o",
            "-",
            info_plist.to_str().ok_or("non-utf8 path")?,
        ],
        Duration::from_secs(2),
    )
    .ok_or_else(|| "Failed to inspect Info.plist CFBundleIdentifier".to_string())?;
    let bundle_id = bundle_id.trim();
    if bundle_id != "local.secure-desktop-stream.Moonlight"
        && bundle_id != "com.moonlight-stream.Moonlight"
    {
        return Err(format!("Unexpected CFBundleIdentifier: {bundle_id}"));
    }

    let main_bin = source_app.join("Contents/MacOS/Moonlight");
    let bin_info = inspect_binary_header(&main_bin).map_err(|e| e.to_string())?;
    if bin_info.format != BinaryFormat::MachO {
        return Err("Moonlight main binary is not Mach-O".into());
    }
    emit.emit(
        "install-client",
        "info",
        format!(
            "Verified Mach-O client ({}, bundle id {bundle_id})",
            bin_info.arch
        ),
    );

    let staging_dir = tempfile::Builder::new()
        .prefix(".sds-client-stage-")
        .tempdir_in(dest_parent)
        .map_err(|e| format!("create same-fs staging in {}: {e}", dest_parent.display()))?;
    let staged_app = staging_dir.path().join("Moonlight Secure Desktop.app");

    let (ditto_ok, _, ditto_err) = run_cmd_timeout(
        "/usr/bin/ditto",
        &[
            source_app.to_str().ok_or("non-utf8 path")?,
            staged_app.to_str().ok_or("non-utf8 path")?,
        ],
        Duration::from_secs(60),
    )
    .ok_or_else(|| "ditto timed out copying bundle".to_string())?;
    if !ditto_ok {
        return Err(format!("ditto failed: {ditto_err}"));
    }

    if let Some(id) = signing_identity {
        emit.emit(
            "install-client",
            "info",
            format!("Re-signing bundle with identity {id}"),
        );
        let (ok, _, err) = run_cmd_timeout(
            "/usr/bin/codesign",
            &[
                "--force",
                "--deep",
                "--options",
                "runtime",
                "-s",
                id,
                staged_app.to_str().ok_or("non-utf8 path")?,
            ],
            Duration::from_secs(60),
        )
        .ok_or_else(|| "codesign timed out".to_string())?;
        if !ok {
            return Err(format!("Local codesign failed: {err}"));
        }
    }

    let (verify_ok, _, verify_err) = run_cmd_timeout(
        "/usr/bin/codesign",
        &[
            "--verify",
            "--deep",
            "--strict",
            staged_app.to_str().ok_or("non-utf8 path")?,
        ],
        Duration::from_secs(20),
    )
    .ok_or_else(|| "codesign --verify timed out".to_string())?;
    if !verify_ok {
        return Err(format!(
            "codesign --verify --deep --strict failed: {verify_err}"
        ));
    }

    if allow_unnotarized {
        emit.emit(
            "install-client",
            "info",
            "Removing com.apple.quarantine on verified app bundle (explicit opt-in; global Gatekeeper remains enabled)",
        );
        let _ = run_cmd_timeout(
            "/usr/bin/xattr",
            &[
                "-dr",
                "com.apple.quarantine",
                staged_app.to_str().ok_or("non-utf8 path")?,
            ],
            Duration::from_secs(15),
        );
    }

    // Atomic swap with rollback backup
    let backup = if destination.exists() {
        let bak = dest_parent.join(format!(
            "Moonlight Secure Desktop.previous.{}.{}.app",
            now_unix(),
            std::process::id()
        ));
        fs::rename(destination, &bak).map_err(|e| format!("move previous app to backup: {e}"))?;
        Some(bak)
    } else {
        None
    };

    if let Err(e) = fs::rename(&staged_app, destination) {
        if let Some(ref bak) = backup {
            let _ = fs::rename(bak, destination);
        }
        return Err(format!("atomic install swap failed: {e}"));
    }

    let exe_sha = compute_file_sha256(&destination.join("Contents/MacOS/Moonlight"))
        .map_err(|e| e.to_string())?;
    let mut files = BTreeMap::new();
    files.insert("Contents/MacOS/Moonlight".into(), exe_sha);
    let receipt = InstallReceipt {
        version: 1,
        component: "client".into(),
        revision: archive_digest.to_string(),
        platform: "macos".into(),
        arch: current_arch().into(),
        installed_at_unix: now_unix(),
        archive_sha256: archive_digest.to_string(),
        files,
    };
    let receipt_path =
        home.join("Library/Application Support/SecureDesktopStream/client-receipt.json");
    let receipt_json = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    write_atomic(&receipt_path, &receipt_json, false).map_err(|e| e.to_string())?;
    Ok(destination.to_path_buf())
}

fn install_linux_client_dir(
    source_dir: &Path,
    destination: &Path,
    archive_digest: &str,
    home: &Path,
    emit: &ProgressEmitter,
) -> Result<PathBuf, String> {
    let bin = if source_dir.join("moonlight").is_file() {
        source_dir.join("moonlight")
    } else if source_dir.join("Moonlight").is_file() {
        source_dir.join("Moonlight")
    } else {
        return Err(format!(
            "Linux client binary ('moonlight' or 'Moonlight') missing in {}",
            source_dir.display()
        ));
    };
    let info = inspect_binary_header(&bin).map_err(|e| e.to_string())?;
    if info.format != BinaryFormat::Elf {
        return Err("Linux client executable is not an ELF binary".into());
    }
    let bin_name = bin
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid bin name")?;

    let dest_parent = destination
        .parent()
        .ok_or_else(|| "destination has no parent".to_string())?;
    set_dir_private(dest_parent)?;

    if let Ok(meta) = fs::symlink_metadata(destination) {
        if meta.file_type().is_symlink() {
            return Err("Refusing symlink client destination".into());
        }
    }

    let staging = tempfile::Builder::new()
        .prefix(".sds-client-stage-")
        .tempdir_in(dest_parent)
        .map_err(|e| format!("create staging dir: {e}"))?;
    let staged_app = staging.path().join("app");
    copy_dir_recursive_no_symlinks(source_dir, &staged_app)?;

    let backup = if destination.exists() {
        let bak = dest_parent.join(format!("previous-{}-{}", now_unix(), std::process::id()));
        fs::rename(destination, &bak).map_err(|e| format!("backup existing client: {e}"))?;
        Some(bak)
    } else {
        None
    };

    if let Err(e) = fs::rename(&staged_app, destination) {
        if let Some(ref bak) = backup {
            let _ = fs::rename(bak, destination);
        }
        return Err(format!("atomic swap failed: {e}"));
    }

    #[cfg(unix)]
    {
        let local_bin = home.join(".local/bin");
        fs::create_dir_all(&local_bin).map_err(|e| e.to_string())?;
        let launcher = local_bin.join("moonlight-sds");
        let tmp_link = local_bin.join(format!(".moonlight-sds.{}", std::process::id()));
        let _ = fs::remove_file(&tmp_link);
        std::os::unix::fs::symlink(destination.join(bin_name), &tmp_link)
            .map_err(|e| format!("create launcher symlink: {e}"))?;
        fs::rename(&tmp_link, &launcher).map_err(|e| format!("install launcher: {e}"))?;
    }

    let desktop_dir = home.join(".local/share/applications");
    fs::create_dir_all(&desktop_dir).map_err(|e| e.to_string())?;
    let exec_path = destination.join(bin_name).display().to_string();
    let escaped_exec = exec_path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
        .replace('%', "%%");
    let desktop_entry = format!(
        "[Desktop Entry]\nType=Application\nName=Moonlight Secure Desktop\nExec=\"{escaped_exec}\"\nTerminal=false\nCategories=Network;RemoteAccess;\n"
    );
    write_atomic(
        &desktop_dir.join("sds-moonlight.desktop"),
        desktop_entry.as_bytes(),
        false,
    )
    .map_err(|e| e.to_string())?;

    emit.emit(
        "install-client",
        "info",
        "Created ~/.local/bin/moonlight-sds and desktop entry",
    );
    let exe_sha = compute_file_sha256(&destination.join(bin_name)).map_err(|e| e.to_string())?;
    let mut files = BTreeMap::new();
    files.insert(bin_name.to_string(), exe_sha);
    let receipt = InstallReceipt {
        version: 1,
        component: "client".into(),
        revision: archive_digest.to_string(),
        platform: "linux".into(),
        arch: current_arch().into(),
        installed_at_unix: now_unix(),
        archive_sha256: archive_digest.to_string(),
        files,
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    write_atomic(
        &dest_parent.join("client-receipt.json"),
        &receipt_bytes,
        false,
    )
    .map_err(|e| e.to_string())?;
    Ok(destination.to_path_buf())
}

fn install_windows_client_dir(
    source_dir: &Path,
    install_root: &Path,
    archive_digest: &str,
    allow_unnotarized: bool,
    emit: &ProgressEmitter,
) -> Result<PathBuf, String> {
    let exe = source_dir.join("Moonlight.exe");
    let info = inspect_binary_header(&exe).map_err(|e| e.to_string())?;
    if info.format != BinaryFormat::Pe {
        return Err("Windows client Moonlight.exe is not a valid PE binary".into());
    }
    let version_dir = install_root.join("versions").join(&archive_digest[..16]);
    fs::create_dir_all(&version_dir).map_err(|e| format!("create version dir: {e}"))?;
    copy_dir_recursive_no_symlinks(source_dir, &version_dir)?;

    if allow_unnotarized {
        emit.emit(
            "install-client",
            "info",
            "Applying Unblock-File to verified Windows binaries (SmartScreen stays enabled)",
        );
        let _ = run_cmd_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                &format!(
                    "Get-ChildItem -LiteralPath '{}' -Recurse -File | Unblock-File",
                    version_dir.display().to_string().replace('\'', "''")
                ),
            ],
            Duration::from_secs(20),
        );
    }

    let receipt = InstallReceipt {
        version: 1,
        component: "client".into(),
        revision: archive_digest.to_string(),
        platform: "windows".into(),
        arch: current_arch().into(),
        installed_at_unix: now_unix(),
        archive_sha256: archive_digest.to_string(),
        files: BTreeMap::new(),
    };
    let receipt_bytes = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    write_atomic(
        &version_dir.join("install-receipt.json"),
        &receipt_bytes,
        false,
    )
    .map_err(|e| e.to_string())?;
    update_windows_junction(&install_root.join("current"), &version_dir)
}

fn copy_dir_recursive_no_symlinks(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create dir {}: {e}", dst.display()))?;
    for entry in fs::read_dir(src).map_err(|e| format!("read dir {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let p = entry.path();
        let meta = fs::symlink_metadata(&p).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("Refusing symlink in payload: {}", p.display()));
        }
        let target = dst.join(entry.file_name());
        if meta.is_dir() {
            copy_dir_recursive_no_symlinks(&p, &target)?;
        } else if meta.is_file() {
            fs::copy(&p, &target).map_err(|e| format!("copy {}: {e}", p.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o755;
                let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

fn host_dep_roles(profile: HostProfileKind, from_source: bool) -> Vec<DependencyRole> {
    let mut roles = vec![match profile {
        HostProfileKind::LinuxVirtualX11 => DependencyRole::HostVirtual,
        HostProfileKind::LinuxPhysicalX11 => DependencyRole::HostPhysical,
        HostProfileKind::WindowsHost => DependencyRole::HostWindows,
    }];
    if from_source && profile != HostProfileKind::WindowsHost {
        roles.push(DependencyRole::HostBuild);
    }
    roles
}

fn build_host_manifest_entry(
    profile: HostProfileKind,
    firewall_backend: crate::config_gen::FirewallBackend,
    bundle: &crate::config_gen::GeneratedBundle,
    stage_root: &Path,
    home: &Path,
) -> HostManifestEntry {
    let install_dir = if profile == HostProfileKind::WindowsHost {
        env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join("AppData/Local"))
            .join("Programs/SecureDesktopStream/Sunshine")
            .display()
            .to_string()
    } else {
        format!("/opt/secure-desktop-stream-{}", bundle.instance_name)
    };
    let mut systemd_units = Vec::new();
    let mut paths = vec![stage_root.display().to_string(), install_dir.clone()];
    for file in bundle.files.values() {
        if let Some(unit) = file.target_hint.strip_prefix("~/.config/systemd/user/") {
            if unit.ends_with(".service") {
                systemd_units.push(unit.to_string());
            }
        }
        if file.target_hint.starts_with("~/") {
            let expanded = expand_tilde(&file.target_hint, home);
            paths.push(expanded.display().to_string());
        } else if file.target_hint.starts_with('/') {
            paths.push(file.target_hint.clone());
        }
    }
    if profile == HostProfileKind::LinuxVirtualX11 {
        paths.push(
            home.join(".config/systemd/user")
                .join(format!("{}-display.service.d", bundle.instance_name))
                .display()
                .to_string(),
        );
        paths.push(
            home.join(".config/systemd/user")
                .join(format!("{}-sunshine.service.d", bundle.instance_name))
                .display()
                .to_string(),
        );
    } else if profile == HostProfileKind::LinuxPhysicalX11 {
        paths.push(
            home.join(".config/systemd/user")
                .join(format!("{}-sunshine.service.d", bundle.instance_name))
                .display()
                .to_string(),
        );
    }
    let config_paths = vec![
        home.join(".config")
            .join(format!("{}-sunshine", bundle.instance_name))
            .display()
            .to_string(),
        home.join(".config")
            .join(format!("{}-desktop", bundle.instance_name))
            .display()
            .to_string(),
        home.join(".local/share")
            .join(format!("{}-sunshine", bundle.instance_name))
            .display()
            .to_string(),
        home.join(".local/share")
            .join(format!("{}-desktop", bundle.instance_name))
            .display()
            .to_string(),
        home.join(".local/state")
            .join(format!("{}-audio", bundle.instance_name))
            .display()
            .to_string(),
    ];
    HostManifestEntry {
        instance_name: bundle.instance_name.clone(),
        install_dir,
        systemd_units,
        firewall_backend: Some(firewall_backend),
        paths,
        config_paths,
    }
}

fn expand_target_hint(hint: &str, home: &Path) -> Option<PathBuf> {
    if hint.starts_with("~/") || hint == "~" {
        Some(expand_tilde(hint, home))
    } else if let Some(rest) = hint.strip_prefix("%LOCALAPPDATA%") {
        let local = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Local"));
        let trimmed = rest.trim_start_matches(['\\', '/']);
        Some(if trimmed.is_empty() {
            local
        } else {
            local.join(trimmed.replace('\\', "/"))
        })
    } else {
        None
    }
}

fn install_windows_host_binary(
    bin_path: &Path,
    install_root: &Path,
    digest: &str,
    emit: &ProgressEmitter,
) -> Result<PathBuf, String> {
    let info = inspect_binary_header(bin_path).map_err(|e| e.to_string())?;
    if info.format != BinaryFormat::Pe {
        return Err("Windows host sunshine.exe is not a valid PE binary".into());
    }
    let src_dir = bin_path
        .parent()
        .ok_or_else(|| "sunshine.exe has no parent directory".to_string())?;
    let version_dir = install_root.join("versions").join(&digest[..16]);
    fs::create_dir_all(&version_dir).map_err(|e| format!("create version dir: {e}"))?;
    copy_dir_recursive_no_symlinks(src_dir, &version_dir)?;
    emit.emit(
        "install-host",
        "info",
        format!(
            "Installed Sunshine PE payload into {}",
            version_dir.display()
        ),
    );
    update_windows_junction(&install_root.join("current"), &version_dir)
}

/// Generates and applies local host configs/units safely, returning explicit sudo/admin steps.
pub async fn install_host_local(
    req: &LocalHostInstallRequest,
    emit: &ProgressEmitter,
) -> Result<ActionResult, String> {
    let mut cfg = req.config.clone();
    if cfg.profile != HostProfileKind::WindowsHost
        && cfg.firewall_backend == crate::config_gen::FirewallBackend::Auto
    {
        if crate::platform::command_exists("ufw").is_some() {
            cfg.firewall_backend = crate::config_gen::FirewallBackend::Ufw;
        } else if crate::platform::command_exists("firewall-cmd").is_some() {
            cfg.firewall_backend = crate::config_gen::FirewallBackend::Firewalld;
        } else if crate::platform::command_exists("nft").is_some() {
            cfg.firewall_backend = crate::config_gen::FirewallBackend::Nftables;
        }
    }
    let bundle = generate_host_bundle(&cfg)?;
    let home = user_home()?;
    let stage_root = home
        .join(".local/share/sds-installer-stage")
        .join(&bundle.instance_name);
    let mut elevated = Vec::new();
    let mut planned = Vec::new();

    for file in bundle.files.values() {
        planned.push(format!("write {} (mode {})", file.target_hint, file.mode));
        if file.requires_root {
            let staged_src = stage_root.join(&file.rel_path);
            if file.target_hint.starts_with('/') {
                elevated.push(format!(
                    "sudo install -D -m {} {} {}",
                    file.mode,
                    shell_single_quote(&staged_src.display().to_string()),
                    shell_single_quote(&file.target_hint)
                ));
            }
        }
    }
    if cfg.profile != HostProfileKind::WindowsHost {
        elevated.push("sudo loginctl enable-linger \"$USER\"".into());
    }
    elevated.extend(bundle.firewall.setup_streaming.clone());

    if let Some(ref archive) = req.archive_path {
        let expected = req.archive_sha256.as_deref().ok_or_else(|| {
            "archive_sha256 is required when archive_path is specified".to_string()
        })?;
        validate_sha256_hex(expected).map_err(|e| e.to_string())?;
        planned.push(format!("verify host archive {archive} against {expected}"));
    }
    let build_repo_root = if req.from_source {
        let root = detect_repo_root(req.repo_root.as_deref().map(Path::new))
            .ok_or_else(|| "Repo root not found for --from-source host build".to_string())?;
        if cfg.profile == HostProfileKind::WindowsHost || current_os() == "windows" {
            planned.push(
                "cross-build Windows Sunshine via tools/builder-sunshine-windows/build-sunshine-windows.sh"
                    .into(),
            );
        } else {
            planned.push(format!(
                "bash {}/tools/builder-sunshine-linux.sh {}/sunshine <cpus>",
                root.display(),
                root.display()
            ));
        }
        Some(root)
    } else {
        None
    };

    let os = current_os();
    let dep_roles = host_dep_roles(cfg.profile, req.from_source);
    if req.auto_deps {
        let can_sudo = os != "linux"
            || run_cmd_timeout("sudo", &["-n", "true"], Duration::from_secs(2))
                .is_some_and(|o| o.0);
        for role in dep_roles {
            let dep_res = install_missing_dependencies(
                &DependencyInstallRequest {
                    role,
                    ssh_target: None,
                    require_pq_ssh: true,
                    strict_ssh_host_key: false,
                    include_optional: false,
                    execute_sudo: !req.dry_run && can_sudo,
                    dry_run: req.dry_run,
                },
                emit,
            )
            .await?;
            planned.extend(dep_res.commands_executed_or_planned);
            for cmd in dep_res.elevated_commands {
                if !elevated.contains(&cmd) {
                    elevated.push(cmd);
                }
            }
            if role == DependencyRole::HostBuild && !req.dry_run && !dep_res.ok {
                return Err(dep_res.summary);
            }
        }
    } else if !req.dry_run {
        for role in dep_roles {
            if let Ok(rep) = check_dependencies(&DependencyCheckRequest {
                role,
                ssh_target: None,
                require_pq_ssh: true,
                strict_ssh_host_key: false,
            })
            .await
            {
                if !rep.all_satisfied {
                    emit.emit(
                        "install-host",
                        "warn",
                        format!(
                            "Missing host dependencies for {}: {} (pass --auto-deps or run: sds-installer deps install --role {})",
                            role.as_str(),
                            rep.missing_required.join(", "),
                            role.as_str()
                        ),
                    );
                }
            }
        }
    }

    if req.dry_run {
        emit.finish(
            "install-host",
            true,
            format!(
                "Dry-run host configuration verified ({} files, {} firewall rules)",
                bundle.files.len(),
                bundle.firewall.setup_streaming.len()
            ),
        );
        return Ok(ActionResult {
            ok: true,
            dry_run: true,
            summary: format!("Dry-run validated host profile '{}'", cfg.profile.as_str()),
            installed_path: Some(stage_root.display().to_string()),
            commands_executed_or_planned: planned,
            elevated_commands: elevated,
            logs: emit.snapshot_logs(),
            probe_report: None,
        });
    }

    if let Some(ref root) = build_repo_root {
        if cfg.profile == HostProfileKind::WindowsHost || os == "windows" {
            return Err(
                "Windows Sunshine must be cross-compiled on a Linux host via tools/builder-sunshine-windows/build-sunshine-windows.sh and passed via --archive <zip> --sha256 <hex>."
                    .into(),
            );
        }
        if os != "linux" {
            return Err(format!(
                "Local host build is only supported on Linux; deploy to Linux over PQ SSH or cross-build instead (os={os})."
            ));
        }
        if crate::platform::command_exists("docker").is_none() {
            return Err(
                "Docker is required for --from-source Linux host builds (or pass a verified --archive)."
                    .into(),
            );
        }
        let sunshine_dir = root.join("sunshine");
        if !sunshine_dir.join("CMakeLists.txt").is_file() {
            return Err("sunshine submodule checkout missing (sunshine/CMakeLists.txt)".into());
        }
        let builder = root.join("tools/builder-sunshine-linux.sh");
        if !builder.is_file() {
            return Err("tools/builder-sunshine-linux.sh missing".into());
        }
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get().max(1))
            .unwrap_or(2)
            .to_string();
        emit.emit(
            "install-host",
            "info",
            format!(
                "Building Sunshine via {} ({cpus} CPUs)...",
                builder.display()
            ),
        );
        run_streaming_command(
            "bash",
            &[
                builder.to_str().ok_or("non-utf8 path")?,
                sunshine_dir.to_str().ok_or("non-utf8 path")?,
                &cpus,
            ],
            Some(root),
            emit,
            "build-sunshine-linux",
        )
        .await?;
        let container_name = env::var("NAME").unwrap_or_else(|_| "sds-build-sunshine".into());
        let _ = run_streaming_command(
            "docker",
            &["logs", "-f", &container_name],
            Some(root),
            emit,
            "build-sunshine-docker",
        )
        .await;
        let wait_out = Command::new("docker")
            .args(["wait", &container_name])
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| format!("docker wait failed: {e}"))?;
        let exit_code = String::from_utf8_lossy(&wait_out.stdout).trim().to_string();
        if !wait_out.status.success() || exit_code != "0" {
            return Err(format!(
                "Sunshine Docker build container '{container_name}' exited with status '{exit_code}'"
            ));
        }
    }

    set_dir_private(&stage_root)?;
    let inbox = home.join("Downloads/Moonlight");
    let outbox = inbox.join("Outbox");
    set_dir_private(&inbox)?;
    set_dir_private(&outbox)?;

    if let Some(ref archive) = req.archive_path {
        let expected = req.archive_sha256.as_deref().unwrap_or("");
        let ap = Path::new(archive);
        verify_archive_file(ap, expected, MAX_ARCHIVE_BYTES).map_err(|e| e.to_string())?;
        let bin_stage = stage_root.join("payload");
        extract_any_client_archive(ap, &bin_stage, false)?;
        if cfg.profile == HostProfileKind::WindowsHost || os == "windows" {
            let exe = find_binary_recursive(&bin_stage, &["sunshine.exe"])
                .ok_or_else(|| "sunshine.exe not found inside verified host archive".to_string())?;
            let install_root =
                expand_target_hint(&bundle.install_dir, &home).unwrap_or_else(|| {
                    home.join("AppData/Local/Programs/SecureDesktopStream/Sunshine")
                });
            install_windows_host_binary(&exe, &install_root, expected, emit)?;
        } else {
            let bin = find_binary_recursive(&bin_stage, &["sunshine"]).ok_or_else(|| {
                "sunshine binary not found inside verified host archive".to_string()
            })?;
            let b_info = inspect_binary_header(&bin).map_err(|e| e.to_string())?;
            if b_info.format != BinaryFormat::Elf {
                return Err("Host sunshine binary in archive is not an ELF executable".into());
            }
            let target_bin = format!("{}/sunshine", bundle.install_dir);
            elevated.push(format!(
                "sudo install -D -m 0755 {} {}",
                shell_single_quote(&bin.display().to_string()),
                shell_single_quote(&target_bin)
            ));
            if let Some(assets_dir) = bin.parent().map(|p| p.join("assets")) {
                if assets_dir.is_dir() {
                    let target_assets = format!("{}/assets", bundle.install_dir);
                    elevated.push(format!(
                        "sudo install -d -m 0755 {} && sudo cp -a {}/. {}/",
                        shell_single_quote(&target_assets),
                        shell_single_quote(&assets_dir.display().to_string()),
                        shell_single_quote(&target_assets)
                    ));
                }
            }
        }
        emit.emit(
            "install-host",
            "info",
            format!(
                "Verified and staged host payload in {}",
                bin_stage.display()
            ),
        );
    } else if let Some(ref root) = build_repo_root {
        let built_bin = root.join("sunshine/build/sunshine");
        if built_bin.is_file() {
            let target_bin = format!("{}/sunshine", bundle.install_dir);
            elevated.push(format!(
                "sudo install -D -m 0755 {} {}",
                shell_single_quote(&built_bin.display().to_string()),
                shell_single_quote(&target_bin)
            ));
            let built_assets = root.join("sunshine/build/assets");
            if built_assets.is_dir() {
                let target_assets = format!("{}/assets", bundle.install_dir);
                elevated.push(format!(
                    "sudo install -d -m 0755 {} && sudo cp -a {}/. {}/",
                    shell_single_quote(&target_assets),
                    shell_single_quote(&built_assets.display().to_string()),
                    shell_single_quote(&target_assets)
                ));
            }
        }
    }

    for file in bundle.files.values() {
        let staged_path = stage_root.join(&file.rel_path);
        let exec = file.mode == "0755";
        write_atomic(&staged_path, file.content.as_bytes(), exec).map_err(|e| e.to_string())?;

        if !file.requires_root {
            if let Some(dest) = expand_target_hint(&file.target_hint, &home) {
                // Preserve existing sunshine_state/credentials; if sunshine.conf exists, back it up.
                if dest.file_name().and_then(|n| n.to_str()) == Some("sunshine.conf")
                    && dest.exists()
                {
                    let bak = dest.with_extension(format!("conf.bak.{}", now_unix()));
                    fs::copy(&dest, &bak).map_err(|e| format!("backup sunshine.conf: {e}"))?;
                }
                write_atomic(&dest, file.content.as_bytes(), exec).map_err(|e| e.to_string())?;
                emit.emit("install-host", "info", format!("Wrote {}", dest.display()));
            }
        }
    }

    if current_os() == "linux" {
        let _ = run_cmd_timeout(
            "systemctl",
            &["--user", "daemon-reload"],
            Duration::from_secs(5),
        );
    }

    let manifest_entry = build_host_manifest_entry(
        cfg.profile,
        cfg.firewall_backend,
        &bundle,
        &stage_root,
        &home,
    );
    let _ = record_host_install(&home, current_os(), manifest_entry);

    emit.finish(
        "install-host",
        true,
        format!(
            "User configs written and privileged files staged at {}",
            stage_root.display()
        ),
    );
    Ok(ActionResult {
        ok: true,
        dry_run: false,
        summary: format!(
            "Host profile '{}' prepared; review elevated commands to finalize /opt and firewall",
            cfg.profile.as_str()
        ),
        installed_path: Some(stage_root.display().to_string()),
        commands_executed_or_planned: planned,
        elevated_commands: elevated,
        logs: emit.snapshot_logs(),
        probe_report: None,
    })
}

fn ssh_base_args(require_pq_ssh: bool, strict_host_key: bool) -> Vec<String> {
    let mut args = vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-o".to_string(),
        format!(
            "StrictHostKeyChecking={}",
            if strict_host_key { "yes" } else { "accept-new" }
        ),
    ];
    if require_pq_ssh {
        args.push("-o".into());
        args.push("KexAlgorithms=mlkem768x25519-sha256".into());
    }
    args
}

fn detect_remote_firewall_from_preflight(
    stdout: &str,
) -> Option<crate::config_gen::FirewallBackend> {
    for line in stdout.lines() {
        match line.trim() {
            "FW=ufw" => return Some(crate::config_gen::FirewallBackend::Ufw),
            "FW=firewalld" => return Some(crate::config_gen::FirewallBackend::Firewalld),
            "FW=nftables" => return Some(crate::config_gen::FirewallBackend::Nftables),
            _ => {}
        }
    }
    None
}

fn build_deploy_elevated_commands(
    bundle: &crate::config_gen::GeneratedBundle,
    has_archive: bool,
) -> Vec<String> {
    let mut elevated = Vec::new();
    for file in bundle.files.values() {
        if file.requires_root && file.target_hint.starts_with('/') {
            elevated.push(format!(
                "sudo install -D -m {} \"$HOME/.local/share/sds-installer-stage/{}/{}\" {}",
                file.mode,
                bundle.instance_name,
                file.rel_path,
                shell_single_quote(&file.target_hint)
            ));
        }
    }
    if has_archive {
        let target_bin = format!("{}/sunshine", bundle.install_dir);
        let target_assets = format!("{}/assets", bundle.install_dir);
        elevated.push(format!(
            "sudo sh -c 'set -e; b=$(find \"$1\" -type f -name sunshine | head -n 1); test -n \"$b\"; install -D -m 0755 \"$b\" {}; a=$(dirname \"$b\")/assets; if [ -d \"$a\" ]; then install -d -m 0755 {} && cp -a \"$a\"/. {}/; fi' _ \"$HOME/.local/share/sds-installer-stage/{}/payload-unpacked\"",
            shell_single_quote(&target_bin),
            shell_single_quote(&target_assets),
            shell_single_quote(&target_assets),
            bundle.instance_name
        ));
    }
    elevated.push("sudo loginctl enable-linger \"$USER\"".into());
    elevated.extend(bundle.firewall.setup_streaming.clone());
    elevated
}

/// Deploys generated host configuration and verified binaries to a remote host over PQ SSH.
pub async fn deploy_host_ssh(
    req: &SshDeployRequest,
    emit: &ProgressEmitter,
) -> Result<ActionResult, String> {
    let ssh_target = validate_ssh_target(&req.ssh_target).map_err(|e| e.to_string())?;
    let host_ip = validate_ip_or_host(&req.host_ip).map_err(|e| e.to_string())?;
    let mut bundle = generate_host_bundle(&req.config)?;

    let mut planned = Vec::new();
    let mut elevated = build_deploy_elevated_commands(&bundle, req.archive_path.is_some());
    let remote_stage = format!(
        "~/.local/share/sds-installer-stage/{}",
        bundle.instance_name
    );

    let pq_flag = if req.require_pq_ssh {
        " -o KexAlgorithms=mlkem768x25519-sha256"
    } else {
        ""
    };
    planned.push(format!("ssh{pq_flag} {ssh_target} <remote preflight>"));
    planned.push(format!(
        "scp{pq_flag} -r <staged configs> {ssh_target}:{remote_stage}/"
    ));
    if let Some(ref archive) = req.archive_path {
        let sha = req
            .archive_sha256
            .as_deref()
            .ok_or_else(|| "archive_sha256 required with archive_path".to_string())?;
        validate_sha256_hex(sha).map_err(|e| e.to_string())?;
        planned.push(format!(
            "scp{pq_flag} {archive} {ssh_target}:{remote_stage}/payload.archive && remote sha256 verify ({sha})"
        ));
    }
    planned.push(format!("probe_host({host_ip}, ssh={ssh_target})"));

    if req.auto_deps {
        for role in host_dep_roles(req.config.profile, false) {
            if req.dry_run {
                planned.push(format!(
                    "ssh{pq_flag} {ssh_target} <check & auto-install missing Linux packages for role '{}' via apt/dnf/pacman/zypper>",
                    role.as_str()
                ));
            } else {
                let dep_res = install_missing_dependencies(
                    &DependencyInstallRequest {
                        role,
                        ssh_target: Some(ssh_target.clone()),
                        require_pq_ssh: req.require_pq_ssh,
                        strict_ssh_host_key: req.strict_ssh_host_key,
                        include_optional: false,
                        execute_sudo: req.execute_sudo,
                        dry_run: false,
                    },
                    emit,
                )
                .await?;
                planned.extend(dep_res.commands_executed_or_planned);
                for cmd in dep_res.elevated_commands {
                    if !elevated.contains(&cmd) {
                        elevated.push(cmd);
                    }
                }
            }
        }
    }

    if req.dry_run {
        emit.finish(
            "deploy-ssh",
            true,
            format!("Dry-run validated for {ssh_target} ({host_ip})"),
        );
        return Ok(ActionResult {
            ok: true,
            dry_run: true,
            summary: format!("Dry-run PQ SSH deploy plan ready for {ssh_target}"),
            installed_path: Some(remote_stage),
            commands_executed_or_planned: planned,
            elevated_commands: elevated,
            logs: emit.snapshot_logs(),
            probe_report: None,
        });
    }

    // 1. Remote preflight (including live firewall backend detection)
    emit.emit(
        "deploy-ssh",
        "info",
        format!("Running remote preflight on {ssh_target}"),
    );
    let mut pre_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
    pre_args.push("--".into());
    pre_args.push(ssh_target.clone());
    pre_args.push(
        "uname -sm; if command -v ufw >/dev/null 2>&1; then echo FW=ufw; elif command -v firewall-cmd >/dev/null 2>&1; then echo FW=firewalld; elif command -v nft >/dev/null 2>&1; then echo FW=nftables; else echo FW=none; fi; command -v systemctl || true; ls /dev/dri/renderD* 2>/dev/null || true".into(),
    );
    let pre_out = Command::new("ssh")
        .args(&pre_args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| format!("ssh preflight spawn failed: {e}"))?;
    if !pre_out.status.success() {
        let err = String::from_utf8_lossy(&pre_out.stderr).trim().to_string();
        emit.finish("deploy-ssh", false, format!("SSH preflight failed: {err}"));
        return Err(format!("SSH preflight failed on {ssh_target}: {err}"));
    }
    let pre_stdout = String::from_utf8_lossy(&pre_out.stdout).to_string();
    emit.emit(
        "deploy-ssh",
        "info",
        format!("Remote preflight:\n{}", pre_stdout.trim()),
    );
    if req.config.firewall_backend == crate::config_gen::FirewallBackend::Auto {
        if let Some(detected_fw) = detect_remote_firewall_from_preflight(&pre_stdout) {
            let mut updated_cfg = req.config.clone();
            updated_cfg.firewall_backend = detected_fw;
            bundle = generate_host_bundle(&updated_cfg)?;
            elevated = build_deploy_elevated_commands(&bundle, req.archive_path.is_some());
        }
    }

    // 2. Stage locally and upload via scp
    let temp = tempfile::Builder::new()
        .prefix("sds-ssh-stage-")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let local_stage = temp.path().join(&bundle.instance_name);
    set_dir_private(&local_stage)?;
    for file in bundle.files.values() {
        write_atomic(
            &local_stage.join(&file.rel_path),
            file.content.as_bytes(),
            file.mode == "0755",
        )
        .map_err(|e| e.to_string())?;
    }

    let mut mkdir_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
    mkdir_args.push("--".into());
    mkdir_args.push(ssh_target.clone());
    mkdir_args.push(format!(
        "umask 077 && mkdir -p \"$HOME/.local/share/sds-installer-stage/{}\" \"$HOME/Downloads/Moonlight\" \"$HOME/Downloads/Moonlight/Outbox\"",
        bundle.instance_name
    ));
    let mk_out = Command::new("ssh")
        .args(&mkdir_args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !mk_out.status.success() {
        return Err(format!(
            "Remote mkdir failed: {}",
            String::from_utf8_lossy(&mk_out.stderr)
        ));
    }

    let mut scp_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
    scp_args.push("-r".into());
    scp_args.push("--".into());
    scp_args.push(local_stage.display().to_string());
    scp_args.push(format!("{ssh_target}:.local/share/sds-installer-stage/"));
    emit.emit(
        "deploy-ssh",
        "info",
        "Uploading generated configs over PQ SSH/SCP",
    );
    let scp_out = Command::new("scp")
        .args(&scp_args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !scp_out.status.success() {
        return Err(format!(
            "SCP upload failed: {}",
            String::from_utf8_lossy(&scp_out.stderr)
        ));
    }

    if let Some(ref archive) = req.archive_path {
        let sha = req.archive_sha256.as_deref().unwrap_or("");
        let ap = Path::new(archive);
        verify_archive_file(ap, sha, MAX_ARCHIVE_BYTES).map_err(|e| e.to_string())?;
        let archive_kind = detect_archive_kind(ap).map_err(|e| e.to_string())?;
        let scp_src =
            if !ap.is_absolute() && !archive.starts_with("./") && !archive.starts_with("../") {
                format!("./{archive}")
            } else {
                archive.clone()
            };
        let mut scp_bin = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
        scp_bin.push("--".into());
        scp_bin.push(scp_src);
        scp_bin.push(format!(
            "{ssh_target}:.local/share/sds-installer-stage/{}/payload.archive",
            bundle.instance_name
        ));
        let b_out = Command::new("scp")
            .args(&scp_bin)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !b_out.status.success() {
            return Err(format!(
                "Archive upload failed: {}",
                String::from_utf8_lossy(&b_out.stderr)
            ));
        }
        let unpack_cmd = match archive_kind {
            ArchiveKind::TarGz => "tar -xzf \"$arch\" -C \"$dst\"",
            ArchiveKind::Zip => "unzip -qo \"$arch\" -d \"$dst\"",
        };
        let mut verify_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
        verify_args.push("--".into());
        verify_args.push(ssh_target.clone());
        verify_args.push(format!(
            "arch=\"$HOME/.local/share/sds-installer-stage/{}/payload.archive\" && dst=\"$HOME/.local/share/sds-installer-stage/{}/payload-unpacked\" && printf '%s  %s\\n' {} \"$arch\" | sha256sum -c - && rm -rf -- \"$dst\" && mkdir -p \"$dst\" && {unpack_cmd}",
            bundle.instance_name,
            bundle.instance_name,
            shell_single_quote(sha)
        ));
        let v_out = Command::new("ssh")
            .args(&verify_args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !v_out.status.success() {
            return Err(format!(
                "Remote SHA-256 verification or extraction of uploaded archive failed: {}",
                String::from_utf8_lossy(&v_out.stderr).trim()
            ));
        }
    }

    // Install user-owned configs and reload systemd --user without overwriting existing pairing credentials.
    let mut install_user_cmd = vec![
        "umask 077".to_string(),
        format!(
            "stage=\"$HOME/.local/share/sds-installer-stage/{}\"",
            bundle.instance_name
        ),
        format!(
            "mkdir -p \"$HOME/.config/{}-sunshine/config\" \"$HOME/.config/systemd/user\"",
            bundle.instance_name
        ),
    ];
    for file in bundle.files.values() {
        if !file.requires_root && !file.target_hint.starts_with('%') {
            let rel_home = file
                .target_hint
                .strip_prefix("~/")
                .unwrap_or(&file.target_hint);
            install_user_cmd.push(format!(
                "install -D -m {} \"$stage/{}\" \"$HOME/{}\"",
                file.mode, file.rel_path, rel_home
            ));
        }
    }
    install_user_cmd.push("systemctl --user daemon-reload || true".into());

    let mut apply_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
    apply_args.push("--".into());
    apply_args.push(ssh_target.clone());
    apply_args.push(install_user_cmd.join(" && "));
    let apply_out = Command::new("ssh")
        .args(&apply_args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !apply_out.status.success() {
        return Err(format!(
            "Remote user unit placement failed: {}",
            String::from_utf8_lossy(&apply_out.stderr)
        ));
    }

    let mut sudo_ok = true;
    let mut sudo_err_msg = None;
    if req.execute_sudo && !elevated.is_empty() {
        emit.emit(
            "deploy-ssh",
            "info",
            "Applying root-owned files, payload & firewall via sudo -n",
        );
        let sudo_cmd = elevated
            .iter()
            .map(|c| c.replacen("sudo ", "sudo -n ", 1))
            .collect::<Vec<_>>()
            .join(" && ");
        let mut s_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
        s_args.push("--".into());
        s_args.push(ssh_target.clone());
        s_args.push(sudo_cmd);
        let s_out = Command::new("ssh")
            .args(&s_args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !s_out.status.success() {
            sudo_ok = false;
            let err = String::from_utf8_lossy(&s_out.stderr).trim().to_string();
            sudo_err_msg = Some(err.clone());
            emit.emit(
                "deploy-ssh",
                "error",
                format!("Non-interactive sudo failed: {err}"),
            );
        }
    }

    // Enable and start systemd user services when the installed binary is present.
    let target_units: Vec<String> = match req.config.profile {
        HostProfileKind::LinuxVirtualX11 => vec![
            format!("{}-audio.service", bundle.instance_name),
            format!("{}-display.service", bundle.instance_name),
            format!("{}-sunshine.service", bundle.instance_name),
        ],
        HostProfileKind::LinuxPhysicalX11 => {
            vec![format!("{}-sunshine.service", bundle.instance_name)]
        }
        HostProfileKind::WindowsHost => Vec::new(),
    };
    if !target_units.is_empty() {
        let mut start_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
        start_args.push("--".into());
        start_args.push(ssh_target.clone());
        start_args.push(format!(
            "systemctl --user daemon-reload >/dev/null 2>&1 || true; if [ -x {}/sunshine ]; then systemctl --user enable --now {} >/dev/null 2>&1 || true; fi",
            shell_single_quote(&bundle.install_dir),
            target_units.join(" ")
        ));
        let _ = Command::new("ssh")
            .args(&start_args)
            .stdin(Stdio::null())
            .output()
            .await;
    }

    // 3. Cryptographically probe deployed host
    let probe_report = probe_host(&HostProbeRequest {
        host: host_ip.clone(),
        https_port: 47984,
        http_port: 47989,
        webui_port: 47990,
        rtsp_port: 48010,
        ssh_target: Some(ssh_target.clone()),
        require_pq_ssh: req.require_pq_ssh,
        strict_ssh_host_key: req.strict_ssh_host_key,
        ssh_cert_path: None,
    })
    .await
    .ok();

    let summary = if sudo_ok {
        format!("Deployed host configuration to {ssh_target} ({host_ip})")
    } else {
        format!(
            "User configs deployed to {ssh_target} ({host_ip}), but sudo -n failed: {}",
            sudo_err_msg.unwrap_or_default()
        )
    };
    emit.finish("deploy-ssh", sudo_ok, summary.clone());
    Ok(ActionResult {
        ok: sudo_ok,
        dry_run: false,
        summary,
        installed_path: Some(remote_stage),
        commands_executed_or_planned: planned,
        elevated_commands: elevated,
        logs: emit.snapshot_logs(),
        probe_report,
    })
}

async fn run_streaming_command(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    emit: &ProgressEmitter,
    step: &str,
) -> Result<(), String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn {program}: {e}"))?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let emit_out = emit.clone();
    let step_out = step.to_string();
    let t_out = tokio::spawn(async move {
        if let Some(out) = stdout {
            let mut lines = BufReader::new(out).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                emit_out.emit(&step_out, "info", line);
            }
        }
    });
    let emit_err = emit.clone();
    let step_err = step.to_string();
    let t_err = tokio::spawn(async move {
        if let Some(err) = stderr {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                emit_err.emit(&step_err, "warn", line);
            }
        }
    });

    let status = child
        .wait()
        .await
        .map_err(|e| format!("wait {program}: {e}"))?;
    let _ = t_out.await;
    let _ = t_err.await;
    if !status.success() {
        return Err(format!("{program} exited with status {status}"));
    }
    Ok(())
}

/// Opens a guided pairing session:
/// 1) Verifies host PQ TLS 1.3 + SSH cert fingerprint match (anti-MITM)
/// 2) Prepares firewall commands to temporarily allow 47989/tcp from controller_ip
/// 3) Spawns a managed loopback-only SSH tunnel to 127.0.0.1:47990
pub async fn open_pairing_session(
    mgr: &PairingManager,
    req: &OpenPairingRequest,
    emit: &ProgressEmitter,
) -> Result<OpenPairingResponse, String> {
    let host = validate_ip_or_host(&req.host).map_err(|e| e.to_string())?;
    let ssh_target = validate_ssh_target(&req.ssh_target).map_err(|e| e.to_string())?;
    let controller_ip =
        validate_ipv4_or_ipv6_literal(&req.controller_ip).map_err(|e| e.to_string())?;
    let mut effective_fw = req.firewall_backend;
    if effective_fw == crate::config_gen::FirewallBackend::Auto && !req.dry_run {
        let mut fw_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
        fw_args.push("--".into());
        fw_args.push(ssh_target.clone());
        fw_args.push(
            "if command -v ufw >/dev/null 2>&1; then echo FW=ufw; elif command -v firewall-cmd >/dev/null 2>&1; then echo FW=firewalld; elif command -v nft >/dev/null 2>&1; then echo FW=nftables; fi".into(),
        );
        if let Ok(out) = Command::new("ssh")
            .args(&fw_args)
            .stdin(Stdio::null())
            .output()
            .await
        {
            if out.status.success() {
                if let Some(detected) =
                    detect_remote_firewall_from_preflight(&String::from_utf8_lossy(&out.stdout))
                {
                    effective_fw = detected;
                }
            }
        }
    }
    let fw = crate::config_gen::generate_firewall_commands(effective_fw, controller_ip, false);

    if req.dry_run {
        return Ok(OpenPairingResponse {
            session_id: "dry-run".into(),
            host,
            local_tunnel_port: 0,
            cert_sha256_hex: String::new(),
            open_firewall_commands: fw.open_pairing_47989,
            firewall_opened_automatically: false,
            dry_run: true,
            pending_pairings: Vec::new(),
        });
    }

    emit.emit(
        "pairing",
        "info",
        format!("Verifying PQ TLS 1.3 & SSH cert match for {host}"),
    );
    let probe = probe_host(&HostProbeRequest {
        host: host.clone(),
        https_port: 47984,
        http_port: 47989,
        webui_port: 47990,
        rtsp_port: 48010,
        ssh_target: Some(ssh_target.clone()),
        require_pq_ssh: req.require_pq_ssh,
        strict_ssh_host_key: req.strict_ssh_host_key,
        ssh_cert_path: req.ssh_cert_path.clone(),
    })
    .await?;

    if !probe.pq_tls13_ok || probe.verdict == HostProbeVerdict::InsecureConfiguration {
        return Err("Refusing pairing: host failed PQ TLS 1.3 or hygiene verification".into());
    }
    if probe.ssh_fingerprint_status != SshFingerprintStatus::Matched {
        return Err(format!(
            "Refusing pairing: SSH certificate fingerprint check status is {:?} ({})",
            probe.ssh_fingerprint_status,
            probe.ssh_detail.unwrap_or_default()
        ));
    }
    let cert_sha = probe
        .cert_sha256_hex
        .ok_or_else(|| "Missing verified server certificate SHA-256".to_string())?;

    let mut firewall_opened_automatically = false;
    if req.execute_sudo_firewall && !fw.open_pairing_47989.is_empty() {
        let cmd_str = fw
            .open_pairing_47989
            .iter()
            .map(|c| c.replacen("sudo ", "sudo -n ", 1))
            .collect::<Vec<_>>()
            .join(" && ");
        let mut args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
        args.push("--".into());
        args.push(ssh_target.clone());
        args.push(cmd_str);
        if let Ok(out) = Command::new("ssh")
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .await
        {
            firewall_opened_automatically = out.status.success();
        }
    }

    // Reserve an unused local loopback port briefly, then pass it to ssh -N -L
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let local_port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);

    let mut tunnel_args = ssh_base_args(req.require_pq_ssh, req.strict_ssh_host_key);
    tunnel_args.extend([
        "-N".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-L".into(),
        format!("127.0.0.1:{local_port}:127.0.0.1:47990"),
        "--".into(),
        ssh_target.clone(),
    ]);
    let mut child = Command::new("ssh")
        .args(&tunnel_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start SSH admin tunnel: {e}"))?;

    let mut ready = false;
    for _ in 0..40 {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("SSH tunnel exited prematurely with {status}"));
        }
        if tokio::net::TcpStream::connect(("127.0.0.1", local_port))
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        let _ = child.start_kill();
        return Err("Timed out waiting for SSH loopback tunnel to 127.0.0.1:47990".into());
    }

    let mut session_rand = [0u8; 16];
    aws_lc_rs::rand::fill(&mut session_rand).map_err(|_| "RNG failed".to_string())?;
    let session_id = hex::encode(session_rand);

    if let Ok(mut guard) = mgr.sessions.lock() {
        guard.insert(
            session_id.clone(),
            ActivePairingSession {
                host: host.clone(),
                ssh_target,
                require_pq_ssh: req.require_pq_ssh,
                strict_ssh_host_key: req.strict_ssh_host_key,
                local_port,
                cert_sha256_hex: cert_sha.clone(),
                open_cmds: fw.open_pairing_47989.clone(),
                close_cmds: fw.close_pairing_47989,
                tunnel_child: Some(child),
            },
        );
    }

    emit.emit(
        "pairing",
        "ok",
        format!("Loopback PQ-SSH tunnel ready on 127.0.0.1:{local_port} -> 127.0.0.1:47990"),
    );

    Ok(OpenPairingResponse {
        session_id,
        host,
        local_tunnel_port: local_port,
        cert_sha256_hex: cert_sha,
        open_firewall_commands: fw.open_pairing_47989,
        firewall_opened_automatically,
        dry_run: false,
        pending_pairings: Vec::new(),
    })
}

#[derive(Debug)]
struct PinnedSha256ServerVerifier {
    algs: WebPkiSupportedAlgorithms,
    expected_sha256: String,
}

impl ServerCertVerifier for PinnedSha256ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = sha256_der_hex(end_entity.as_ref());
        if !constant_time_hex_eq(&actual, &self.expected_sha256) {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General(
            "TLS 1.2 disabled for pairing tunnel".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn is_chunked_transfer_encoding(headers: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, val)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && val
                    .to_ascii_lowercase()
                    .split(',')
                    .any(|part| part.trim() == "chunked")
        })
    })
}

/// Decodes an HTTP/1.1 `Transfer-Encoding: chunked` byte stream into payload bytes.
pub fn decode_chunked_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut rest = bytes;
    loop {
        let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Err("Malformed chunked HTTP response: missing chunk size CRLF".into());
        };
        let size_line = std::str::from_utf8(&rest[..pos])
            .map_err(|_| "Malformed chunked HTTP response: non-UTF8 size line".to_string())?;
        let hex_size = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex_size, 16)
            .map_err(|_| format!("Malformed chunked HTTP chunk size: '{hex_size}'"))?;
        rest = &rest[pos + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size + 2 {
            return Err("Truncated chunked HTTP response body".into());
        }
        out.extend_from_slice(&rest[..size]);
        if &rest[size..size + 2] != b"\r\n" {
            return Err("Malformed chunked HTTP response: missing chunk CRLF terminator".into());
        }
        rest = &rest[size + 2..];
    }
}

async fn pinned_admin_https_request(
    local_port: u16,
    expected_cert_sha256: &str,
    method: &str,
    path: &str,
    basic_auth_header: &str,
    csrf_token: Option<&str>,
    json_body: Option<&str>,
) -> Result<(u16, String), String> {
    if method.contains(['\r', '\n'])
        || path.contains(['\r', '\n'])
        || basic_auth_header.contains(['\r', '\n'])
    {
        return Err("Invalid CRLF in HTTP request header".into());
    }
    if let Some(csrf) = csrf_token {
        if csrf.contains('\r') || csrf.contains('\n') {
            return Err("Invalid CRLF in CSRF token".into());
        }
    }
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites = vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    let verifier = Arc::new(PinnedSha256ServerVerifier {
        algs: provider.signature_verification_algorithms,
        expected_sha256: expected_cert_sha256.to_string(),
    });
    let cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(("127.0.0.1", local_port)),
    )
    .await
    .map_err(|_| "Timed out connecting to local SSH tunnel".to_string())?
    .map_err(|e| format!("Local tunnel TCP connect failed: {e}"))?;

    let sname = ServerName::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into());
    let mut tls = TlsConnector::from(Arc::new(cfg))
        .connect(sname, tcp)
        .await
        .map_err(|e| format!("Pinned PQ TLS 1.3 to Sunshine Web UI failed: {e}"))?;

    let body = json_body.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:47990\r\nOrigin: https://127.0.0.1:47990\r\nAuthorization: {basic_auth_header}\r\nConnection: close\r\n"
    );
    if let Some(csrf) = csrf_token {
        req.push_str(&format!("X-CSRF-Token: {csrf}\r\n"));
    }
    if json_body.is_some() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    req.push_str("\r\n");
    req.push_str(body);

    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("Write request failed: {e}"))?;
    tls.flush().await.map_err(|e| e.to_string())?;

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), tls.read_to_end(&mut raw))
        .await
        .map_err(|_| "Timed out reading Sunshine admin response".to_string())?
        .map_err(|e| format!("Read response failed: {e}"))?;

    let hdr_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response from Sunshine".to_string())?;
    let head = String::from_utf8_lossy(&raw[..hdr_end]);
    let raw_body = &raw[hdr_end + 4..];
    let status_line = head.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let resp_body = if is_chunked_transfer_encoding(&head) {
        let decoded = decode_chunked_bytes(raw_body)?;
        String::from_utf8_lossy(&decoded).to_string()
    } else {
        String::from_utf8_lossy(raw_body).to_string()
    };
    Ok((status_code, resp_body))
}

/// Submits PIN pairing and client permissions over the pinned loopback SSH tunnel (never logging secrets).
pub async fn submit_pairing_pin(
    mgr: &PairingManager,
    req: &SubmitPairingPinRequest,
    emit: &ProgressEmitter,
) -> Result<SubmitPairingPinResponse, String> {
    let pin = validate_pin(&req.pin).map_err(|e| e.to_string())?;
    let client_name = req.client_name.trim();
    if client_name.is_empty()
        || client_name.len() > 128
        || client_name.chars().any(char::is_control)
    {
        return Err("Client name must be 1..128 printable characters".into());
    }

    let (local_port, cert_sha) = {
        let guard = mgr
            .sessions
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?;
        let sess = guard
            .get(&req.session_id)
            .ok_or_else(|| "Unknown or closed pairing session_id".to_string())?;
        (sess.local_port, sess.cert_sha256_hex.clone())
    };

    let auth_raw = format!("{}:{}", req.admin_user, req.admin_pass);
    let auth_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(auth_raw.as_bytes())
    );

    emit.emit(
        "pairing",
        "info",
        "Fetching CSRF token from pinned Sunshine Web UI",
    );
    let (csrf_status, csrf_body) = pinned_admin_https_request(
        local_port,
        &cert_sha,
        "GET",
        "/api/csrf-token",
        &auth_header,
        None,
        None,
    )
    .await?;
    if csrf_status != 200 {
        return Err(format!(
            "Sunshine authentication failed (HTTP {csrf_status})"
        ));
    }
    let csrf_json: serde_json::Value =
        serde_json::from_str(&csrf_body).map_err(|e| e.to_string())?;
    let csrf_token = csrf_json
        .get("csrf_token")
        .or_else(|| csrf_json.get("token"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing csrf_token in Sunshine response".to_string())?
        .to_string();

    let pairing_id = if let Some(ref pid) = req.pairing_id {
        if !pid.trim().is_empty() {
            pid.trim().to_string()
        } else {
            fetch_latest_pairing_id(local_port, &cert_sha, &auth_header).await?
        }
    } else {
        fetch_latest_pairing_id(local_port, &cert_sha, &auth_header).await?
    };

    let pin_payload = serde_json::json!({
        "pairing_id": pairing_id,
        "pin": pin,
        "name": client_name,
    })
    .to_string();

    emit.emit("pairing", "info", "Submitting PIN approval to Sunshine");
    let (pin_status, pin_body) = pinned_admin_https_request(
        local_port,
        &cert_sha,
        "POST",
        "/api/pin",
        &auth_header,
        Some(&csrf_token),
        Some(&pin_payload),
    )
    .await?;
    if pin_status != 200 {
        return Err(format!("Sunshine /api/pin returned HTTP {pin_status}"));
    }
    let pin_json: serde_json::Value = serde_json::from_str(&pin_body).map_err(|e| e.to_string())?;
    let paired = pin_json
        .get("status")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !paired {
        return Ok(SubmitPairingPinResponse {
            paired: false,
            client_uuid: None,
            applied_permissions: Vec::new(),
            message: "Sunshine rejected PIN or pairing timed out".into(),
        });
    }

    let mut client_uuid = None;
    let mut applied_permissions = Vec::new();
    let allowed_perms = [
        "clipboard_read",
        "clipboard_write",
        "file_upload",
        "file_download",
        "mic",
    ];
    let wanted_perms: Vec<String> = req
        .permissions
        .iter()
        .filter(|p| allowed_perms.contains(&p.as_str()))
        .cloned()
        .collect();

    if !wanted_perms.is_empty() {
        let (list_status, list_body) = pinned_admin_https_request(
            local_port,
            &cert_sha,
            "GET",
            "/api/clients/list",
            &auth_header,
            None,
            None,
        )
        .await?;
        if list_status != 200 {
            return Err(format!(
                "GET /api/clients/list failed with HTTP {list_status}"
            ));
        }
        let list_json: serde_json::Value = serde_json::from_str(&list_body)
            .map_err(|e| format!("Invalid JSON from /api/clients/list: {e}"))?;
        let arr = list_json
            .get("named_certs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "Missing named_certs in /api/clients/list response".to_string())?;
        let found = arr
            .iter()
            .rev()
            .find(|c| c.get("name").and_then(|v| v.as_str()) == Some(client_name))
            .ok_or_else(|| {
                format!("Newly paired client '{client_name}' not found in /api/clients/list")
            })?;
        let uuid = found
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("Client '{client_name}' entry has no uuid"))?;
        client_uuid = Some(uuid.to_string());
        let perm_payload = serde_json::json!({
            "uuid": uuid,
            "permissions": wanted_perms,
        })
        .to_string();
        let (p_status, p_body) = pinned_admin_https_request(
            local_port,
            &cert_sha,
            "POST",
            "/api/clients/permissions",
            &auth_header,
            Some(&csrf_token),
            Some(&perm_payload),
        )
        .await?;
        if p_status != 200 {
            return Err(format!(
                "POST /api/clients/permissions failed with HTTP {p_status}"
            ));
        }
        let p_json: serde_json::Value = serde_json::from_str(&p_body)
            .map_err(|e| format!("Invalid JSON from /api/clients/permissions: {e}"))?;
        if let Some(perms) = p_json.get("permissions").and_then(|v| v.as_array()) {
            applied_permissions = perms
                .iter()
                .filter_map(|v| v.as_str().map(ToString::to_string))
                .collect();
        }
    }

    emit.emit("pairing", "ok", "Client paired and permissions updated");
    Ok(SubmitPairingPinResponse {
        paired: true,
        client_uuid,
        applied_permissions,
        message: "Pairing completed; close 47989/tcp to lock down host".into(),
    })
}

async fn fetch_latest_pairing_id(
    local_port: u16,
    cert_sha: &str,
    auth_header: &str,
) -> Result<String, String> {
    let (status, body) = pinned_admin_https_request(
        local_port,
        cert_sha,
        "GET",
        "/api/pin",
        auth_header,
        None,
        None,
    )
    .await?;
    if status != 200 {
        return Err(format!("GET /api/pin failed with HTTP {status}"));
    }
    let val: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    let id = val
        .get("pairings")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.last())
        .and_then(|item| item.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "No pending pairing request found on Sunshine. Add the host IP in Moonlight first so Moonlight initiates pairing.".to_string()
        })?;
    Ok(id.to_string())
}

/// Terminates the SSH tunnel, closes 47989/tcp (if authorized), and re-probes host security.
pub async fn close_pairing_session(
    mgr: &PairingManager,
    req: &ClosePairingRequest,
    emit: &ProgressEmitter,
) -> Result<ClosePairingResponse, String> {
    let session = {
        let mut guard = mgr
            .sessions
            .lock()
            .map_err(|_| "lock poisoned".to_string())?;
        guard
            .remove(&req.session_id)
            .ok_or_else(|| "Unknown or already closed pairing session".to_string())?
    };

    let close_cmds = session.close_cmds.clone();
    let mut firewall_closed_automatically = false;
    if !req.dry_run && req.execute_sudo_firewall && !close_cmds.is_empty() {
        let cmd_str = close_cmds
            .iter()
            .map(|c| c.replacen("sudo ", "sudo -n ", 1))
            .collect::<Vec<_>>()
            .join(" && ");
        let mut args = ssh_base_args(session.require_pq_ssh, session.strict_ssh_host_key);
        args.push("--".into());
        args.push(session.ssh_target.clone());
        args.push(cmd_str);
        if let Ok(out) = Command::new("ssh")
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .await
        {
            firewall_closed_automatically = out.status.success();
        }
    }

    let host = session.host.clone();
    let ssh_target = session.ssh_target.clone();
    let require_pq_ssh = session.require_pq_ssh;
    let strict_ssh_host_key = session.strict_ssh_host_key;
    drop(session); // Explicitly drops & kills tunnel_child

    let post_probe = if !req.dry_run {
        probe_host(&HostProbeRequest {
            host,
            https_port: 47984,
            http_port: 47989,
            webui_port: 47990,
            rtsp_port: 48010,
            ssh_target: Some(ssh_target),
            require_pq_ssh,
            strict_ssh_host_key,
            ssh_cert_path: None,
        })
        .await
        .ok()
    } else {
        None
    };

    let _ = &open_cmds_unused_guard;
    emit.finish("pairing", true, "Pairing SSH tunnel closed");
    Ok(ClosePairingResponse {
        closed: true,
        close_firewall_commands: close_cmds,
        firewall_closed_automatically,
        post_lockdown_probe: post_probe,
    })
}

fn open_cmds_unused_guard(_s: &ActivePairingSession) -> &[String] {
    &_s.open_cmds
}
