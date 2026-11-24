//! CLI command definitions and execution handlers for `sds-installer`.

use crate::archive::{
    detect_archive_kind, extract_tar_gz_safe, extract_zip_safe, inspect_binary_header,
    verify_archive_file, write_atomic, ArchiveKind, ExtractionLimits, MAX_ARCHIVE_BYTES,
};
use crate::config_gen::{
    generate_host_bundle, EncoderKind, FirewallBackend, HostConfigParams, HostProfileKind,
};
use crate::deps::{
    check_dependencies, install_missing_dependencies, DependencyCheckRequest,
    DependencyInstallRequest, DependencyRole,
};
use crate::installer_ops::{
    deploy_host_ssh, install_client, install_host_local, ClientInstallRequest, ClientSource,
    InstallScope, LocalHostInstallRequest, ProgressEmitter, ProgressEvent, SshDeployRequest,
};
use crate::native_gui::run_native_gui;
use crate::platform::{collect_preflight, current_os, detect_repo_root};
use crate::probe::{probe_host, HostProbeRequest, HostProbeVerdict};
use crate::tui::run_tui;
use crate::ui_state::{select_ui_launch_mode, UiLaunchMode};
use crate::uninstall::{run_uninstall, UninstallComponent, UninstallRequest};
use clap::{Parser, Subcommand, ValueEnum};
use std::env;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use tokio::runtime::Runtime;
use tokio::sync::broadcast;

#[derive(Debug, Parser)]
#[command(
    name = "sds-installer",
    version,
    about = "Cross-platform hardened installer, dependency manager & uninstaller for Secure Desktop Stream"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProfileArg {
    LinuxVirtualX11,
    LinuxPhysicalX11,
    WindowsHost,
}

impl From<ProfileArg> for HostProfileKind {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::LinuxVirtualX11 => Self::LinuxVirtualX11,
            ProfileArg::LinuxPhysicalX11 => Self::LinuxPhysicalX11,
            ProfileArg::WindowsHost => Self::WindowsHost,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EncoderArg {
    Auto,
    Vaapi,
    Nvenc,
    Amf,
    Quicksync,
    Software,
}

impl From<EncoderArg> for EncoderKind {
    fn from(value: EncoderArg) -> Self {
        match value {
            EncoderArg::Auto => Self::Auto,
            EncoderArg::Vaapi => Self::Vaapi,
            EncoderArg::Nvenc => Self::Nvenc,
            EncoderArg::Amf => Self::Amf,
            EncoderArg::Quicksync => Self::Quicksync,
            EncoderArg::Software => Self::Software,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FirewallArg {
    Auto,
    Ufw,
    Firewalld,
    Nftables,
    Windows,
}

impl From<FirewallArg> for FirewallBackend {
    fn from(value: FirewallArg) -> Self {
        match value {
            FirewallArg::Auto => Self::Auto,
            FirewallArg::Ufw => Self::Ufw,
            FirewallArg::Firewalld => Self::Firewalld,
            FirewallArg::Nftables => Self::Nftables,
            FirewallArg::Windows => Self::Windows,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ScopeArg {
    User,
    System,
}

impl From<ScopeArg> for InstallScope {
    fn from(value: ScopeArg) -> Self {
        match value {
            ScopeArg::User => Self::User,
            ScopeArg::System => Self::System,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DepRoleArg {
    Client,
    ClientBuild,
    HostVirtual,
    HostPhysical,
    HostWindows,
    HostBuild,
    InstallerBuild,
    All,
}

impl From<DepRoleArg> for DependencyRole {
    fn from(value: DepRoleArg) -> Self {
        match value {
            DepRoleArg::Client => Self::Client,
            DepRoleArg::ClientBuild => Self::ClientBuild,
            DepRoleArg::HostVirtual => Self::HostVirtual,
            DepRoleArg::HostPhysical => Self::HostPhysical,
            DepRoleArg::HostWindows => Self::HostWindows,
            DepRoleArg::HostBuild => Self::HostBuild,
            DepRoleArg::InstallerBuild => Self::InstallerBuild,
            DepRoleArg::All => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum UninstallComponentArg {
    All,
    Client,
    Host,
    Installer,
}

impl From<UninstallComponentArg> for UninstallComponent {
    fn from(value: UninstallComponentArg) -> Self {
        match value {
            UninstallComponentArg::All => Self::All,
            UninstallComponentArg::Client => Self::Client,
            UninstallComponentArg::Host => Self::Host,
            UninstallComponentArg::Installer => Self::Installer,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum DepsAction {
    /// Check required and optional runtime/build dependencies locally or over PQ SSH
    Check {
        #[arg(long, value_enum, default_value = "all")]
        role: DepRoleArg,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long)]
        no_require_pq_ssh: bool,
        #[arg(long)]
        strict_ssh_host_key: bool,
        #[arg(long)]
        json: bool,
    },
    /// Install missing allowlisted runtime/build dependencies automatically (or preview with --dry-run)
    Install {
        #[arg(long, value_enum, default_value = "all")]
        role: DepRoleArg,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long)]
        no_require_pq_ssh: bool,
        #[arg(long)]
        strict_ssh_host_key: bool,
        #[arg(long)]
        include_optional: bool,
        #[arg(long)]
        execute_sudo: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Launch the pure native software-rendered GUI wizard (default on desktop)
    Gui {
        #[arg(long)]
        repo_root: Option<PathBuf>,
    },
    /// Launch the interactive native terminal wizard (default on SSH / headless TTY)
    Tui {
        #[arg(long)]
        repo_root: Option<PathBuf>,
    },
    /// Inspect local OS, architecture, SSH PQ support, GPU devices, and existing installs
    Preflight {
        #[arg(long)]
        repo_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Check or automatically install required runtime & build dependencies
    Deps {
        #[command(subcommand)]
        action: DepsAction,
    },
    /// Cryptographically probe a host for PQ TLS 1.3 (X25519MLKEM768) and firewall hygiene
    Probe {
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 47984)]
        port: u16,
        #[arg(long, default_value_t = 47989)]
        http_port: u16,
        #[arg(long, default_value_t = 47990)]
        webui_port: u16,
        #[arg(long, default_value_t = 48010)]
        rtsp_port: u16,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long)]
        no_require_pq_ssh: bool,
        #[arg(long)]
        strict_ssh_host_key: bool,
        #[arg(long)]
        cert_path: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Generate hardened Sunshine configs, systemd units, and firewall rules to a directory
    GenConfig {
        #[arg(long, value_enum)]
        profile: ProfileArg,
        #[arg(long)]
        controller_ip: String,
        #[arg(long, default_value = "sds-host")]
        instance_name: String,
        #[arg(long, default_value = ":97")]
        display: String,
        #[arg(long, default_value = "1920x1080")]
        resolution: String,
        #[arg(long, value_enum, default_value = "auto")]
        encoder: EncoderArg,
        #[arg(long)]
        render_device: Option<String>,
        #[arg(long, value_enum, default_value = "auto")]
        firewall: FirewallArg,
        #[arg(long)]
        no_clipboard: bool,
        #[arg(long)]
        no_file_transfer: bool,
        #[arg(long)]
        no_native_file_clipboard: bool,
        #[arg(long)]
        no_mic: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// Install or build the Moonlight Secure Desktop client
    InstallClient {
        #[arg(long)]
        archive: Option<String>,
        #[arg(long)]
        release_url: Option<String>,
        #[arg(long)]
        sha256: Option<String>,
        #[arg(long)]
        from_source: bool,
        #[arg(long)]
        repo_root: Option<String>,
        #[arg(long, value_enum, default_value = "user")]
        scope: ScopeArg,
        #[arg(long)]
        allow_unnotarized: bool,
        #[arg(long)]
        local_sign: Option<String>,
        #[arg(long)]
        auto_deps: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Generate and install hardened host configuration locally
    InstallHost {
        #[arg(long, value_enum)]
        profile: ProfileArg,
        #[arg(long)]
        controller_ip: String,
        #[arg(long, default_value = "sds-host")]
        instance_name: String,
        #[arg(long, default_value = ":97")]
        display: String,
        #[arg(long, default_value = "1920x1080")]
        resolution: String,
        #[arg(long, value_enum, default_value = "auto")]
        encoder: EncoderArg,
        #[arg(long)]
        render_device: Option<String>,
        #[arg(long, value_enum, default_value = "auto")]
        firewall: FirewallArg,
        #[arg(long)]
        archive: Option<String>,
        #[arg(long)]
        sha256: Option<String>,
        #[arg(long)]
        from_source: bool,
        #[arg(long)]
        repo_root: Option<String>,
        #[arg(long)]
        auto_deps: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Deploy hardened Sunshine profile and verified payload over PQ SSH
    DeploySsh {
        #[arg(long)]
        ssh: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        controller_ip: String,
        #[arg(long, value_enum)]
        profile: ProfileArg,
        #[arg(long, default_value = "sds-host")]
        instance_name: String,
        #[arg(long, default_value = ":97")]
        display: String,
        #[arg(long, default_value = "1920x1080")]
        resolution: String,
        #[arg(long, value_enum, default_value = "auto")]
        encoder: EncoderArg,
        #[arg(long)]
        render_device: Option<String>,
        #[arg(long, value_enum, default_value = "auto")]
        firewall: FirewallArg,
        #[arg(long)]
        archive: Option<String>,
        #[arg(long)]
        sha256: Option<String>,
        #[arg(long)]
        no_require_pq_ssh: bool,
        #[arg(long)]
        strict_ssh_host_key: bool,
        #[arg(long)]
        execute_sudo: bool,
        #[arg(long)]
        auto_deps: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Uninstall Secure Desktop Stream components cleanly using allowlisted manifest checks
    Uninstall {
        #[arg(long, value_enum, default_value = "all")]
        component: UninstallComponentArg,
        #[arg(long, alias = "instance-name", default_value = "sds-host")]
        instance: String,
        #[arg(long)]
        purge_config: bool,
        #[arg(long)]
        keep_firewall: bool,
        #[arg(long)]
        ssh: Option<String>,
        #[arg(long)]
        no_require_pq_ssh: bool,
        #[arg(long)]
        strict_ssh_host_key: bool,
        #[arg(long)]
        execute_sudo: bool,
        #[arg(long)]
        user_only: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, short = 'y')]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Verify archive SHA-256, safe member paths, and binary ELF/Mach-O/PE headers
    VerifyArchive {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        platform: Option<String>,
    },
}

fn spawn_cli_log_printer() -> ProgressEmitter {
    let (tx, mut rx) = broadcast::channel::<ProgressEvent>(128);
    tokio::spawn(async move {
        while let Ok(ev) = rx.recv().await {
            println!("[{}] [{}] {}", ev.level, ev.step, ev.message);
        }
    });
    ProgressEmitter::new(Some(tx))
}

fn has_linux_display() -> bool {
    !env::var("DISPLAY").unwrap_or_default().trim().is_empty()
        || !env::var("WAYLAND_DISPLAY")
            .unwrap_or_default()
            .trim()
            .is_empty()
}

fn is_ssh_session() -> bool {
    !env::var("SSH_CONNECTION")
        .unwrap_or_default()
        .trim()
        .is_empty()
        || !env::var("SSH_TTY").unwrap_or_default().trim().is_empty()
}

fn is_interactive_tty() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn resolve_default_launch() -> Option<Commands> {
    match select_ui_launch_mode(
        false,
        false,
        current_os(),
        has_linux_display(),
        is_ssh_session(),
        is_interactive_tty(),
    ) {
        UiLaunchMode::NativeGui => Some(Commands::Gui { repo_root: None }),
        UiLaunchMode::Tui => Some(Commands::Tui { repo_root: None }),
        UiLaunchMode::NonInteractiveCli => None,
    }
}

pub fn run_cli(cli: Cli) -> ExitCode {
    let command = match cli.command {
        Some(cmd) => cmd,
        None => match resolve_default_launch() {
            Some(cmd) => cmd,
            None => {
                eprintln!(
                    "No desktop display or interactive TTY detected (headless / non-interactive shell)."
                );
                eprintln!(
                    "Run inside an interactive terminal with `sds-installer tui`, or use CLI subcommands:"
                );
                eprintln!(
                    "  sds-installer preflight | deps | probe | gen-config | install-client | install-host | deploy-ssh | uninstall"
                );
                return ExitCode::from(2);
            }
        },
    };

    match command {
        Commands::Gui { repo_root } => {
            if current_os() == "linux" && !has_linux_display() {
                eprintln!("Cannot start desktop GUI: neither DISPLAY nor WAYLAND_DISPLAY is set.");
                eprintln!("Run `sds-installer tui` for the native terminal wizard instead.");
                return ExitCode::from(2);
            }
            let detected_root = detect_repo_root(repo_root.as_deref());
            match run_native_gui(detected_root) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("Error starting native GUI: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::Tui { repo_root } => {
            if !is_interactive_tty() {
                eprintln!("`sds-installer tui` requires an interactive terminal (TTY).");
                return ExitCode::from(2);
            }
            let detected_root = detect_repo_root(repo_root.as_deref());
            match run_tui(detected_root) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("Error running native TUI: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::Preflight { repo_root, json } => {
            let report = collect_preflight(repo_root.as_deref());
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!(
                    "OS/Arch: {} / {} ({})",
                    report.os, report.arch, report.os_version
                );
                println!(
                    "Hostname: {} (headless={}, rosetta2={})",
                    report.hostname, report.is_headless, report.is_rosetta2
                );
                println!(
                    "SSH: {:?}, PQ KEX: {}",
                    report.ssh_version, report.pq_ssh_supported
                );
                println!(
                    "Cargo: {} ({:?})",
                    report.cargo_available, report.rustc_version
                );
                for w in &report.warnings {
                    println!("  [{}] {}: {}", w.severity, w.code, w.title_en);
                }
            }
            ExitCode::SUCCESS
        }
        Commands::GenConfig {
            profile,
            controller_ip,
            instance_name,
            display,
            resolution,
            encoder,
            render_device,
            firewall,
            no_clipboard,
            no_file_transfer,
            no_native_file_clipboard,
            no_mic,
            out,
        } => {
            let params = HostConfigParams {
                instance_name,
                controller_ip,
                profile: profile.into(),
                display,
                resolution,
                encoder: encoder.into(),
                render_device,
                enable_clipboard: !no_clipboard,
                enable_file_transfer: !no_file_transfer,
                enable_native_file_clipboard: !no_native_file_clipboard,
                enable_mic: !no_mic,
                firewall_backend: firewall.into(),
                install_dir: None,
            };
            match generate_host_bundle(&params) {
                Ok(bundle) => {
                    for file in bundle.files.values() {
                        let dest = out.join(&file.rel_path);
                        let exec = file.mode == "0755";
                        if let Err(e) = write_atomic(&dest, file.content.as_bytes(), exec) {
                            eprintln!("Failed writing {}: {e}", dest.display());
                            return ExitCode::from(1);
                        }
                    }
                    let fw_json = serde_json::to_vec_pretty(&bundle.firewall).unwrap_or_default();
                    let _ = write_atomic(&out.join("firewall-commands.json"), &fw_json, false);
                    println!(
                        "Generated {} files for '{}' in {}",
                        bundle.files.len(),
                        bundle.profile.as_str(),
                        out.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Config generation error: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::VerifyArchive {
            archive,
            sha256,
            platform,
        } => {
            if let Err(e) = verify_archive_file(&archive, &sha256, MAX_ARCHIVE_BYTES) {
                eprintln!("Archive verification failed: {e}");
                return ExitCode::from(1);
            }
            let tmp = match tempfile::tempdir() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Temp dir failed: {e}");
                    return ExitCode::from(1);
                }
            };
            let limits = ExtractionLimits {
                allow_bundle_internal_symlinks: platform.as_deref() == Some("macos"),
                ..ExtractionLimits::default()
            };
            let extracted = match detect_archive_kind(&archive) {
                Ok(ArchiveKind::TarGz) => extract_tar_gz_safe(&archive, tmp.path(), limits),
                Ok(ArchiveKind::Zip) => extract_zip_safe(&archive, tmp.path(), limits),
                Err(e) => Err(e),
            };
            match extracted {
                Ok(paths) => {
                    let mut binaries = 0usize;
                    for p in &paths {
                        if let Ok(info) = inspect_binary_header(p) {
                            binaries += 1;
                            println!(
                                "Verified binary: {} -> {:?} ({})",
                                p.display(),
                                info.format,
                                info.arch
                            );
                        }
                    }
                    println!(
                        "Verified archive {} ({} files, {} recognized executables)",
                        archive.display(),
                        paths.len(),
                        binaries
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Archive extraction check failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        async_cmd => {
            let rt = match Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed starting Tokio runtime: {e}");
                    return ExitCode::from(1);
                }
            };
            rt.block_on(run_async_command(async_cmd))
        }
    }
}

async fn run_async_command(cmd: Commands) -> ExitCode {
    match cmd {
        Commands::Deps { action } => match action {
            DepsAction::Check {
                role,
                ssh,
                no_require_pq_ssh,
                strict_ssh_host_key,
                json,
            } => {
                let req = DependencyCheckRequest {
                    role: role.into(),
                    ssh_target: ssh,
                    require_pq_ssh: !no_require_pq_ssh,
                    strict_ssh_host_key,
                };
                match check_dependencies(&req).await {
                    Ok(rep) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&rep).unwrap_or_else(|_| "{}".into())
                            );
                        } else {
                            println!(
                                "Target: {} ({}/{}, PM: {}) | Satisfied: {}",
                                rep.target_label,
                                rep.os,
                                rep.arch,
                                rep.package_manager.as_str(),
                                rep.all_satisfied
                            );
                            for it in &rep.items {
                                let mark = if it.present {
                                    "OK"
                                } else if it.required {
                                    "MISSING"
                                } else {
                                    "OPT"
                                };
                                let ver = it.detected_version.as_deref().unwrap_or("-");
                                let pkg = it.package_name.as_deref().unwrap_or("-");
                                println!("  [{mark}] {} (pkg={pkg}, ver={ver})", it.name);
                            }
                            if !rep.install_commands.is_empty() {
                                println!(
                                    "\nInstall commands:\n  {}",
                                    rep.install_commands.join("\n  ")
                                );
                            }
                        }
                        if rep.all_satisfied {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::from(10)
                        }
                    }
                    Err(e) => {
                        eprintln!("Dependency check failed: {e}");
                        ExitCode::from(1)
                    }
                }
            }
            DepsAction::Install {
                role,
                ssh,
                no_require_pq_ssh,
                strict_ssh_host_key,
                include_optional,
                execute_sudo,
                dry_run,
                json,
            } => {
                let req = DependencyInstallRequest {
                    role: role.into(),
                    ssh_target: ssh,
                    require_pq_ssh: !no_require_pq_ssh,
                    strict_ssh_host_key,
                    include_optional,
                    execute_sudo,
                    dry_run,
                };
                let emitter = spawn_cli_log_printer();
                match install_missing_dependencies(&req, &emitter).await {
                    Ok(res) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&res).unwrap_or_else(|_| "{}".into())
                            );
                        } else {
                            println!("{}", res.summary);
                            if !res.commands_executed_or_planned.is_empty() {
                                println!(
                                    "Commands:\n  {}",
                                    res.commands_executed_or_planned.join("\n  ")
                                );
                            }
                            if !res.elevated_commands.is_empty() {
                                println!("Elevated:\n  {}", res.elevated_commands.join("\n  "));
                            }
                            if !res.manual_steps.is_empty() {
                                println!("Manual steps:\n  {}", res.manual_steps.join("\n  "));
                            }
                        }
                        if res.ok || res.dry_run {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::from(2)
                        }
                    }
                    Err(e) => {
                        eprintln!("Dependency installation failed: {e}");
                        ExitCode::from(1)
                    }
                }
            }
        },
        Commands::Probe {
            host,
            port,
            http_port,
            webui_port,
            rtsp_port,
            ssh,
            no_require_pq_ssh,
            strict_ssh_host_key,
            cert_path,
            json,
        } => {
            let req = HostProbeRequest {
                host,
                https_port: port,
                http_port,
                webui_port,
                rtsp_port,
                ssh_target: ssh,
                require_pq_ssh: !no_require_pq_ssh,
                strict_ssh_host_key,
                ssh_cert_path: cert_path,
            };
            match probe_host(&req).await {
                Ok(report) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
                        );
                    } else {
                        println!("Host: {} | Verdict: {:?}", report.host, report.verdict);
                        println!(
                            "PQ TLS 1.3: {} | Classical Rejected: {} | TLS 1.2 Rejected: {}",
                            report.pq_tls13_ok,
                            report.classical_kex_rejected,
                            report.tls12_rejected
                        );
                        println!(
                            "Ports: 47984={} 47989={} 47990={} 48010={}",
                            report.https_port_open,
                            report.port_47989_http_open,
                            report.port_47990_webui_open,
                            report.port_48010_rtsp_open
                        );
                        if let Some(ref fp) = report.cert_sha256_fingerprint {
                            println!("Cert SHA-256: {fp}");
                        }
                        println!(
                            "SSH fingerprint status: {:?}",
                            report.ssh_fingerprint_status
                        );
                    }
                    match report.verdict {
                        HostProbeVerdict::ReadyHardened => ExitCode::SUCCESS,
                        HostProbeVerdict::ReadyNeedsPairingLockdown => ExitCode::from(10),
                        _ => ExitCode::from(2),
                    }
                }
                Err(e) => {
                    eprintln!("Probe error: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::InstallClient {
            archive,
            release_url,
            sha256,
            from_source,
            repo_root,
            scope,
            allow_unnotarized,
            local_sign,
            auto_deps,
            dry_run,
        } => {
            let source = if from_source {
                ClientSource::FromSource { repo_root }
            } else if let Some(path) = archive {
                let Some(digest) = sha256 else {
                    eprintln!("--sha256 is required with --archive");
                    return ExitCode::from(2);
                };
                ClientSource::Archive {
                    path,
                    sha256: digest,
                }
            } else if let Some(url) = release_url {
                let Some(digest) = sha256 else {
                    eprintln!("--sha256 is required with --release-url");
                    return ExitCode::from(2);
                };
                ClientSource::ReleaseUrl {
                    url,
                    sha256: digest,
                }
            } else {
                eprintln!("Specify one of --from-source, --archive, or --release-url");
                return ExitCode::from(2);
            };

            let req = ClientInstallRequest {
                source,
                scope: scope.into(),
                allow_unnotarized,
                local_signing_identity: local_sign,
                auto_deps,
                dry_run,
            };
            let emitter = spawn_cli_log_printer();
            match install_client(&req, &emitter).await {
                Ok(res) => {
                    println!("{}", res.summary);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Client install failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::InstallHost {
            profile,
            controller_ip,
            instance_name,
            display,
            resolution,
            encoder,
            render_device,
            firewall,
            archive,
            sha256,
            from_source,
            repo_root,
            auto_deps,
            dry_run,
        } => {
            let req = LocalHostInstallRequest {
                config: HostConfigParams {
                    instance_name,
                    controller_ip,
                    profile: profile.into(),
                    display,
                    resolution,
                    encoder: encoder.into(),
                    render_device,
                    enable_clipboard: true,
                    enable_file_transfer: true,
                    enable_native_file_clipboard: true,
                    enable_mic: true,
                    firewall_backend: firewall.into(),
                    install_dir: None,
                },
                archive_path: archive,
                archive_sha256: sha256,
                from_source,
                repo_root,
                auto_deps,
                dry_run,
            };
            let emitter = spawn_cli_log_printer();
            match install_host_local(&req, &emitter).await {
                Ok(res) => {
                    println!("{}", res.summary);
                    if !res.elevated_commands.is_empty() {
                        println!(
                            "\nPrivileged commands to run:\n  {}",
                            res.elevated_commands.join("\n  ")
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Host install failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::DeploySsh {
            ssh,
            host,
            controller_ip,
            profile,
            instance_name,
            display,
            resolution,
            encoder,
            render_device,
            firewall,
            archive,
            sha256,
            no_require_pq_ssh,
            strict_ssh_host_key,
            execute_sudo,
            auto_deps,
            dry_run,
        } => {
            let req = SshDeployRequest {
                ssh_target: ssh,
                host_ip: host,
                require_pq_ssh: !no_require_pq_ssh,
                strict_ssh_host_key,
                config: HostConfigParams {
                    instance_name,
                    controller_ip,
                    profile: profile.into(),
                    display,
                    resolution,
                    encoder: encoder.into(),
                    render_device,
                    enable_clipboard: true,
                    enable_file_transfer: true,
                    enable_native_file_clipboard: true,
                    enable_mic: true,
                    firewall_backend: firewall.into(),
                    install_dir: None,
                },
                archive_path: archive,
                archive_sha256: sha256,
                execute_sudo,
                auto_deps,
                dry_run,
            };
            let emitter = spawn_cli_log_printer();
            match deploy_host_ssh(&req, &emitter).await {
                Ok(res) => {
                    println!("{}", res.summary);
                    if !res.elevated_commands.is_empty() {
                        println!(
                            "\nPrivileged commands to run on host:\n  {}",
                            res.elevated_commands.join("\n  ")
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("SSH deploy failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::Uninstall {
            component,
            instance,
            purge_config,
            keep_firewall,
            ssh,
            no_require_pq_ssh,
            strict_ssh_host_key,
            execute_sudo,
            user_only,
            dry_run,
            yes,
            json,
        } => {
            if !dry_run && !yes {
                eprintln!(
                    "Refusing non-dry-run uninstall without explicit confirmation. Pass --dry-run to preview or --yes to proceed."
                );
                return ExitCode::from(2);
            }
            let req = UninstallRequest {
                component: component.into(),
                instance_name: instance,
                purge_config,
                remove_firewall: !keep_firewall,
                ssh_target: ssh,
                require_pq_ssh: !no_require_pq_ssh,
                strict_ssh_host_key,
                execute_sudo,
                user_only,
                dry_run,
            };
            let emitter = spawn_cli_log_printer();
            match run_uninstall(&req, &emitter).await {
                Ok(res) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&res).unwrap_or_else(|_| "{}".into())
                        );
                    } else {
                        println!("{}", res.summary);
                        if !res.elevated_commands.is_empty() {
                            println!(
                                "Elevated commands remaining:\n  {}",
                                res.elevated_commands.join("\n  ")
                            );
                        }
                    }
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(e) => {
                    eprintln!("Uninstall failed: {e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => unreachable!("sync commands handled in run_cli"),
    }
}
