//! Shared headless-testable UI state, launch-mode selection, form validation,
//! and RU/EN localization strings used by both the Floem native GUI and Ratatui TUI.

use crate::config_gen::{EncoderKind, FirewallBackend, HostConfigParams, HostProfileKind};
use crate::deps::{DependencyCheckRequest, DependencyInstallRequest, DependencyRole};
use crate::installer_ops::{
    ClientInstallRequest, ClientSource, InstallScope, LocalHostInstallRequest, OpenPairingRequest,
    SshDeployRequest, SubmitPairingPinRequest,
};
use crate::probe::HostProbeRequest;
use crate::uninstall::{UninstallComponent, UninstallRequest};
use crate::validation::{
    validate_instance_name, validate_ip_or_host, validate_ipv4_or_ipv6_literal, validate_pin,
    validate_render_device, validate_resolution, validate_sha256_hex, validate_signing_identity,
    validate_ssh_target, validate_x11_display,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UiLaunchMode {
    NativeGui,
    Tui,
    NonInteractiveCli,
}

/// Chooses the safest UI mode for the current OS, display environment, SSH status, and TTY.
pub fn select_ui_launch_mode(
    force_gui: bool,
    force_tui: bool,
    os: &str,
    has_display: bool,
    is_ssh: bool,
    is_tty: bool,
) -> UiLaunchMode {
    if force_gui {
        return UiLaunchMode::NativeGui;
    }
    if force_tui {
        return if is_tty {
            UiLaunchMode::Tui
        } else {
            UiLaunchMode::NonInteractiveCli
        };
    }
    if is_ssh || (os == "linux" && !has_display) {
        return if is_tty {
            UiLaunchMode::Tui
        } else {
            UiLaunchMode::NonInteractiveCli
        };
    }
    UiLaunchMode::NativeGui
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiTab {
    Overview,
    Client,
    Host,
    VerifyPair,
    Uninstall,
}

impl UiTab {
    pub fn all() -> [Self; 5] {
        [
            Self::Overview,
            Self::Client,
            Self::Host,
            Self::VerifyPair,
            Self::Uninstall,
        ]
    }

    pub fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Client => 1,
            Self::Host => 2,
            Self::VerifyPair => 3,
            Self::Uninstall => 4,
        }
    }

    pub fn next(self) -> Self {
        let all = Self::all();
        all[(self.index() + 1) % all.len()]
    }

    pub fn prev(self) -> Self {
        let all = Self::all();
        all[(self.index() + all.len() - 1) % all.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiLang {
    Ru,
    En,
}

impl UiLang {
    pub fn toggle(self) -> Self {
        match self {
            Self::Ru => Self::En,
            Self::En => Self::Ru,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiTheme {
    Dark,
    Light,
}

impl UiTheme {
    pub fn toggle(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::Dark,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSourceKind {
    FromSource,
    Archive,
    ReleaseUrl,
}

impl ClientSourceKind {
    pub fn cycle(self) -> Self {
        match self {
            Self::FromSource => Self::Archive,
            Self::Archive => Self::ReleaseUrl,
            Self::ReleaseUrl => Self::FromSource,
        }
    }

    pub fn label(self, lang: UiLang) -> &'static str {
        match (self, lang) {
            (Self::FromSource, UiLang::Ru) => "Собрать из исходников (From Source)",
            (Self::FromSource, UiLang::En) => "Build From Source",
            (Self::Archive, UiLang::Ru) => "Локальный архив (.zip / .tar.gz) + SHA-256",
            (Self::Archive, UiLang::En) => "Local Archive (.zip / .tar.gz) + SHA-256",
            (Self::ReleaseUrl, UiLang::Ru) => "HTTPS URL релиза + SHA-256",
            (Self::ReleaseUrl, UiLang::En) => "HTTPS Release URL + SHA-256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDeployMode {
    Ssh,
    Local,
}

impl HostDeployMode {
    pub fn toggle(self) -> Self {
        match self {
            Self::Ssh => Self::Local,
            Self::Local => Self::Ssh,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingConfirmation {
    InstallClient,
    InstallHostLocal,
    DeployHostSsh,
    InstallDeps,
    Uninstall,
    UninstallPurge,
}

#[derive(Debug, Clone)]
pub struct ClientFormState {
    pub source_kind: ClientSourceKind,
    pub scope: InstallScope,
    pub repo_root: String,
    pub archive_location: String,
    pub sha256: String,
    pub local_signing_identity: String,
    pub allow_unnotarized: bool,
    pub auto_deps: bool,
}

impl Default for ClientFormState {
    fn default() -> Self {
        Self {
            source_kind: ClientSourceKind::FromSource,
            scope: InstallScope::User,
            repo_root: String::new(),
            archive_location: String::new(),
            sha256: String::new(),
            local_signing_identity: String::new(),
            allow_unnotarized: false,
            auto_deps: true,
        }
    }
}

impl ClientFormState {
    pub fn to_client_install_request(&self, dry_run: bool) -> Result<ClientInstallRequest, String> {
        let local_signing_identity = if self.local_signing_identity.trim().is_empty() {
            None
        } else {
            Some(
                validate_signing_identity(&self.local_signing_identity)
                    .map_err(|e| e.to_string())?,
            )
        };

        let source = match self.source_kind {
            ClientSourceKind::FromSource => ClientSource::FromSource {
                repo_root: if self.repo_root.trim().is_empty() {
                    None
                } else {
                    Some(self.repo_root.trim().to_string())
                },
            },
            ClientSourceKind::Archive => {
                let path = self.archive_location.trim();
                if path.is_empty() {
                    return Err("Archive path is required".into());
                }
                let sha256 = validate_sha256_hex(&self.sha256).map_err(|e| e.to_string())?;
                ClientSource::Archive {
                    path: path.to_string(),
                    sha256,
                }
            }
            ClientSourceKind::ReleaseUrl => {
                let url = crate::validation::validate_https_url(&self.archive_location)
                    .map_err(|e| e.to_string())?;
                let sha256 = validate_sha256_hex(&self.sha256).map_err(|e| e.to_string())?;
                ClientSource::ReleaseUrl { url, sha256 }
            }
        };

        Ok(ClientInstallRequest {
            source,
            scope: self.scope,
            allow_unnotarized: self.allow_unnotarized,
            local_signing_identity,
            auto_deps: self.auto_deps,
            dry_run,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HostFormState {
    pub deploy_mode: HostDeployMode,
    pub ssh_target: String,
    pub host_ip: String,
    pub controller_ip: String,
    pub profile: HostProfileKind,
    pub instance_name: String,
    pub display: String,
    pub resolution: String,
    pub encoder: EncoderKind,
    pub firewall_backend: FirewallBackend,
    pub render_device: String,
    pub archive_path: String,
    pub archive_sha256: String,
    pub from_source: bool,
    pub enable_clipboard: bool,
    pub enable_file_transfer: bool,
    pub enable_native_file_clipboard: bool,
    pub enable_mic: bool,
    pub require_pq_ssh: bool,
    pub execute_sudo: bool,
    pub auto_deps: bool,
    pub show_advanced: bool,
}

impl Default for HostFormState {
    fn default() -> Self {
        Self {
            deploy_mode: HostDeployMode::Ssh,
            ssh_target: String::new(),
            host_ip: String::new(),
            controller_ip: String::new(),
            profile: HostProfileKind::LinuxVirtualX11,
            instance_name: "sds-host".to_string(),
            display: ":97".to_string(),
            resolution: "1920x1080".to_string(),
            encoder: EncoderKind::Auto,
            firewall_backend: FirewallBackend::Auto,
            render_device: String::new(),
            archive_path: String::new(),
            archive_sha256: String::new(),
            from_source: false,
            enable_clipboard: true,
            enable_file_transfer: true,
            enable_native_file_clipboard: true,
            enable_mic: true,
            require_pq_ssh: true,
            execute_sudo: false,
            auto_deps: true,
            show_advanced: false,
        }
    }
}

impl HostFormState {
    fn validated_archive(&self) -> Result<(Option<String>, Option<String>), String> {
        let arch = self.archive_path.trim();
        if arch.is_empty() {
            return Ok((None, None));
        }
        if arch.contains('\0') {
            return Err("Invalid NUL byte in host archive path".into());
        }
        let sha = validate_sha256_hex(&self.archive_sha256).map_err(|e| e.to_string())?;
        Ok((Some(arch.to_string()), Some(sha)))
    }

    pub fn to_host_config_params(&self) -> Result<HostConfigParams, String> {
        let instance_name =
            validate_instance_name(&self.instance_name).map_err(|e| e.to_string())?;
        let controller_ip = validate_ipv4_or_ipv6_literal(&self.controller_ip)
            .map_err(|e| e.to_string())?
            .to_string();
        let display = validate_x11_display(&self.display).map_err(|e| e.to_string())?;
        let _ = validate_resolution(&self.resolution).map_err(|e| e.to_string())?;
        let render_device = if self.render_device.trim().is_empty() {
            None
        } else {
            Some(validate_render_device(&self.render_device).map_err(|e| e.to_string())?)
        };

        Ok(HostConfigParams {
            instance_name,
            controller_ip,
            profile: self.profile,
            display,
            resolution: self.resolution.trim().to_string(),
            encoder: self.encoder,
            render_device,
            enable_clipboard: self.enable_clipboard,
            enable_file_transfer: self.enable_file_transfer,
            enable_native_file_clipboard: self.enable_native_file_clipboard,
            enable_mic: self.enable_mic,
            firewall_backend: self.firewall_backend,
            install_dir: None,
        })
    }

    pub fn to_local_host_request(
        &self,
        dry_run: bool,
        repo_root: Option<String>,
    ) -> Result<LocalHostInstallRequest, String> {
        let (archive_path, archive_sha256) = self.validated_archive()?;
        Ok(LocalHostInstallRequest {
            config: self.to_host_config_params()?,
            archive_path,
            archive_sha256,
            from_source: self.from_source,
            repo_root,
            auto_deps: self.auto_deps,
            dry_run,
        })
    }

    pub fn to_ssh_deploy_request(&self, dry_run: bool) -> Result<SshDeployRequest, String> {
        let ssh_target = validate_ssh_target(&self.ssh_target).map_err(|e| e.to_string())?;
        let host_ip = validate_ip_or_host(&self.host_ip).map_err(|e| e.to_string())?;
        let (archive_path, archive_sha256) = self.validated_archive()?;
        let config = self.to_host_config_params()?;
        Ok(SshDeployRequest {
            ssh_target,
            host_ip,
            require_pq_ssh: self.require_pq_ssh,
            strict_ssh_host_key: false,
            config,
            archive_path,
            archive_sha256,
            execute_sudo: self.execute_sudo,
            auto_deps: self.auto_deps,
            dry_run,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProbePairFormState {
    pub host: String,
    pub ssh_target: String,
    pub require_pq_ssh: bool,
    pub controller_ip: String,
    pub firewall_backend: FirewallBackend,
    pub execute_sudo_firewall: bool,
    pub pin: String,
    pub client_name: String,
    pub admin_user: String,
    pub admin_pass: String,
    pub perm_clipboard_read: bool,
    pub perm_clipboard_write: bool,
    pub perm_file_upload: bool,
    pub perm_file_download: bool,
    pub perm_mic: bool,
}

impl Default for ProbePairFormState {
    fn default() -> Self {
        Self {
            host: String::new(),
            ssh_target: String::new(),
            require_pq_ssh: true,
            controller_ip: String::new(),
            firewall_backend: FirewallBackend::Auto,
            execute_sudo_firewall: false,
            pin: String::new(),
            client_name: "Desktop Controller".to_string(),
            admin_user: "sds-admin".to_string(),
            admin_pass: String::new(),
            perm_clipboard_read: true,
            perm_clipboard_write: true,
            perm_file_upload: true,
            perm_file_download: true,
            perm_mic: true,
        }
    }
}

impl ProbePairFormState {
    pub fn to_probe_request(&self) -> Result<HostProbeRequest, String> {
        let host = validate_ip_or_host(&self.host).map_err(|e| e.to_string())?;
        let ssh_target = if self.ssh_target.trim().is_empty() {
            None
        } else {
            Some(validate_ssh_target(&self.ssh_target).map_err(|e| e.to_string())?)
        };
        Ok(HostProbeRequest {
            host,
            https_port: 47984,
            http_port: 47989,
            webui_port: 47990,
            rtsp_port: 48010,
            ssh_target,
            require_pq_ssh: self.require_pq_ssh,
            strict_ssh_host_key: false,
            ssh_cert_path: None,
        })
    }

    pub fn to_open_pairing_request(&self, dry_run: bool) -> Result<OpenPairingRequest, String> {
        let host = validate_ip_or_host(&self.host).map_err(|e| e.to_string())?;
        let ssh_target = validate_ssh_target(&self.ssh_target).map_err(|e| e.to_string())?;
        let controller_ip = validate_ipv4_or_ipv6_literal(&self.controller_ip)
            .map_err(|e| e.to_string())?
            .to_string();
        Ok(OpenPairingRequest {
            host,
            ssh_target,
            controller_ip,
            require_pq_ssh: self.require_pq_ssh,
            strict_ssh_host_key: false,
            execute_sudo_firewall: self.execute_sudo_firewall,
            ssh_cert_path: None,
            firewall_backend: self.firewall_backend,
            dry_run,
        })
    }

    pub fn to_submit_pin_request(
        &self,
        session_id: &str,
    ) -> Result<SubmitPairingPinRequest, String> {
        if session_id.trim().is_empty() {
            return Err("Open a pairing tunnel first".into());
        }
        let pin = validate_pin(&self.pin).map_err(|e| e.to_string())?;
        if self.client_name.trim().is_empty() {
            return Err("Client name is required".into());
        }
        if self.admin_user.trim().is_empty() || self.admin_pass.is_empty() {
            return Err("Sunshine admin username and password are required".into());
        }
        let mut permissions = Vec::new();
        if self.perm_clipboard_read {
            permissions.push("clipboard_read".into());
        }
        if self.perm_clipboard_write {
            permissions.push("clipboard_write".into());
        }
        if self.perm_file_upload {
            permissions.push("file_upload".into());
        }
        if self.perm_file_download {
            permissions.push("file_download".into());
        }
        if self.perm_mic {
            permissions.push("mic".into());
        }
        Ok(SubmitPairingPinRequest {
            session_id: session_id.to_string(),
            pin,
            client_name: self.client_name.trim().to_string(),
            pairing_id: None,
            admin_user: self.admin_user.trim().to_string(),
            admin_pass: self.admin_pass.clone(),
            permissions,
        })
    }

    /// Wipes sensitive ephemeral credentials from memory immediately after pairing submit.
    pub fn clear_secrets(&mut self) {
        self.admin_pass.clear();
        self.pin.clear();
    }
}

#[derive(Debug, Clone)]
pub struct DepsFormState {
    pub role: DependencyRole,
    pub ssh_target: String,
    pub require_pq_ssh: bool,
    pub include_optional: bool,
    pub execute_sudo: bool,
}

impl Default for DepsFormState {
    fn default() -> Self {
        Self {
            role: DependencyRole::All,
            ssh_target: String::new(),
            require_pq_ssh: true,
            include_optional: false,
            execute_sudo: false,
        }
    }
}

impl DepsFormState {
    fn normalized_ssh(&self) -> Result<Option<String>, String> {
        let t = self.ssh_target.trim();
        if t.is_empty() {
            Ok(None)
        } else {
            Ok(Some(validate_ssh_target(t).map_err(|e| e.to_string())?))
        }
    }

    pub fn to_check_request(&self) -> Result<DependencyCheckRequest, String> {
        Ok(DependencyCheckRequest {
            role: self.role,
            ssh_target: self.normalized_ssh()?,
            require_pq_ssh: self.require_pq_ssh,
            strict_ssh_host_key: false,
        })
    }

    pub fn to_install_request(&self, dry_run: bool) -> Result<DependencyInstallRequest, String> {
        Ok(DependencyInstallRequest {
            role: self.role,
            ssh_target: self.normalized_ssh()?,
            require_pq_ssh: self.require_pq_ssh,
            strict_ssh_host_key: false,
            include_optional: self.include_optional,
            execute_sudo: self.execute_sudo,
            dry_run,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UninstallFormState {
    pub component: UninstallComponent,
    pub instance_name: String,
    pub ssh_target: String,
    pub require_pq_ssh: bool,
    pub purge_config: bool,
    pub remove_firewall: bool,
    pub execute_sudo: bool,
}

impl Default for UninstallFormState {
    fn default() -> Self {
        Self {
            component: UninstallComponent::All,
            instance_name: "sds-host".to_string(),
            ssh_target: String::new(),
            require_pq_ssh: true,
            purge_config: false,
            remove_firewall: true,
            execute_sudo: false,
        }
    }
}

impl UninstallFormState {
    pub fn to_uninstall_request(&self, dry_run: bool) -> Result<UninstallRequest, String> {
        let instance_name =
            validate_instance_name(&self.instance_name).map_err(|e| e.to_string())?;
        let ssh_target = if self.ssh_target.trim().is_empty() {
            None
        } else {
            Some(validate_ssh_target(&self.ssh_target).map_err(|e| e.to_string())?)
        };
        Ok(UninstallRequest {
            component: self.component,
            instance_name,
            purge_config: self.purge_config,
            remove_firewall: self.remove_firewall,
            ssh_target,
            require_pq_ssh: self.require_pq_ssh,
            strict_ssh_host_key: false,
            execute_sudo: self.execute_sudo,
            user_only: false,
            dry_run,
        })
    }
}

pub fn cycle_profile(p: HostProfileKind) -> HostProfileKind {
    match p {
        HostProfileKind::LinuxVirtualX11 => HostProfileKind::LinuxPhysicalX11,
        HostProfileKind::LinuxPhysicalX11 => HostProfileKind::WindowsHost,
        HostProfileKind::WindowsHost => HostProfileKind::LinuxVirtualX11,
    }
}

pub fn cycle_encoder(e: EncoderKind) -> EncoderKind {
    match e {
        EncoderKind::Auto => EncoderKind::Vaapi,
        EncoderKind::Vaapi => EncoderKind::Nvenc,
        EncoderKind::Nvenc => EncoderKind::Amf,
        EncoderKind::Amf => EncoderKind::Quicksync,
        EncoderKind::Quicksync => EncoderKind::Software,
        EncoderKind::Software => EncoderKind::Auto,
    }
}

pub fn cycle_firewall(f: FirewallBackend) -> FirewallBackend {
    match f {
        FirewallBackend::Auto => FirewallBackend::Ufw,
        FirewallBackend::Ufw => FirewallBackend::Firewalld,
        FirewallBackend::Firewalld => FirewallBackend::Nftables,
        FirewallBackend::Nftables => FirewallBackend::Windows,
        FirewallBackend::Windows => FirewallBackend::Auto,
    }
}

/// Returns a bilingual Russian/English label for core UI sections and actions.
pub fn tr(lang: UiLang, key: &'static str) -> &'static str {
    match (lang, key) {
        (UiLang::Ru, "app_title") => "Secure Desktop Stream — Нативный мастер",
        (UiLang::En, "app_title") => "Secure Desktop Stream — Native Installer",
        (UiLang::Ru, "app_subtitle") => "Без WebView и HTML · Программный рендер (tiny-skia) · PQ TLS 1.3",
        (UiLang::En, "app_subtitle") => "Zero WebView & HTML · Software Renderer (tiny-skia) · PQ TLS 1.3",
        (UiLang::Ru, "tab_overview") => "1. Обзор и зависимости",
        (UiLang::En, "tab_overview") => "1. Overview & Deps",
        (UiLang::Ru, "tab_client") => "2. Клиент",
        (UiLang::En, "tab_client") => "2. Client",
        (UiLang::Ru, "tab_host") => "3. Хост / PQ SSH",
        (UiLang::En, "tab_host") => "3. Host / PQ SSH",
        (UiLang::Ru, "tab_verify") => "4. Проверка и пейринг",
        (UiLang::En, "tab_verify") => "4. Verify & Pair",
        (UiLang::Ru, "tab_uninstall") => "5. Удаление",
        (UiLang::En, "tab_uninstall") => "5. Uninstall",
        (UiLang::Ru, "topology") => "Архитектура: Контроллер [Moonlight] <-- 47984 PQ mTLS (X25519MLKEM768) / 48010 rtspenc / 47998-48002 UDP --> Хосты [Hardened Sunshine] + SSH-туннель 127.0.0.1:47990",
        (UiLang::En, "topology") => "Topology: Controller [Moonlight] <-- 47984 PQ mTLS (X25519MLKEM768) / 48010 rtspenc / 47998-48002 UDP --> Hosts [Hardened Sunshine] + SSH tunnel 127.0.0.1:47990",
        (UiLang::Ru, "unsigned_note") => "Сборки без платных подписей Apple/Microsoft: проверка SHA-256/заголовков или сборка из исходников; снятие карантина/MOTW только по явному выбору (Gatekeeper/SmartScreen остаются включены).",
        (UiLang::En, "unsigned_note") => "No paid Apple/Microsoft certs needed: verifies SHA-256/headers or builds from source; quarantine/MOTW removal is opt-in only (Gatekeeper/SmartScreen stay enabled).",
        (UiLang::Ru, "host_runtime_note") => "Параметры стриминга (кодек, YCoCg-R 4:4:4, адаптер GPU, энкодер, динамическое разрешение, битрейт) настраиваются в Moonlight и Web UI Sunshine через SSH-туннель — мастер установки их не дублирует.",
        (UiLang::En, "host_runtime_note") => "Runtime streaming settings (codec, YCoCg-R 4:4:4, GPU adapter, encoder, dynamic resolution, bitrate) live in Moonlight and Sunshine's Web UI over SSH tunnel — the installer only provisions install-time host services & firewall.",
        (UiLang::Ru, "btn_rescan") => "Обновить диагностику",
        (UiLang::En, "btn_rescan") => "Refresh Preflight",
        (UiLang::Ru, "btn_check_deps") => "Проверить зависимости",
        (UiLang::En, "btn_check_deps") => "Check Dependencies",
        (UiLang::Ru, "btn_dry_run_deps") => "Dry-Run зависимостей",
        (UiLang::En, "btn_dry_run_deps") => "Dry-Run Dependencies",
        (UiLang::Ru, "btn_install_deps") => "Доустановить зависимости",
        (UiLang::En, "btn_install_deps") => "Auto-Install Missing Deps",
        (UiLang::Ru, "btn_dry_run") => "Dry-Run (план)",
        (UiLang::En, "btn_dry_run") => "Dry-Run Plan",
        (UiLang::Ru, "btn_install_client") => "Установить клиент",
        (UiLang::En, "btn_install_client") => "Install Client",
        (UiLang::Ru, "btn_preview") => "Предпросмотр конфигов",
        (UiLang::En, "btn_preview") => "Preview Configs",
        (UiLang::Ru, "btn_deploy_host") => "Применить / Деплой",
        (UiLang::En, "btn_deploy_host") => "Apply / Deploy",
        (UiLang::Ru, "btn_toggle_advanced") => "Дополнительные параметры профиля",
        (UiLang::En, "btn_toggle_advanced") => "Advanced Profile Overrides",
        (UiLang::Ru, "btn_probe") => "Проверить сервер",
        (UiLang::En, "btn_probe") => "Verify Server",
        (UiLang::Ru, "btn_deploy_missing") => "Сервер не найден -> Деплой по PQ SSH ->",
        (UiLang::En, "btn_deploy_missing") => "Server missing -> Deploy via PQ SSH ->",
        (UiLang::Ru, "btn_open_pair") => "1. Сверить отпечаток и открыть туннель",
        (UiLang::En, "btn_open_pair") => "1. Verify Fingerprint & Open Tunnel",
        (UiLang::Ru, "btn_submit_pin") => "2. Подтвердить PIN и выдать права",
        (UiLang::En, "btn_submit_pin") => "2. Submit PIN & Grant Permissions",
        (UiLang::Ru, "btn_close_pair") => "3. Закрыть 47989/tcp и туннель",
        (UiLang::En, "btn_close_pair") => "3. Close 47989/tcp & Tunnel",
        (UiLang::Ru, "btn_dry_run_uninstall") => "Dry-Run удаления",
        (UiLang::En, "btn_dry_run_uninstall") => "Dry-Run Uninstall",
        (UiLang::Ru, "btn_uninstall") => "Удалить компоненты SDS",
        (UiLang::En, "btn_uninstall") => "Uninstall SDS Components",
        (UiLang::Ru, "confirm_title") => "Подтвердите действие:",
        (UiLang::En, "confirm_title") => "Confirm action:",
        (UiLang::Ru, "btn_cancel") => "Отмена",
        (UiLang::En, "btn_cancel") => "Cancel",
        (UiLang::Ru, "btn_confirm") => "Подтвердить",
        (UiLang::En, "btn_confirm") => "Proceed",
        (UiLang::Ru, "logs_title") => "Журнал операций",
        (UiLang::En, "logs_title") => "Operation Log",
        _ => key,
    }
}
