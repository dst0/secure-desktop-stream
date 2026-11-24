//! Pure native terminal UI (`ratatui` + `crossterm`) for headless Linux / SSH sessions
//! and explicit `tui` invocations. Zero HTML, zero WebView, zero HTTP server.

use crate::config_gen::{generate_host_bundle, GeneratedBundle};
use crate::deps::{
    check_dependencies, install_missing_dependencies, DependencyCheckReport,
    DependencyInstallResult,
};
use crate::installer_ops::{
    close_pairing_session, deploy_host_ssh, install_client, install_host_local,
    open_pairing_session, submit_pairing_pin, ActionResult, ClosePairingRequest,
    ClosePairingResponse, InstallScope, OpenPairingResponse, PairingManager, ProgressEmitter,
    ProgressEvent,
};
use crate::platform::{collect_preflight, current_os, PreflightReport};
use crate::probe::{probe_host, HostProbeReport, HostProbeVerdict};
use crate::ui_state::{
    cycle_encoder, cycle_firewall, cycle_profile, tr, ClientFormState, DepsFormState,
    HostDeployMode, HostFormState, PendingConfirmation, ProbePairFormState, UiLang, UiTab,
    UninstallFormState,
};
use crate::uninstall::{run_uninstall, UninstallResult};
use crossterm::cursor::Show;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use ratatui::{Frame, Terminal};
use std::io::{self, Stdout};
use std::panic;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TuiAction {
    RefreshPreflight,
    DepsCheck,
    DepsDryRun,
    DepsInstall,
    GoClient,
    GoHost,
    GoVerify,
    GoUninstall,
    ClientDryRun,
    ClientInstall,
    HostToggleAdvanced,
    HostPreview,
    HostDryRun,
    HostDeploy,
    ProbeHost,
    DeployMissingServer,
    OpenPairing,
    SubmitPin,
    ClosePairing,
    UninstallDryRun,
    UninstallRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowId {
    OverviewPreflight,
    OverviewDepsRole,
    OverviewDepsSsh,
    OverviewDepsPqSsh,
    OverviewDepsOptional,
    OverviewDepsSudo,
    OverviewDepsCheckBtn,
    OverviewDepsDryRunBtn,
    OverviewDepsInstallBtn,
    OverviewGoClient,
    OverviewGoHost,
    OverviewGoVerify,
    OverviewGoUninstall,

    ClientSourceKind,
    ClientScope,
    ClientAutoDeps,
    ClientRepoRoot,
    ClientArchiveLoc,
    ClientSha256,
    ClientSignId,
    ClientAllowUnnotarized,
    ClientDryRun,
    ClientInstall,

    HostDeployMode,
    HostSshTarget,
    HostIp,
    HostControllerIp,
    HostProfile,
    HostFirewall,
    HostAutoDeps,
    HostRequirePqSsh,
    HostExecuteSudo,
    HostToggleAdvancedBtn,
    HostInstanceName,
    HostDisplay,
    HostResolution,
    HostEncoder,
    HostRenderDevice,
    HostArchivePath,
    HostArchiveSha256,
    HostFromSource,
    HostClipboard,
    HostFileTransfer,
    HostNativeFileClipboard,
    HostMic,
    HostPreview,
    HostDryRun,
    HostDeploy,

    VerifyHost,
    VerifySshTarget,
    VerifyControllerIp,
    VerifyFirewall,
    VerifyRequirePqSsh,
    VerifyExecuteSudoFw,
    VerifyProbeBtn,
    VerifyDeployMissingBtn,
    VerifyPin,
    VerifyClientName,
    VerifyAdminUser,
    VerifyAdminPass,
    VerifyPermClipRead,
    VerifyPermClipWrite,
    VerifyPermFileUpload,
    VerifyPermFileDownload,
    VerifyPermMic,
    VerifyOpenPairingBtn,
    VerifySubmitPinBtn,
    VerifyClosePairingBtn,

    UninstallComponent,
    UninstallInstanceName,
    UninstallSshTarget,
    UninstallPurgeConfig,
    UninstallRemoveFirewall,
    UninstallRequirePqSsh,
    UninstallExecuteSudo,
    UninstallDryRunBtn,
    UninstallRunBtn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    Text { masked: bool },
    ToggleOrCycle,
    Action(TuiAction),
}

struct RenderedRow {
    id: RowId,
    label: String,
    value: String,
    kind: RowKind,
}

pub struct TuiApp {
    pub lang: UiLang,
    pub tab: UiTab,
    pub preflight: PreflightReport,
    pub deps: DepsFormState,
    pub deps_report: Option<DependencyCheckReport>,
    pub deps_install_res: Option<DependencyInstallResult>,
    pub client: ClientFormState,
    pub host: HostFormState,
    pub probe_pair: ProbePairFormState,
    pub uninstall: UninstallFormState,
    pub uninstall_result: Option<UninstallResult>,
    pub last_action: Option<ActionResult>,
    pub probe_report: Option<HostProbeReport>,
    pub pairing_open: Option<OpenPairingResponse>,
    pub pairing_status: Option<String>,
    pub preview_bundle: Option<GeneratedBundle>,
    pub preview_scroll: u16,
    pub pending_confirm: Option<PendingConfirmation>,
    pub status_line: String,
    pub busy: bool,
    pub logs: Vec<String>,
    pub selected_idx: usize,
    pub editing: bool,
    pub should_quit: bool,
}

impl TuiApp {
    pub fn new(repo_root: Option<PathBuf>) -> Self {
        let preflight = collect_preflight(repo_root.as_deref());
        let repo_str = preflight
            .repo_checkout
            .as_ref()
            .map(|r| r.root.clone())
            .or_else(|| repo_root.map(|p| p.display().to_string()))
            .unwrap_or_default();

        let mut client = ClientFormState {
            repo_root: repo_str,
            ..Default::default()
        };
        if preflight.os != "macos" {
            client.local_signing_identity.clear();
        }
        let host = HostFormState::default();
        let initial_log = format!(
            "[init] Native TUI ready: {} / {} (zero HTML/WebView)",
            preflight.os, preflight.arch
        );
        Self {
            lang: UiLang::En,
            tab: UiTab::Overview,
            preflight,
            deps: DepsFormState::default(),
            deps_report: None,
            deps_install_res: None,
            client,
            host,
            probe_pair: ProbePairFormState::default(),
            uninstall: UninstallFormState::default(),
            uninstall_result: None,
            last_action: None,
            probe_report: None,
            pairing_open: None,
            pairing_status: None,
            preview_bundle: None,
            preview_scroll: 0,
            pending_confirm: None,
            status_line: "Ready (headless / SSH native TUI)".into(),
            busy: false,
            logs: vec![initial_log],
            selected_idx: 0,
            editing: false,
            should_quit: false,
        }
    }

    pub fn push_log(&mut self, line: String) {
        self.logs.push(line);
        if self.logs.len() > 250 {
            let excess = self.logs.len() - 250;
            self.logs.drain(0..excess);
        }
    }

    fn current_rows(&self) -> Vec<RenderedRow> {
        let mut rows = Vec::new();
        match self.tab {
            UiTab::Overview => {
                rows.push(RenderedRow {
                    id: RowId::OverviewPreflight,
                    label: tr(self.lang, "btn_rescan").into(),
                    value: "[Action]".into(),
                    kind: RowKind::Action(TuiAction::RefreshPreflight),
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewDepsRole,
                    label: "Dependency Role".into(),
                    value: self.deps.role.as_str().into(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewDepsSsh,
                    label: "Deps SSH Target (opt)".into(),
                    value: self.deps.ssh_target.clone(),
                    kind: RowKind::Text { masked: false },
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewDepsPqSsh,
                    label: "Require PQ SSH".into(),
                    value: self.deps.require_pq_ssh.to_string(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewDepsOptional,
                    label: "Include Optional Deps".into(),
                    value: self.deps.include_optional.to_string(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewDepsSudo,
                    label: "sudo -n (Linux)".into(),
                    value: self.deps.execute_sudo.to_string(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewDepsCheckBtn,
                    label: tr(self.lang, "btn_check_deps").into(),
                    value: "[Action]".into(),
                    kind: RowKind::Action(TuiAction::DepsCheck),
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewDepsDryRunBtn,
                    label: tr(self.lang, "btn_dry_run_deps").into(),
                    value: "[Dry-Run]".into(),
                    kind: RowKind::Action(TuiAction::DepsDryRun),
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewDepsInstallBtn,
                    label: tr(self.lang, "btn_install_deps").into(),
                    value: "[Confirm]".into(),
                    kind: RowKind::Action(TuiAction::DepsInstall),
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewGoClient,
                    label: tr(self.lang, "tab_client").into(),
                    value: "[Switch Tab]".into(),
                    kind: RowKind::Action(TuiAction::GoClient),
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewGoHost,
                    label: tr(self.lang, "tab_host").into(),
                    value: "[Switch Tab]".into(),
                    kind: RowKind::Action(TuiAction::GoHost),
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewGoVerify,
                    label: tr(self.lang, "tab_verify").into(),
                    value: "[Switch Tab]".into(),
                    kind: RowKind::Action(TuiAction::GoVerify),
                });
                rows.push(RenderedRow {
                    id: RowId::OverviewGoUninstall,
                    label: tr(self.lang, "tab_uninstall").into(),
                    value: "[Switch Tab]".into(),
                    kind: RowKind::Action(TuiAction::GoUninstall),
                });
            }
            UiTab::Client => {
                rows.push(RenderedRow {
                    id: RowId::ClientSourceKind,
                    label: "Source Mode".into(),
                    value: self.client.source_kind.label(self.lang).into(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::ClientScope,
                    label: "Install Scope".into(),
                    value: match self.client.scope {
                        InstallScope::User => "user",
                        InstallScope::System => "system",
                    }
                    .into(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::ClientAutoDeps,
                    label: "Auto-check/install deps".into(),
                    value: self.client.auto_deps.to_string(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::ClientRepoRoot,
                    label: "Repo Root".into(),
                    value: self.client.repo_root.clone(),
                    kind: RowKind::Text { masked: false },
                });
                rows.push(RenderedRow {
                    id: RowId::ClientArchiveLoc,
                    label: "Archive / HTTPS URL".into(),
                    value: self.client.archive_location.clone(),
                    kind: RowKind::Text { masked: false },
                });
                rows.push(RenderedRow {
                    id: RowId::ClientSha256,
                    label: "SHA-256 (64 hex)".into(),
                    value: self.client.sha256.clone(),
                    kind: RowKind::Text { masked: false },
                });
                rows.push(RenderedRow {
                    id: RowId::ClientSignId,
                    label: "macOS Local Sign SHA-1".into(),
                    value: self.client.local_signing_identity.clone(),
                    kind: RowKind::Text { masked: false },
                });
                rows.push(RenderedRow {
                    id: RowId::ClientAllowUnnotarized,
                    label: "Allow Unnotarized".into(),
                    value: self.client.allow_unnotarized.to_string(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::ClientDryRun,
                    label: tr(self.lang, "btn_dry_run").into(),
                    value: "[Action]".into(),
                    kind: RowKind::Action(TuiAction::ClientDryRun),
                });
                rows.push(RenderedRow {
                    id: RowId::ClientInstall,
                    label: tr(self.lang, "btn_install_client").into(),
                    value: "[Confirm]".into(),
                    kind: RowKind::Action(TuiAction::ClientInstall),
                });
            }
            UiTab::Host => {
                rows.push(RenderedRow {
                    id: RowId::HostDeployMode,
                    label: "Deploy Mode".into(),
                    value: match self.host.deploy_mode {
                        HostDeployMode::Ssh => "PQ SSH",
                        HostDeployMode::Local => "Local",
                    }
                    .into(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::HostSshTarget,
                    label: "SSH Target (user@host)".into(),
                    value: self.host.ssh_target.clone(),
                    kind: RowKind::Text { masked: false },
                });
                rows.push(RenderedRow {
                    id: RowId::HostIp,
                    label: "Host LAN IP".into(),
                    value: self.host.host_ip.clone(),
                    kind: RowKind::Text { masked: false },
                });
                rows.push(RenderedRow {
                    id: RowId::HostControllerIp,
                    label: "Controller IP (allow)".into(),
                    value: self.host.controller_ip.clone(),
                    kind: RowKind::Text { masked: false },
                });
                rows.push(RenderedRow {
                    id: RowId::HostProfile,
                    label: "Profile".into(),
                    value: self.host.profile.as_str().into(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::HostFirewall,
                    label: "Firewall Backend".into(),
                    value: format!("{:?}", self.host.firewall_backend),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::HostAutoDeps,
                    label: "Auto-check/install deps".into(),
                    value: self.host.auto_deps.to_string(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::HostRequirePqSsh,
                    label: "Require PQ SSH".into(),
                    value: self.host.require_pq_ssh.to_string(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::HostExecuteSudo,
                    label: "Execute sudo -n".into(),
                    value: self.host.execute_sudo.to_string(),
                    kind: RowKind::ToggleOrCycle,
                });
                rows.push(RenderedRow {
                    id: RowId::HostToggleAdvancedBtn,
                    label: tr(self.lang, "btn_toggle_advanced").into(),
                    value: if self.host.show_advanced {
                        "[Expanded]"
                    } else {
                        "[Collapsed]"
                    }
                    .into(),
                    kind: RowKind::Action(TuiAction::HostToggleAdvanced),
                });
                if self.host.show_advanced {
                    rows.extend([
                        RenderedRow {
                            id: RowId::HostInstanceName,
                            label: "Instance Slug".into(),
                            value: self.host.instance_name.clone(),
                            kind: RowKind::Text { masked: false },
                        },
                        RenderedRow {
                            id: RowId::HostDisplay,
                            label: "X11 Display".into(),
                            value: self.host.display.clone(),
                            kind: RowKind::Text { masked: false },
                        },
                        RenderedRow {
                            id: RowId::HostResolution,
                            label: "Resolution".into(),
                            value: self.host.resolution.clone(),
                            kind: RowKind::Text { masked: false },
                        },
                        RenderedRow {
                            id: RowId::HostEncoder,
                            label: "Encoder".into(),
                            value: format!("{:?}", self.host.encoder),
                            kind: RowKind::ToggleOrCycle,
                        },
                        RenderedRow {
                            id: RowId::HostRenderDevice,
                            label: "DRM Render Node (opt)".into(),
                            value: self.host.render_device.clone(),
                            kind: RowKind::Text { masked: false },
                        },
                        RenderedRow {
                            id: RowId::HostArchivePath,
                            label: "Host Archive Path (opt)".into(),
                            value: self.host.archive_path.clone(),
                            kind: RowKind::Text { masked: false },
                        },
                        RenderedRow {
                            id: RowId::HostArchiveSha256,
                            label: "Host Archive SHA-256".into(),
                            value: self.host.archive_sha256.clone(),
                            kind: RowKind::Text { masked: false },
                        },
                        RenderedRow {
                            id: RowId::HostFromSource,
                            label: "Build Host from Source".into(),
                            value: self.host.from_source.to_string(),
                            kind: RowKind::ToggleOrCycle,
                        },
                        RenderedRow {
                            id: RowId::HostClipboard,
                            label: "Clipboard".into(),
                            value: self.host.enable_clipboard.to_string(),
                            kind: RowKind::ToggleOrCycle,
                        },
                        RenderedRow {
                            id: RowId::HostFileTransfer,
                            label: "File Transfer".into(),
                            value: self.host.enable_file_transfer.to_string(),
                            kind: RowKind::ToggleOrCycle,
                        },
                        RenderedRow {
                            id: RowId::HostNativeFileClipboard,
                            label: "File Copy/Paste".into(),
                            value: self.host.enable_native_file_clipboard.to_string(),
                            kind: RowKind::ToggleOrCycle,
                        },
                        RenderedRow {
                            id: RowId::HostMic,
                            label: "Mic 48002".into(),
                            value: self.host.enable_mic.to_string(),
                            kind: RowKind::ToggleOrCycle,
                        },
                    ]);
                }
                rows.push(RenderedRow {
                    id: RowId::HostPreview,
                    label: tr(self.lang, "btn_preview").into(),
                    value: "[Modal]".into(),
                    kind: RowKind::Action(TuiAction::HostPreview),
                });
                rows.push(RenderedRow {
                    id: RowId::HostDryRun,
                    label: tr(self.lang, "btn_dry_run").into(),
                    value: "[Action]".into(),
                    kind: RowKind::Action(TuiAction::HostDryRun),
                });
                rows.push(RenderedRow {
                    id: RowId::HostDeploy,
                    label: tr(self.lang, "btn_deploy_host").into(),
                    value: "[Confirm]".into(),
                    kind: RowKind::Action(TuiAction::HostDeploy),
                });
            }
            UiTab::VerifyPair => {
                rows.extend([
                    RenderedRow {
                        id: RowId::VerifyHost,
                        label: "Host LAN IP / Hostname".into(),
                        value: self.probe_pair.host.clone(),
                        kind: RowKind::Text { masked: false },
                    },
                    RenderedRow {
                        id: RowId::VerifySshTarget,
                        label: "SSH Target".into(),
                        value: self.probe_pair.ssh_target.clone(),
                        kind: RowKind::Text { masked: false },
                    },
                    RenderedRow {
                        id: RowId::VerifyControllerIp,
                        label: "Controller IP (47989)".into(),
                        value: self.probe_pair.controller_ip.clone(),
                        kind: RowKind::Text { masked: false },
                    },
                    RenderedRow {
                        id: RowId::VerifyFirewall,
                        label: "Firewall Backend".into(),
                        value: format!("{:?}", self.probe_pair.firewall_backend),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::VerifyRequirePqSsh,
                        label: "Require PQ SSH".into(),
                        value: self.probe_pair.require_pq_ssh.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::VerifyExecuteSudoFw,
                        label: "sudo -n for 47989".into(),
                        value: self.probe_pair.execute_sudo_firewall.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::VerifyProbeBtn,
                        label: tr(self.lang, "btn_probe").into(),
                        value: "[Action]".into(),
                        kind: RowKind::Action(TuiAction::ProbeHost),
                    },
                ]);
                if self
                    .probe_report
                    .as_ref()
                    .is_some_and(|r| r.verdict == HostProbeVerdict::HostNotInstalledOrUnreachable)
                {
                    rows.push(RenderedRow {
                        id: RowId::VerifyDeployMissingBtn,
                        label: tr(self.lang, "btn_deploy_missing").into(),
                        value: "[Jump Host]".into(),
                        kind: RowKind::Action(TuiAction::DeployMissingServer),
                    });
                }
                rows.extend([
                    RenderedRow {
                        id: RowId::VerifyOpenPairingBtn,
                        label: tr(self.lang, "btn_open_pair").into(),
                        value: "[Action]".into(),
                        kind: RowKind::Action(TuiAction::OpenPairing),
                    },
                    RenderedRow {
                        id: RowId::VerifyPin,
                        label: "Moonlight PIN (4 digits)".into(),
                        value: self.probe_pair.pin.clone(),
                        kind: RowKind::Text { masked: false },
                    },
                    RenderedRow {
                        id: RowId::VerifyClientName,
                        label: "Client Name".into(),
                        value: self.probe_pair.client_name.clone(),
                        kind: RowKind::Text { masked: false },
                    },
                    RenderedRow {
                        id: RowId::VerifyAdminUser,
                        label: "Sunshine Admin User".into(),
                        value: self.probe_pair.admin_user.clone(),
                        kind: RowKind::Text { masked: false },
                    },
                    RenderedRow {
                        id: RowId::VerifyAdminPass,
                        label: "Admin Password (ephemeral)".into(),
                        value: "*".repeat(self.probe_pair.admin_pass.chars().count()),
                        kind: RowKind::Text { masked: true },
                    },
                    RenderedRow {
                        id: RowId::VerifyPermClipRead,
                        label: "Perm: clipboard_read".into(),
                        value: self.probe_pair.perm_clipboard_read.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::VerifyPermClipWrite,
                        label: "Perm: clipboard_write".into(),
                        value: self.probe_pair.perm_clipboard_write.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::VerifyPermFileUpload,
                        label: "Perm: file_upload".into(),
                        value: self.probe_pair.perm_file_upload.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::VerifyPermFileDownload,
                        label: "Perm: file_download".into(),
                        value: self.probe_pair.perm_file_download.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::VerifyPermMic,
                        label: "Perm: mic".into(),
                        value: self.probe_pair.perm_mic.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::VerifySubmitPinBtn,
                        label: tr(self.lang, "btn_submit_pin").into(),
                        value: "[Action]".into(),
                        kind: RowKind::Action(TuiAction::SubmitPin),
                    },
                    RenderedRow {
                        id: RowId::VerifyClosePairingBtn,
                        label: tr(self.lang, "btn_close_pair").into(),
                        value: "[Action]".into(),
                        kind: RowKind::Action(TuiAction::ClosePairing),
                    },
                ]);
            }
            UiTab::Uninstall => {
                rows.extend([
                    RenderedRow {
                        id: RowId::UninstallComponent,
                        label: "Component".into(),
                        value: self.uninstall.component.as_str().into(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::UninstallInstanceName,
                        label: "Host Instance Slug".into(),
                        value: self.uninstall.instance_name.clone(),
                        kind: RowKind::Text { masked: false },
                    },
                    RenderedRow {
                        id: RowId::UninstallSshTarget,
                        label: "Remote SSH Target (opt)".into(),
                        value: self.uninstall.ssh_target.clone(),
                        kind: RowKind::Text { masked: false },
                    },
                    RenderedRow {
                        id: RowId::UninstallPurgeConfig,
                        label: "Purge configs/keys/certs".into(),
                        value: self.uninstall.purge_config.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::UninstallRemoveFirewall,
                        label: "Remove SDS firewall rules".into(),
                        value: self.uninstall.remove_firewall.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::UninstallRequirePqSsh,
                        label: "Require PQ SSH".into(),
                        value: self.uninstall.require_pq_ssh.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::UninstallExecuteSudo,
                        label: "Execute sudo -n".into(),
                        value: self.uninstall.execute_sudo.to_string(),
                        kind: RowKind::ToggleOrCycle,
                    },
                    RenderedRow {
                        id: RowId::UninstallDryRunBtn,
                        label: tr(self.lang, "btn_dry_run_uninstall").into(),
                        value: "[Dry-Run]".into(),
                        kind: RowKind::Action(TuiAction::UninstallDryRun),
                    },
                    RenderedRow {
                        id: RowId::UninstallRunBtn,
                        label: tr(self.lang, "btn_uninstall").into(),
                        value: "[Confirm]".into(),
                        kind: RowKind::Action(TuiAction::UninstallRun),
                    },
                ]);
            }
        }
        rows
    }

    fn text_field_mut(&mut self, id: RowId) -> Option<&mut String> {
        match id {
            RowId::OverviewDepsSsh => Some(&mut self.deps.ssh_target),
            RowId::ClientRepoRoot => Some(&mut self.client.repo_root),
            RowId::ClientArchiveLoc => Some(&mut self.client.archive_location),
            RowId::ClientSha256 => Some(&mut self.client.sha256),
            RowId::ClientSignId => Some(&mut self.client.local_signing_identity),
            RowId::HostSshTarget => Some(&mut self.host.ssh_target),
            RowId::HostIp => Some(&mut self.host.host_ip),
            RowId::HostControllerIp => Some(&mut self.host.controller_ip),
            RowId::HostInstanceName => Some(&mut self.host.instance_name),
            RowId::HostDisplay => Some(&mut self.host.display),
            RowId::HostResolution => Some(&mut self.host.resolution),
            RowId::HostRenderDevice => Some(&mut self.host.render_device),
            RowId::HostArchivePath => Some(&mut self.host.archive_path),
            RowId::HostArchiveSha256 => Some(&mut self.host.archive_sha256),
            RowId::VerifyHost => Some(&mut self.probe_pair.host),
            RowId::VerifySshTarget => Some(&mut self.probe_pair.ssh_target),
            RowId::VerifyControllerIp => Some(&mut self.probe_pair.controller_ip),
            RowId::VerifyPin => Some(&mut self.probe_pair.pin),
            RowId::VerifyClientName => Some(&mut self.probe_pair.client_name),
            RowId::VerifyAdminUser => Some(&mut self.probe_pair.admin_user),
            RowId::VerifyAdminPass => Some(&mut self.probe_pair.admin_pass),
            RowId::UninstallInstanceName => Some(&mut self.uninstall.instance_name),
            RowId::UninstallSshTarget => Some(&mut self.uninstall.ssh_target),
            _ => None,
        }
    }

    fn toggle_row(&mut self, id: RowId) {
        match id {
            RowId::OverviewDepsRole => self.deps.role = self.deps.role.cycle(),
            RowId::OverviewDepsPqSsh => self.deps.require_pq_ssh = !self.deps.require_pq_ssh,
            RowId::OverviewDepsOptional => self.deps.include_optional = !self.deps.include_optional,
            RowId::OverviewDepsSudo => self.deps.execute_sudo = !self.deps.execute_sudo,
            RowId::ClientSourceKind => self.client.source_kind = self.client.source_kind.cycle(),
            RowId::ClientScope => {
                self.client.scope = match self.client.scope {
                    InstallScope::User => InstallScope::System,
                    InstallScope::System => InstallScope::User,
                }
            }
            RowId::ClientAutoDeps => self.client.auto_deps = !self.client.auto_deps,
            RowId::ClientAllowUnnotarized => {
                self.client.allow_unnotarized = !self.client.allow_unnotarized
            }
            RowId::HostDeployMode => self.host.deploy_mode = self.host.deploy_mode.toggle(),
            RowId::HostProfile => self.host.profile = cycle_profile(self.host.profile),
            RowId::HostEncoder => self.host.encoder = cycle_encoder(self.host.encoder),
            RowId::HostFirewall => {
                self.host.firewall_backend = cycle_firewall(self.host.firewall_backend)
            }
            RowId::HostAutoDeps => self.host.auto_deps = !self.host.auto_deps,
            RowId::HostFromSource => self.host.from_source = !self.host.from_source,
            RowId::HostClipboard => self.host.enable_clipboard = !self.host.enable_clipboard,
            RowId::HostFileTransfer => {
                self.host.enable_file_transfer = !self.host.enable_file_transfer
            }
            RowId::HostNativeFileClipboard => {
                self.host.enable_native_file_clipboard = !self.host.enable_native_file_clipboard
            }
            RowId::HostMic => self.host.enable_mic = !self.host.enable_mic,
            RowId::HostRequirePqSsh => self.host.require_pq_ssh = !self.host.require_pq_ssh,
            RowId::HostExecuteSudo => self.host.execute_sudo = !self.host.execute_sudo,
            RowId::VerifyFirewall => {
                self.probe_pair.firewall_backend = cycle_firewall(self.probe_pair.firewall_backend)
            }
            RowId::VerifyRequirePqSsh => {
                self.probe_pair.require_pq_ssh = !self.probe_pair.require_pq_ssh
            }
            RowId::VerifyExecuteSudoFw => {
                self.probe_pair.execute_sudo_firewall = !self.probe_pair.execute_sudo_firewall
            }
            RowId::VerifyPermClipRead => {
                self.probe_pair.perm_clipboard_read = !self.probe_pair.perm_clipboard_read
            }
            RowId::VerifyPermClipWrite => {
                self.probe_pair.perm_clipboard_write = !self.probe_pair.perm_clipboard_write
            }
            RowId::VerifyPermFileUpload => {
                self.probe_pair.perm_file_upload = !self.probe_pair.perm_file_upload
            }
            RowId::VerifyPermFileDownload => {
                self.probe_pair.perm_file_download = !self.probe_pair.perm_file_download
            }
            RowId::VerifyPermMic => self.probe_pair.perm_mic = !self.probe_pair.perm_mic,
            RowId::UninstallComponent => {
                self.uninstall.component = self.uninstall.component.cycle()
            }
            RowId::UninstallPurgeConfig => {
                self.uninstall.purge_config = !self.uninstall.purge_config
            }
            RowId::UninstallRemoveFirewall => {
                self.uninstall.remove_firewall = !self.uninstall.remove_firewall
            }
            RowId::UninstallRequirePqSsh => {
                self.uninstall.require_pq_ssh = !self.uninstall.require_pq_ssh
            }
            RowId::UninstallExecuteSudo => {
                self.uninstall.execute_sudo = !self.uninstall.execute_sudo
            }
            _ => {}
        }
    }

    fn clamped_index(&self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            self.selected_idx.min(len - 1)
        }
    }
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self, String> {
        enable_raw_mode().map_err(|e| format!("Failed to enable terminal raw mode: {e}"))?;
        let mut stdout = io::stdout();
        if let Err(e) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(format!("Failed to enter alternate screen: {e}"));
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
            format!("Failed to initialize TUI terminal backend: {e}")
        })?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, Show);
        let _ = self.terminal.show_cursor();
    }
}

enum WorkerMsg {
    Preflight(Box<PreflightReport>),
    DepsCheck(Result<DependencyCheckReport, String>),
    DepsInstall(Result<DependencyInstallResult, String>),
    Action(Result<ActionResult, String>),
    Probe(Result<HostProbeReport, String>),
    OpenPairing(Result<OpenPairingResponse, String>),
    SubmitPin(Result<(bool, Option<String>, Vec<String>, String), String>),
    ClosePairing(Result<ClosePairingResponse, String>),
    Uninstall(Result<UninstallResult, String>),
}

struct WorkerCtx {
    rt: Runtime,
    events_tx: broadcast::Sender<ProgressEvent>,
    events_rx: broadcast::Receiver<ProgressEvent>,
    tx: mpsc::Sender<WorkerMsg>,
    rx: mpsc::Receiver<WorkerMsg>,
    pairing_mgr: Arc<PairingManager>,
    repo_root: Option<PathBuf>,
}

/// Launches the pure native `ratatui` terminal UI for headless / SSH environments.
pub fn run_tui(repo_root: Option<PathBuf>) -> Result<(), String> {
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
        orig_hook(info);
    }));

    let mut guard = TerminalGuard::enter()?;
    let mut app = TuiApp::new(repo_root.clone());

    let rt = Runtime::new().map_err(|e| format!("Failed to start Tokio runtime: {e}"))?;
    let (events_tx, events_rx) = broadcast::channel::<ProgressEvent>(256);
    let (tx, rx) = mpsc::channel::<WorkerMsg>();
    let mut ctx = WorkerCtx {
        rt,
        events_tx,
        events_rx,
        tx,
        rx,
        pairing_mgr: Arc::new(PairingManager::new()),
        repo_root,
    };

    dispatch_deps_check(&mut app, &ctx);

    while !app.should_quit {
        drain_worker_messages(&mut app, &mut ctx);
        guard
            .terminal
            .draw(|f| render_tui_frame(f, &app))
            .map_err(|e| format!("TUI draw error: {e}"))?;

        if event::poll(Duration::from_millis(80)).map_err(|e| format!("TUI poll error: {e}"))? {
            if let Event::Key(key) = event::read().map_err(|e| format!("TUI read error: {e}"))? {
                handle_key_event(&mut app, &ctx, key);
            }
        }
    }

    ctx.pairing_mgr.shutdown_all();
    Ok(())
}

fn drain_worker_messages(app: &mut TuiApp, ctx: &mut WorkerCtx) {
    loop {
        match ctx.events_rx.try_recv() {
            Ok(ev) => {
                app.push_log(format!("[{}:{}] {}", ev.level, ev.step, ev.message));
                app.status_line = format!("[{}] {}", ev.step, ev.message);
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                app.push_log(format!(
                    "[warn] skipped {n} log event(s) during high log throughput"
                ));
            }
            Err(_) => break,
        }
    }
    while let Ok(msg) = ctx.rx.try_recv() {
        app.busy = false;
        match msg {
            WorkerMsg::Preflight(rep) => {
                app.preflight = *rep;
                app.status_line = "Preflight refreshed".into();
                app.push_log("[preflight] Host diagnostics updated".into());
            }
            WorkerMsg::DepsCheck(Ok(rep)) => {
                app.status_line = format!(
                    "Deps ({}): satisfied={}, missing={}",
                    rep.role.as_str(),
                    rep.all_satisfied,
                    rep.missing_required.len()
                );
                app.push_log(format!("[deps] {}", app.status_line));
                app.deps_report = Some(rep);
            }
            WorkerMsg::DepsCheck(Err(e)) => {
                app.status_line = format!("Deps check error: {e}");
                app.push_log(format!("[error] {e}"));
            }
            WorkerMsg::DepsInstall(Ok(res)) => {
                app.status_line = res.summary.clone();
                app.push_log(format!("[deps] {}", res.summary));
                let latest = res.after.clone().unwrap_or_else(|| res.before.clone());
                app.deps_report = Some(latest);
                app.deps_install_res = Some(res);
            }
            WorkerMsg::DepsInstall(Err(e)) => {
                app.status_line = format!("Deps install error: {e}");
                app.push_log(format!("[error] {e}"));
            }
            WorkerMsg::Action(Ok(res)) => {
                app.status_line = res.summary.clone();
                app.push_log(format!("[action] {}", res.summary));
                if let Some(p) = &res.probe_report {
                    app.probe_report = Some(p.clone());
                }
                app.last_action = Some(res);
            }
            WorkerMsg::Action(Err(e)) => {
                app.status_line = format!("Action error: {e}");
                app.push_log(format!("[error] {e}"));
            }
            WorkerMsg::Probe(Ok(rep)) => {
                let summary = format!(
                    "{:?} | pq_tls13={} | classical_rejected={} | 47989_open={} | 48010_open={}",
                    rep.verdict,
                    rep.pq_tls13_ok,
                    rep.classical_kex_rejected,
                    rep.port_47989_http_open,
                    rep.port_48010_rtsp_open
                );
                app.status_line = format!("Probe: {summary}");
                app.push_log(format!("[probe] {summary}"));
                app.probe_report = Some(rep);
            }
            WorkerMsg::Probe(Err(e)) => {
                app.status_line = format!("Probe error: {e}");
                app.push_log(format!("[error] {e}"));
            }
            WorkerMsg::OpenPairing(Ok(open)) => {
                app.pairing_status = Some(format!(
                    "Tunnel 127.0.0.1:{} ready | SHA-256={} ({})",
                    open.local_tunnel_port,
                    open.cert_sha256_hex,
                    open.open_firewall_commands.join("; ")
                ));
                app.pairing_open = Some(open);
                app.status_line = "Pairing tunnel open; enter PIN + admin creds".into();
            }
            WorkerMsg::OpenPairing(Err(e)) => {
                app.status_line = format!("Open pairing error: {e}");
                app.push_log(format!("[error] {e}"));
            }
            WorkerMsg::SubmitPin(Ok((paired, uuid, perms, message))) => {
                app.probe_pair.clear_secrets();
                app.pairing_status = Some(format!(
                    "paired={paired} | uuid={uuid:?} | perms={perms:?} | {message}"
                ));
                app.status_line = message;
            }
            WorkerMsg::SubmitPin(Err(e)) => {
                app.probe_pair.clear_secrets();
                app.status_line = format!("Submit PIN error: {e}");
                app.push_log(format!("[error] {e}"));
            }
            WorkerMsg::ClosePairing(Ok(close)) => {
                app.pairing_open = None;
                app.pairing_status = Some(format!(
                    "Closed tunnel | 47989_closed={}",
                    close.firewall_closed_automatically
                ));
                if let Some(pr) = close.post_lockdown_probe {
                    app.probe_report = Some(pr);
                }
                app.status_line = "Pairing lockdown finalized".into();
            }
            WorkerMsg::ClosePairing(Err(e)) => {
                app.status_line = format!("Close pairing error: {e}");
                app.push_log(format!("[error] {e}"));
            }
            WorkerMsg::Uninstall(Ok(res)) => {
                app.status_line = res.summary.clone();
                app.push_log(format!("[uninstall] {}", res.summary));
                app.uninstall_result = Some(res);
            }
            WorkerMsg::Uninstall(Err(e)) => {
                app.status_line = format!("Uninstall error: {e}");
                app.push_log(format!("[error] {e}"));
            }
        }
    }
}

fn handle_key_event(app: &mut TuiApp, ctx: &WorkerCtx, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return;
    }

    if app.preview_bundle.is_some() {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                app.preview_bundle = None;
                app.preview_scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.preview_scroll = app.preview_scroll.saturating_add(1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.preview_scroll = app.preview_scroll.saturating_sub(1);
            }
            KeyCode::PageDown => {
                app.preview_scroll = app.preview_scroll.saturating_add(10);
            }
            KeyCode::PageUp => {
                app.preview_scroll = app.preview_scroll.saturating_sub(10);
            }
            _ => {}
        }
        return;
    }

    if let Some(confirm) = app.pending_confirm {
        match key.code {
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.pending_confirm = None;
                match confirm {
                    PendingConfirmation::InstallDeps => dispatch_deps_install(app, ctx, false),
                    PendingConfirmation::InstallClient => {
                        dispatch_client_install(app, ctx, false);
                    }
                    PendingConfirmation::InstallHostLocal => dispatch_host_local(app, ctx, false),
                    PendingConfirmation::DeployHostSsh => dispatch_host_ssh(app, ctx, false),
                    PendingConfirmation::Uninstall | PendingConfirmation::UninstallPurge => {
                        dispatch_uninstall(app, ctx, false);
                    }
                }
            }
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                app.pending_confirm = None;
                app.status_line = "Cancelled".into();
            }
            _ => {}
        }
        return;
    }

    let rows = app.current_rows();
    let idx = app.clamped_index(rows.len());

    if app.editing {
        if let Some(row) = rows.get(idx) {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => {
                    app.editing = false;
                }
                KeyCode::Backspace => {
                    if let Some(buf) = app.text_field_mut(row.id) {
                        buf.pop();
                    }
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if let Some(buf) = app.text_field_mut(row.id) {
                        buf.push(c);
                    }
                }
                _ => {}
            }
        } else {
            app.editing = false;
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::F(2) => app.lang = app.lang.toggle(),
        KeyCode::Tab | KeyCode::Right => {
            app.tab = app.tab.next();
            app.selected_idx = 0;
        }
        KeyCode::BackTab | KeyCode::Left => {
            app.tab = app.tab.prev();
            app.selected_idx = 0;
        }
        KeyCode::Down | KeyCode::Char('j') if !rows.is_empty() => {
            app.selected_idx = (idx + 1) % rows.len();
        }
        KeyCode::Up | KeyCode::Char('k') if !rows.is_empty() => {
            app.selected_idx = (idx + rows.len() - 1) % rows.len();
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if let Some(row) = rows.get(idx) {
                match row.kind {
                    RowKind::Text { .. } => {
                        app.editing = true;
                    }
                    RowKind::ToggleOrCycle => {
                        app.toggle_row(row.id);
                    }
                    RowKind::Action(action) => run_tui_action(app, ctx, action),
                }
            }
        }
        KeyCode::Char(d) if matches!(d, '1' | '2' | '3' | '4' | '5') => {
            app.tab = match d {
                '1' => UiTab::Overview,
                '2' => UiTab::Client,
                '3' => UiTab::Host,
                '4' => UiTab::VerifyPair,
                _ => UiTab::Uninstall,
            };
            app.selected_idx = 0;
        }
        _ => {}
    }
}

fn run_tui_action(app: &mut TuiApp, ctx: &WorkerCtx, action: TuiAction) {
    match action {
        TuiAction::GoClient => {
            app.tab = UiTab::Client;
            app.selected_idx = 0;
        }
        TuiAction::GoHost => {
            app.tab = UiTab::Host;
            app.selected_idx = 0;
        }
        TuiAction::GoVerify => {
            app.tab = UiTab::VerifyPair;
            app.selected_idx = 0;
        }
        TuiAction::GoUninstall => {
            app.tab = UiTab::Uninstall;
            app.selected_idx = 0;
        }
        TuiAction::RefreshPreflight => {
            if app.busy {
                return;
            }
            app.busy = true;
            let root = ctx.repo_root.clone();
            let tx = ctx.tx.clone();
            ctx.rt.spawn_blocking(move || {
                let rep = collect_preflight(root.as_deref());
                let _ = tx.send(WorkerMsg::Preflight(Box::new(rep)));
            });
        }
        TuiAction::DepsCheck => dispatch_deps_check(app, ctx),
        TuiAction::DepsDryRun => dispatch_deps_install(app, ctx, true),
        TuiAction::DepsInstall => {
            if let Err(e) = app.deps.to_install_request(false) {
                app.status_line = e.clone();
                app.push_log(format!("[validation] {e}"));
            } else {
                app.pending_confirm = Some(PendingConfirmation::InstallDeps);
            }
        }
        TuiAction::ClientDryRun => dispatch_client_install(app, ctx, true),
        TuiAction::ClientInstall => {
            if let Err(e) = app.client.to_client_install_request(false) {
                app.status_line = e.clone();
                app.push_log(format!("[validation] {e}"));
            } else {
                app.pending_confirm = Some(PendingConfirmation::InstallClient);
            }
        }
        TuiAction::HostToggleAdvanced => {
            app.host.show_advanced = !app.host.show_advanced;
        }
        TuiAction::HostPreview => match app.host.to_host_config_params() {
            Ok(params) => match generate_host_bundle(&params) {
                Ok(b) => {
                    app.preview_scroll = 0;
                    app.preview_bundle = Some(b);
                }
                Err(e) => {
                    app.status_line = e.clone();
                    app.push_log(format!("[error] {e}"));
                }
            },
            Err(e) => {
                app.status_line = e.clone();
                app.push_log(format!("[validation] {e}"));
            }
        },
        TuiAction::HostDryRun => match app.host.deploy_mode {
            HostDeployMode::Local => dispatch_host_local(app, ctx, true),
            HostDeployMode::Ssh => dispatch_host_ssh(app, ctx, true),
        },
        TuiAction::HostDeploy => match app.host.deploy_mode {
            HostDeployMode::Local => {
                let root = ctx.repo_root.as_ref().map(|p| p.display().to_string());
                if let Err(e) = app.host.to_local_host_request(false, root) {
                    app.status_line = e.clone();
                    app.push_log(format!("[validation] {e}"));
                } else {
                    app.pending_confirm = Some(PendingConfirmation::InstallHostLocal);
                }
            }
            HostDeployMode::Ssh => {
                if let Err(e) = app.host.to_ssh_deploy_request(false) {
                    app.status_line = e.clone();
                    app.push_log(format!("[validation] {e}"));
                } else {
                    app.pending_confirm = Some(PendingConfirmation::DeployHostSsh);
                }
            }
        },
        TuiAction::ProbeHost => dispatch_probe(app, ctx),
        TuiAction::DeployMissingServer => {
            app.host.deploy_mode = HostDeployMode::Ssh;
            if let Some(ref rep) = app.probe_report {
                app.host.host_ip = rep.host.clone();
            }
            if !app.probe_pair.ssh_target.trim().is_empty() {
                app.host.ssh_target = app.probe_pair.ssh_target.clone();
            }
            app.tab = UiTab::Host;
            app.selected_idx = 0;
        }
        TuiAction::OpenPairing => dispatch_open_pairing(app, ctx),
        TuiAction::SubmitPin => dispatch_submit_pin(app, ctx),
        TuiAction::ClosePairing => dispatch_close_pairing(app, ctx),
        TuiAction::UninstallDryRun => dispatch_uninstall(app, ctx, true),
        TuiAction::UninstallRun => {
            if let Err(e) = app.uninstall.to_uninstall_request(false) {
                app.status_line = e.clone();
                app.push_log(format!("[validation] {e}"));
            } else {
                app.pending_confirm = Some(if app.uninstall.purge_config {
                    PendingConfirmation::UninstallPurge
                } else {
                    PendingConfirmation::Uninstall
                });
            }
        }
    }
}

fn dispatch_deps_check(app: &mut TuiApp, ctx: &WorkerCtx) {
    if app.busy {
        return;
    }
    let req = match app.deps.to_check_request() {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.busy = true;
    app.status_line = "Checking dependencies...".into();
    let tx = ctx.tx.clone();
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::DepsCheck(check_dependencies(&req).await));
    });
}

fn dispatch_deps_install(app: &mut TuiApp, ctx: &WorkerCtx, dry_run: bool) {
    if app.busy {
        return;
    }
    let req = match app.deps.to_install_request(dry_run) {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.busy = true;
    let tx = ctx.tx.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::DepsInstall(
            install_missing_dependencies(&req, &emit).await,
        ));
    });
}

fn dispatch_client_install(app: &mut TuiApp, ctx: &WorkerCtx, dry_run: bool) {
    if app.busy {
        return;
    }
    let req = match app.client.to_client_install_request(dry_run) {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.busy = true;
    let tx = ctx.tx.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::Action(install_client(&req, &emit).await));
    });
}

fn dispatch_host_local(app: &mut TuiApp, ctx: &WorkerCtx, dry_run: bool) {
    if app.busy {
        return;
    }
    let root = ctx.repo_root.as_ref().map(|p| p.display().to_string());
    let req = match app.host.to_local_host_request(dry_run, root) {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.busy = true;
    let tx = ctx.tx.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::Action(install_host_local(&req, &emit).await));
    });
}

fn dispatch_host_ssh(app: &mut TuiApp, ctx: &WorkerCtx, dry_run: bool) {
    if app.busy {
        return;
    }
    let req = match app.host.to_ssh_deploy_request(dry_run) {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.busy = true;
    let tx = ctx.tx.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::Action(deploy_host_ssh(&req, &emit).await));
    });
}

fn dispatch_probe(app: &mut TuiApp, ctx: &WorkerCtx) {
    if app.busy {
        return;
    }
    let req = match app.probe_pair.to_probe_request() {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.busy = true;
    let tx = ctx.tx.clone();
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::Probe(probe_host(&req).await));
    });
}

fn dispatch_open_pairing(app: &mut TuiApp, ctx: &WorkerCtx) {
    if app.busy {
        return;
    }
    let req = match app.probe_pair.to_open_pairing_request(false) {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.busy = true;
    let mgr = ctx.pairing_mgr.clone();
    let tx = ctx.tx.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::OpenPairing(
            open_pairing_session(&mgr, &req, &emit).await,
        ));
    });
}

fn dispatch_submit_pin(app: &mut TuiApp, ctx: &WorkerCtx) {
    if app.busy {
        return;
    }
    let sid = app
        .pairing_open
        .as_ref()
        .map(|o| o.session_id.clone())
        .unwrap_or_default();
    let req = match app.probe_pair.to_submit_pin_request(&sid) {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.probe_pair.clear_secrets();
    app.busy = true;
    let mgr = ctx.pairing_mgr.clone();
    let tx = ctx.tx.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    ctx.rt.spawn(async move {
        let res = submit_pairing_pin(&mgr, &req, &emit)
            .await
            .map(|r| (r.paired, r.client_uuid, r.applied_permissions, r.message));
        let _ = tx.send(WorkerMsg::SubmitPin(res));
    });
}

fn dispatch_close_pairing(app: &mut TuiApp, ctx: &WorkerCtx) {
    if app.busy {
        return;
    }
    let Some(open) = &app.pairing_open else {
        app.status_line = "No active pairing session to close".into();
        app.push_log("[pairing] No active pairing session open".into());
        return;
    };
    let req = ClosePairingRequest {
        session_id: open.session_id.clone(),
        execute_sudo_firewall: app.probe_pair.execute_sudo_firewall,
        dry_run: false,
    };
    app.busy = true;
    let mgr = ctx.pairing_mgr.clone();
    let tx = ctx.tx.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::ClosePairing(
            close_pairing_session(&mgr, &req, &emit).await,
        ));
    });
}

fn dispatch_uninstall(app: &mut TuiApp, ctx: &WorkerCtx, dry_run: bool) {
    if app.busy {
        return;
    }
    let req = match app.uninstall.to_uninstall_request(dry_run) {
        Ok(r) => r,
        Err(e) => {
            app.status_line = e.clone();
            app.push_log(format!("[validation] {e}"));
            return;
        }
    };
    app.busy = true;
    let tx = ctx.tx.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    ctx.rt.spawn(async move {
        let _ = tx.send(WorkerMsg::Uninstall(run_uninstall(&req, &emit).await));
    });
}

/// Renders one complete native terminal UI frame (also callable cleanly from headless tests).
pub fn render_tui_frame(frame: &mut Frame, app: &TuiApp) {
    let area = frame.area();
    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(7),
            Constraint::Length(2),
        ])
        .split(area);

    let title_str = format!(
        " {} [{}] | {} ",
        tr(app.lang, "app_title"),
        if app.busy { "BUSY..." } else { "IDLE" },
        app.status_line
    );
    let header = Paragraph::new(Line::from(vec![Span::styled(
        tr(app.lang, "topology"),
        Style::default().fg(Color::Gray),
    )]))
    .block(Block::default().borders(Borders::ALL).title(title_str))
    .wrap(Wrap { trim: true });
    frame.render_widget(header, root_chunks[0]);

    let tab_titles: Vec<Line> = UiTab::all()
        .iter()
        .map(|t| {
            let k = match t {
                UiTab::Overview => "tab_overview",
                UiTab::Client => "tab_client",
                UiTab::Host => "tab_host",
                UiTab::VerifyPair => "tab_verify",
                UiTab::Uninstall => "tab_uninstall",
            };
            Line::from(tr(app.lang, k))
        })
        .collect();
    let tabs = Tabs::new(tab_titles)
        .select(app.tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(tr(app.lang, "unsigned_note")),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, root_chunks[1]);

    render_body(frame, app, root_chunks[2]);
    render_logs(frame, app, root_chunks[3]);

    let help_text = if app.editing {
        "EDIT MODE: type text | Backspace: erase | Enter / Esc: finish editing"
    } else {
        "Tab/1-5: switch tab | Up/Down: select | Enter/Space: edit/toggle/run | F2: RU/EN | q: quit"
    };
    let footer = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::TOP));
    frame.render_widget(footer, root_chunks[4]);

    if let Some(bundle) = &app.preview_bundle {
        render_preview_modal(frame, bundle, app.preview_scroll);
    } else if let Some(confirm) = app.pending_confirm {
        render_confirm_modal(frame, app, confirm);
    }
}

fn render_body(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(area);

    let rows = app.current_rows();
    let idx = app.clamped_index(rows.len());
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let selected = i == idx;
            let cursor = if selected { "> " } else { "  " };
            let edit_suffix = if selected && app.editing { "_" } else { "" };
            let line = match row.kind {
                RowKind::Action(_) => format!("{cursor}[ {} ] {}", row.label, row.value),
                RowKind::Text { .. } | RowKind::ToggleOrCycle => {
                    format!("{cursor}{}: {}{edit_suffix}", row.label, row.value)
                }
            };
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(line)).style(style)
        })
        .collect();

    let form_list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Controls & Form "),
    );
    let mut list_state = ListState::default();
    if !rows.is_empty() {
        list_state.select(Some(idx));
    }
    frame.render_stateful_widget(form_list, cols[0], &mut list_state);

    let detail_text = build_detail_text(app);
    let details = Paragraph::new(detail_text).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Preflight / Deps / Details "),
    );
    frame.render_widget(details, cols[1]);
}

fn build_detail_text(app: &TuiApp) -> String {
    let mut out = String::new();
    match app.tab {
        UiTab::Overview => {
            let p = &app.preflight;
            out.push_str(&format!(
                "OS: {} ({}) | Version: {}\nSSH: {:?} | PQ KEX: {}\nCargo: {} ({:?})\nRepo: {}\n",
                p.os,
                p.arch,
                p.os_version,
                p.ssh_version,
                p.pq_ssh_supported,
                p.cargo_available,
                p.rustc_version,
                p.repo_checkout
                    .as_ref()
                    .map_or("not found", |r| r.root.as_str()),
            ));
            for w in &p.warnings {
                let (title, detail) = match app.lang {
                    UiLang::Ru => (&w.title_ru, &w.detail_ru),
                    UiLang::En => (&w.title_en, &w.detail_en),
                };
                out.push_str(&format!("\n! [{}] {}: {}\n", w.severity, title, detail));
            }
            if let Some(ref rep) = app.deps_report {
                out.push_str(&format!(
                    "\n--- Deps ({}, PM={}) satisfied={} ---\n",
                    rep.role.as_str(),
                    rep.package_manager.as_str(),
                    rep.all_satisfied
                ));
                for it in &rep.items {
                    let st = if it.present {
                        "OK"
                    } else if it.required {
                        "MISSING"
                    } else {
                        "OPT"
                    };
                    out.push_str(&format!("[{st}] {}\n", it.name));
                }
            }
            if let Some(ref res) = app.deps_install_res {
                out.push_str(&format!("\nDeps Install: {}\n", res.summary));
            }
        }
        UiTab::Client | UiTab::Host => {
            if app.tab == UiTab::Host {
                out.push_str(tr(app.lang, "host_runtime_note"));
                out.push_str("\n\n");
            }
            if let Some(res) = &app.last_action {
                out.push_str(&format!("OK={} | DryRun={}\n", res.ok, res.dry_run));
                out.push_str(&format!("Summary: {}\n", res.summary));
                if let Some(path) = &res.installed_path {
                    out.push_str(&format!("Installed: {path}\n"));
                }
                if !res.elevated_commands.is_empty() {
                    out.push_str("\nElevated Commands:\n");
                    for c in &res.elevated_commands {
                        out.push_str(&format!("  {c}\n"));
                    }
                }
            } else {
                out.push_str(
                    "Select Dry-Run Plan first to inspect commands and files before applying.",
                );
            }
        }
        UiTab::VerifyPair => {
            if let Some(st) = &app.pairing_status {
                out.push_str(&format!("Pairing: {st}\n\n"));
            }
            if let Some(open) = &app.pairing_open {
                out.push_str(&format!(
                    "Active Session: {}\nLocal Port: 127.0.0.1:{}\nCert FP: {}\n\n",
                    open.session_id, open.local_tunnel_port, open.cert_sha256_hex
                ));
            }
            if let Some(pr) = &app.probe_report {
                out.push_str(&format!(
                    "Verdict: {:?}\nPQ TLS 1.3={} (kx={:?}) | classical_rejected={} | 47989_open={} | 48010_open={}\n",
                    pr.verdict,
                    pr.pq_tls13_ok,
                    pr.negotiated_kx_group,
                    pr.classical_kex_rejected,
                    pr.port_47989_http_open,
                    pr.port_48010_rtsp_open
                ));
                for f in &pr.findings {
                    let msg = match app.lang {
                        UiLang::Ru => &f.message_ru,
                        UiLang::En => &f.message_en,
                    };
                    out.push_str(&format!("- [{}] {}: {msg}\n", f.severity, f.code));
                }
            } else {
                out.push_str("Run Probe Host first to check PQ TLS 1.3 (X25519MLKEM768), classical rejection, 47989 lockdown, and RTSP 48010.");
            }
        }
        UiTab::Uninstall => {
            if let Some(res) = &app.uninstall_result {
                out.push_str(&format!(
                    "OK={} | DryRun={} | VerifiedClean={}\nSummary: {}\n",
                    res.ok, res.dry_run, res.verified_clean, res.summary
                ));
                if !res.removed_paths.is_empty() {
                    out.push_str("\nRemoved:\n");
                    for p in &res.removed_paths {
                        out.push_str(&format!("  {p}\n"));
                    }
                }
                if !res.remaining_artifacts.is_empty() {
                    out.push_str("\nPlanned / Remaining:\n");
                    for p in &res.remaining_artifacts {
                        out.push_str(&format!("  {p}\n"));
                    }
                }
                if !res.elevated_commands.is_empty() {
                    out.push_str("\nElevated Commands:\n");
                    for c in &res.elevated_commands {
                        out.push_str(&format!("  {c}\n"));
                    }
                }
            } else {
                out.push_str(
                    "Run Dry-Run Uninstall first to preview allowlisted files & firewall rules. Config/keys stay unless Purge is explicitly enabled.",
                );
            }
        }
    }
    if out.is_empty() {
        out.push_str(current_os());
    }
    out
}

fn render_logs(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let max_lines = area.height.saturating_sub(2) as usize;
    let start = app.logs.len().saturating_sub(max_lines);
    let text = app.logs[start..].join("\n");
    let block = Block::default()
        .borders(Borders::ALL)
        .title(tr(app.lang, "logs_title"));
    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn render_confirm_modal(frame: &mut Frame, app: &TuiApp, confirm: PendingConfirmation) {
    let area = centered_rect(72, 34, frame.area());
    frame.render_widget(Clear, area);
    let desc = match (confirm, app.lang) {
        (PendingConfirmation::InstallDeps, UiLang::Ru) => {
            "Автоматически установить недостающие зависимости из белого списка"
        }
        (PendingConfirmation::InstallDeps, UiLang::En) => {
            "Auto-install missing allowlisted dependencies"
        }
        (PendingConfirmation::InstallClient, UiLang::Ru) => "Установить клиент Moonlight SDS",
        (PendingConfirmation::InstallClient, UiLang::En) => "Install SDS Client cleanly",
        (PendingConfirmation::InstallHostLocal, UiLang::Ru) => {
            "Установить / обновить локальный хост SDS"
        }
        (PendingConfirmation::InstallHostLocal, UiLang::En) => "Install / update local SDS Host",
        (PendingConfirmation::DeployHostSsh, UiLang::Ru) => {
            "Развернуть конфигурацию хоста SDS по PQ SSH"
        }
        (PendingConfirmation::DeployHostSsh, UiLang::En) => "Deploy SDS Host config over PQ SSH",
        (PendingConfirmation::Uninstall, UiLang::Ru) => {
            "Удалить бинарники и юниты SDS (конфиги сохраняются)"
        }
        (PendingConfirmation::Uninstall, UiLang::En) => {
            "Uninstall SDS binaries & units (configs preserved)"
        }
        (PendingConfirmation::UninstallPurge, UiLang::Ru) => {
            "ВНИМАНИЕ: удалить SDS и полностью очистить все конфиги, сертификаты и правила файрвола!"
        }
        (PendingConfirmation::UninstallPurge, UiLang::En) => {
            "WARNING: Uninstall SDS AND purge all configs, certs & firewall rules!"
        }
    };
    let text = match app.lang {
        UiLang::Ru => format!(
            "{} {desc}\n\nНажмите [Enter] или [y] для подтверждения, или [Esc] / [n] для отмены.",
            tr(app.lang, "confirm_title")
        ),
        UiLang::En => format!(
            "{} {desc}\n\nPress [Enter] or [y] to proceed, or [Esc] / [n] to cancel.",
            tr(app.lang, "confirm_title")
        ),
    };
    let title = match app.lang {
        UiLang::Ru => " Подтверждение ",
        UiLang::En => " Confirmation ",
    };
    let modal = Paragraph::new(text)
        .style(Style::default().fg(Color::Yellow))
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(modal, area);
}

fn render_preview_modal(frame: &mut Frame, bundle: &GeneratedBundle, scroll: u16) {
    let area = centered_rect(86, 80, frame.area());
    frame.render_widget(Clear, area);
    let mut text = format!(
        "Profile: {} | Instance: {} | Controller: {}\nFirewall ({}):\n{}\n",
        bundle.profile.as_str(),
        bundle.instance_name,
        bundle.controller_ip,
        bundle.firewall.backend,
        bundle.firewall.setup_streaming.join("\n"),
    );
    for file in bundle.files.values() {
        text.push_str(&format!(
            "\n--- {} ({}) ---\n{}\n",
            file.rel_path, file.target_hint, file.content
        ));
    }
    let modal = Paragraph::new(text)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Preview Configs (Up/Down/PgUp/PgDn scroll, Esc close) "),
        );
    frame.render_widget(modal, area);
}

fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(vert[1])[1]
}
