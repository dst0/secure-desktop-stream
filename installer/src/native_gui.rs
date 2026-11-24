//! Pure native software-rendered GUI (`floem 0.2` + `tiny-skia` / `softbuffer`).
//! Zero HTML, zero WebView, zero localhost HTTP server.

use crate::config_gen::{generate_host_bundle, GeneratedBundle, HostProfileKind};
use crate::deps::{
    check_dependencies, install_missing_dependencies, DependencyCheckReport,
    DependencyInstallResult, DependencyRole,
};
use crate::installer_ops::{
    close_pairing_session, deploy_host_ssh, install_client, install_host_local,
    open_pairing_session, submit_pairing_pin, ActionResult, ClientInstallRequest, ClientSource,
    ClosePairingRequest, ClosePairingResponse, LocalHostInstallRequest, OpenPairingResponse,
    PairingManager, ProgressEmitter, ProgressEvent, SshDeployRequest, SubmitPairingPinResponse,
};
use crate::platform::{collect_preflight, current_os, PreflightReport};
use crate::probe::{probe_host, HostProbeReport, HostProbeVerdict};
use crate::ui_state::{
    cycle_encoder, cycle_firewall, cycle_profile, tr, ClientFormState, ClientSourceKind,
    DepsFormState, HostDeployMode, HostFormState, PendingConfirmation, ProbePairFormState, UiLang,
    UiTab, UiTheme, UninstallFormState,
};
use crate::uninstall::{run_uninstall, UninstallComponent, UninstallResult};
use floem::ext_event::{create_ext_action, create_signal_from_channel};
use floem::kurbo::Size;
use floem::peniko::Color;
use floem::reactive::{create_effect, RwSignal, Scope, SignalGet, SignalUpdate};
use floem::style::CursorStyle;
use floem::views::{
    button, container, dyn_container, empty, h_stack, label, scroll, text_input, v_stack, Checkbox,
    Decorators,
};
use floem::window::WindowConfig;
use floem::{AppEvent, Application, IntoView};
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use tokio::sync::broadcast;

#[derive(Clone, Copy)]
struct Palette {
    bg: Color,
    surface: Color,
    surface_alt: Color,
    border: Color,
    text: Color,
    muted: Color,
    brand: Color,
    brand_fg: Color,
    warn: Color,
}

fn palette(theme: UiTheme) -> Palette {
    match theme {
        UiTheme::Dark => Palette {
            bg: Color::rgb8(15, 20, 27),
            surface: Color::rgb8(24, 32, 44),
            surface_alt: Color::rgb8(32, 42, 56),
            border: Color::rgb8(54, 67, 86),
            text: Color::rgb8(230, 237, 245),
            muted: Color::rgb8(156, 163, 175),
            brand: Color::rgb8(59, 130, 246),
            brand_fg: Color::rgb8(255, 255, 255),
            warn: Color::rgb8(251, 191, 36),
        },
        UiTheme::Light => Palette {
            bg: Color::rgb8(244, 246, 249),
            surface: Color::rgb8(255, 255, 255),
            surface_alt: Color::rgb8(234, 239, 246),
            border: Color::rgb8(209, 213, 219),
            text: Color::rgb8(17, 24, 39),
            muted: Color::rgb8(75, 85, 99),
            brand: Color::rgb8(29, 78, 216),
            brand_fg: Color::rgb8(255, 255, 255),
            warn: Color::rgb8(180, 83, 9),
        },
    }
}

#[derive(Clone)]
struct GuiCtx {
    root_scope: Scope,
    rt: Arc<Runtime>,
    repo_root: Option<PathBuf>,
    pairing_mgr: PairingManager,
    events_tx: broadcast::Sender<ProgressEvent>,
    log_buffer: Arc<Mutex<Vec<String>>>,
    log_bump_tx: crossbeam_channel::Sender<()>,
    tab: RwSignal<UiTab>,
    lang: RwSignal<UiLang>,
    theme: RwSignal<UiTheme>,
    busy_count: RwSignal<usize>,
    status_line: RwSignal<String>,
    preflight: RwSignal<Option<PreflightReport>>,
    deps_report: RwSignal<Option<DependencyCheckReport>>,
    deps_install_res: RwSignal<Option<DependencyInstallResult>>,
    client_action: RwSignal<Option<ActionResult>>,
    host_action: RwSignal<Option<ActionResult>>,
    probe_report: RwSignal<Option<HostProbeReport>>,
    pairing_open: RwSignal<Option<OpenPairingResponse>>,
    pairing_status: RwSignal<Option<String>>,
    uninstall_result: RwSignal<Option<UninstallResult>>,
    preview_bundle: RwSignal<Option<GeneratedBundle>>,
    pending_confirm: RwSignal<Option<PendingConfirmation>>,
    log_text: RwSignal<String>,

    // Dependency checker form signals
    d_role: RwSignal<DependencyRole>,
    d_ssh: RwSignal<String>,
    d_pq_ssh: RwSignal<bool>,
    d_optional: RwSignal<bool>,
    d_sudo: RwSignal<bool>,

    // Client form signals
    c_source: RwSignal<ClientSourceKind>,
    c_scope_system: RwSignal<bool>,
    c_repo_root: RwSignal<String>,
    c_archive_loc: RwSignal<String>,
    c_sha256: RwSignal<String>,
    c_sign_id: RwSignal<String>,
    c_allow_unnotarized: RwSignal<bool>,
    c_auto_deps: RwSignal<bool>,

    // Host form signals (install-time primary + collapsible overrides)
    h_mode: RwSignal<HostDeployMode>,
    h_ssh: RwSignal<String>,
    h_ip: RwSignal<String>,
    h_ctrl_ip: RwSignal<String>,
    h_profile: RwSignal<HostProfileKind>,
    h_instance: RwSignal<String>,
    h_display: RwSignal<String>,
    h_resolution: RwSignal<String>,
    h_encoder: RwSignal<crate::config_gen::EncoderKind>,
    h_fw: RwSignal<crate::config_gen::FirewallBackend>,
    h_render_dev: RwSignal<String>,
    h_archive_path: RwSignal<String>,
    h_archive_sha256: RwSignal<String>,
    h_from_source: RwSignal<bool>,
    h_clip: RwSignal<bool>,
    h_files: RwSignal<bool>,
    h_file_clip: RwSignal<bool>,
    h_mic: RwSignal<bool>,
    h_pq_ssh: RwSignal<bool>,
    h_sudo: RwSignal<bool>,
    h_auto_deps: RwSignal<bool>,
    h_show_advanced: RwSignal<bool>,

    // Probe & pairing form signals
    p_host: RwSignal<String>,
    p_ssh: RwSignal<String>,
    p_pq_ssh: RwSignal<bool>,
    p_ctrl_ip: RwSignal<String>,
    p_fw: RwSignal<crate::config_gen::FirewallBackend>,
    p_sudo_fw: RwSignal<bool>,
    p_pin: RwSignal<String>,
    p_client_name: RwSignal<String>,
    p_admin_user: RwSignal<String>,
    p_admin_pass: RwSignal<String>,
    p_perm_cr: RwSignal<bool>,
    p_perm_cw: RwSignal<bool>,
    p_perm_fu: RwSignal<bool>,
    p_perm_fd: RwSignal<bool>,
    p_perm_mic: RwSignal<bool>,

    // Uninstall form signals
    u_component: RwSignal<UninstallComponent>,
    u_instance: RwSignal<String>,
    u_ssh: RwSignal<String>,
    u_pq_ssh: RwSignal<bool>,
    u_purge_config: RwSignal<bool>,
    u_remove_firewall: RwSignal<bool>,
    u_sudo: RwSignal<bool>,
}

impl GuiCtx {
    fn snapshot_deps_form(&self) -> DepsFormState {
        DepsFormState {
            role: self.d_role.get_untracked(),
            ssh_target: self.d_ssh.get_untracked(),
            require_pq_ssh: self.d_pq_ssh.get_untracked(),
            include_optional: self.d_optional.get_untracked(),
            execute_sudo: self.d_sudo.get_untracked(),
        }
    }

    fn snapshot_client_form(&self) -> ClientFormState {
        ClientFormState {
            source_kind: self.c_source.get_untracked(),
            scope: if self.c_scope_system.get_untracked() {
                crate::installer_ops::InstallScope::System
            } else {
                crate::installer_ops::InstallScope::User
            },
            repo_root: self.c_repo_root.get_untracked(),
            archive_location: self.c_archive_loc.get_untracked(),
            sha256: self.c_sha256.get_untracked(),
            local_signing_identity: self.c_sign_id.get_untracked(),
            allow_unnotarized: self.c_allow_unnotarized.get_untracked(),
            auto_deps: self.c_auto_deps.get_untracked(),
        }
    }

    fn snapshot_host_form(&self) -> HostFormState {
        HostFormState {
            deploy_mode: self.h_mode.get_untracked(),
            ssh_target: self.h_ssh.get_untracked(),
            host_ip: self.h_ip.get_untracked(),
            controller_ip: self.h_ctrl_ip.get_untracked(),
            profile: self.h_profile.get_untracked(),
            instance_name: self.h_instance.get_untracked(),
            display: self.h_display.get_untracked(),
            resolution: self.h_resolution.get_untracked(),
            encoder: self.h_encoder.get_untracked(),
            firewall_backend: self.h_fw.get_untracked(),
            render_device: self.h_render_dev.get_untracked(),
            archive_path: self.h_archive_path.get_untracked(),
            archive_sha256: self.h_archive_sha256.get_untracked(),
            from_source: self.h_from_source.get_untracked(),
            enable_clipboard: self.h_clip.get_untracked(),
            enable_file_transfer: self.h_files.get_untracked(),
            enable_native_file_clipboard: self.h_file_clip.get_untracked(),
            enable_mic: self.h_mic.get_untracked(),
            require_pq_ssh: self.h_pq_ssh.get_untracked(),
            execute_sudo: self.h_sudo.get_untracked(),
            auto_deps: self.h_auto_deps.get_untracked(),
            show_advanced: self.h_show_advanced.get_untracked(),
        }
    }

    fn snapshot_probe_form(&self) -> ProbePairFormState {
        ProbePairFormState {
            host: self.p_host.get_untracked(),
            ssh_target: self.p_ssh.get_untracked(),
            require_pq_ssh: self.p_pq_ssh.get_untracked(),
            controller_ip: self.p_ctrl_ip.get_untracked(),
            firewall_backend: self.p_fw.get_untracked(),
            execute_sudo_firewall: self.p_sudo_fw.get_untracked(),
            pin: self.p_pin.get_untracked(),
            client_name: self.p_client_name.get_untracked(),
            admin_user: self.p_admin_user.get_untracked(),
            admin_pass: self.p_admin_pass.get_untracked(),
            perm_clipboard_read: self.p_perm_cr.get_untracked(),
            perm_clipboard_write: self.p_perm_cw.get_untracked(),
            perm_file_upload: self.p_perm_fu.get_untracked(),
            perm_file_download: self.p_perm_fd.get_untracked(),
            perm_mic: self.p_perm_mic.get_untracked(),
        }
    }

    fn snapshot_uninstall_form(&self) -> UninstallFormState {
        UninstallFormState {
            component: self.u_component.get_untracked(),
            instance_name: self.u_instance.get_untracked(),
            ssh_target: self.u_ssh.get_untracked(),
            require_pq_ssh: self.u_pq_ssh.get_untracked(),
            purge_config: self.u_purge_config.get_untracked(),
            remove_firewall: self.u_remove_firewall.get_untracked(),
            execute_sudo: self.u_sudo.get_untracked(),
        }
    }

    fn push_log(&self, line: String) {
        if let Ok(mut guard) = self.log_buffer.lock() {
            guard.push(line);
            if guard.len() > 400 {
                let drop_n = guard.len() - 400;
                guard.drain(..drop_n);
            }
        }
        let _ = self.log_bump_tx.try_send(());
    }
}

/// Ensures Floem defaults to software rendering unless GPU rendering was explicitly enabled.
pub fn configure_software_renderer_env() {
    if env::var_os("SDS_INSTALLER_GPU").as_deref() != Some(OsStr::new("1"))
        && env::var_os("FLOEM_FORCE_TINY_SKIA").is_none()
    {
        env::set_var("FLOEM_FORCE_TINY_SKIA", "1");
    }
}

/// Launches the pure native software-rendered `floem` GUI window on the calling main thread.
pub fn run_native_gui(repo_root: Option<PathBuf>) -> Result<(), String> {
    if current_os() == "linux"
        && env::var_os("DISPLAY").is_none()
        && env::var_os("WAYLAND_DISPLAY").is_none()
    {
        return Err(
            "No DISPLAY or WAYLAND_DISPLAY set. Run `sds-installer tui` for terminal UI or pass CLI subcommands."
                .into(),
        );
    }

    configure_software_renderer_env();

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("failed to start background tokio runtime: {e}"))?,
    );
    let pairing_mgr = PairingManager::new();
    let pairing_cleanup = pairing_mgr.clone();

    let (events_tx, mut events_rx) = broadcast::channel::<ProgressEvent>(256);
    let log_buffer = Arc::new(Mutex::new(Vec::<String>::new()));
    let (log_bump_tx, log_bump_rx) = crossbeam_channel::unbounded::<()>();

    let buf_fwd = log_buffer.clone();
    let bump_fwd = log_bump_tx.clone();
    rt.spawn(async move {
        while let Ok(ev) = events_rx.recv().await {
            let line = format!("[{}] [{}] {}", ev.level, ev.step, ev.message);
            if let Ok(mut g) = buf_fwd.lock() {
                g.push(line);
                if g.len() > 400 {
                    let drop_n = g.len() - 400;
                    g.drain(..drop_n);
                }
            }
            let _ = bump_fwd.try_send(());
        }
    });

    let cfg = WindowConfig::default()
        .title("Secure Desktop Stream — Native Installer")
        .size(Size::new(1120.0, 860.0));

    Application::new()
        .on_event(move |ev| {
            if matches!(ev, AppEvent::WillTerminate) {
                pairing_cleanup.shutdown_all();
            }
        })
        .window(
            move |_| {
                build_root_view(
                    rt,
                    repo_root,
                    pairing_mgr,
                    events_tx,
                    log_buffer,
                    log_bump_tx,
                    log_bump_rx,
                )
            },
            Some(cfg),
        )
        .run();

    Ok(())
}

fn build_root_view(
    rt: Arc<Runtime>,
    repo_root: Option<PathBuf>,
    pairing_mgr: PairingManager,
    events_tx: broadcast::Sender<ProgressEvent>,
    log_buffer: Arc<Mutex<Vec<String>>>,
    log_bump_tx: crossbeam_channel::Sender<()>,
    log_bump_rx: crossbeam_channel::Receiver<()>,
) -> impl IntoView {
    let default_deps = DepsFormState::default();
    let default_client = ClientFormState::default();
    let default_host = HostFormState::default();
    let default_probe = ProbePairFormState::default();
    let default_uninstall = UninstallFormState::default();

    let ctx = GuiCtx {
        root_scope: Scope::current(),
        rt,
        repo_root,
        pairing_mgr,
        events_tx,
        log_buffer: log_buffer.clone(),
        log_bump_tx,
        tab: RwSignal::new(UiTab::Overview),
        lang: RwSignal::new(UiLang::En),
        theme: RwSignal::new(UiTheme::Dark),
        busy_count: RwSignal::new(0),
        status_line: RwSignal::new("Ready (tiny-skia CPU renderer)".into()),
        preflight: RwSignal::new(None),
        deps_report: RwSignal::new(None),
        deps_install_res: RwSignal::new(None),
        client_action: RwSignal::new(None),
        host_action: RwSignal::new(None),
        probe_report: RwSignal::new(None),
        pairing_open: RwSignal::new(None),
        pairing_status: RwSignal::new(None),
        uninstall_result: RwSignal::new(None),
        preview_bundle: RwSignal::new(None),
        pending_confirm: RwSignal::new(None),
        log_text: RwSignal::new(String::new()),

        d_role: RwSignal::new(default_deps.role),
        d_ssh: RwSignal::new(default_deps.ssh_target),
        d_pq_ssh: RwSignal::new(default_deps.require_pq_ssh),
        d_optional: RwSignal::new(default_deps.include_optional),
        d_sudo: RwSignal::new(default_deps.execute_sudo),

        c_source: RwSignal::new(default_client.source_kind),
        c_scope_system: RwSignal::new(false),
        c_repo_root: RwSignal::new(default_client.repo_root),
        c_archive_loc: RwSignal::new(default_client.archive_location),
        c_sha256: RwSignal::new(default_client.sha256),
        c_sign_id: RwSignal::new(default_client.local_signing_identity),
        c_allow_unnotarized: RwSignal::new(default_client.allow_unnotarized),
        c_auto_deps: RwSignal::new(default_client.auto_deps),

        h_mode: RwSignal::new(default_host.deploy_mode),
        h_ssh: RwSignal::new(default_host.ssh_target),
        h_ip: RwSignal::new(default_host.host_ip),
        h_ctrl_ip: RwSignal::new(default_host.controller_ip),
        h_profile: RwSignal::new(default_host.profile),
        h_instance: RwSignal::new(default_host.instance_name),
        h_display: RwSignal::new(default_host.display),
        h_resolution: RwSignal::new(default_host.resolution),
        h_encoder: RwSignal::new(default_host.encoder),
        h_fw: RwSignal::new(default_host.firewall_backend),
        h_render_dev: RwSignal::new(default_host.render_device),
        h_archive_path: RwSignal::new(default_host.archive_path),
        h_archive_sha256: RwSignal::new(default_host.archive_sha256),
        h_from_source: RwSignal::new(default_host.from_source),
        h_clip: RwSignal::new(default_host.enable_clipboard),
        h_files: RwSignal::new(default_host.enable_file_transfer),
        h_file_clip: RwSignal::new(default_host.enable_native_file_clipboard),
        h_mic: RwSignal::new(default_host.enable_mic),
        h_pq_ssh: RwSignal::new(default_host.require_pq_ssh),
        h_sudo: RwSignal::new(default_host.execute_sudo),
        h_auto_deps: RwSignal::new(default_host.auto_deps),
        h_show_advanced: RwSignal::new(default_host.show_advanced),

        p_host: RwSignal::new(default_probe.host),
        p_ssh: RwSignal::new(default_probe.ssh_target),
        p_pq_ssh: RwSignal::new(default_probe.require_pq_ssh),
        p_ctrl_ip: RwSignal::new(default_probe.controller_ip),
        p_fw: RwSignal::new(default_probe.firewall_backend),
        p_sudo_fw: RwSignal::new(default_probe.execute_sudo_firewall),
        p_pin: RwSignal::new(default_probe.pin),
        p_client_name: RwSignal::new(default_probe.client_name),
        p_admin_user: RwSignal::new(default_probe.admin_user),
        p_admin_pass: RwSignal::new(default_probe.admin_pass),
        p_perm_cr: RwSignal::new(default_probe.perm_clipboard_read),
        p_perm_cw: RwSignal::new(default_probe.perm_clipboard_write),
        p_perm_fu: RwSignal::new(default_probe.perm_file_upload),
        p_perm_fd: RwSignal::new(default_probe.perm_file_download),
        p_perm_mic: RwSignal::new(default_probe.perm_mic),

        u_component: RwSignal::new(default_uninstall.component),
        u_instance: RwSignal::new(default_uninstall.instance_name),
        u_ssh: RwSignal::new(default_uninstall.ssh_target),
        u_pq_ssh: RwSignal::new(default_uninstall.require_pq_ssh),
        u_purge_config: RwSignal::new(default_uninstall.purge_config),
        u_remove_firewall: RwSignal::new(default_uninstall.remove_firewall),
        u_sudo: RwSignal::new(default_uninstall.execute_sudo),
    };

    let log_bump_sig = create_signal_from_channel(log_bump_rx);
    let log_text_sig = ctx.log_text;
    create_effect(move |_| {
        if log_bump_sig.get().is_some() {
            if let Ok(g) = log_buffer.lock() {
                log_text_sig.set(g.join("\n"));
            }
        }
    });

    trigger_preflight(&ctx);
    trigger_deps_check(&ctx);

    let c_top = ctx.clone();
    let c_tabs = ctx.clone();
    let c_confirm = ctx.clone();
    let c_preview = ctx.clone();
    let c_body = ctx.clone();
    let c_log = ctx.clone();
    let theme_sig = ctx.theme;

    v_stack((
        top_bar(c_top),
        topology_banner(ctx.clone()),
        tab_bar(c_tabs),
        confirmation_banner(c_confirm),
        preview_overlay(c_preview),
        scroll(
            dyn_container(
                move || c_body.tab.get(),
                move |tab| {
                    let c = c_body.clone();
                    match tab {
                        UiTab::Overview => overview_panel(c).into_any(),
                        UiTab::Client => client_panel(c).into_any(),
                        UiTab::Host => host_panel(c).into_any(),
                        UiTab::VerifyPair => verify_panel(c).into_any(),
                        UiTab::Uninstall => uninstall_panel(c).into_any(),
                    }
                },
            )
            .style(|s| s.width_full().padding(8.0)),
        )
        .style(|s| s.width_full().flex_grow(1.0_f32).min_height(260.0)),
        log_panel(c_log),
    ))
    .style(move |s| {
        let pal = palette(theme_sig.get());
        s.width_full()
            .height_full()
            .padding(14.0)
            .gap(10.0)
            .background(pal.bg)
            .color(pal.text)
    })
}

fn styled_btn(
    ctx: &GuiCtx,
    text_fn: impl Fn(UiLang) -> String + 'static,
    primary: bool,
    on_click: impl FnMut() + 'static,
) -> impl IntoView {
    let lang = ctx.lang;
    let theme = ctx.theme;
    button(label(move || text_fn(lang.get())))
        .action(on_click)
        .style(move |s| {
            let pal = palette(theme.get());
            s.padding_horiz(12.0)
                .padding_vert(7.0)
                .border_radius(6.0)
                .border(1.0)
                .border_color(if primary { pal.brand } else { pal.border })
                .background(if primary { pal.brand } else { pal.surface_alt })
                .color(if primary { pal.brand_fg } else { pal.text })
                .cursor(CursorStyle::Pointer)
                .font_size(13.0)
        })
}

fn card(theme: RwSignal<UiTheme>, child: impl IntoView + 'static) -> impl IntoView {
    container(child).style(move |s| {
        let pal = palette(theme.get());
        s.width_full()
            .padding(12.0)
            .border_radius(8.0)
            .border(1.0)
            .border_color(pal.border)
            .background(pal.surface)
    })
}

fn input_field(
    ctx: &GuiCtx,
    title: impl Fn(UiLang) -> String + 'static,
    sig: RwSignal<String>,
    placeholder: &'static str,
) -> impl IntoView {
    let lang = ctx.lang;
    let theme = ctx.theme;
    v_stack((
        label(move || title(lang.get())).style(move |s| {
            let pal = palette(theme.get());
            s.font_size(12.0).color(pal.muted)
        }),
        text_input(sig).placeholder(placeholder).style(move |s| {
            let pal = palette(theme.get());
            s.width_full()
                .padding_horiz(8.0)
                .padding_vert(6.0)
                .border_radius(6.0)
                .border(1.0)
                .border_color(pal.border)
                .background(pal.bg)
                .color(pal.text)
                .font_size(13.0)
        }),
    ))
    .style(|s| s.gap(4.0).flex_grow(1.0_f32).min_width(210.0))
}

fn top_bar(ctx: GuiCtx) -> impl IntoView {
    let lang = ctx.lang;
    let theme = ctx.theme;
    let busy_count = ctx.busy_count;
    let status = ctx.status_line;
    let c_refresh = ctx.clone();

    h_stack((
        v_stack((
            label(move || tr(lang.get(), "app_title").to_string())
                .style(|s| s.font_size(17.0).font_bold()),
            label(move || {
                let base = tr(lang.get(), "app_subtitle");
                if busy_count.get() > 0 {
                    format!("{base}  |  ⏳ {}", status.get())
                } else {
                    format!("{base}  |  {}", status.get())
                }
            })
            .style(move |s| {
                let pal = palette(theme.get());
                s.font_size(12.0).color(pal.muted)
            }),
        ))
        .style(|s| s.flex_grow(1.0_f32).gap(2.0)),
        styled_btn(
            &ctx,
            |_| "RU / EN".into(),
            false,
            move || {
                lang.update(|l| *l = l.toggle());
            },
        ),
        styled_btn(
            &ctx,
            move |_| match theme.get() {
                UiTheme::Dark => "Light".into(),
                UiTheme::Light => "Dark".into(),
            },
            false,
            move || {
                theme.update(|t| *t = t.toggle());
            },
        ),
        styled_btn(
            &ctx,
            |l| tr(l, "btn_rescan").into(),
            false,
            move || trigger_preflight(&c_refresh),
        ),
    ))
    .style(|s| s.width_full().items_center().gap(8.0))
}

fn topology_banner(ctx: GuiCtx) -> impl IntoView {
    let lang = ctx.lang;
    let theme = ctx.theme;
    card(
        theme,
        v_stack((
            label(move || tr(lang.get(), "topology").to_string())
                .style(|s| s.font_size(12.5).font_bold()),
            label(move || tr(lang.get(), "unsigned_note").to_string()).style(move |s| {
                let pal = palette(theme.get());
                s.font_size(11.5).color(pal.muted)
            }),
        ))
        .style(|s| s.gap(4.0)),
    )
}

fn tab_bar(ctx: GuiCtx) -> impl IntoView {
    let make_tab = |tab_item: UiTab| {
        let lang = ctx.lang;
        let theme = ctx.theme;
        let active_tab = ctx.tab;
        let key = match tab_item {
            UiTab::Overview => "tab_overview",
            UiTab::Client => "tab_client",
            UiTab::Host => "tab_host",
            UiTab::VerifyPair => "tab_verify",
            UiTab::Uninstall => "tab_uninstall",
        };
        button(label(move || tr(lang.get(), key).to_string()))
            .action(move || active_tab.set(tab_item))
            .style(move |s| {
                let pal = palette(theme.get());
                let is_active = active_tab.get() == tab_item;
                s.padding_horiz(14.0)
                    .padding_vert(7.0)
                    .border_radius(6.0)
                    .border(1.0)
                    .border_color(if is_active { pal.brand } else { pal.border })
                    .background(if is_active { pal.brand } else { pal.surface })
                    .color(if is_active { pal.brand_fg } else { pal.text })
                    .cursor(CursorStyle::Pointer)
                    .font_size(13.0)
            })
    };
    h_stack((
        make_tab(UiTab::Overview),
        make_tab(UiTab::Client),
        make_tab(UiTab::Host),
        make_tab(UiTab::VerifyPair),
        make_tab(UiTab::Uninstall),
    ))
    .style(|s| s.gap(8.0).flex_wrap(floem::style::FlexWrap::Wrap))
}

fn confirm_desc(kind: PendingConfirmation, l: UiLang) -> &'static str {
    match (kind, l) {
        (PendingConfirmation::InstallDeps, UiLang::Ru) => {
            "Подтвердите автоматическую доустановку недостающих системных зависимостей"
        }
        (PendingConfirmation::InstallDeps, UiLang::En) => {
            "Confirm automatically installing missing allowlisted dependencies"
        }
        (PendingConfirmation::InstallClient, UiLang::Ru) => {
            "Подтвердите установку / обновление клиента Moonlight Secure Desktop"
        }
        (PendingConfirmation::InstallClient, UiLang::En) => {
            "Confirm installing / updating Moonlight Secure Desktop client"
        }
        (PendingConfirmation::InstallHostLocal, UiLang::Ru) => {
            "Подтвердите запись конфигов и юнитов хоста на этом компьютере"
        }
        (PendingConfirmation::InstallHostLocal, UiLang::En) => {
            "Confirm writing host configuration and units locally"
        }
        (PendingConfirmation::DeployHostSsh, UiLang::Ru) => {
            "Подтвердите деплой конфигурации и проверку по PQ SSH на удалённый хост"
        }
        (PendingConfirmation::DeployHostSsh, UiLang::En) => {
            "Confirm deploying host configuration over PQ SSH"
        }
        (PendingConfirmation::Uninstall, UiLang::Ru) => {
            "Подтвердите удаление компонентов SDS (конфиги и ключи сохраняются)"
        }
        (PendingConfirmation::Uninstall, UiLang::En) => {
            "Confirm uninstalling SDS binaries & units (configs & keys preserved)"
        }
        (PendingConfirmation::UninstallPurge, UiLang::Ru) => {
            "ВНИМАНИЕ: удаление SDS с полной очисткой конфигов, сертификатов и правил файрвола!"
        }
        (PendingConfirmation::UninstallPurge, UiLang::En) => {
            "WARNING: Confirm uninstalling SDS AND purging configs, certificates & firewall rules!"
        }
    }
}

fn confirmation_banner(ctx: GuiCtx) -> impl IntoView {
    let c = ctx.clone();
    dyn_container(
        move || c.pending_confirm.get(),
        move |pending| {
            let Some(kind) = pending else {
                return empty().into_any();
            };
            let c_yes = c.clone();
            let c_no = c.clone();
            let lang = c.lang;
            let theme = c.theme;
            container(
                h_stack((
                    label(move || {
                        let l = lang.get();
                        format!("{} {}", tr(l, "confirm_title"), confirm_desc(kind, l))
                    })
                    .style(|s| s.flex_grow(1.0_f32).font_bold()),
                    styled_btn(
                        &c,
                        |l| tr(l, "btn_cancel").into(),
                        false,
                        move || {
                            c_no.pending_confirm.set(None);
                        },
                    ),
                    styled_btn(
                        &c,
                        |l| tr(l, "btn_confirm").into(),
                        true,
                        move || {
                            c_yes.pending_confirm.set(None);
                            match kind {
                                PendingConfirmation::InstallDeps => {
                                    trigger_deps_install(&c_yes, false);
                                }
                                PendingConfirmation::InstallClient => {
                                    trigger_client_install(&c_yes, false);
                                }
                                PendingConfirmation::InstallHostLocal => {
                                    trigger_local_host(&c_yes, false);
                                }
                                PendingConfirmation::DeployHostSsh => {
                                    trigger_ssh_deploy(&c_yes, false);
                                }
                                PendingConfirmation::Uninstall
                                | PendingConfirmation::UninstallPurge => {
                                    trigger_uninstall(&c_yes, false);
                                }
                            }
                        },
                    ),
                ))
                .style(|s| s.items_center().gap(8.0).width_full()),
            )
            .style(move |s| {
                let pal = palette(theme.get());
                s.width_full()
                    .padding(10.0)
                    .border_radius(8.0)
                    .border(2.0)
                    .border_color(pal.warn)
                    .background(pal.surface_alt)
            })
            .into_any()
        },
    )
}

fn preview_overlay(ctx: GuiCtx) -> impl IntoView {
    let c = ctx.clone();
    dyn_container(
        move || c.preview_bundle.get(),
        move |opt_bundle| {
            let Some(bundle) = opt_bundle else {
                return empty().into_any();
            };
            let c_close = c.clone();
            let theme = c.theme;
            let mut text = format!(
                "Profile: {} | Instance: {} | Controller: {}\n=== Firewall ({}) ===\n{}\n=== Pairing 47989 ===\n{}\n{}\n",
                bundle.profile.as_str(),
                bundle.instance_name,
                bundle.controller_ip,
                bundle.firewall.backend,
                bundle.firewall.setup_streaming.join("\n"),
                bundle.firewall.open_pairing_47989.join("\n"),
                bundle.firewall.close_pairing_47989.join("\n"),
            );
            for file in bundle.files.values() {
                text.push_str(&format!(
                    "\n--- {} -> {} (mode {}) ---\n{}\n",
                    file.rel_path, file.target_hint, file.mode, file.content
                ));
            }
            card(
                theme,
                v_stack((
                    h_stack((
                        label(|| "Generated Files & Firewall Preview".to_string())
                            .style(|s| s.flex_grow(1.0_f32).font_bold()),
                        styled_btn(
                            &c,
                            |_| "Close".into(),
                            false,
                            move || {
                                c_close.preview_bundle.set(None);
                            },
                        ),
                    ))
                    .style(|s| s.width_full().items_center()),
                    scroll(label(move || text.clone()).style(|s| s.font_size(12.0)))
                        .style(|s| s.max_height(240.0).width_full()),
                ))
                .style(|s| s.gap(6.0)),
            )
            .into_any()
        },
    )
}

fn overview_panel(ctx: GuiCtx) -> impl IntoView {
    let c1 = ctx.clone();
    let c2 = ctx.clone();
    let c3 = ctx.clone();
    let c4 = ctx.clone();
    let c_pf = ctx.clone();
    let c_dchk = ctx.clone();
    let c_ddry = ctx.clone();
    let c_dinst = ctx.clone();
    let c_drep = ctx.clone();
    let c_dres = ctx.clone();
    let d_role = ctx.d_role;
    let theme = ctx.theme;
    let lang = ctx.lang;

    v_stack((
        card(
            theme,
            dyn_container(
                move || c_pf.preflight.get(),
                move |opt| match opt {
                    None => label(|| "Collecting system preflight...").into_any(),
                    Some(pf) => {
                        let summary = format!(
                            "OS/Arch: {} / {} ({})  |  Host: {}\nSSH: {:?}  |  PQ KEX (mlkem768x25519-sha256): {}\nCargo: {} ({:?})\nRepo checkout: {}\nInstalled clients: {}\nInstalled hosts: {}",
                            pf.os,
                            pf.arch,
                            pf.os_version,
                            pf.hostname,
                            pf.ssh_version,
                            pf.pq_ssh_supported,
                            pf.cargo_available,
                            pf.rustc_version,
                            pf.repo_checkout
                                .as_ref()
                                .map_or("not detected", |r| r.root.as_str()),
                            pf.existing_installs
                                .client_paths
                                .iter()
                                .map(|c| c.path.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                            pf.existing_installs
                                .host_paths
                                .iter()
                                .map(|h| h.path.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                        let pf_warnings = pf.warnings.clone();
                        v_stack((
                            label(move || summary.clone()).style(|s| s.font_size(13.0)),
                            label(move || {
                                let is_ru = lang.get() == UiLang::Ru;
                                pf_warnings
                                    .iter()
                                    .map(|w| {
                                        if is_ru {
                                            format!(
                                                "[{}] {}: {}",
                                                w.severity, w.title_ru, w.detail_ru
                                            )
                                        } else {
                                            format!(
                                                "[{}] {}: {}",
                                                w.severity, w.title_en, w.detail_en
                                            )
                                        }
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            })
                            .style(move |s| {
                                let pal = palette(theme.get());
                                s.font_size(12.0).color(pal.warn)
                            }),
                        ))
                        .style(|s| s.gap(8.0))
                        .into_any()
                    }
                },
            ),
        ),
        card(
            theme,
            v_stack((
                label(move || {
                    if lang.get() == UiLang::Ru {
                        "Автоматическая проверка и установка зависимостей".to_string()
                    } else {
                        "Automatic Dependency Check & Installation".to_string()
                    }
                })
                .style(|s| s.font_size(14.0).font_bold()),
                h_stack((
                    styled_btn(
                        &ctx,
                        move |_| format!("Role: {}", d_role.get().as_str()),
                        false,
                        move || d_role.update(|r| *r = r.cycle()),
                    ),
                    input_field(
                        &ctx,
                        |_| "Optional Remote SSH Target (empty = local)".into(),
                        ctx.d_ssh,
                        "user@linux-host",
                    ),
                ))
                .style(|s| s.gap(10.0).items_end().width_full()),
                h_stack((
                    Checkbox::labeled_rw(ctx.d_pq_ssh, move || "Require PQ SSH".to_string()),
                    Checkbox::labeled_rw(ctx.d_optional, move || "Include Optional".to_string()),
                    Checkbox::labeled_rw(ctx.d_sudo, move || "sudo -n (Linux)".to_string()),
                ))
                .style(|s| s.gap(10.0).flex_wrap(floem::style::FlexWrap::Wrap)),
                h_stack((
                    styled_btn(&ctx, |l| tr(l, "btn_check_deps").into(), false, move || {
                        trigger_deps_check(&c_dchk);
                    }),
                    styled_btn(&ctx, |l| tr(l, "btn_dry_run_deps").into(), false, move || {
                        trigger_deps_install(&c_ddry, true);
                    }),
                    styled_btn(&ctx, |l| tr(l, "btn_install_deps").into(), true, move || {
                        c_dinst
                            .pending_confirm
                            .set(Some(PendingConfirmation::InstallDeps));
                    }),
                ))
                .style(|s| s.gap(8.0)),
                dyn_container(
                    move || c_drep.deps_report.get(),
                    move |opt| match opt {
                        None => empty().into_any(),
                        Some(rep) => {
                            let lines = rep
                                .items
                                .iter()
                                .map(|it| {
                                    let mark = if it.present {
                                        "OK"
                                    } else if it.required {
                                        "MISSING"
                                    } else {
                                        "OPTIONAL"
                                    };
                                    let ver = it.detected_version.as_deref().unwrap_or("-");
                                    let pkg = it.package_name.as_deref().unwrap_or("-");
                                    format!("[{mark}] {} (pkg={pkg}, ver={ver})", it.name)
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            let txt = format!(
                                "Target: {} ({}/{}, PM: {}) | Satisfied: {}\n{}",
                                rep.target_label,
                                rep.os,
                                rep.arch,
                                rep.package_manager.as_str(),
                                rep.all_satisfied,
                                lines
                            );
                            label(move || txt.clone())
                                .style(|s| s.font_size(12.0))
                                .into_any()
                        }
                    },
                ),
                dyn_container(
                    move || c_dres.deps_install_res.get(),
                    move |opt| match opt {
                        None => empty().into_any(),
                        Some(res) => {
                            let mut txt = format!(
                                "{} (dry_run={}, ok={})",
                                res.summary, res.dry_run, res.ok
                            );
                            if !res.commands_executed_or_planned.is_empty() {
                                txt.push_str("\nCommands:\n  ");
                                txt.push_str(&res.commands_executed_or_planned.join("\n  "));
                            }
                            if !res.elevated_commands.is_empty() {
                                txt.push_str("\nElevated:\n  ");
                                txt.push_str(&res.elevated_commands.join("\n  "));
                            }
                            label(move || txt.clone())
                                .style(move |s| {
                                    let pal = palette(theme.get());
                                    s.font_size(12.0).color(pal.warn)
                                })
                                .into_any()
                        }
                    },
                ),
            ))
            .style(|s| s.gap(8.0).width_full()),
        ),
        h_stack((
            styled_btn(&ctx, |l| tr(l, "tab_client").into(), true, move || {
                c1.tab.set(UiTab::Client);
            }),
            styled_btn(&ctx, |l| tr(l, "tab_host").into(), true, move || {
                c2.h_mode.set(HostDeployMode::Ssh);
                c2.tab.set(UiTab::Host);
            }),
            styled_btn(&ctx, |l| tr(l, "tab_verify").into(), true, move || {
                c3.tab.set(UiTab::VerifyPair);
            }),
            styled_btn(&ctx, |l| tr(l, "tab_uninstall").into(), false, move || {
                c4.tab.set(UiTab::Uninstall);
            }),
        ))
        .style(|s| s.gap(8.0).flex_wrap(floem::style::FlexWrap::Wrap)),
    ))
    .style(|s| s.gap(10.0).width_full())
}

fn client_panel(ctx: GuiCtx) -> impl IntoView {
    let lang = ctx.lang;
    let theme = ctx.theme;
    let c_src = ctx.c_source;
    let c_dry = ctx.clone();
    let c_inst = ctx.clone();
    let c_res = ctx.clone();

    v_stack((
        card(
            theme,
            v_stack((
                h_stack((
                    styled_btn(
                        &ctx,
                        move |l| format!("Source: {}", c_src.get().label(l)),
                        false,
                        move || c_src.update(|v| *v = v.cycle()),
                    ),
                    Checkbox::labeled_rw(ctx.c_scope_system, move || {
                        if lang.get() == UiLang::Ru {
                            "Установить для всех (/Applications)".to_string()
                        } else {
                            "System scope (/Applications)".to_string()
                        }
                    }),
                    Checkbox::labeled_rw(ctx.c_auto_deps, move || {
                        if lang.get() == UiLang::Ru {
                            "Автоматически проверить и установить зависимости".to_string()
                        } else {
                            "Auto-check & install missing dependencies".to_string()
                        }
                    }),
                ))
                .style(|s| s.gap(10.0).items_center().flex_wrap(floem::style::FlexWrap::Wrap)),
                h_stack((
                    input_field(
                        &ctx,
                        |l| {
                            if l == UiLang::Ru {
                                "Путь к репозиторию (опционально для From Source)".into()
                            } else {
                                "Repo checkout path (optional for From Source)".into()
                            }
                        },
                        ctx.c_repo_root,
                        "/path/to/secure-desktop-stream",
                    ),
                    input_field(
                        &ctx,
                        |l| {
                            if l == UiLang::Ru {
                                "Путь к архиву или https:// URL".into()
                            } else {
                                "Archive path or https:// URL".into()
                            }
                        },
                        ctx.c_archive_loc,
                        "/path/to/Moonlight.zip",
                    ),
                ))
                .style(|s| s.gap(10.0).width_full()),
                h_stack((
                    input_field(
                        &ctx,
                        |_| "SHA-256 (64 hex)".into(),
                        ctx.c_sha256,
                        "64 hex chars",
                    ),
                    input_field(
                        &ctx,
                        |_| "macOS Local Sign SHA-1 (40 hex, optional)".into(),
                        ctx.c_sign_id,
                        "optional 40 hex SHA-1",
                    ),
                ))
                .style(|s| s.gap(10.0).width_full()),
                Checkbox::labeled_rw(ctx.c_allow_unnotarized, move || {
                    if lang.get() == UiLang::Ru {
                        "Разрешить неподписанную сборку (--allow-unnotarized: снять quarantine/MOTW только с этого приложения)".to_string()
                    } else {
                        "Allow unsigned build (strip quarantine/MOTW on this verified app only)".to_string()
                    }
                }),
                h_stack((
                    styled_btn(&ctx, |l| tr(l, "btn_dry_run").into(), false, move || {
                        trigger_client_install(&c_dry, true);
                    }),
                    styled_btn(
                        &ctx,
                        |l| tr(l, "btn_install_client").into(),
                        true,
                        move || {
                            c_inst
                                .pending_confirm
                                .set(Some(PendingConfirmation::InstallClient));
                        },
                    ),
                ))
                .style(|s| s.gap(8.0)),
            ))
            .style(|s| s.gap(10.0).width_full()),
        ),
        action_result_card(c_res.client_action, theme),
    ))
    .style(|s| s.gap(10.0).width_full())
}

fn host_panel(ctx: GuiCtx) -> impl IntoView {
    let theme = ctx.theme;
    let lang = ctx.lang;
    let h_mode = ctx.h_mode;
    let h_prof = ctx.h_profile;
    let h_enc = ctx.h_encoder;
    let h_fw = ctx.h_fw;
    let h_adv = ctx.h_show_advanced;
    let c_adv_box = ctx.clone();
    let c_prev = ctx.clone();
    let c_dry = ctx.clone();
    let c_apply = ctx.clone();
    let c_res = ctx.clone();

    v_stack((
        card(
            theme,
            v_stack((
                label(move || tr(lang.get(), "host_runtime_note").to_string()).style(move |s| {
                    let pal = palette(theme.get());
                    s.font_size(12.0).color(pal.muted)
                }),
                h_stack((
                    styled_btn(
                        &ctx,
                        move |_| format!("Mode: {:?}", h_mode.get()),
                        false,
                        move || h_mode.update(|m| *m = m.toggle()),
                    ),
                    styled_btn(
                        &ctx,
                        move |_| format!("Profile: {}", h_prof.get().as_str()),
                        false,
                        move || h_prof.update(|p| *p = cycle_profile(*p)),
                    ),
                    styled_btn(
                        &ctx,
                        move |_| format!("Firewall: {:?}", h_fw.get()),
                        false,
                        move || h_fw.update(|f| *f = cycle_firewall(*f)),
                    ),
                ))
                .style(|s| s.gap(8.0).flex_wrap(floem::style::FlexWrap::Wrap)),
                h_stack((
                    input_field(
                        &ctx,
                        |_| "SSH Target (user@host)".into(),
                        ctx.h_ssh,
                        "user@linux-host",
                    ),
                    input_field(&ctx, |_| "Host LAN IP".into(), ctx.h_ip, "192.0.2.50"),
                    input_field(
                        &ctx,
                        |_| "Controller IP (Firewall Allow)".into(),
                        ctx.h_ctrl_ip,
                        "192.0.2.10",
                    ),
                ))
                .style(|s| s.gap(10.0).width_full()),
                h_stack((
                    Checkbox::labeled_rw(ctx.h_auto_deps, move || {
                        "Auto-check & install missing dependencies".to_string()
                    }),
                    Checkbox::labeled_rw(ctx.h_pq_ssh, move || "PQ SSH".to_string()),
                    Checkbox::labeled_rw(ctx.h_sudo, move || "sudo -n".to_string()),
                    styled_btn(
                        &ctx,
                        move |l| {
                            let prefix = if h_adv.get() { "[-] " } else { "[+] " };
                            format!("{prefix}{}", tr(l, "btn_toggle_advanced"))
                        },
                        false,
                        move || h_adv.update(|v| *v = !*v),
                    ),
                ))
                .style(|s| {
                    s.gap(10.0)
                        .items_center()
                        .flex_wrap(floem::style::FlexWrap::Wrap)
                }),
                dyn_container(
                    move || c_adv_box.h_show_advanced.get(),
                    move |show| {
                        if !show {
                            return empty().into_any();
                        }
                        let c = c_adv_box.clone();
                        v_stack((
                            h_stack((
                                styled_btn(
                                    &c,
                                    move |_| format!("Encoder: {:?}", h_enc.get()),
                                    false,
                                    move || h_enc.update(|e| *e = cycle_encoder(*e)),
                                ),
                                input_field(
                                    &c,
                                    |_| "Instance slug".into(),
                                    c.h_instance,
                                    "sds-host",
                                ),
                                input_field(
                                    &c,
                                    |_| "X11 Display (:1..:99)".into(),
                                    c.h_display,
                                    ":97",
                                ),
                                input_field(
                                    &c,
                                    |_| "Resolution".into(),
                                    c.h_resolution,
                                    "1920x1080",
                                ),
                                input_field(
                                    &c,
                                    |_| "DRM Render Node (optional)".into(),
                                    c.h_render_dev,
                                    "/dev/dri/renderD128",
                                ),
                            ))
                            .style(|s| {
                                s.gap(8.0)
                                    .flex_wrap(floem::style::FlexWrap::Wrap)
                                    .width_full()
                            }),
                            h_stack((
                                input_field(
                                    &c,
                                    |_| "Host Archive Path (opt)".into(),
                                    c.h_archive_path,
                                    "/path/to/sunshine.tar.gz or .zip",
                                ),
                                input_field(
                                    &c,
                                    |_| "Host Archive SHA-256 (64 hex)".into(),
                                    c.h_archive_sha256,
                                    "64 hex chars",
                                ),
                            ))
                            .style(|s| s.gap(8.0).width_full()),
                            h_stack((
                                Checkbox::labeled_rw(c.h_from_source, move || {
                                    "Build Sunshine from source (Linux Docker)".to_string()
                                }),
                                Checkbox::labeled_rw(c.h_clip, move || "Clipboard".to_string()),
                                Checkbox::labeled_rw(c.h_files, move || "Files".to_string()),
                                Checkbox::labeled_rw(c.h_file_clip, move || {
                                    "File Copy/Paste".to_string()
                                }),
                                Checkbox::labeled_rw(c.h_mic, move || "Mic 48002".to_string()),
                            ))
                            .style(|s| s.gap(10.0).flex_wrap(floem::style::FlexWrap::Wrap)),
                        ))
                        .style(|s| s.gap(8.0).width_full())
                        .into_any()
                    },
                ),
                h_stack((
                    styled_btn(
                        &ctx,
                        |l| tr(l, "btn_preview").into(),
                        false,
                        move || {
                            let form = c_prev.snapshot_host_form();
                            match form
                                .to_host_config_params()
                                .and_then(|p| generate_host_bundle(&p))
                            {
                                Ok(b) => c_prev.preview_bundle.set(Some(b)),
                                Err(e) => c_prev.push_log(format!("[error] [preview] {e}")),
                            }
                        },
                    ),
                    styled_btn(
                        &ctx,
                        |l| tr(l, "btn_dry_run").into(),
                        false,
                        move || {
                            if c_dry.h_mode.get_untracked() == HostDeployMode::Ssh {
                                trigger_ssh_deploy(&c_dry, true);
                            } else {
                                trigger_local_host(&c_dry, true);
                            }
                        },
                    ),
                    styled_btn(
                        &ctx,
                        |l| tr(l, "btn_deploy_host").into(),
                        true,
                        move || {
                            let confirm = if c_apply.h_mode.get_untracked() == HostDeployMode::Ssh {
                                PendingConfirmation::DeployHostSsh
                            } else {
                                PendingConfirmation::InstallHostLocal
                            };
                            c_apply.pending_confirm.set(Some(confirm));
                        },
                    ),
                ))
                .style(|s| s.gap(8.0)),
            ))
            .style(|s| s.gap(10.0).width_full()),
        ),
        action_result_card(c_res.host_action, theme),
    ))
    .style(|s| s.gap(10.0).width_full())
}

fn verify_panel(ctx: GuiCtx) -> impl IntoView {
    let theme = ctx.theme;
    let c_probe = ctx.clone();
    let c_rep = ctx.clone();
    let c_open = ctx.clone();
    let c_pin = ctx.clone();
    let c_close = ctx.clone();
    let p_fw = ctx.p_fw;

    v_stack((
        card(
            theme,
            v_stack((
                h_stack((
                    input_field(
                        &ctx,
                        |_| "Host LAN IP / Hostname".into(),
                        ctx.p_host,
                        "192.0.2.50",
                    ),
                    input_field(
                        &ctx,
                        |_| "PQ SSH Target (optional)".into(),
                        ctx.p_ssh,
                        "user@linux-host",
                    ),
                ))
                .style(|s| s.gap(10.0).width_full()),
                h_stack((
                    Checkbox::labeled_rw(ctx.p_pq_ssh, move || {
                        "Require PQ SSH (mlkem768x25519-sha256)".to_string()
                    }),
                    styled_btn(&ctx, |l| tr(l, "btn_probe").into(), true, move || {
                        trigger_probe(&c_probe);
                    }),
                ))
                .style(|s| s.gap(10.0).items_center()),
                dyn_container(
                    move || c_rep.probe_report.get(),
                    move |opt| match opt {
                        None => empty().into_any(),
                        Some(rep) => {
                            let missing =
                                rep.verdict == HostProbeVerdict::HostNotInstalledOrUnreachable;
                            let c_jump = c_rep.clone();
                            let rep_host = rep.host.clone();
                            let text = format!(
                                "Host: {}  |  Verdict: {:?}\n47984 HTTPS: {} | PQ TLS 1.3 (X25519MLKEM768): {} | mTLS client auth: {}\nClassical Rejected: {} | TLS 1.2 Rejected: {} | 47990 WebUI Exposed: {} | 47989 Open: {}\nCert SHA-256: {}\nSSH Fingerprint: {:?}",
                                rep.host,
                                rep.verdict,
                                rep.https_port_open,
                                rep.pq_tls13_ok,
                                rep.mtls_client_auth_required,
                                rep.classical_kex_rejected,
                                rep.tls12_rejected,
                                rep.port_47990_webui_open,
                                rep.port_47989_http_open,
                                rep.cert_sha256_fingerprint.as_deref().unwrap_or("-"),
                                rep.ssh_fingerprint_status,
                            );
                            let findings_list = rep.findings.clone();
                            let lang_findings = c_rep.lang;
                            v_stack((
                                label(move || {
                                    let is_ru = lang_findings.get() == UiLang::Ru;
                                    let mut out = text.clone();
                                    if !findings_list.is_empty() {
                                        out.push_str("\n\nFindings:");
                                        for f in &findings_list {
                                            let msg = if is_ru {
                                                &f.message_ru
                                            } else {
                                                &f.message_en
                                            };
                                            out.push_str(&format!(
                                                "\n- [{}] {}: {msg}",
                                                f.severity, f.code
                                            ));
                                        }
                                    }
                                    out
                                })
                                .style(|s| s.font_size(12.5)),
                                if missing {
                                    styled_btn(
                                        &c_rep,
                                        |l| tr(l, "btn_deploy_missing").into(),
                                        true,
                                        move || {
                                            c_jump.h_mode.set(HostDeployMode::Ssh);
                                            c_jump.h_ip.set(rep_host.clone());
                                            let ssh_val = c_jump.p_ssh.get_untracked();
                                            if !ssh_val.is_empty() {
                                                c_jump.h_ssh.set(ssh_val);
                                            }
                                            c_jump.tab.set(UiTab::Host);
                                        },
                                    )
                                    .into_any()
                                } else {
                                    empty().into_any()
                                },
                            ))
                            .style(|s| s.gap(6.0))
                            .into_any()
                        }
                    },
                ),
            ))
            .style(|s| s.gap(8.0).width_full()),
        ),
        card(
            theme,
            v_stack((
                h_stack((
                    input_field(
                        &ctx,
                        |_| "Controller IP (for 47989 rule)".into(),
                        ctx.p_ctrl_ip,
                        "192.0.2.10",
                    ),
                    styled_btn(
                        &ctx,
                        move |_| format!("Firewall: {:?}", p_fw.get()),
                        false,
                        move || p_fw.update(|f| *f = cycle_firewall(*f)),
                    ),
                    Checkbox::labeled_rw(ctx.p_sudo_fw, move || "sudo -n for 47989".to_string()),
                    styled_btn(&ctx, |l| tr(l, "btn_open_pair").into(), true, move || {
                        trigger_open_pairing(&c_open);
                    }),
                ))
                .style(|s| {
                    s.gap(8.0)
                        .items_end()
                        .flex_wrap(floem::style::FlexWrap::Wrap)
                }),
                h_stack((
                    input_field(&ctx, |_| "Moonlight PIN (4 digits)".into(), ctx.p_pin, "1234"),
                    input_field(
                        &ctx,
                        |_| "Client Name".into(),
                        ctx.p_client_name,
                        "Desktop Controller",
                    ),
                    input_field(
                        &ctx,
                        |_| "Sunshine Admin User".into(),
                        ctx.p_admin_user,
                        "sds-admin",
                    ),
                    input_field(
                        &ctx,
                        |_| "Admin Password (ephemeral, cleared on submit)".into(),
                        ctx.p_admin_pass,
                        "password",
                    ),
                ))
                .style(|s| s.gap(8.0).width_full()),
                h_stack((
                    Checkbox::labeled_rw(ctx.p_perm_cr, move || "clipboard_read".to_string()),
                    Checkbox::labeled_rw(ctx.p_perm_cw, move || "clipboard_write".to_string()),
                    Checkbox::labeled_rw(ctx.p_perm_fu, move || "file_upload".to_string()),
                    Checkbox::labeled_rw(ctx.p_perm_fd, move || "file_download".to_string()),
                    Checkbox::labeled_rw(ctx.p_perm_mic, move || "mic".to_string()),
                ))
                .style(|s| s.gap(8.0).flex_wrap(floem::style::FlexWrap::Wrap)),
                h_stack((
                    styled_btn(&ctx, |l| tr(l, "btn_submit_pin").into(), true, move || {
                        trigger_submit_pin(&c_pin);
                    }),
                    styled_btn(&ctx, |l| tr(l, "btn_close_pair").into(), false, move || {
                        trigger_close_pairing(&c_close);
                    }),
                ))
                .style(|s| s.gap(8.0)),
                dyn_container(
                    move || ctx.pairing_status.get(),
                    move |st| match st {
                        None => empty().into_any(),
                        Some(msg) => label(move || msg.clone())
                            .style(|s| s.font_size(12.5))
                            .into_any(),
                    },
                ),
            ))
            .style(|s| s.gap(8.0).width_full()),
        ),
    ))
    .style(|s| s.gap(10.0).width_full())
}

fn uninstall_panel(ctx: GuiCtx) -> impl IntoView {
    let theme = ctx.theme;
    let lang = ctx.lang;
    let u_comp = ctx.u_component;
    let c_dry = ctx.clone();
    let c_run = ctx.clone();
    let c_res = ctx.clone();

    v_stack((
        card(
            theme,
            v_stack((
                h_stack((
                    styled_btn(
                        &ctx,
                        move |_| format!("Component: {}", u_comp.get().as_str()),
                        false,
                        move || u_comp.update(|c| *c = c.cycle()),
                    ),
                    input_field(
                        &ctx,
                        |_| "Host Instance Slug".into(),
                        ctx.u_instance,
                        "sds-host",
                    ),
                    input_field(
                        &ctx,
                        |_| "Optional Remote SSH Target (empty = local)".into(),
                        ctx.u_ssh,
                        "user@linux-host",
                    ),
                ))
                .style(|s| s.gap(10.0).items_end().width_full()),
                h_stack((
                    Checkbox::labeled_rw(ctx.u_purge_config, move || {
                        if lang.get() == UiLang::Ru {
                            "Удалить также конфиги, ключи и сертификаты (--purge-config)"
                                .to_string()
                        } else {
                            "Also purge configs, keys & certificates (--purge-config)".to_string()
                        }
                    }),
                    Checkbox::labeled_rw(ctx.u_remove_firewall, move || {
                        "Remove SDS firewall rules".to_string()
                    }),
                    Checkbox::labeled_rw(ctx.u_pq_ssh, move || "PQ SSH".to_string()),
                    Checkbox::labeled_rw(ctx.u_sudo, move || "sudo -n".to_string()),
                ))
                .style(|s| s.gap(10.0).flex_wrap(floem::style::FlexWrap::Wrap)),
                h_stack((
                    styled_btn(
                        &ctx,
                        |l| tr(l, "btn_dry_run_uninstall").into(),
                        false,
                        move || trigger_uninstall(&c_dry, true),
                    ),
                    styled_btn(
                        &ctx,
                        |l| tr(l, "btn_uninstall").into(),
                        true,
                        move || {
                            let conf = if c_run.u_purge_config.get_untracked() {
                                PendingConfirmation::UninstallPurge
                            } else {
                                PendingConfirmation::Uninstall
                            };
                            c_run.pending_confirm.set(Some(conf));
                        },
                    ),
                ))
                .style(|s| s.gap(8.0)),
            ))
            .style(|s| s.gap(10.0).width_full()),
        ),
        dyn_container(
            move || c_res.uninstall_result.get(),
            move |opt| match opt {
                None => empty().into_any(),
                Some(res) => {
                    let mut text = format!(
                        "{} (dry_run={}, ok={}, verified_clean={})\n",
                        res.summary, res.dry_run, res.ok, res.verified_clean
                    );
                    if !res.removed_paths.is_empty() {
                        text.push_str("Removed:\n  ");
                        text.push_str(&res.removed_paths.join("\n  "));
                        text.push('\n');
                    }
                    if !res.remaining_artifacts.is_empty() {
                        text.push_str("Planned / Remaining:\n  ");
                        text.push_str(&res.remaining_artifacts.join("\n  "));
                        text.push('\n');
                    }
                    if !res.elevated_commands.is_empty() {
                        text.push_str("Elevated Commands:\n  ");
                        text.push_str(&res.elevated_commands.join("\n  "));
                    }
                    card(
                        theme,
                        label(move || text.clone()).style(|s| s.font_size(12.5)),
                    )
                    .into_any()
                }
            },
        ),
    ))
    .style(|s| s.gap(10.0).width_full())
}

fn action_result_card(
    res_sig: RwSignal<Option<ActionResult>>,
    theme: RwSignal<UiTheme>,
) -> impl IntoView {
    dyn_container(
        move || res_sig.get(),
        move |opt| match opt {
            None => empty().into_any(),
            Some(res) => {
                let mut text =
                    format!("{} (dry_run={}, ok={})\n", res.summary, res.dry_run, res.ok);
                if let Some(ref p) = res.installed_path {
                    text.push_str(&format!("Path: {p}\n"));
                }
                if !res.commands_executed_or_planned.is_empty() {
                    text.push_str("Steps:\n  ");
                    text.push_str(&res.commands_executed_or_planned.join("\n  "));
                    text.push('\n');
                }
                if !res.elevated_commands.is_empty() {
                    text.push_str("Elevated (sudo / Admin):\n  ");
                    text.push_str(&res.elevated_commands.join("\n  "));
                }
                card(
                    theme,
                    label(move || text.clone()).style(|s| s.font_size(12.5)),
                )
                .into_any()
            }
        },
    )
}

fn log_panel(ctx: GuiCtx) -> impl IntoView {
    let lang = ctx.lang;
    let theme = ctx.theme;
    let log_text = ctx.log_text;
    let c_clear = ctx.clone();

    card(
        theme,
        v_stack((
            h_stack((
                label(move || tr(lang.get(), "logs_title").to_string())
                    .style(|s| s.flex_grow(1.0_f32).font_bold().font_size(12.5)),
                styled_btn(
                    &ctx,
                    |_| "Clear".into(),
                    false,
                    move || {
                        if let Ok(mut g) = c_clear.log_buffer.lock() {
                            g.clear();
                        }
                        c_clear.log_text.set(String::new());
                    },
                ),
            ))
            .style(|s| s.width_full().items_center()),
            scroll(label(move || log_text.get()).style(move |s| {
                let pal = palette(theme.get());
                s.font_size(11.5).color(pal.muted)
            }))
            .style(|s| s.height(110.0).width_full()),
        ))
        .style(|s| s.gap(4.0)),
    )
}

// --- Background Tokio Task Triggers ---

fn bump_busy(sig: RwSignal<usize>) {
    sig.update(|c| *c = c.saturating_add(1));
}

fn drop_busy(sig: RwSignal<usize>) {
    sig.update(|c| *c = c.saturating_sub(1));
}

fn trigger_preflight(ctx: &GuiCtx) {
    let root = ctx.repo_root.clone();
    let pf_sig = ctx.preflight;
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    bump_busy(busy);
    status.set("Scanning preflight...".into());
    let done = create_ext_action(ctx.root_scope, move |report: PreflightReport| {
        pf_sig.set(Some(report));
        drop_busy(busy);
        status.set("Ready".into());
    });
    ctx.rt.spawn(async move {
        let rep = tokio::task::spawn_blocking(move || collect_preflight(root.as_deref()))
            .await
            .unwrap_or_else(|_| collect_preflight(None));
        done(rep);
    });
}

fn trigger_deps_check(ctx: &GuiCtx) {
    let req = match ctx.snapshot_deps_form().to_check_request() {
        Ok(r) => r,
        Err(e) => {
            ctx.push_log(format!("[error] [deps] {e}"));
            return;
        }
    };
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let rep_sig = ctx.deps_report;
    let ctx_log = ctx.clone();
    bump_busy(busy);
    status.set("Checking dependencies...".into());
    let done = create_ext_action(
        ctx.root_scope,
        move |res: Result<DependencyCheckReport, String>| {
            drop_busy(busy);
            match res {
                Ok(r) => {
                    status.set(format!(
                        "Deps ({}): satisfied={}, missing={}",
                        r.role.as_str(),
                        r.all_satisfied,
                        r.missing_required.len()
                    ));
                    rep_sig.set(Some(r));
                }
                Err(e) => {
                    status.set(format!("Deps check error: {e}"));
                    ctx_log.push_log(format!("[error] [deps] {e}"));
                }
            }
        },
    );
    ctx.rt.spawn(async move {
        done(check_dependencies(&req).await);
    });
}

fn trigger_deps_install(ctx: &GuiCtx, dry_run: bool) {
    let req = match ctx.snapshot_deps_form().to_install_request(dry_run) {
        Ok(r) => r,
        Err(e) => {
            ctx.push_log(format!("[error] [deps] {e}"));
            return;
        }
    };
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let out_sig = ctx.deps_install_res;
    let rep_sig = ctx.deps_report;
    let ctx_log = ctx.clone();
    bump_busy(busy);
    status.set("Resolving dependencies...".into());
    let done = create_ext_action(
        ctx.root_scope,
        move |res: Result<DependencyInstallResult, String>| {
            drop_busy(busy);
            match res {
                Ok(r) => {
                    status.set(r.summary.clone());
                    let latest = r.after.clone().unwrap_or_else(|| r.before.clone());
                    rep_sig.set(Some(latest));
                    out_sig.set(Some(r));
                }
                Err(e) => {
                    status.set(format!("Deps install error: {e}"));
                    ctx_log.push_log(format!("[error] [deps] {e}"));
                }
            }
        },
    );
    ctx.rt.spawn(async move {
        done(install_missing_dependencies(&req, &emit).await);
    });
}

fn trigger_client_install(ctx: &GuiCtx, dry_run: bool) {
    let mut req: ClientInstallRequest = match ctx
        .snapshot_client_form()
        .to_client_install_request(dry_run)
    {
        Ok(r) => r,
        Err(e) => {
            ctx.push_log(format!("[error] [client] {e}"));
            return;
        }
    };
    if let ClientSource::FromSource { ref mut repo_root } = req.source {
        if repo_root.is_none() {
            *repo_root = ctx.repo_root.as_ref().map(|p| p.display().to_string());
        }
    }
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let out_sig = ctx.client_action;
    let ctx_log = ctx.clone();
    bump_busy(busy);
    status.set("Client install...".into());
    let done = create_ext_action(ctx.root_scope, move |res: Result<ActionResult, String>| {
        drop_busy(busy);
        match res {
            Ok(r) => {
                status.set(r.summary.clone());
                out_sig.set(Some(r));
            }
            Err(e) => {
                status.set(format!("Error: {e}"));
                ctx_log.push_log(format!("[error] [client] {e}"));
            }
        }
    });
    ctx.rt.spawn(async move {
        done(install_client(&req, &emit).await);
    });
}

fn trigger_local_host(ctx: &GuiCtx, dry_run: bool) {
    let root = ctx.repo_root.as_ref().map(|p| p.display().to_string());
    let req: LocalHostInstallRequest = match ctx
        .snapshot_host_form()
        .to_local_host_request(dry_run, root)
    {
        Ok(r) => r,
        Err(e) => {
            ctx.push_log(format!("[error] [host] {e}"));
            return;
        }
    };
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let out_sig = ctx.host_action;
    let ctx_log = ctx.clone();
    bump_busy(busy);
    status.set("Local host setup...".into());
    let done = create_ext_action(ctx.root_scope, move |res: Result<ActionResult, String>| {
        drop_busy(busy);
        match res {
            Ok(r) => {
                status.set(r.summary.clone());
                out_sig.set(Some(r));
            }
            Err(e) => {
                status.set(format!("Error: {e}"));
                ctx_log.push_log(format!("[error] [host] {e}"));
            }
        }
    });
    ctx.rt.spawn(async move {
        done(install_host_local(&req, &emit).await);
    });
}

fn trigger_ssh_deploy(ctx: &GuiCtx, dry_run: bool) {
    let req: SshDeployRequest = match ctx.snapshot_host_form().to_ssh_deploy_request(dry_run) {
        Ok(r) => r,
        Err(e) => {
            ctx.push_log(format!("[error] [deploy-ssh] {e}"));
            return;
        }
    };
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let out_sig = ctx.host_action;
    let ctx_log = ctx.clone();
    bump_busy(busy);
    status.set("PQ SSH deploy...".into());
    let done = create_ext_action(ctx.root_scope, move |res: Result<ActionResult, String>| {
        drop_busy(busy);
        match res {
            Ok(r) => {
                status.set(r.summary.clone());
                out_sig.set(Some(r));
            }
            Err(e) => {
                status.set(format!("Error: {e}"));
                ctx_log.push_log(format!("[error] [deploy-ssh] {e}"));
            }
        }
    });
    ctx.rt.spawn(async move {
        done(deploy_host_ssh(&req, &emit).await);
    });
}

fn trigger_probe(ctx: &GuiCtx) {
    let req = match ctx.snapshot_probe_form().to_probe_request() {
        Ok(r) => r,
        Err(e) => {
            ctx.push_log(format!("[error] [probe] {e}"));
            return;
        }
    };
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let out_sig = ctx.probe_report;
    let ctx_log = ctx.clone();
    bump_busy(busy);
    status.set("Probing host PQ TLS 1.3...".into());
    let done = create_ext_action(
        ctx.root_scope,
        move |res: Result<HostProbeReport, String>| {
            drop_busy(busy);
            match res {
                Ok(r) => {
                    status.set(format!("Probe: {:?}", r.verdict));
                    out_sig.set(Some(r));
                }
                Err(e) => {
                    status.set(format!("Probe error: {e}"));
                    ctx_log.push_log(format!("[error] [probe] {e}"));
                }
            }
        },
    );
    ctx.rt.spawn(async move {
        done(probe_host(&req).await);
    });
}

fn trigger_open_pairing(ctx: &GuiCtx) {
    let req = match ctx.snapshot_probe_form().to_open_pairing_request(false) {
        Ok(r) => r,
        Err(e) => {
            ctx.push_log(format!("[error] [pairing] {e}"));
            return;
        }
    };
    let mgr = ctx.pairing_mgr.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let open_sig = ctx.pairing_open;
    let st_sig = ctx.pairing_status;
    bump_busy(busy);
    status.set("Opening PQ SSH pairing tunnel...".into());
    let done = create_ext_action(
        ctx.root_scope,
        move |res: Result<OpenPairingResponse, String>| {
            drop_busy(busy);
            match res {
                Ok(r) => {
                    status.set(format!(
                        "Pairing tunnel ready on 127.0.0.1:{}",
                        r.local_tunnel_port
                    ));
                    st_sig.set(Some(format!(
                        "Tunnel ready 127.0.0.1:{} -> 47990 | SHA-256: {} | 47989 auto-opened: {}",
                        r.local_tunnel_port, r.cert_sha256_hex, r.firewall_opened_automatically
                    )));
                    open_sig.set(Some(r));
                }
                Err(e) => {
                    status.set(format!("Pairing open failed: {e}"));
                    st_sig.set(Some(format!("Pairing open failed: {e}")));
                }
            }
        },
    );
    ctx.rt.spawn(async move {
        done(open_pairing_session(&mgr, &req, &emit).await);
    });
}

fn trigger_submit_pin(ctx: &GuiCtx) {
    let sess_id = ctx
        .pairing_open
        .get_untracked()
        .map(|s| s.session_id)
        .unwrap_or_default();
    let req = match ctx.snapshot_probe_form().to_submit_pin_request(&sess_id) {
        Ok(r) => r,
        Err(e) => {
            ctx.pairing_status.set(Some(format!("Error: {e}")));
            return;
        }
    };
    ctx.p_admin_pass.set(String::new());
    ctx.p_pin.set(String::new());

    let mgr = ctx.pairing_mgr.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let st_sig = ctx.pairing_status;
    bump_busy(busy);
    status.set("Submitting PIN over pinned PQ TLS...".into());
    let done = create_ext_action(
        ctx.root_scope,
        move |res: Result<SubmitPairingPinResponse, String>| {
            drop_busy(busy);
            match res {
                Ok(r) => {
                    status.set(r.message.clone());
                    st_sig.set(Some(format!(
                        "Paired={} | UUID={:?} | Perms={:?} | {}",
                        r.paired, r.client_uuid, r.applied_permissions, r.message
                    )));
                }
                Err(e) => {
                    status.set(format!("Submit PIN failed: {e}"));
                    st_sig.set(Some(format!("Submit PIN failed: {e}")));
                }
            }
        },
    );
    ctx.rt.spawn(async move {
        done(submit_pairing_pin(&mgr, &req, &emit).await);
    });
}

fn trigger_close_pairing(ctx: &GuiCtx) {
    let Some(open) = ctx.pairing_open.get_untracked() else {
        ctx.status_line
            .set("No active pairing session to close".into());
        ctx.pairing_status
            .set(Some("No active pairing session to close".into()));
        return;
    };
    let req = ClosePairingRequest {
        session_id: open.session_id,
        execute_sudo_firewall: ctx.p_sudo_fw.get_untracked(),
        dry_run: false,
    };
    let mgr = ctx.pairing_mgr.clone();
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let open_sig = ctx.pairing_open;
    let st_sig = ctx.pairing_status;
    let probe_sig = ctx.probe_report;
    bump_busy(busy);
    status.set("Closing pairing tunnel & locking 47989/tcp...".into());
    let done = create_ext_action(
        ctx.root_scope,
        move |res: Result<ClosePairingResponse, String>| {
            drop_busy(busy);
            open_sig.set(None);
            match res {
                Ok(r) => {
                    status.set("Pairing session closed and verified".into());
                    st_sig.set(Some(format!(
                        "Closed tunnel | 47989 auto-closed: {} | Close cmds: {}",
                        r.firewall_closed_automatically,
                        r.close_firewall_commands.join("; ")
                    )));
                    if let Some(pr) = r.post_lockdown_probe {
                        probe_sig.set(Some(pr));
                    }
                }
                Err(e) => {
                    status.set(format!("Close pairing error: {e}"));
                    st_sig.set(Some(format!("Close pairing error: {e}")));
                }
            }
        },
    );
    ctx.rt.spawn(async move {
        done(close_pairing_session(&mgr, &req, &emit).await);
    });
}

fn trigger_uninstall(ctx: &GuiCtx, dry_run: bool) {
    let req = match ctx.snapshot_uninstall_form().to_uninstall_request(dry_run) {
        Ok(r) => r,
        Err(e) => {
            ctx.push_log(format!("[error] [uninstall] {e}"));
            return;
        }
    };
    let emit = ProgressEmitter::new(Some(ctx.events_tx.clone()));
    let busy = ctx.busy_count;
    let status = ctx.status_line;
    let out_sig = ctx.uninstall_result;
    let ctx_log = ctx.clone();
    bump_busy(busy);
    status.set("Running uninstaller...".into());
    let done = create_ext_action(
        ctx.root_scope,
        move |res: Result<UninstallResult, String>| {
            drop_busy(busy);
            match res {
                Ok(r) => {
                    status.set(r.summary.clone());
                    out_sig.set(Some(r));
                }
                Err(e) => {
                    status.set(format!("Uninstall error: {e}"));
                    ctx_log.push_log(format!("[error] [uninstall] {e}"));
                }
            }
        },
    );
    ctx.rt.spawn(async move {
        done(run_uninstall(&req, &emit).await);
    });
}
