//! Hardened configuration, systemd unit, desktop isolation, and firewall generator
//! for Linux (Virtual X11 / Physical X11) and Windows hosts.

use crate::validation::{
    validate_instance_name, validate_ipv4_or_ipv6_literal, validate_render_device,
    validate_resolution, validate_x11_display,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostProfileKind {
    LinuxVirtualX11,
    LinuxPhysicalX11,
    WindowsHost,
}

impl HostProfileKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxVirtualX11 => "linux-virtual-x11",
            Self::LinuxPhysicalX11 => "linux-physical-x11",
            Self::WindowsHost => "windows-host",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncoderKind {
    Auto,
    Vaapi,
    Nvenc,
    Amf,
    Quicksync,
    Software,
}

impl EncoderKind {
    pub fn sunshine_value(self, profile: HostProfileKind) -> Option<&'static str> {
        match self {
            Self::Auto => match profile {
                HostProfileKind::LinuxVirtualX11 | HostProfileKind::LinuxPhysicalX11 => {
                    Some("vaapi")
                }
                HostProfileKind::WindowsHost => None,
            },
            Self::Vaapi => Some("vaapi"),
            Self::Nvenc => Some("nvenc"),
            Self::Amf => Some("amdvce"),
            Self::Quicksync => Some("quicksync"),
            Self::Software => Some("software"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallBackend {
    Auto,
    Ufw,
    Firewalld,
    Nftables,
    Windows,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfigParams {
    #[serde(default = "default_instance_name")]
    pub instance_name: String,
    pub controller_ip: String,
    pub profile: HostProfileKind,
    #[serde(default = "default_display")]
    pub display: String,
    #[serde(default = "default_resolution")]
    pub resolution: String,
    #[serde(default = "default_encoder")]
    pub encoder: EncoderKind,
    #[serde(default)]
    pub render_device: Option<String>,
    #[serde(default = "default_true")]
    pub enable_clipboard: bool,
    #[serde(default = "default_true")]
    pub enable_file_transfer: bool,
    #[serde(default = "default_true")]
    pub enable_native_file_clipboard: bool,
    #[serde(default = "default_true")]
    pub enable_mic: bool,
    #[serde(default = "default_firewall")]
    pub firewall_backend: FirewallBackend,
    #[serde(default)]
    pub install_dir: Option<String>,
}

fn default_instance_name() -> String {
    "sds-host".to_string()
}
fn default_display() -> String {
    ":97".to_string()
}
fn default_resolution() -> String {
    "1920x1080".to_string()
}
fn default_encoder() -> EncoderKind {
    EncoderKind::Auto
}
fn default_firewall() -> FirewallBackend {
    FirewallBackend::Auto
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedFile {
    pub rel_path: String,
    pub target_hint: String,
    pub mode: String,
    pub requires_root: bool,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallCommands {
    pub backend: String,
    pub setup_streaming: Vec<String>,
    pub open_pairing_47989: Vec<String>,
    pub close_pairing_47989: Vec<String>,
    #[serde(default)]
    pub remove_firewall: Vec<String>,
    pub verify_status: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedBundle {
    pub instance_name: String,
    pub profile: HostProfileKind,
    pub controller_ip: String,
    pub install_dir: String,
    pub files: BTreeMap<String, GeneratedFile>,
    pub firewall: FirewallCommands,
    pub commands_preview: Vec<String>,
    pub security_notes: Vec<String>,
}

fn validate_safe_install_dir(raw: &str, profile: HostProfileKind) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 200
        || trimmed.contains('\0')
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains("..")
        || trimmed.contains('\'')
        || trimmed.contains('"')
        || trimmed.contains('$')
        || trimmed.contains('`')
        || trimmed.contains(';')
    {
        return Err(format!("unsafe install_dir: {trimmed}"));
    }
    match profile {
        HostProfileKind::WindowsHost => {
            let valid = trimmed.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, ':' | '\\' | '/' | '_' | '-' | '.' | '%' | ' ')
            });
            if !valid {
                return Err(format!("invalid Windows install_dir: {trimmed}"));
            }
        }
        HostProfileKind::LinuxVirtualX11 | HostProfileKind::LinuxPhysicalX11 => {
            if !trimmed.starts_with('/') {
                return Err(format!("Linux install_dir must be absolute: {trimmed}"));
            }
            let valid = trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'));
            if !valid {
                return Err(format!("invalid Linux install_dir: {trimmed}"));
            }
        }
    }
    Ok(trimmed.to_string())
}

/// Validates parameters and synthesizes a complete hardened host configuration bundle.
pub fn generate_host_bundle(params: &HostConfigParams) -> Result<GeneratedBundle, String> {
    let instance = validate_instance_name(&params.instance_name).map_err(|e| e.to_string())?;
    let controller_ip =
        validate_ipv4_or_ipv6_literal(&params.controller_ip).map_err(|e| e.to_string())?;
    let display = validate_x11_display(&params.display).map_err(|e| e.to_string())?;
    let display_num = display.trim_start_matches(':');
    let (width, height) = validate_resolution(&params.resolution).map_err(|e| e.to_string())?;
    let render_device = match params.render_device.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            Some(validate_render_device(raw).map_err(|e| e.to_string())?)
        }
        _ => None,
    };

    let install_dir = match params.install_dir.as_deref() {
        Some(raw) if !raw.trim().is_empty() => validate_safe_install_dir(raw, params.profile)?,
        _ => match params.profile {
            HostProfileKind::WindowsHost => {
                r"%LOCALAPPDATA%\Programs\SecureDesktopStream\Sunshine".to_string()
            }
            HostProfileKind::LinuxVirtualX11 | HostProfileKind::LinuxPhysicalX11 => {
                format!("/opt/secure-desktop-stream-{instance}")
            }
        },
    };

    let effective_fw = match (params.profile, params.firewall_backend) {
        (HostProfileKind::WindowsHost, _) | (_, FirewallBackend::Windows) => {
            FirewallBackend::Windows
        }
        (_, FirewallBackend::Auto) => FirewallBackend::Ufw,
        (_, other) => other,
    };

    let firewall = generate_firewall_commands(effective_fw, controller_ip, params.enable_mic);
    let mut files = BTreeMap::new();
    let mut commands_preview = Vec::new();
    let mut security_notes = vec![
        "Web Admin UI stays bound to loopback only (origin_web_ui_allowed = pc; port 47990 blocked by firewall).".into(),
        "Mandatory LAN and WAN encryption (lan_encryption_mode = 2, wan_encryption_mode = 2), UPnP/mDNS disabled.".into(),
        "Default paired client permissions are empty; grant clipboard/files/mic explicitly per paired certificate.".into(),
    ];

    let sunshine_conf = render_sunshine_conf(
        &instance,
        params.profile,
        params.encoder,
        render_device.as_deref(),
        params.enable_clipboard,
        params.enable_file_transfer,
        params.enable_native_file_clipboard,
        params.enable_mic,
    );
    files.insert(
        "sunshine.conf".into(),
        GeneratedFile {
            rel_path: "sunshine.conf".into(),
            target_hint: match params.profile {
                HostProfileKind::WindowsHost => {
                    format!(r"{install_dir}\config\sunshine.conf")
                }
                _ => format!("~/.config/{instance}-sunshine/sunshine.conf"),
            },
            mode: "0600".into(),
            requires_root: false,
            content: sunshine_conf,
        },
    );

    match params.profile {
        HostProfileKind::LinuxVirtualX11 => {
            let display_unit = format!("{instance}-display.service");
            let audio_unit = format!("{instance}-audio.service");
            let sunshine_unit = format!("{instance}-sunshine.service");
            let output_sink = format!("{instance}-output");

            files.insert(
                "start-display.sh".into(),
                GeneratedFile {
                    rel_path: "start-display.sh".into(),
                    target_hint: format!("{install_dir}/start-display.sh"),
                    mode: "0755".into(),
                    requires_root: true,
                    content: render_start_display_sh(
                        &instance,
                        &display,
                        display_num,
                        width,
                        height,
                    ),
                },
            );
            files.insert(
                "audio/start-audio.sh".into(),
                GeneratedFile {
                    rel_path: "audio/start-audio.sh".into(),
                    target_hint: format!("{install_dir}/audio/start-audio.sh"),
                    mode: "0755".into(),
                    requires_root: true,
                    content: render_start_audio_sh(&output_sink),
                },
            );
            files.insert(
                "audio/pipewire/pipewire.conf.d/50-sds-output.conf".into(),
                GeneratedFile {
                    rel_path: "audio/pipewire/pipewire.conf.d/50-sds-output.conf".into(),
                    target_hint: format!(
                        "{install_dir}/audio/pipewire/pipewire.conf.d/50-sds-output.conf"
                    ),
                    mode: "0644".into(),
                    requires_root: true,
                    content: render_pw_output_conf(&output_sink),
                },
            );
            files.insert(
                "audio/pipewire/pipewire-pulse.conf.d/50-sds-no-dynamic-sinks.conf".into(),
                GeneratedFile {
                    rel_path: "audio/pipewire/pipewire-pulse.conf.d/50-sds-no-dynamic-sinks.conf".into(),
                    target_hint: format!("{install_dir}/audio/pipewire/pipewire-pulse.conf.d/50-sds-no-dynamic-sinks.conf"),
                    mode: "0644".into(),
                    requires_root: true,
                    content: "pulse.properties = {\n    pulse.allow-module-loading = false\n}\n".into(),
                },
            );
            files.insert(
                "audio/wireplumber/wireplumber.conf.d/50-sds-private.conf".into(),
                GeneratedFile {
                    rel_path: "audio/wireplumber/wireplumber.conf.d/50-sds-private.conf".into(),
                    target_hint: format!("{install_dir}/audio/wireplumber/wireplumber.conf.d/50-sds-private.conf"),
                    mode: "0644".into(),
                    requires_root: true,
                    content: "wireplumber.profiles = {\n  sds-private = { inherits = [ policy, mixin.systemwide-session ] }\n}\n".into(),
                },
            );
            files.insert(
                "pipewire/client.conf.d/50-sds-microphone-priority.conf".into(),
                GeneratedFile {
                    rel_path: "pipewire/client.conf.d/50-sds-microphone-priority.conf".into(),
                    target_hint: format!("~/.config/{instance}-sunshine/config/pipewire/client.conf.d/50-sds-microphone-priority.conf"),
                    mode: "0600".into(),
                    requires_root: false,
                    content: "stream.rules = [ { matches = [ { node.name = \"sunshine-mic\" media.class = \"Audio/Source\" } ] actions = { update-props = { priority.session = 3000 } } } ]\n".into(),
                },
            );

            // NOTE: Intentionally NO NoNewPrivileges on sds-display.service so interactive sudo inside the virtual desktop works!
            files.insert(
                format!("systemd/{display_unit}"),
                GeneratedFile {
                    rel_path: format!("systemd/{display_unit}"),
                    target_hint: format!("~/.config/systemd/user/{display_unit}"),
                    mode: "0644".into(),
                    requires_root: false,
                    content: render_virtual_display_unit(
                        &instance,
                        &display,
                        &install_dir,
                        &sunshine_unit,
                    ),
                },
            );
            files.insert(
                format!("systemd/{audio_unit}"),
                GeneratedFile {
                    rel_path: format!("systemd/{audio_unit}"),
                    target_hint: format!("~/.config/systemd/user/{audio_unit}"),
                    mode: "0644".into(),
                    requires_root: false,
                    content: render_virtual_audio_unit(&instance, &install_dir),
                },
            );
            files.insert(
                format!("systemd/{sunshine_unit}"),
                GeneratedFile {
                    rel_path: format!("systemd/{sunshine_unit}"),
                    target_hint: format!("~/.config/systemd/user/{sunshine_unit}"),
                    mode: "0644".into(),
                    requires_root: false,
                    content: render_virtual_sunshine_unit(
                        &instance,
                        &display,
                        &install_dir,
                        &display_unit,
                    ),
                },
            );
            files.insert(
                "systemd/drop-ins/20-private-audio.conf".into(),
                GeneratedFile {
                    rel_path: "systemd/drop-ins/20-private-audio.conf".into(),
                    target_hint: format!(
                        "~/.config/systemd/user/{sunshine_unit}.d/20-private-audio.conf"
                    ),
                    mode: "0644".into(),
                    requires_root: false,
                    content: render_audio_dropin(&instance, &audio_unit, &output_sink),
                },
            );
            files.insert(
                "systemd/drop-ins/20-private-audio-display.conf".into(),
                GeneratedFile {
                    rel_path: "systemd/drop-ins/20-private-audio-display.conf".into(),
                    target_hint: format!(
                        "~/.config/systemd/user/{display_unit}.d/20-private-audio.conf"
                    ),
                    mode: "0644".into(),
                    requires_root: false,
                    content: render_audio_dropin(&instance, &audio_unit, &output_sink),
                },
            );
            files.insert(
                "systemd/drop-ins/30-private-x11-input.conf".into(),
                GeneratedFile {
                    rel_path: "systemd/drop-ins/30-private-x11-input.conf".into(),
                    target_hint: format!(
                        "~/.config/systemd/user/{sunshine_unit}.d/30-private-x11-input.conf"
                    ),
                    mode: "0644".into(),
                    requires_root: false,
                    content: format!(
                        "[Service]\nEnvironment=SUNSHINE_PRIVATE_X11_INPUT={display}\n"
                    ),
                },
            );
            if params.enable_native_file_clipboard {
                files.insert(
                    "systemd/drop-ins/40-native-file-clipboard.conf".into(),
                    GeneratedFile {
                        rel_path: "systemd/drop-ins/40-native-file-clipboard.conf".into(),
                        target_hint: format!(
                            "~/.config/systemd/user/{sunshine_unit}.d/40-native-file-clipboard.conf"
                        ),
                        mode: "0644".into(),
                        requires_root: false,
                        content: "[Service]\nEnvironment=SDS_FILE_CLIPBOARD=1\n".into(),
                    },
                );
            }
            files.insert(
                "lxqt/lxqt.conf".into(),
                GeneratedFile {
                    rel_path: "lxqt/lxqt.conf".into(),
                    target_hint: format!("~/.config/{instance}-desktop/lxqt/lxqt.conf"),
                    mode: "0600".into(),
                    requires_root: false,
                    content: include_lxqt_conf().into(),
                },
            );
            files.insert(
                "lxqt/panel.conf".into(),
                GeneratedFile {
                    rel_path: "lxqt/panel.conf".into(),
                    target_hint: format!("~/.config/{instance}-desktop/lxqt/panel.conf"),
                    mode: "0600".into(),
                    requires_root: false,
                    content: include_panel_conf().into(),
                },
            );
            files.insert(
                format!("lxqt/pcmanfm-qt/{instance}/settings.conf"),
                GeneratedFile {
                    rel_path: format!("lxqt/pcmanfm-qt/{instance}/settings.conf"),
                    target_hint: format!(
                        "~/.config/{instance}-desktop/pcmanfm-qt/{instance}/settings.conf"
                    ),
                    mode: "0600".into(),
                    requires_root: false,
                    content: include_pcmanfm_conf().into(),
                },
            );
            files.insert(
                "lxqt/user-dirs.dirs".into(),
                GeneratedFile {
                    rel_path: "lxqt/user-dirs.dirs".into(),
                    target_hint: format!("~/.config/{instance}-desktop/user-dirs.dirs"),
                    mode: "0600".into(),
                    requires_root: false,
                    content: format!(
                        "XDG_DESKTOP_DIR=\"$HOME/.local/share/{instance}-desktop/Desktop\"\n"
                    ),
                },
            );

            commands_preview.push("sudo loginctl enable-linger \"$USER\"".into());
            commands_preview.push("systemctl --user daemon-reload".into());
            commands_preview.push(format!(
                "systemctl --user enable --now {audio_unit} {display_unit} {sunshine_unit}"
            ));
            security_notes.push(
                "Display unit intentionally omits NoNewPrivileges so sudo works inside the virtual desktop, while Sunshine and private PipeWire run with NoNewPrivileges=true.".into(),
            );
        }
        HostProfileKind::LinuxPhysicalX11 => {
            let sunshine_unit = format!("{instance}-sunshine.service");
            files.insert(
                format!("systemd/{sunshine_unit}"),
                GeneratedFile {
                    rel_path: format!("systemd/{sunshine_unit}"),
                    target_hint: format!("~/.config/systemd/user/{sunshine_unit}"),
                    mode: "0644".into(),
                    requires_root: false,
                    content: render_physical_sunshine_unit(&instance, &install_dir),
                },
            );
            files.insert(
                format!("{instance}-session.sh"),
                GeneratedFile {
                    rel_path: format!("{instance}-session.sh"),
                    target_hint: format!("{install_dir}/{instance}-session.sh"),
                    mode: "0755".into(),
                    requires_root: true,
                    content: render_physical_session_script(
                        &instance,
                        &sunshine_unit,
                        width,
                        height,
                    ),
                },
            );
            files.insert(
                "60-sds-uinput.rules".into(),
                GeneratedFile {
                    rel_path: "60-sds-uinput.rules".into(),
                    target_hint: "/etc/udev/rules.d/60-sds-uinput.rules".into(),
                    mode: "0644".into(),
                    requires_root: true,
                    content:
                        "SUBSYSTEM==\"misc\", KERNEL==\"uinput\", MODE=\"0660\", TAG+=\"uaccess\"\n"
                            .into(),
                },
            );
            files.insert(
                "pipewire/client.conf.d/50-sds-microphone-priority.conf".into(),
                GeneratedFile {
                    rel_path: "pipewire/client.conf.d/50-sds-microphone-priority.conf".into(),
                    target_hint: format!("~/.config/{instance}-sunshine/config/pipewire/client.conf.d/50-sds-microphone-priority.conf"),
                    mode: "0600".into(),
                    requires_root: false,
                    content: "stream.rules = [ { matches = [ { node.name = \"sunshine-mic\" media.class = \"Audio/Source\" } ] actions = { update-props = { priority.session = 3000 } } } ]\n".into(),
                },
            );
            if params.enable_native_file_clipboard {
                files.insert(
                    "systemd/drop-ins/40-native-file-clipboard.conf".into(),
                    GeneratedFile {
                        rel_path: "systemd/drop-ins/40-native-file-clipboard.conf".into(),
                        target_hint: format!(
                            "~/.config/systemd/user/{sunshine_unit}.d/40-native-file-clipboard.conf"
                        ),
                        mode: "0644".into(),
                        requires_root: false,
                        content: "[Service]\nEnvironment=SDS_FILE_CLIPBOARD=1\n".into(),
                    },
                );
            }
            commands_preview.push(
                "sudo udevadm control --reload-rules && sudo udevadm trigger /dev/uinput".into(),
            );
            commands_preview.push("systemctl --user daemon-reload".into());
            security_notes.push(
                "If running picom on X11, keep backend = \"xrender\" (avoid backend = \"glx\", which can freeze X11 capture on fullscreen browser video).".into(),
            );
        }
        HostProfileKind::WindowsHost => {
            files.insert(
                "configure-windows-host.ps1".into(),
                GeneratedFile {
                    rel_path: "configure-windows-host.ps1".into(),
                    target_hint: format!(r"{install_dir}\configure-windows-host.ps1"),
                    mode: "0644".into(),
                    requires_root: true,
                    content: render_windows_host_ps1(
                        &install_dir,
                        controller_ip,
                        params.enable_mic,
                    ),
                },
            );
            security_notes.push(
                "Windows inbox/outbox directories are hardened with protected SDDL DACLs (session user + SYSTEM + Administrators only) and Zone.Identifier marking.".into(),
            );
        }
    }

    commands_preview.extend(firewall.setup_streaming.clone());

    Ok(GeneratedBundle {
        instance_name: instance,
        profile: params.profile,
        controller_ip: controller_ip.to_string(),
        install_dir,
        files,
        firewall,
        commands_preview,
        security_notes,
    })
}

/// Generates OS-specific host firewall rules strictly scoped to `controller_ip`.
pub fn generate_firewall_commands(
    backend: FirewallBackend,
    controller_ip: IpAddr,
    enable_mic: bool,
) -> FirewallCommands {
    let ip_str = controller_ip.to_string();
    match backend {
        FirewallBackend::Ufw | FirewallBackend::Auto => {
            let mut setup = vec![
                format!("sudo ufw allow in from {ip_str} to any port 47984 proto tcp comment \"sds-https\""),
                format!("sudo ufw allow in from {ip_str} to any port 48010 proto tcp comment \"sds-rtsp\""),
                format!("sudo ufw allow in from {ip_str} to any port 47998:48000 proto udp comment \"sds-av\""),
            ];
            if enable_mic {
                setup.push(format!(
                    "sudo ufw allow in from {ip_str} to any port 48002 proto udp comment \"sds-mic\""
                ));
            }
            setup.push(
                "sudo ufw deny in to any port 47990 proto tcp comment \"sds-block-webui\""
                    .to_string(),
            );
            FirewallCommands {
                backend: "ufw".into(),
                setup_streaming: setup,
                open_pairing_47989: vec![format!(
                    "sudo ufw allow in from {ip_str} to any port 47989 proto tcp comment \"sds-pairing\""
                )],
                close_pairing_47989: vec![format!(
                    "sudo ufw delete allow in from {ip_str} to any port 47989 proto tcp"
                )],
                remove_firewall: vec![
                    "sudo sh -c 'for n in $(ufw status numbered | awk \"/sds-(https|rtsp|av|mic|pairing|block-webui)/ && match(\\$0, /^\\[[[:space:]]*[0-9]+\\]/) { s=substr(\\$0, RSTART, RLENGTH); gsub(/[^0-9]/, \\\"\\\", s); print s }\" | sort -rn); do yes | ufw delete \"$n\"; done'".into(),
                ],
                verify_status: vec!["sudo ufw status numbered".into()],
            }
        }
        FirewallBackend::Firewalld => {
            let (family, cidr) = match controller_ip {
                IpAddr::V4(v4) => ("ipv4", format!("{v4}/32")),
                IpAddr::V6(v6) => ("ipv6", format!("{v6}/128")),
            };
            let mut setup = vec![
                format!("sudo firewall-cmd --permanent --add-rich-rule='rule family=\"{family}\" source address=\"{cidr}\" port port=\"47984\" protocol=\"tcp\" accept'"),
                format!("sudo firewall-cmd --permanent --add-rich-rule='rule family=\"{family}\" source address=\"{cidr}\" port port=\"48010\" protocol=\"tcp\" accept'"),
                format!("sudo firewall-cmd --permanent --add-rich-rule='rule family=\"{family}\" source address=\"{cidr}\" port port=\"47998-48000\" protocol=\"udp\" accept'"),
            ];
            if enable_mic {
                setup.push(format!("sudo firewall-cmd --permanent --add-rich-rule='rule family=\"{family}\" source address=\"{cidr}\" port port=\"48002\" protocol=\"udp\" accept'"));
            }
            setup.push(format!("sudo firewall-cmd --permanent --add-rich-rule='rule family=\"{family}\" port port=\"47990\" protocol=\"tcp\" reject'"));
            setup.push("sudo firewall-cmd --reload".into());
            let remove = vec![
                "sudo sh -c 'firewall-cmd --permanent --list-rich-rules | while IFS= read -r r; do case \"$r\" in *port=\"47984\"*|*port=\"48010\"*|*port=\"47998-48000\"*|*port=\"48002\"*|*port=\"47989\"*|*port=\"47990\"*) firewall-cmd --permanent --remove-rich-rule=\"$r\" || true ;; esac; done && firewall-cmd --reload'".into(),
            ];
            FirewallCommands {
                backend: "firewalld".into(),
                setup_streaming: setup,
                open_pairing_47989: vec![
                    format!("sudo firewall-cmd --add-rich-rule='rule family=\"{family}\" source address=\"{cidr}\" port port=\"47989\" protocol=\"tcp\" accept'"),
                ],
                close_pairing_47989: vec![
                    format!("sudo firewall-cmd --remove-rich-rule='rule family=\"{family}\" source address=\"{cidr}\" port port=\"47989\" protocol=\"tcp\" accept'"),
                ],
                remove_firewall: remove,
                verify_status: vec!["sudo firewall-cmd --list-rich-rules".into()],
            }
        }
        FirewallBackend::Nftables => {
            let (match_expr, ip_lit) = match controller_ip {
                IpAddr::V4(v4) => ("ip saddr", v4.to_string()),
                IpAddr::V6(v6) => ("ip6 saddr", v6.to_string()),
            };
            let mut setup = vec![
                "sudo nft add table inet sds_filter".into(),
                "sudo nft 'add chain inet sds_filter input { type filter hook input priority 0; policy accept; }'".into(),
                "sudo nft flush chain inet sds_filter input".into(),
                "sudo nft add rule inet sds_filter input iif \"lo\" accept".into(),
                "sudo nft add rule inet sds_filter input tcp dport 47990 drop comment \"sds-block-webui\"".into(),
                format!("sudo nft add rule inet sds_filter input {match_expr} {ip_lit} tcp dport {{ 47984, 48010 }} accept comment \"sds-tcp\""),
                format!("sudo nft add rule inet sds_filter input {match_expr} {ip_lit} udp dport 47998-48000 accept comment \"sds-av\""),
            ];
            if enable_mic {
                setup.push(format!(
                    "sudo nft add rule inet sds_filter input {match_expr} {ip_lit} udp dport 48002 accept comment \"sds-mic\""
                ));
            }
            setup.push(
                "sudo nft add rule inet sds_filter input tcp dport { 47984, 47989, 48010 } drop comment \"sds-drop-other-tcp\"".into()
            );
            setup.push(
                "sudo nft add rule inet sds_filter input udp dport { 47998-48002 } drop comment \"sds-drop-other-udp\"".into()
            );
            FirewallCommands {
                backend: "nftables".into(),
                setup_streaming: setup,
                open_pairing_47989: vec![format!(
                    "sudo nft insert rule inet sds_filter input {match_expr} {ip_lit} tcp dport 47989 accept comment \"sds-pairing\""
                )],
                close_pairing_47989: vec![
                    "sudo sh -c 'for h in $(nft -a list chain inet sds_filter input | awk \"/sds-pairing/ {print \\$NF}\"); do nft delete rule inet sds_filter input handle \"$h\"; done'".into(),
                ],
                remove_firewall: vec!["sudo nft delete table inet sds_filter".into()],
                verify_status: vec!["sudo nft list table inet sds_filter".into()],
            }
        }
        FirewallBackend::Windows => FirewallCommands {
            backend: "windows".into(),
            setup_streaming: vec![format!(
                "powershell -ExecutionPolicy Bypass -File configure-windows-host.ps1 -ControllerIp {ip_str}"
            )],
            open_pairing_47989: vec![format!(
                "powershell -ExecutionPolicy Bypass -File configure-windows-host.ps1 -ControllerIp {ip_str} -OpenPairing"
            )],
            close_pairing_47989: vec![format!(
                "powershell -ExecutionPolicy Bypass -File configure-windows-host.ps1 -ControllerIp {ip_str} -ClosePairing"
            )],
            remove_firewall: vec![
                "powershell -ExecutionPolicy Bypass -File configure-windows-host.ps1 -Uninstall".into(),
            ],
            verify_status: vec![
                "powershell -NoProfile -Command \"Get-NetFirewallRule -DisplayName 'SDS-*' | Select-Object DisplayName,Enabled,Direction,Action\"".into(),
            ],
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn render_sunshine_conf(
    instance: &str,
    profile: HostProfileKind,
    encoder: EncoderKind,
    render_device: Option<&str>,
    enable_clipboard: bool,
    enable_file_transfer: bool,
    enable_native_file_clipboard: bool,
    enable_mic: bool,
) -> String {
    let b = |v: bool| if v { "enabled" } else { "disabled" };
    let mut out = String::new();
    out.push_str("# Hardened Secure Desktop Stream configuration\n");
    out.push_str("origin_web_ui_allowed = pc\n");
    out.push_str("lan_encryption_mode = 2\n");
    out.push_str("wan_encryption_mode = 2\n");
    out.push_str("upnp = disabled\n");
    out.push_str("mdns_advertise = disabled\n");
    out.push_str("sds_default_permissions =\n");
    out.push_str("stream_audio = enabled\n");
    if profile == HostProfileKind::LinuxVirtualX11 {
        out.push_str(&format!("audio_sink = {instance}-output\n"));
    }
    out.push_str(&format!("clipboard = {}\n", b(enable_clipboard)));
    out.push_str(&format!("file_transfer = {}\n", b(enable_file_transfer)));
    out.push_str(&format!(
        "file_clipboard = {}\n",
        b(enable_native_file_clipboard)
    ));
    out.push_str(&format!("mic_passthrough = {}\n", b(enable_mic)));
    if let Some(enc) = encoder.sunshine_value(profile) {
        out.push_str(&format!("encoder = {enc}\n"));
    }
    if let Some(dev) = render_device {
        out.push_str(&format!("adapter_name = {dev}\n"));
    }
    out
}

fn render_start_display_sh(
    instance: &str,
    display: &str,
    display_num: &str,
    width: u32,
    height: u32,
) -> String {
    let mode = format!("{width}x{height}");
    let mut s = String::new();
    s.push_str("#!/usr/bin/env bash\n");
    s.push_str("set -euo pipefail\n");
    s.push_str("umask 077\n");
    s.push_str(": \"${RUNTIME_DIRECTORY:?start through systemd display service}\"\n");
    s.push_str(": \"${XAUTHORITY:?set service Xauthority path}\"\n");
    s.push_str("[[ -d $RUNTIME_DIRECTORY && ! -L $RUNTIME_DIRECTORY && $(stat -c %u:%a \"$RUNTIME_DIRECTORY\") == \"$UID:700\" ]]\n");
    s.push_str(&format!(
        "[[ $DISPLAY == {display} && $XAUTHORITY == \"$RUNTIME_DIRECTORY/Xauthority\" ]]\n"
    ));
    s.push_str("[[ ! -e $XAUTHORITY && ! -L $XAUTHORITY ]]\n");
    s.push_str("install -m 0600 /dev/null \"$XAUTHORITY\"\n");
    s.push_str("printf 'add %s MIT-MAGIC-COOKIE-1 %s\\n' \"$DISPLAY\" \"$(mcookie)\" | xauth -q -f \"$XAUTHORITY\"\n");
    s.push_str("notify_sock=${NOTIFY_SOCKET:-}\nunset NOTIFY_SOCKET\npids=()\n");
    s.push_str("cleanup() { trap - EXIT; if ((${#pids[@]})); then kill \"${pids[@]}\" 2>/dev/null || true; wait \"${pids[@]}\" 2>/dev/null || true; fi; }\n");
    s.push_str("trap cleanup EXIT\ntrap 'exit 143' TERM INT\n");
    s.push_str("xorg_conf=\"$RUNTIME_DIRECTORY/xorg.conf\"\n");
    s.push_str(&format!(
        "cat > \"$xorg_conf\" <<'EOF'\nSection \"ServerFlags\"\n    Option \"AutoAddDevices\" \"false\"\n    Option \"AllowEmptyInput\" \"true\"\n    Option \"DontVTSwitch\" \"true\"\n    Option \"DontZap\" \"true\"\nEndSection\nSection \"Device\"\n    Identifier \"DummyCard\"\n    Driver \"dummy\"\n    VideoRam 262144\nEndSection\nSection \"Monitor\"\n    Identifier \"DummyMonitor\"\n    HorizSync 5.0 - 1000.0\n    VertRefresh 5.0 - 240.0\nEndSection\nSection \"Screen\"\n    Identifier \"DummyScreen\"\n    Device \"DummyCard\"\n    Monitor \"DummyMonitor\"\n    DefaultDepth 24\n    SubSection \"Display\"\n        Depth 24\n        Virtual 4096 4096\n        Modes \"{mode}\"\n    EndSubSection\nEndSection\nEOF\n"
    ));
    s.push_str(&format!(
        "/usr/lib/xorg/Xorg \"$DISPLAY\" -config \"$xorg_conf\" -logfile \"$RUNTIME_DIRECTORY/Xorg.{display_num}.log\" -nolisten tcp -noreset -auth \"$XAUTHORITY\" &\n"
    ));
    s.push_str("x_pid=$!\npids+=(\"$x_pid\")\nready=0\n");
    s.push_str("for ((attempt=0; attempt<80; attempt++)); do\n    if xdpyinfo >/dev/null 2>&1; then ready=1; break; fi\n    kill -0 \"$x_pid\"; sleep .1\ndone\n(( ready == 1 ))\n");
    s.push_str(&format!(
        "[[ -f /tmp/.X{display_num}-lock && ! -L /tmp/.X{display_num}-lock && $(stat -c %u /tmp/.X{display_num}-lock) == \"$UID\" ]]\n"
    ));
    s.push_str(&format!(
        "[[ $(tr -d '[:space:]' < /tmp/.X{display_num}-lock) == \"$x_pid\" ]]\n"
    ));
    s.push_str("[[ -d /tmp/.X11-unix && ! -L /tmp/.X11-unix ]]\n");
    s.push_str(&format!(
        "[[ -S /tmp/.X11-unix/X{display_num} && ! -L /tmp/.X11-unix/X{display_num} && $(stat -c %u /tmp/.X11-unix/X{display_num}) == \"$UID\" ]]\n"
    ));
    s.push_str(&format!(
        "xrandr --output DUMMY0 --mode {mode} >/dev/null\nxset s off -dpms >/dev/null 2>&1 || true\n"
    ));
    s.push_str(&format!(
        "openbox &\nwm_pid=$!\npids+=(\"$wm_pid\")\npcmanfm-qt --desktop --profile {instance} &\ndesktop_pid=$!\npids+=(\"$desktop_pid\")\nlxqt-panel &\npanel_pid=$!\npids+=(\"$panel_pid\")\n"
    ));
    s.push_str("mapped_window() {\n    local tree=$1 class=$2 geometry=$3 window\n    while read -r window; do\n        if xwininfo -id \"$window\" | grep 'Map State: IsViewable' >/dev/null; then\n            return 0\n        fi\n    done < <(awk -v class=\"$class\" -v geometry=\"$geometry\" 'tolower($0) ~ class && $0 ~ geometry && $1 ~ /^0x[[:xdigit:]]+$/ {print $1}' <<<\"$tree\")\n    return 1\n}\n");
    s.push_str(&format!(
        "for ((attempt=0; attempt<160; attempt++)); do\n    tree=$(xwininfo -root -tree 2>/dev/null || true)\n    if xprop -root _NET_SUPPORTING_WM_CHECK | grep 'window id #' >/dev/null &&\n        mapped_window \"$tree\" '\"lxqt-panel\"' \" {width}x[1-9][0-9]+[+-]\" &&\n        mapped_window \"$tree\" '\"pcmanfm-qt\"' \" {width}x{height}[+-]\"; then\n        NOTIFY_SOCKET=\"$notify_sock\" systemd-notify --ready\n        wait -n \"$x_pid\" \"$wm_pid\" \"$desktop_pid\" \"$panel_pid\"\n        exit 1\n    fi\n    kill -0 \"$x_pid\" \"$wm_pid\" \"$desktop_pid\" \"$panel_pid\"; sleep .1\ndone\nprintf 'Virtual desktop did not become ready\\n' >&2\nexit 1\n"
    ));
    s
}

fn render_start_audio_sh(output_sink: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\numask 077\n: \"${{RUNTIME_DIRECTORY:?missing}}\"\n: \"${{XDG_CONFIG_HOME:?missing}}\"\n: \"${{XDG_STATE_HOME:?missing}}\"\n[[ -d $RUNTIME_DIRECTORY && ! -L $RUNTIME_DIRECTORY && $(stat -c %u:%a \"$RUNTIME_DIRECTORY\") == \"$UID:700\" ]]\nexport GIO_USE_VFS=local XDG_RUNTIME_DIR=$RUNTIME_DIRECTORY PIPEWIRE_RUNTIME_DIR=$RUNTIME_DIRECTORY PIPEWIRE_REMOTE=pipewire-0\nexport PULSE_RUNTIME_PATH=$RUNTIME_DIRECTORY/pulse PULSE_SERVER=unix:$PULSE_RUNTIME_PATH/native\nnotify_sock=${{NOTIFY_SOCKET:-}}\nunset NOTIFY_SOCKET\npids=()\ncleanup() {{ trap - EXIT; if ((${{#pids[@]}})); then kill \"${{pids[@]}}\" 2>/dev/null || true; wait \"${{pids[@]}}\" 2>/dev/null || true; fi; }}\ntrap cleanup EXIT\ntrap 'exit 143' TERM INT\npipewire &\npids+=(\"$!\")\nfor ((attempt=0; attempt<100; attempt++)); do [[ -S $RUNTIME_DIRECTORY/pipewire-0 ]] && break; kill -0 \"${{pids[0]}}\"; sleep .1; done\n[[ -S $RUNTIME_DIRECTORY/pipewire-0 ]]\nwireplumber --profile=sds-private &\npids+=(\"$!\")\npipewire-pulse &\npids+=(\"$!\")\nfor ((attempt=0; attempt<100; attempt++)); do\n    if [[ -S $PULSE_RUNTIME_PATH/native ]] && wpctl status -n | grep -F '{output_sink}' >/dev/null; then\n        NOTIFY_SOCKET=\"$notify_sock\" systemd-notify --ready\n        wait -n \"${{pids[@]}}\"\n        exit 1\n    fi\n    kill -0 \"${{pids[@]}}\"; sleep .1\ndone\nprintf 'Private audio graph failed readiness\\n' >&2\nexit 1\n"
    )
}

fn render_pw_output_conf(output_sink: &str) -> String {
    format!(
        "context.objects = [\n  {{ factory = adapter args = {{\n      factory.name = support.null-audio-sink\n      node.name = {output_sink}\n      node.description = \"Secure Desktop Output\"\n      media.class = Audio/Sink\n      audio.position = [ FL FR ]\n      object.linger = true\n      priority.session = 2000\n    }}\n  }}\n]\n"
    )
}

fn render_virtual_display_unit(
    instance: &str,
    display: &str,
    install_dir: &str,
    sunshine_unit: &str,
) -> String {
    format!(
        "[Unit]\nDescription=Private virtual desktop for {instance}\nStartLimitIntervalSec=0\nUpholds={sunshine_unit}\n\n[Service]\nType=notify\nNotifyAccess=all\nEnvironment=DISPLAY={display} XAUTHORITY=%t/{instance}-display/Xauthority\nEnvironment=XDG_SESSION_TYPE=x11 XDG_CURRENT_DESKTOP=LXQt XDG_MENU_PREFIX=lxqt-\nEnvironment=GDK_BACKEND=x11 QT_QPA_PLATFORM=xcb QT_QPA_PLATFORMTHEME=lxqt GVFS_DISABLE_FUSE=1 NO_AT_BRIDGE=1\nEnvironment=XDG_CONFIG_HOME=%h/.config/{instance}-desktop\nEnvironment=XDG_DATA_HOME=%h/.local/share/{instance}-desktop\nEnvironment=XDG_CACHE_HOME=%h/.cache/{instance}-desktop\nUnsetEnvironment=WAYLAND_DISPLAY WAYLAND_SOCKET DBUS_SESSION_BUS_ADDRESS SSH_AUTH_SOCK GNOME_KEYRING_CONTROL GPG_AGENT_INFO XDG_SESSION_ID XDG_SEAT XDG_VTNR PULSE_COOKIE\nRuntimeDirectory={instance}-display\nRuntimeDirectoryMode=0700\nUMask=0077\nExecStart=/usr/bin/dbus-run-session -- {install_dir}/start-display.sh\nRestart=always\nRestartSec=3s\nTimeoutStartSec=35s\n\n[Install]\nWantedBy=default.target\n"
    )
}

fn render_virtual_audio_unit(instance: &str, install_dir: &str) -> String {
    format!(
        "[Unit]\nDescription=Private audio graph for {instance}\nStartLimitIntervalSec=0\n\n[Service]\nType=notify\nNotifyAccess=all\nRuntimeDirectory={instance}-audio\nRuntimeDirectoryMode=0700\nEnvironment=XDG_CONFIG_HOME={install_dir}/audio\nEnvironment=XDG_STATE_HOME=%h/.local/state/{instance}-audio\nUnsetEnvironment=PIPEWIRE_CONFIG_DIR PIPEWIRE_CONFIG_NAME PIPEWIRE_CONFIG_PREFIX\nUnsetEnvironment=PULSE_SERVER PULSE_RUNTIME_PATH PIPEWIRE_REMOTE PIPEWIRE_RUNTIME_DIR\nUnsetEnvironment=DBUS_SESSION_BUS_ADDRESS\nUMask=0077\nExecStart=/usr/bin/dbus-run-session -- {install_dir}/audio/start-audio.sh\nRestart=always\nRestartSec=3s\nTimeoutStartSec=20s\nNoNewPrivileges=true\nLockPersonality=true\nRestrictSUIDSGID=true\nSystemCallArchitectures=native\nKillMode=control-group\n\n[Install]\nWantedBy=default.target\n"
    )
}

fn render_virtual_sunshine_unit(
    instance: &str,
    display: &str,
    install_dir: &str,
    display_unit: &str,
) -> String {
    format!(
        "[Unit]\nDescription=Sunshine for private desktop ({instance})\nBindsTo={display_unit}\nAfter={display_unit}\nPartOf={display_unit}\nStartLimitIntervalSec=0\n\n[Service]\nEnvironment=DISPLAY={display} XAUTHORITY=%t/{instance}-display/Xauthority\nEnvironment=XDG_SESSION_TYPE=x11\nEnvironment=XDG_CONFIG_HOME=%h/.config/{instance}-sunshine/config\nEnvironment=XDG_DATA_HOME=%h/.local/share/{instance}-sunshine\nEnvironment=XDG_CACHE_HOME=%h/.cache/{instance}-sunshine\nEnvironment=XDG_STATE_HOME=%h/.local/state/{instance}-sunshine\nEnvironment=SUNSHINE_ASSETS_DIR={install_dir}/assets\nUnsetEnvironment=WAYLAND_DISPLAY WAYLAND_SOCKET DBUS_SESSION_BUS_ADDRESS SSH_AUTH_SOCK GNOME_KEYRING_CONTROL GPG_AGENT_INFO\nUMask=0077\nExecStart={install_dir}/sunshine %h/.config/{instance}-sunshine/sunshine.conf\nRestart=on-failure\nRestartSec=5s\nNoNewPrivileges=true\nLockPersonality=true\nRestrictSUIDSGID=true\nSystemCallArchitectures=native\nInaccessiblePaths=-/run/docker.sock\n\n[Install]\nWantedBy={display_unit}\n"
    )
}

fn render_audio_dropin(instance: &str, audio_unit: &str, output_sink: &str) -> String {
    format!(
        "[Unit]\nRequires={audio_unit}\nAfter={audio_unit}\n\n[Service]\nEnvironment=PIPEWIRE_RUNTIME_DIR=%t/{instance}-audio\nEnvironment=PIPEWIRE_REMOTE=pipewire-0\nEnvironment=PULSE_SERVER=unix:%t/{instance}-audio/pulse/native\nEnvironment=PULSE_SINK={output_sink}\nUnsetEnvironment=PULSE_SOURCE\n"
    )
}

fn render_physical_sunshine_unit(instance: &str, install_dir: &str) -> String {
    format!(
        "[Unit]\nDescription=Secure Desktop Stream Sunshine ({instance})\nAfter=pipewire.service pipewire-pulse.service\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=exec\nWorkingDirectory={install_dir}\nEnvironment=XDG_CONFIG_HOME=%h/.config/{instance}-sunshine/config\nEnvironment=XDG_CACHE_HOME=%h/.cache/{instance}-sunshine\nEnvironment=SUNSHINE_ASSETS_DIR={install_dir}/assets\nUnsetEnvironment=WAYLAND_DISPLAY WAYLAND_SOCKET DBUS_SESSION_BUS_ADDRESS SSH_AUTH_SOCK GNOME_KEYRING_CONTROL GPG_AGENT_INFO\nEnvironmentFile=%t/{instance}-sunshine.env\nExecStart={install_dir}/sunshine %h/.config/{instance}-sunshine/sunshine.conf\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=12s\nUMask=0077\nNoNewPrivileges=true\nLockPersonality=true\nRestrictSUIDSGID=true\nSystemCallArchitectures=native\nInaccessiblePaths=-/run/docker.sock\n"
    )
}

fn render_physical_session_script(
    instance: &str,
    sunshine_unit: &str,
    width: u32,
    height: u32,
) -> String {
    let mode = format!("{width}x{height}");
    format!(
        "#!/bin/bash\nset -euo pipefail\numask 077\n[[ ${{XDG_SESSION_TYPE:-}} == x11 && -n ${{XDG_RUNTIME_DIR:-}} ]]\n[[ ${{DISPLAY:-}} =~ ^:[0-9]+(\\.[0-9]+)?$ ]]\nauthority=${{XAUTHORITY:-$HOME/.Xauthority}}\n[[ -f \"$authority\" && -O \"$authority\" && -r \"$authority\" ]]\nexport XAUTHORITY=\"$authority\"\nmonitors=$(/usr/bin/xrandr --listactivemonitors)\nif [[ \"$monitors\" == 'Monitors: 0' ]]; then\n  output=$(/usr/bin/xrandr --query | awk '/ connected/ {{print $1; exit}}')\n  if [[ -n \"$output\" ]]; then\n    /usr/bin/xrandr --output \"$output\" --mode {mode} --primary\n  fi\nfi\nenv_file=$(mktemp \"$XDG_RUNTIME_DIR/.{instance}-sunshine.XXXXXXXX\")\ntrap 'rm -f -- \"$env_file\"' EXIT\nprintf 'DISPLAY=%s\\nXAUTHORITY=%s\\n' \"$DISPLAY\" \"$XAUTHORITY\" >\"$env_file\"\nmv -T -- \"$env_file\" \"$XDG_RUNTIME_DIR/{instance}-sunshine.env\"\nexec /usr/bin/systemctl --user start {sunshine_unit}\n"
    )
}

fn render_windows_host_ps1(install_dir: &str, controller_ip: IpAddr, enable_mic: bool) -> String {
    let ip_str = controller_ip.to_string();
    let mic_line = if enable_mic {
        "New-NetFirewallRule -DisplayName 'SDS-Allow-Mic-48002' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 48002 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null\n"
    } else {
        ""
    };
    format!(
        r#"param(
    [string]$ControllerIp = '{ip_str}',
    [string]$InstallDir = '{install_dir}',
    [switch]$OpenPairing,
    [switch]$ClosePairing,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Uninstall) {{
    Get-NetFirewallRule -DisplayName 'SDS-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Output 'Removed all SDS-* firewall rules'
    exit 0
}}

$parsedIp = $null
if (-not [System.Net.IPAddress]::TryParse($ControllerIp, [ref]$parsedIp) -or $parsedIp.Equals([System.Net.IPAddress]::Any) -or $parsedIp.Equals([System.Net.IPAddress]::IPv6Any)) {{
    throw "ControllerIp must be a specific IPv4/IPv6 literal, not Any/unspecified: $ControllerIp"
}}

$expandedDir = [Environment]::ExpandEnvironmentVariables($InstallDir)
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function Protect-PrivateDirectory([string]$Path) {{
    if (-not (Test-Path -LiteralPath $Path)) {{ New-Item -ItemType Directory -Path $Path -Force | Out-Null }}
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm("O:$sid" + "D:P(A;OICI;FA;;;$sid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    Set-Acl -LiteralPath $Path -AclObject $acl
}}

Protect-PrivateDirectory (Join-Path $env:USERPROFILE 'Downloads\Moonlight')
Protect-PrivateDirectory (Join-Path $env:USERPROFILE 'Downloads\Moonlight\Outbox')
Protect-PrivateDirectory (Join-Path $expandedDir 'config')

if ($OpenPairing) {{
    Get-NetFirewallRule -DisplayName 'SDS-Pairing-47989' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'SDS-Pairing-47989' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47989 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
    Write-Output "Opened 47989/tcp temporarily for pairing from $ControllerIp"
    exit 0
}}

if ($ClosePairing) {{
    Get-NetFirewallRule -DisplayName 'SDS-Pairing-47989' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Output 'Closed 47989/tcp pairing firewall rule'
    exit 0
}}

Get-NetFirewallRule -DisplayName 'SDS-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'SDS-Block-WebUI-47990' -Direction Inbound -Action Block -Protocol TCP -LocalPort 47990 | Out-Null
New-NetFirewallRule -DisplayName 'SDS-Allow-HTTPS-47984' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47984 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
New-NetFirewallRule -DisplayName 'SDS-Allow-RTSP-48010' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 48010 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
New-NetFirewallRule -DisplayName 'SDS-Allow-Stream-UDP' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 47998-48000 -RemoteAddress $ControllerIp -Profile Private,Domain | Out-Null
{mic_line}Write-Output "Hardened Windows firewall and private directories configured for controller $ControllerIp"
"#
    )
}

fn include_lxqt_conf() -> &'static str {
    "[General]\n__userfile__=true\ntheme=ambiance\nicon_theme=Papirus\nicon_follow_color_scheme=false\nsingle_click_activate=false\n\n[Mouse]\ncursor_theme=breeze_cursors\n\n[Qt]\nstyle=Fusion\n"
}

fn include_panel_conf() -> &'static str {
    concat!(
        "[General]\n__userfile__=true\npanels=panel1\n\n",
        "[panel1]\nposition=Bottom\ndesktop=0\nwidth=100\nwidth-percent=true\npanelSize=36\niconSize=24\nreserve-space=true\nhidable=false\nplugins=fancymenu, desktopswitch, quicklaunch, showdesktop, taskbar, volume, tray, statusnotifier, worldclock\n\n",
        "[fancymenu]\ntype=fancymenu\nalignment=Left\nbuttonsAtTop=false\ncategoriesAtRight=false\nfilterClear=true\nautoSel=true\nmenu_file=/etc/xdg/menus/lxqt-applications-compact.menu\nshowText=false\nfavorites\\1\\desktopFile=/usr/share/applications/pcmanfm-qt.desktop\nfavorites\\2\\desktopFile=/usr/share/applications/qterminal.desktop\nfavorites\\size=2\n\n",
        "[desktopswitch]\ntype=desktopswitch\nalignment=Left\n\n",
        "[quicklaunch]\ntype=quicklaunch\nalignment=Left\napps\\1\\desktop=/usr/share/applications/pcmanfm-qt.desktop\napps\\2\\desktop=/usr/share/applications/qterminal.desktop\napps\\size=2\n\n",
        "[showdesktop]\ntype=showdesktop\nalignment=Left\n\n",
        "[taskbar]\ntype=taskbar\nalignment=Left\nbuttonWidth=220\ncloseOnMiddleClick=false\ngroupingEnabled=false\n\n",
        "[volume]\ntype=volume\nalignment=Right\n\n",
        "[tray]\ntype=tray\nalignment=Right\n\n",
        "[statusnotifier]\ntype=statusnotifier\nalignment=Right\n\n",
        "[worldclock]\ntype=worldclock\nalignment=Right\n"
    )
}

fn include_pcmanfm_conf() -> &'static str {
    "[System]\nArchiver=lxqt-archiver\nIconThemeName=Papirus\nTerminal=qterminal\n\n[Behavior]\nUseTrash=true\nConfirmDelete=true\nConfirmTrash=false\nQuickExec=true\nSingleClick=false\n\n[Volume]\nMountOnStartup=false\nMountRemovable=false\nAutoRun=false\n"
}
