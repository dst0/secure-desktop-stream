//! Cross-platform runtime & build dependency checker and safe auto-installer.
//! Supports local checks/installs (Homebrew, apt, dnf, pacman, zypper, winget, choco) as well as
//! remote Linux host checks/installs over post-quantum SSH using static package allowlists.

use crate::installer_ops::ProgressEmitter;
use crate::platform::{command_exists, current_arch, current_os, run_cmd_timeout};
use crate::validation::{shell_single_quote, validate_ssh_target};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyRole {
    Client,
    ClientBuild,
    HostVirtual,
    HostPhysical,
    HostWindows,
    HostBuild,
    InstallerBuild,
    All,
}

impl DependencyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::ClientBuild => "client-build",
            Self::HostVirtual => "host-virtual",
            Self::HostPhysical => "host-physical",
            Self::HostWindows => "host-windows",
            Self::HostBuild => "host-build",
            Self::InstallerBuild => "installer-build",
            Self::All => "all",
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            Self::All => Self::Client,
            Self::Client => Self::ClientBuild,
            Self::ClientBuild => Self::HostVirtual,
            Self::HostVirtual => Self::HostPhysical,
            Self::HostPhysical => Self::HostBuild,
            Self::HostBuild => Self::InstallerBuild,
            Self::InstallerBuild => Self::HostWindows,
            Self::HostWindows => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackageManagerKind {
    Homebrew,
    Apt,
    Dnf,
    Pacman,
    Zypper,
    Winget,
    Choco,
    Unknown,
}

impl PackageManagerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Homebrew => "homebrew",
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Zypper => "zypper",
            Self::Winget => "winget",
            Self::Choco => "choco",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyItem {
    pub id: String,
    pub name: String,
    pub category: String, // "runtime" | "build" | "install"
    pub required: bool,
    pub present: bool,
    pub detected_version: Option<String>,
    pub package_name: Option<String>,
    pub install_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCheckReport {
    pub os: String,
    pub arch: String,
    pub package_manager: PackageManagerKind,
    pub role: DependencyRole,
    pub target_label: String,
    pub items: Vec<DependencyItem>,
    pub missing_required: Vec<String>,
    pub missing_optional: Vec<String>,
    pub install_commands: Vec<String>,
    pub manual_steps: Vec<String>,
    pub all_satisfied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCheckRequest {
    pub role: DependencyRole,
    #[serde(default)]
    pub ssh_target: Option<String>,
    #[serde(default = "default_true")]
    pub require_pq_ssh: bool,
    #[serde(default)]
    pub strict_ssh_host_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInstallRequest {
    pub role: DependencyRole,
    #[serde(default)]
    pub ssh_target: Option<String>,
    #[serde(default = "default_true")]
    pub require_pq_ssh: bool,
    #[serde(default)]
    pub strict_ssh_host_key: bool,
    #[serde(default)]
    pub include_optional: bool,
    #[serde(default)]
    pub execute_sudo: bool,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInstallResult {
    pub ok: bool,
    pub dry_run: bool,
    pub before: DependencyCheckReport,
    pub after: Option<DependencyCheckReport>,
    pub commands_executed_or_planned: Vec<String>,
    pub elevated_commands: Vec<String>,
    #[serde(default)]
    pub manual_steps: Vec<String>,
    pub summary: String,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Copy)]
struct DepSpec {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    required: bool,
    os_mask: &'static str, // "macos" | "linux" | "windows" | "unix" | "all"
    roles: &'static [DependencyRole],
    brew_pkg: Option<&'static str>,
    apt_pkg: Option<&'static str>,
    dnf_pkg: Option<&'static str>,
    pacman_pkg: Option<&'static str>,
    zypper_pkg: Option<&'static str>,
    winget_id: Option<&'static str>,
    choco_pkg: Option<&'static str>,
    manual_hint: &'static str,
}

const ALL_SPECS: &[DepSpec] = &[
    // Common / Installer / SSH
    DepSpec {
        id: "ssh",
        name: "OpenSSH Client (PQ mlkem768x25519-sha256)",
        category: "runtime",
        required: true,
        os_mask: "all",
        roles: &[
            DependencyRole::Client,
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::All,
        ],
        brew_pkg: Some("openssh"),
        apt_pkg: Some("openssh-client"),
        dnf_pkg: Some("openssh-clients"),
        pacman_pkg: Some("openssh"),
        zypper_pkg: Some("openssh"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install OpenSSH >= 9.9 for mlkem768x25519-sha256 PQ SSH",
    },
    DepSpec {
        id: "git",
        name: "Git",
        category: "build",
        required: true,
        os_mask: "all",
        roles: &[
            DependencyRole::ClientBuild,
            DependencyRole::HostBuild,
            DependencyRole::InstallerBuild,
            DependencyRole::All,
        ],
        brew_pkg: Some("git"),
        apt_pkg: Some("git"),
        dnf_pkg: Some("git"),
        pacman_pkg: Some("git"),
        zypper_pkg: Some("git"),
        winget_id: Some("Git.Git"),
        choco_pkg: Some("git"),
        manual_hint: "Install Git",
    },
    DepSpec {
        id: "cargo",
        name: "Rust Toolchain (cargo + rustc)",
        category: "build",
        required: true,
        os_mask: "all",
        roles: &[
            DependencyRole::HostBuild,
            DependencyRole::InstallerBuild,
            DependencyRole::All,
        ],
        brew_pkg: Some("rust"),
        apt_pkg: Some("cargo"),
        dnf_pkg: Some("cargo"),
        pacman_pkg: Some("rust"),
        zypper_pkg: Some("rust"),
        winget_id: Some("Rustlang.Rustup"),
        choco_pkg: Some("rustup.install"),
        manual_hint: "Install Rust toolchain (rustup / cargo)",
    },
    DepSpec {
        id: "c_compiler",
        name: "C/C++ Compiler Toolchain (gcc / clang / make)",
        category: "build",
        required: true,
        os_mask: "linux",
        roles: &[
            DependencyRole::InstallerBuild,
            DependencyRole::HostBuild,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("build-essential"),
        dnf_pkg: Some("gcc"),
        pacman_pkg: Some("base-devel"),
        zypper_pkg: Some("gcc"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install gcc / clang / make",
    },
    DepSpec {
        id: "curl",
        name: "curl (HTTPS TLS 1.2+ downloader)",
        category: "install",
        required: true,
        os_mask: "unix",
        roles: &[
            DependencyRole::Client,
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::InstallerBuild,
            DependencyRole::All,
        ],
        brew_pkg: Some("curl"),
        apt_pkg: Some("curl"),
        dnf_pkg: Some("curl"),
        pacman_pkg: Some("curl"),
        zypper_pkg: Some("curl"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install curl",
    },
    DepSpec {
        id: "unzip",
        name: "unzip (release archive inspector/extractor)",
        category: "install",
        required: true,
        os_mask: "linux",
        roles: &[
            DependencyRole::Client,
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("unzip"),
        dnf_pkg: Some("unzip"),
        pacman_pkg: Some("unzip"),
        zypper_pkg: Some("unzip"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install unzip",
    },
    // macOS client build
    DepSpec {
        id: "xcode_clt",
        name: "Xcode Command Line Tools",
        category: "build",
        required: true,
        os_mask: "macos",
        roles: &[
            DependencyRole::ClientBuild,
            DependencyRole::InstallerBuild,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Run: xcode-select --install",
    },
    DepSpec {
        id: "brew",
        name: "Homebrew",
        category: "install",
        required: true,
        os_mask: "macos",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install Homebrew from https://brew.sh",
    },
    DepSpec {
        id: "qt6",
        name: "Qt 6 (qmake6 / macdeployqt)",
        category: "build",
        required: true,
        os_mask: "macos",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: Some("qt"),
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "brew install qt",
    },
    DepSpec {
        id: "sdl2",
        name: "SDL2 & SDL2_ttf",
        category: "build",
        required: true,
        os_mask: "macos",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: Some("sdl2"),
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "brew install sdl2 sdl2_ttf",
    },
    DepSpec {
        id: "sdl2_ttf",
        name: "SDL2_ttf",
        category: "build",
        required: true,
        os_mask: "macos",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: Some("sdl2_ttf"),
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "brew install sdl2_ttf",
    },
    DepSpec {
        id: "sdl3",
        name: "SDL3 (optional client graphics/audio dev)",
        category: "build",
        required: false,
        os_mask: "macos",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: Some("sdl3"),
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "brew install sdl3",
    },
    DepSpec {
        id: "ffmpeg",
        name: "FFmpeg",
        category: "build",
        required: true,
        os_mask: "macos",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: Some("ffmpeg"),
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "brew install ffmpeg",
    },
    DepSpec {
        id: "opus",
        name: "Opus Audio Codec",
        category: "build",
        required: true,
        os_mask: "macos",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: Some("opus"),
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "brew install opus",
    },
    DepSpec {
        id: "openssl",
        name: "OpenSSL 3",
        category: "build",
        required: true,
        os_mask: "macos",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: Some("openssl@3"),
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "brew install openssl@3",
    },
    DepSpec {
        id: "pkg_config",
        name: "pkg-config",
        category: "build",
        required: true,
        os_mask: "unix",
        roles: &[
            DependencyRole::ClientBuild,
            DependencyRole::HostBuild,
            DependencyRole::InstallerBuild,
            DependencyRole::All,
        ],
        brew_pkg: Some("pkg-config"),
        apt_pkg: Some("pkg-config"),
        dnf_pkg: Some("pkgconf-pkg-config"),
        pacman_pkg: Some("pkgconf"),
        zypper_pkg: Some("pkg-config"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install pkg-config",
    },
    // Linux Virtual X11 Host runtime
    DepSpec {
        id: "xorg",
        name: "Rootless Xorg Server",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::HostVirtual, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("xserver-xorg-core"),
        dnf_pkg: Some("xorg-x11-server-Xorg"),
        pacman_pkg: Some("xorg-server"),
        zypper_pkg: Some("xorg-x11-server"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install Xorg server",
    },
    DepSpec {
        id: "xorg_dummy",
        name: "Xorg dummy video driver (XRandR up to 4096x4096)",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::HostVirtual, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("xserver-xorg-video-dummy"),
        dnf_pkg: Some("xorg-x11-drv-dummy"),
        pacman_pkg: Some("xf86-video-dummy"),
        zypper_pkg: Some("xf86-video-dummy"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install xserver-xorg-video-dummy",
    },
    DepSpec {
        id: "x11_utils",
        name: "X11 utilities (xrandr / xauth / xdpyinfo / xprop / mcookie)",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("x11-xserver-utils"),
        dnf_pkg: Some("xrandr"),
        pacman_pkg: Some("xorg-xrandr"),
        zypper_pkg: Some("xrandr"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install x11-xserver-utils + x11-utils + xauth",
    },
    DepSpec {
        id: "x11_query_tools",
        name: "X11 query tools (xdpyinfo / xprop / xwininfo)",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::HostVirtual, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("x11-utils"),
        dnf_pkg: Some("xdpyinfo"),
        pacman_pkg: Some("xorg-xdpyinfo"),
        zypper_pkg: Some("xdpyinfo"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install x11-utils (xdpyinfo/xprop/xwininfo)",
    },
    DepSpec {
        id: "xauth",
        name: "xauth (per-service MIT-MAGIC-COOKIE)",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::HostVirtual, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("xauth"),
        dnf_pkg: Some("xorg-x11-xauth"),
        pacman_pkg: Some("xorg-xauth"),
        zypper_pkg: Some("xauth"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install xauth",
    },
    DepSpec {
        id: "openbox",
        name: "Openbox Window Manager",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::HostVirtual, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("openbox"),
        dnf_pkg: Some("openbox"),
        pacman_pkg: Some("openbox"),
        zypper_pkg: Some("openbox"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install openbox",
    },
    DepSpec {
        id: "lxqt_desktop",
        name: "LXQt Desktop Shell (pcmanfm-qt & lxqt-panel)",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::HostVirtual, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("pcmanfm-qt"),
        dnf_pkg: Some("pcmanfm-qt"),
        pacman_pkg: Some("pcmanfm-qt"),
        zypper_pkg: Some("pcmanfm-qt"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install pcmanfm-qt and lxqt-panel",
    },
    DepSpec {
        id: "lxqt_panel",
        name: "LXQt Panel",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::HostVirtual, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("lxqt-panel"),
        dnf_pkg: Some("lxqt-panel"),
        pacman_pkg: Some("lxqt-panel"),
        zypper_pkg: Some("lxqt-panel"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install lxqt-panel",
    },
    DepSpec {
        id: "dbus_session",
        name: "dbus-run-session (private D-Bus isolation)",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::HostVirtual, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("dbus-x11"),
        dnf_pkg: Some("dbus-daemon"),
        pacman_pkg: Some("dbus"),
        zypper_pkg: Some("dbus-1-x11"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install dbus-run-session",
    },
    DepSpec {
        id: "pipewire_stack",
        name: "PipeWire + PipeWire-Pulse + WirePlumber",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("pipewire"),
        dnf_pkg: Some("pipewire"),
        pacman_pkg: Some("pipewire"),
        zypper_pkg: Some("pipewire"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install pipewire, pipewire-pulse, and wireplumber",
    },
    DepSpec {
        id: "pipewire_pulse",
        name: "pipewire-pulse (PulseAudio compatibility)",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("pipewire-pulse"),
        dnf_pkg: Some("pipewire-pulseaudio"),
        pacman_pkg: Some("pipewire-pulse"),
        zypper_pkg: Some("pipewire-pulseaudio"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install pipewire-pulse",
    },
    DepSpec {
        id: "wireplumber",
        name: "WirePlumber Session Manager",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("wireplumber"),
        dnf_pkg: Some("wireplumber"),
        pacman_pkg: Some("wireplumber"),
        zypper_pkg: Some("wireplumber"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install wireplumber",
    },
    DepSpec {
        id: "vaapi_runtime",
        name: "Mesa VA-API Runtime (libva / radeonsi)",
        category: "runtime",
        required: false,
        os_mask: "linux",
        roles: &[
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("mesa-va-drivers"),
        dnf_pkg: Some("mesa-va-drivers"),
        pacman_pkg: Some("libva-mesa-driver"),
        zypper_pkg: Some("Mesa-libva"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install mesa-va-drivers for hardware AMD/Intel VAAPI encoding",
    },
    DepSpec {
        id: "firewall_linux",
        name: "Host Firewall (ufw / firewalld / nftables)",
        category: "runtime",
        required: true,
        os_mask: "linux",
        roles: &[
            DependencyRole::HostVirtual,
            DependencyRole::HostPhysical,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("ufw"),
        dnf_pkg: Some("firewalld"),
        pacman_pkg: Some("ufw"),
        zypper_pkg: Some("firewalld"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install ufw, firewalld, or nftables",
    },
    DepSpec {
        id: "picom",
        name: "picom X11 Compositor (optional; configure backend=xrender)",
        category: "runtime",
        required: false,
        os_mask: "linux",
        roles: &[DependencyRole::HostPhysical],
        brew_pkg: None,
        apt_pkg: Some("picom"),
        dnf_pkg: Some("picom"),
        pacman_pkg: Some("picom"),
        zypper_pkg: Some("picom"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Optional: install picom and set backend = \"xrender\"",
    },
    // Linux Client & Host & Installer Build deps
    DepSpec {
        id: "linux_client_build",
        name: "Qt 6 + SDL2 + FFmpeg + Opus Dev Packages (Linux Moonlight Build)",
        category: "build",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::ClientBuild, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("qt6-base-dev"),
        dnf_pkg: Some("qt6-qtbase-devel"),
        pacman_pkg: Some("qt6-base"),
        zypper_pkg: Some("qt6-base-devel"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install Qt6 (base, declarative, svg), SDL2, FFmpeg, Opus, and OpenSSL dev packages",
    },
    DepSpec {
        id: "linux_installer_gui_build",
        name: "CMake + X11/XKB/Fontconfig/Wayland Dev Headers (Floem + aws-lc-rs)",
        category: "build",
        required: true,
        os_mask: "linux",
        roles: &[
            DependencyRole::InstallerBuild,
            DependencyRole::HostBuild,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: Some("cmake"),
        dnf_pkg: Some("cmake"),
        pacman_pkg: Some("cmake"),
        zypper_pkg: Some("cmake"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install cmake, libxkbcommon-dev, libfontconfig1-dev, libxcb1-dev, libwayland-dev",
    },
    DepSpec {
        id: "linux_xkb_dev",
        name: "libxkbcommon + fontconfig + xcb Dev Headers",
        category: "build",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::InstallerBuild, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("libxkbcommon-dev"),
        dnf_pkg: Some("libxkbcommon-devel"),
        pacman_pkg: Some("libxkbcommon"),
        zypper_pkg: Some("libxkbcommon-devel"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install libxkbcommon-dev libfontconfig1-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev",
    },
    DepSpec {
        id: "linux_fontconfig_dev",
        name: "libfontconfig Dev Headers",
        category: "build",
        required: true,
        os_mask: "linux",
        roles: &[DependencyRole::InstallerBuild, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("libfontconfig1-dev"),
        dnf_pkg: Some("fontconfig-devel"),
        pacman_pkg: Some("fontconfig"),
        zypper_pkg: Some("fontconfig-devel"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install libfontconfig1-dev",
    },
    DepSpec {
        id: "docker",
        name: "Docker Engine (for containerized Sunshine Linux/Windows builds)",
        category: "build",
        required: false,
        os_mask: "linux",
        roles: &[DependencyRole::HostBuild, DependencyRole::All],
        brew_pkg: None,
        apt_pkg: Some("docker.io"),
        dnf_pkg: Some("docker"),
        pacman_pkg: Some("docker"),
        zypper_pkg: Some("docker"),
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Install docker.io (or build Sunshine natively with CMake + Ninja + Node.js)",
    },
    // Windows Host & Build
    DepSpec {
        id: "powershell",
        name: "Windows PowerShell 5.1 / PowerShell 7+",
        category: "runtime",
        required: true,
        os_mask: "windows",
        roles: &[
            DependencyRole::Client,
            DependencyRole::HostWindows,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: None,
        choco_pkg: None,
        manual_hint: "Windows PowerShell is built into Windows 10/11",
    },
    DepSpec {
        id: "vcredist",
        name: "Microsoft Visual C++ 2015-2022 Redistributable (x64)",
        category: "runtime",
        required: true,
        os_mask: "windows",
        roles: &[
            DependencyRole::Client,
            DependencyRole::HostWindows,
            DependencyRole::All,
        ],
        brew_pkg: None,
        apt_pkg: None,
        dnf_pkg: None,
        pacman_pkg: None,
        zypper_pkg: None,
        winget_id: Some("Microsoft.VCRedist.2015+.x64"),
        choco_pkg: Some("vcredist140"),
        manual_hint: "winget install Microsoft.VCRedist.2015+.x64",
    },
    DepSpec {
        id: "cmake",
        name: "CMake",
        category: "build",
        required: true,
        os_mask: "windows",
        roles: &[
            DependencyRole::InstallerBuild,
            DependencyRole::HostBuild,
            DependencyRole::All,
        ],
        brew_pkg: Some("cmake"),
        apt_pkg: Some("cmake"),
        dnf_pkg: Some("cmake"),
        pacman_pkg: Some("cmake"),
        zypper_pkg: Some("cmake"),
        winget_id: Some("Kitware.CMake"),
        choco_pkg: Some("cmake"),
        manual_hint: "winget install Kitware.CMake",
    },
];

/// Additional multi-package expansions for compound Linux build dependency IDs.
fn expand_linux_packages(id: &str, pm: PackageManagerKind) -> &'static [&'static str] {
    match (id, pm) {
        ("cargo", PackageManagerKind::Apt) => &["cargo", "rustc"],
        ("cargo", PackageManagerKind::Dnf) => &["cargo", "rust"],
        ("cargo", PackageManagerKind::Zypper) => &["cargo", "rust"],
        ("c_compiler", PackageManagerKind::Apt) => &["build-essential"],
        ("c_compiler", PackageManagerKind::Dnf) => &["gcc", "gcc-c++", "make", "clang"],
        ("c_compiler", PackageManagerKind::Pacman) => &["base-devel"],
        ("c_compiler", PackageManagerKind::Zypper) => &["gcc", "gcc-c++", "make"],
        ("x11_utils", PackageManagerKind::Dnf) => &["xrandr", "xset"],
        ("x11_utils", PackageManagerKind::Pacman) => &["xorg-xrandr", "xorg-xset"],
        ("x11_utils", PackageManagerKind::Zypper) => &["xrandr", "xset"],
        ("x11_query_tools", PackageManagerKind::Dnf) => &["xdpyinfo", "xprop", "xwininfo"],
        ("x11_query_tools", PackageManagerKind::Pacman) => {
            &["xorg-xdpyinfo", "xorg-xprop", "xorg-xwininfo"]
        }
        ("x11_query_tools", PackageManagerKind::Zypper) => &["xdpyinfo", "xprop", "xwininfo"],
        ("linux_client_build", PackageManagerKind::Apt) => &[
            "qt6-base-dev",
            "qt6-declarative-dev",
            "qt6-svg-dev",
            "qmake6",
            "libsdl2-dev",
            "libsdl2-ttf-dev",
            "libavcodec-dev",
            "libavformat-dev",
            "libavutil-dev",
            "libswscale-dev",
            "libopus-dev",
            "libssl-dev",
            "libva-dev",
            "g++",
            "make",
        ],
        ("linux_client_build", PackageManagerKind::Dnf) => &[
            "qt6-qtbase-devel",
            "qt6-qtdeclarative-devel",
            "qt6-qtsvg-devel",
            "SDL2-devel",
            "SDL2_ttf-devel",
            "ffmpeg-free-devel",
            "opus-devel",
            "openssl-devel",
            "libva-devel",
            "gcc-c++",
            "make",
        ],
        ("linux_client_build", PackageManagerKind::Pacman) => &[
            "qt6-base",
            "qt6-declarative",
            "qt6-svg",
            "sdl2",
            "sdl2_ttf",
            "ffmpeg",
            "opus",
            "openssl",
            "libva",
            "base-devel",
        ],
        ("linux_client_build", PackageManagerKind::Zypper) => &[
            "qt6-base-devel",
            "qt6-declarative-devel",
            "qt6-svg-devel",
            "SDL2-devel",
            "libSDL2_ttf-devel",
            "ffmpeg-6-libavcodec-devel",
            "libopus-devel",
            "libopenssl-devel",
            "libva-devel",
            "gcc-c++",
            "make",
        ],
        ("linux_xkb_dev", PackageManagerKind::Apt) => &[
            "libx11-dev",
            "libxcursor-dev",
            "libxrandr-dev",
            "libxi-dev",
            "libxkbcommon-dev",
            "libxkbcommon-x11-dev",
            "libxcb1-dev",
            "libxcb-render0-dev",
            "libxcb-shape0-dev",
            "libxcb-xfixes0-dev",
            "libwayland-dev",
        ],
        ("linux_xkb_dev", PackageManagerKind::Dnf) => &[
            "libX11-devel",
            "libXcursor-devel",
            "libXrandr-devel",
            "libXi-devel",
            "libxkbcommon-devel",
            "libxkbcommon-x11-devel",
            "libxcb-devel",
            "wayland-devel",
        ],
        ("linux_xkb_dev", PackageManagerKind::Pacman) => &[
            "libx11",
            "libxcursor",
            "libxrandr",
            "libxi",
            "libxkbcommon",
            "libxkbcommon-x11",
            "libxcb",
            "wayland",
        ],
        ("linux_xkb_dev", PackageManagerKind::Zypper) => &[
            "libX11-devel",
            "libXcursor-devel",
            "libXrandr-devel",
            "libXi-devel",
            "libxkbcommon-devel",
            "libxkbcommon-x11-devel",
            "libxcb-devel",
            "wayland-devel",
        ],
        _ => &[],
    }
}

fn spec_matches_os(spec: &DepSpec, os: &str) -> bool {
    match spec.os_mask {
        "all" => true,
        "unix" => os == "macos" || os == "linux",
        other => other == os,
    }
}

fn spec_matches_role(spec: &DepSpec, role: DependencyRole) -> bool {
    role == DependencyRole::All || spec.roles.contains(&role)
}

fn detect_local_package_manager(os: &str) -> PackageManagerKind {
    match os {
        "macos" => {
            if Path::new("/opt/homebrew/bin/brew").exists()
                || Path::new("/usr/local/bin/brew").exists()
                || command_exists("brew").is_some()
            {
                PackageManagerKind::Homebrew
            } else {
                PackageManagerKind::Unknown
            }
        }
        "linux" => {
            if command_exists("apt-get").is_some() {
                PackageManagerKind::Apt
            } else if command_exists("dnf").is_some() {
                PackageManagerKind::Dnf
            } else if command_exists("pacman").is_some() {
                PackageManagerKind::Pacman
            } else if command_exists("zypper").is_some() {
                PackageManagerKind::Zypper
            } else {
                PackageManagerKind::Unknown
            }
        }
        "windows" => {
            if command_exists("winget").is_some() {
                PackageManagerKind::Winget
            } else if command_exists("choco").is_some() {
                PackageManagerKind::Choco
            } else {
                PackageManagerKind::Unknown
            }
        }
        _ => PackageManagerKind::Unknown,
    }
}

fn package_for_pm(spec: &DepSpec, pm: PackageManagerKind) -> Option<&'static str> {
    match pm {
        PackageManagerKind::Homebrew => spec.brew_pkg,
        PackageManagerKind::Apt => spec.apt_pkg,
        PackageManagerKind::Dnf => spec.dnf_pkg,
        PackageManagerKind::Pacman => spec.pacman_pkg,
        PackageManagerKind::Zypper => spec.zypper_pkg,
        PackageManagerKind::Winget => spec.winget_id,
        PackageManagerKind::Choco => spec.choco_pkg,
        PackageManagerKind::Unknown => None,
    }
}

fn check_local_spec(id: &str, os: &str) -> (bool, Option<String>) {
    match id {
        "ssh" => {
            let Some(path) = command_exists("ssh") else {
                return (false, None);
            };
            let ver = run_cmd_timeout(&path, &["-V"], Duration::from_secs(2)).and_then(
                |(_, out, err)| {
                    err.lines()
                        .chain(out.lines())
                        .next()
                        .map(|s| s.trim().to_string())
                },
            );
            let pq = run_cmd_timeout(&path, &["-Q", "kex"], Duration::from_secs(2)).is_some_and(
                |(ok, out, _)| ok && out.lines().any(|l| l.trim() == "mlkem768x25519-sha256"),
            );
            let label = match ver {
                Some(v) => Some(format!("{v} (pq_kex={pq})")),
                None => Some(format!("pq_kex={pq}")),
            };
            (true, label)
        }
        "git" => check_cmd_ver("git", &["--version"]),
        "cargo" => check_cmd_ver("cargo", &["--version"]),
        "c_compiler" => (
            command_exists("cc").is_some()
                || command_exists("gcc").is_some()
                || command_exists("clang").is_some(),
            None,
        ),
        "curl" => check_cmd_ver("curl", &["--version"]),
        "unzip" => check_cmd_ver("unzip", &["-v"]),
        "xcode_clt" => {
            let ok = run_cmd_timeout("/usr/bin/xcode-select", &["-p"], Duration::from_secs(2))
                .is_some_and(|(ok, out, _)| ok && !out.trim().is_empty());
            (ok, ok.then(|| "installed".to_string()))
        }
        "brew" => {
            let bin = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
                .into_iter()
                .find(|p| Path::new(p).exists())
                .map(ToString::to_string)
                .or_else(|| command_exists("brew"));
            match bin {
                Some(b) => {
                    let ver = run_cmd_timeout(&b, &["--version"], Duration::from_secs(3)).and_then(
                        |(ok, out, _)| {
                            ok.then(|| out.lines().next().unwrap_or("").trim().to_string())
                        },
                    );
                    (true, ver)
                }
                None => (false, None),
            }
        }
        "qt6" => {
            if os == "macos" {
                let qm = ["/opt/homebrew/bin/qmake6", "/usr/local/bin/qmake6"]
                    .into_iter()
                    .find(|p| Path::new(p).exists())
                    .map(ToString::to_string)
                    .or_else(|| command_exists("qmake6"));
                let md = [
                    "/opt/homebrew/bin/macdeployqt",
                    "/usr/local/bin/macdeployqt",
                ]
                .into_iter()
                .find(|p| Path::new(p).exists())
                .map(ToString::to_string)
                .or_else(|| command_exists("macdeployqt"));
                match (qm, md) {
                    (Some(q), Some(_)) => {
                        let ver = run_cmd_timeout(&q, &["-v"], Duration::from_secs(2)).and_then(
                            |(_, out, _)| out.lines().last().map(|l| l.trim().to_string()),
                        );
                        (true, ver.or_else(|| Some("qmake6 + macdeployqt".into())))
                    }
                    _ => (false, None),
                }
            } else {
                check_cmd_ver("qmake6", &["-v"])
            }
        }
        "sdl2" => check_brew_or_pkg("sdl2"),
        "sdl2_ttf" => check_brew_or_pkg("sdl2_ttf"),
        "sdl3" => check_brew_or_pkg("sdl3"),
        "ffmpeg" => {
            if command_exists("ffmpeg").is_some() {
                check_cmd_ver("ffmpeg", &["-version"])
            } else {
                check_brew_or_pkg("ffmpeg")
            }
        }
        "opus" => check_brew_or_pkg("opus"),
        "openssl" => check_brew_or_pkg("openssl@3"),
        "pkg_config" => check_cmd_ver("pkg-config", &["--version"]),
        "xorg" => (
            Path::new("/usr/lib/xorg/Xorg").exists() || command_exists("Xorg").is_some(),
            None,
        ),
        "xorg_dummy" => {
            let dummy_exists = [
                "/usr/lib/xorg/modules/drivers/dummy_drv.so",
                "/usr/lib64/xorg/modules/drivers/dummy_drv.so",
            ]
            .into_iter()
            .any(|p| Path::new(p).exists());
            (dummy_exists, dummy_exists.then(|| "dummy_drv.so".into()))
        }
        "x11_utils" => (
            command_exists("xrandr").is_some() && command_exists("xset").is_some(),
            None,
        ),
        "x11_query_tools" => (
            command_exists("xdpyinfo").is_some()
                && command_exists("xprop").is_some()
                && command_exists("xwininfo").is_some(),
            None,
        ),
        "xauth" => (
            command_exists("xauth").is_some() && command_exists("mcookie").is_some(),
            None,
        ),
        "openbox" => check_cmd_ver("openbox", &["--version"]),
        "lxqt_desktop" => (command_exists("pcmanfm-qt").is_some(), None),
        "lxqt_panel" => (command_exists("lxqt-panel").is_some(), None),
        "dbus_session" => (command_exists("dbus-run-session").is_some(), None),
        "pipewire_stack" => check_cmd_ver("pipewire", &["--version"]),
        "pipewire_pulse" => (command_exists("pipewire-pulse").is_some(), None),
        "wireplumber" => check_cmd_ver("wireplumber", &["--version"]),
        "vaapi_runtime" => {
            let has_va = [
                "/usr/lib/x86_64-linux-gnu/libva.so.2",
                "/usr/lib/aarch64-linux-gnu/libva.so.2",
                "/usr/lib64/libva.so.2",
                "/usr/lib/libva.so.2",
            ]
            .into_iter()
            .any(|p| Path::new(p).exists());
            (has_va, has_va.then(|| "libva.so.2".into()))
        }
        "firewall_linux" => {
            if command_exists("ufw").is_some() {
                (true, Some("ufw".into()))
            } else if command_exists("firewall-cmd").is_some() {
                (true, Some("firewalld".into()))
            } else if command_exists("nft").is_some() {
                (true, Some("nftables".into()))
            } else {
                (false, None)
            }
        }
        "picom" => check_cmd_ver("picom", &["--version"]),
        "linux_client_build" => {
            let qm = command_exists("qmake6").is_some()
                || command_exists("qmake-qt6").is_some()
                || Path::new("/usr/lib/qt6/bin/qmake").exists()
                || Path::new("/usr/lib64/qt6/bin/qmake").exists();
            let cc = command_exists("g++").is_some();
            let pc = check_pkg_config("sdl2")
                && check_pkg_config("SDL2_ttf")
                && check_pkg_config("libavcodec")
                && check_pkg_config("libavformat")
                && check_pkg_config("libavutil")
                && check_pkg_config("libswscale")
                && check_pkg_config("opus")
                && check_pkg_config("openssl");
            (qm && cc && pc, None)
        }
        "linux_installer_gui_build" => check_cmd_ver("cmake", &["--version"]),
        "linux_xkb_dev" => (check_pkg_config("xkbcommon"), None),
        "linux_fontconfig_dev" => (check_pkg_config("fontconfig"), None),
        "docker" => check_cmd_ver("docker", &["--version"]),
        "powershell" => {
            let ps = command_exists("pwsh").or_else(|| command_exists("powershell"));
            (ps.is_some(), ps)
        }
        "vcredist" => {
            let sysroot = std::env::var("SystemRoot")
                .or_else(|_| std::env::var("WINDIR"))
                .unwrap_or_else(|_| r"C:\Windows".to_string());
            let ok = std::path::PathBuf::from(sysroot)
                .join("System32")
                .join("vcruntime140.dll")
                .exists();
            (ok, ok.then(|| "vcruntime140.dll".into()))
        }
        "cmake" => check_cmd_ver("cmake", &["--version"]),
        _ => (false, None),
    }
}

fn check_cmd_ver(cmd: &str, args: &[&str]) -> (bool, Option<String>) {
    let Some(path) = command_exists(cmd) else {
        return (false, None);
    };
    let ver = run_cmd_timeout(&path, args, Duration::from_secs(2))
        .and_then(|(ok, out, _)| ok.then(|| out.lines().next().unwrap_or("").trim().to_string()));
    (true, ver)
}

fn check_pkg_config(lib: &str) -> bool {
    let Some(pc) = command_exists("pkg-config") else {
        return false;
    };
    run_cmd_timeout(&pc, &["--exists", lib], Duration::from_secs(2)).is_some_and(|(ok, _, _)| ok)
}

fn check_brew_or_pkg(formula: &str) -> (bool, Option<String>) {
    let prefixes = ["/opt/homebrew/opt", "/usr/local/opt"];
    for pref in prefixes {
        let dir = Path::new(pref).join(formula);
        if dir.exists() {
            return (true, Some(dir.display().to_string()));
        }
    }
    (check_pkg_config(formula), None)
}

fn build_install_commands(pm: PackageManagerKind, packages: &[String]) -> Vec<String> {
    if packages.is_empty() {
        return Vec::new();
    }
    let joined = packages.join(" ");
    match pm {
        PackageManagerKind::Homebrew => vec![format!("brew install {joined}")],
        PackageManagerKind::Apt => vec![
            "sudo apt-get update".into(),
            format!("sudo apt-get install -y {joined}"),
        ],
        PackageManagerKind::Dnf => vec![format!("sudo dnf install -y {joined}")],
        PackageManagerKind::Pacman => vec![format!("sudo pacman -S --needed --noconfirm {joined}")],
        PackageManagerKind::Zypper => vec![format!("sudo zypper --non-interactive install {joined}")],
        PackageManagerKind::Winget => packages
            .iter()
            .map(|id| {
                format!("winget install --id {id} -e --silent --accept-package-agreements --accept-source-agreements")
            })
            .collect(),
        PackageManagerKind::Choco => packages
            .iter()
            .map(|id| format!("choco install -y {id}"))
            .collect(),
        PackageManagerKind::Unknown => Vec::new(),
    }
}

/// Checks all relevant runtime and build dependencies locally or on a remote Linux host via PQ SSH.
pub async fn check_dependencies(
    req: &DependencyCheckRequest,
) -> Result<DependencyCheckReport, String> {
    if let Some(ref raw_ssh) = req.ssh_target {
        let trimmed = raw_ssh.trim();
        if !trimmed.is_empty() {
            let ssh = validate_ssh_target(trimmed).map_err(|e| e.to_string())?;
            return check_remote_linux_deps(
                req.role,
                &ssh,
                req.require_pq_ssh,
                req.strict_ssh_host_key,
            )
            .await;
        }
    }
    let os = current_os().to_string();
    let arch = current_arch().to_string();
    let pm = detect_local_package_manager(&os);
    Ok(build_report_from_checks(
        &os,
        &arch,
        pm,
        req.role,
        "local",
        |id| check_local_spec(id, &os),
    ))
}

fn build_report_from_checks<F>(
    os: &str,
    arch: &str,
    pm: PackageManagerKind,
    role: DependencyRole,
    target_label: &str,
    mut checker: F,
) -> DependencyCheckReport
where
    F: FnMut(&str) -> (bool, Option<String>),
{
    let mut items = Vec::new();
    let mut missing_required = Vec::new();
    let mut missing_optional = Vec::new();
    let mut packages_needed = BTreeSet::new();
    let mut manual_steps = Vec::new();

    for spec in ALL_SPECS {
        if !spec_matches_os(spec, os) || !spec_matches_role(spec, role) {
            continue;
        }
        let (present, detected_version) = checker(spec.id);
        let pkg = package_for_pm(spec, pm).map(ToString::to_string);
        if !present {
            if spec.required {
                missing_required.push(spec.id.to_string());
            } else {
                missing_optional.push(spec.id.to_string());
            }
            if spec.required {
                let extra = if os == "linux" {
                    expand_linux_packages(spec.id, pm)
                } else {
                    &[]
                };
                if !extra.is_empty() {
                    for p in extra {
                        packages_needed.insert((*p).to_string());
                    }
                } else if let Some(ref p) = pkg {
                    packages_needed.insert(p.clone());
                } else {
                    manual_steps.push(format!("{}: {}", spec.name, spec.manual_hint));
                }
            }
        }
        items.push(DependencyItem {
            id: spec.id.to_string(),
            name: spec.name.to_string(),
            category: spec.category.to_string(),
            required: spec.required,
            present,
            detected_version,
            package_name: pkg,
            install_hint: spec.manual_hint.to_string(),
        });
    }

    let pkg_vec: Vec<String> = packages_needed.into_iter().collect();
    let install_commands = build_install_commands(pm, &pkg_vec);
    let all_satisfied = missing_required.is_empty();

    DependencyCheckReport {
        os: os.to_string(),
        arch: arch.to_string(),
        package_manager: pm,
        role,
        target_label: target_label.to_string(),
        items,
        missing_required,
        missing_optional,
        install_commands,
        manual_steps,
        all_satisfied,
    }
}

fn ssh_args(require_pq: bool, strict_host_key: bool) -> Vec<String> {
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
    if require_pq {
        args.push("-o".into());
        args.push("KexAlgorithms=mlkem768x25519-sha256".into());
    }
    args
}

async fn check_remote_linux_deps(
    role: DependencyRole,
    ssh_target: &str,
    require_pq_ssh: bool,
    strict_host_key: bool,
) -> Result<DependencyCheckReport, String> {
    let probe_script = r#"
echo "ARCH=$(uname -m)"
if command -v apt-get >/dev/null 2>&1; then echo "PM=apt"
elif command -v dnf >/dev/null 2>&1; then echo "PM=dnf"
elif command -v pacman >/dev/null 2>&1; then echo "PM=pacman"
elif command -v zypper >/dev/null 2>&1; then echo "PM=zypper"
else echo "PM=unknown"; fi
has() { command -v "$1" >/dev/null 2>&1 && echo "OK:$2" || echo "MISS:$2"; }
has ssh ssh
has git git
has cargo cargo
(command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1) && echo "OK:c_compiler" || echo "MISS:c_compiler"
has curl curl
has unzip unzip
has pkg-config pkg_config
[ -x /usr/lib/xorg/Xorg ] || command -v Xorg >/dev/null 2>&1 && echo "OK:xorg" || echo "MISS:xorg"
([ -f /usr/lib/xorg/modules/drivers/dummy_drv.so ] || [ -f /usr/lib64/xorg/modules/drivers/dummy_drv.so ]) && echo "OK:xorg_dummy" || echo "MISS:xorg_dummy"
(command -v xrandr >/dev/null 2>&1 && command -v xset >/dev/null 2>&1) && echo "OK:x11_utils" || echo "MISS:x11_utils"
(command -v xdpyinfo >/dev/null 2>&1 && command -v xprop >/dev/null 2>&1 && command -v xwininfo >/dev/null 2>&1) && echo "OK:x11_query_tools" || echo "MISS:x11_query_tools"
(command -v xauth >/dev/null 2>&1 && command -v mcookie >/dev/null 2>&1) && echo "OK:xauth" || echo "MISS:xauth"
has openbox openbox
has pcmanfm-qt lxqt_desktop
has lxqt-panel lxqt_panel
has dbus-run-session dbus_session
has pipewire pipewire_stack
has pipewire-pulse pipewire_pulse
has wireplumber wireplumber
va_ok=0
for f in /usr/lib/x86_64-linux-gnu/libva.so.2 /usr/lib/aarch64-linux-gnu/libva.so.2 /usr/lib64/libva.so.2 /usr/lib/libva.so.2; do
  [ -e "$f" ] && va_ok=1 && break
done
[ "$va_ok" = 1 ] && echo "OK:vaapi_runtime" || echo "MISS:vaapi_runtime"
(command -v ufw >/dev/null 2>&1 || command -v firewall-cmd >/dev/null 2>&1 || command -v nft >/dev/null 2>&1) && echo "OK:firewall_linux" || echo "MISS:firewall_linux"
has picom picom
has cmake linux_installer_gui_build
has docker docker
((command -v qmake6 >/dev/null 2>&1 || command -v qmake-qt6 >/dev/null 2>&1 || [ -x /usr/lib/qt6/bin/qmake ] || [ -x /usr/lib64/qt6/bin/qmake ]) && command -v g++ >/dev/null 2>&1 && pkg-config --exists sdl2 SDL2_ttf libavcodec libavformat libavutil libswscale opus openssl >/dev/null 2>&1) && echo "OK:linux_client_build" || echo "MISS:linux_client_build"
(pkg-config --exists xkbcommon >/dev/null 2>&1) && echo "OK:linux_xkb_dev" || echo "MISS:linux_xkb_dev"
(pkg-config --exists fontconfig >/dev/null 2>&1) && echo "OK:linux_fontconfig_dev" || echo "MISS:linux_fontconfig_dev"
"#;
    let mut args = ssh_args(require_pq_ssh, strict_host_key);
    args.push("--".into());
    args.push(ssh_target.to_string());
    args.push(probe_script.to_string());

    let out = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new("ssh")
            .args(&args)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| "Remote dependency check SSH timed out".to_string())?
    .map_err(|e| format!("Failed to spawn ssh: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "Remote dependency check failed on {ssh_target}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut arch = "x86_64".to_string();
    let mut pm = PackageManagerKind::Unknown;
    let mut ok_set = BTreeSet::new();
    for line in stdout.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("ARCH=") {
            arch = if v == "aarch64" {
                "arm64".into()
            } else {
                v.to_string()
            };
        } else if let Some(v) = l.strip_prefix("PM=") {
            pm = match v {
                "apt" => PackageManagerKind::Apt,
                "dnf" => PackageManagerKind::Dnf,
                "pacman" => PackageManagerKind::Pacman,
                "zypper" => PackageManagerKind::Zypper,
                _ => PackageManagerKind::Unknown,
            };
        } else if let Some(id) = l.strip_prefix("OK:") {
            ok_set.insert(id.to_string());
        }
    }

    Ok(build_report_from_checks(
        "linux",
        &arch,
        pm,
        role,
        ssh_target,
        |id| {
            let present = ok_set.contains(id);
            (present, present.then(|| "present".into()))
        },
    ))
}

fn collect_missing_packages(report: &DependencyCheckReport, include_optional: bool) -> Vec<String> {
    let mut pkgs = BTreeSet::new();
    for item in &report.items {
        if item.present {
            continue;
        }
        if !item.required && !include_optional {
            continue;
        }
        let extra = if report.os == "linux" {
            expand_linux_packages(&item.id, report.package_manager)
        } else {
            &[]
        };
        if !extra.is_empty() {
            for p in extra {
                pkgs.insert((*p).to_string());
            }
        } else if let Some(ref p) = item.package_name {
            pkgs.insert(p.clone());
        }
    }
    pkgs.into_iter().collect()
}

/// Validates allowlisted packages and installs missing dependencies (or previews in dry-run).
pub async fn install_missing_dependencies(
    req: &DependencyInstallRequest,
    emit: &ProgressEmitter,
) -> Result<DependencyInstallResult, String> {
    let before = check_dependencies(&DependencyCheckRequest {
        role: req.role,
        ssh_target: req.ssh_target.clone(),
        require_pq_ssh: req.require_pq_ssh,
        strict_ssh_host_key: req.strict_ssh_host_key,
    })
    .await?;

    let packages = collect_missing_packages(&before, req.include_optional);
    let commands = build_install_commands(before.package_manager, &packages);
    let mut elevated = Vec::new();
    if before.os == "linux" {
        elevated.extend(commands.clone());
    }

    if packages.is_empty() && before.manual_steps.is_empty() {
        emit.finish(
            "deps",
            true,
            "All requested dependencies are already satisfied.",
        );
        return Ok(DependencyInstallResult {
            ok: true,
            dry_run: req.dry_run,
            after: Some(before.clone()),
            manual_steps: before.manual_steps.clone(),
            before,
            commands_executed_or_planned: Vec::new(),
            elevated_commands: Vec::new(),
            summary: "All dependencies are satisfied.".into(),
        });
    }

    if req.dry_run {
        emit.finish(
            "deps",
            true,
            format!(
                "Dry-run: {} package(s) missing for role '{}'",
                packages.len(),
                req.role.as_str()
            ),
        );
        return Ok(DependencyInstallResult {
            ok: before.all_satisfied,
            dry_run: true,
            after: None,
            manual_steps: before.manual_steps.clone(),
            before,
            commands_executed_or_planned: commands,
            elevated_commands: elevated,
            summary: format!("Dry-run found {} missing package(s)", packages.len()),
        });
    }

    if let Some(ref raw_ssh) = req.ssh_target {
        let trimmed = raw_ssh.trim();
        if !trimmed.is_empty() {
            let ssh = validate_ssh_target(trimmed).map_err(|e| e.to_string())?;
            if !packages.is_empty() && req.execute_sudo {
                emit.emit(
                    "deps",
                    "info",
                    format!(
                        "Installing {} missing packages on {ssh} via PQ SSH...",
                        packages.len()
                    ),
                );
                let remote_cmd = build_remote_sudo_install_cmd(before.package_manager, &packages)?;
                let mut args = ssh_args(req.require_pq_ssh, req.strict_ssh_host_key);
                args.push("--".into());
                args.push(ssh.clone());
                args.push(remote_cmd);
                let out = Command::new("ssh")
                    .args(&args)
                    .stdin(Stdio::null())
                    .output()
                    .await
                    .map_err(|e| format!("ssh install failed: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "Remote package install failed on {ssh}: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
            } else if !packages.is_empty() {
                emit.emit(
                    "deps",
                    "warn",
                    "execute_sudo is disabled; returning exact commands to run on the remote host.",
                );
            }
            let after = check_dependencies(&DependencyCheckRequest {
                role: req.role,
                ssh_target: Some(ssh),
                require_pq_ssh: req.require_pq_ssh,
                strict_ssh_host_key: req.strict_ssh_host_key,
            })
            .await?;
            let ok = after.all_satisfied;
            emit.finish(
                "deps",
                ok,
                format!("Remote dependency check satisfied={ok}"),
            );
            return Ok(DependencyInstallResult {
                ok,
                dry_run: false,
                before,
                manual_steps: after.manual_steps.clone(),
                after: Some(after),
                commands_executed_or_planned: commands,
                elevated_commands: elevated,
                summary: if ok {
                    "All remote dependencies satisfied.".into()
                } else {
                    "Some remote dependencies still require installation.".into()
                },
            });
        }
    }

    // Local auto-installation via explicit argv arrays (no shell interpolation)
    if !packages.is_empty() {
        execute_local_pkg_install(before.package_manager, &packages, req.execute_sudo, emit)
            .await?;
    }

    let after = check_dependencies(&DependencyCheckRequest {
        role: req.role,
        ssh_target: None,
        require_pq_ssh: req.require_pq_ssh,
        strict_ssh_host_key: req.strict_ssh_host_key,
    })
    .await?;
    let ok = after.all_satisfied;
    emit.finish(
        "deps",
        ok,
        format!("Dependencies re-checked: all_satisfied={ok}"),
    );
    Ok(DependencyInstallResult {
        ok,
        dry_run: false,
        before,
        manual_steps: after.manual_steps.clone(),
        after: Some(after),
        commands_executed_or_planned: commands,
        elevated_commands: elevated,
        summary: if ok {
            "All required dependencies verified.".into()
        } else {
            "Manual or elevated dependency steps remain.".into()
        },
    })
}

fn verify_allowlisted_package(pkg: &str) -> Result<(), String> {
    if pkg.is_empty()
        || pkg.starts_with('-')
        || !pkg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '@'))
    {
        return Err(format!("Refusing non-allowlisted package token: {pkg}"));
    }
    Ok(())
}

fn build_remote_sudo_install_cmd(
    pm: PackageManagerKind,
    packages: &[String],
) -> Result<String, String> {
    for p in packages {
        verify_allowlisted_package(p)?;
    }
    let quoted: Vec<String> = packages.iter().map(|p| shell_single_quote(p)).collect();
    let args = quoted.join(" ");
    match pm {
        PackageManagerKind::Apt => Ok(format!(
            "sudo -n apt-get update && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y {args}"
        )),
        PackageManagerKind::Dnf => Ok(format!("sudo -n dnf install -y {args}")),
        PackageManagerKind::Pacman => Ok(format!("sudo -n pacman -S --needed --noconfirm {args}")),
        PackageManagerKind::Zypper => Ok(format!(
            "sudo -n zypper --non-interactive install {args}"
        )),
        _ => Err("Remote SSH auto-install supports apt, dnf, pacman, and zypper only".into()),
    }
}

async fn execute_local_pkg_install(
    pm: PackageManagerKind,
    packages: &[String],
    execute_sudo: bool,
    emit: &ProgressEmitter,
) -> Result<(), String> {
    for p in packages {
        verify_allowlisted_package(p)?;
    }
    match pm {
        PackageManagerKind::Homebrew => {
            emit.emit(
                "deps",
                "info",
                format!("Running: brew install {}", packages.join(" ")),
            );
            let brew = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
                .into_iter()
                .find(|p| Path::new(p).exists())
                .unwrap_or("brew");
            let mut argv: Vec<&str> = vec!["install"];
            for p in packages {
                argv.push(p.as_str());
            }
            let out = Command::new(brew)
                .args(&argv)
                .stdin(Stdio::null())
                .output()
                .await
                .map_err(|e| format!("failed to run brew install: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "brew install failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        PackageManagerKind::Apt
        | PackageManagerKind::Dnf
        | PackageManagerKind::Pacman
        | PackageManagerKind::Zypper => {
            if !execute_sudo {
                emit.emit(
                    "deps",
                    "warn",
                    "execute_sudo is false; run the listed sudo package commands manually.",
                );
                return Ok(());
            }
            if pm == PackageManagerKind::Apt {
                let upd = Command::new("sudo")
                    .args(["-n", "apt-get", "update"])
                    .stdin(Stdio::null())
                    .output()
                    .await
                    .map_err(|e| format!("sudo apt-get update failed: {e}"))?;
                if !upd.status.success() {
                    return Err(format!(
                        "sudo -n apt-get update failed: {}",
                        String::from_utf8_lossy(&upd.stderr).trim()
                    ));
                }
            }
            let mut argv: Vec<&str> = match pm {
                PackageManagerKind::Apt => vec!["-n", "apt-get", "install", "-y"],
                PackageManagerKind::Dnf => vec!["-n", "dnf", "install", "-y"],
                PackageManagerKind::Pacman => vec!["-n", "pacman", "-S", "--needed", "--noconfirm"],
                PackageManagerKind::Zypper => {
                    vec!["-n", "zypper", "--non-interactive", "install"]
                }
                _ => unreachable!(),
            };
            for p in packages {
                argv.push(p.as_str());
            }
            emit.emit("deps", "info", format!("Running: sudo {}", argv.join(" ")));
            let out = Command::new("sudo")
                .args(&argv)
                .stdin(Stdio::null())
                .output()
                .await
                .map_err(|e| format!("package manager spawn failed: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "Package installation failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        PackageManagerKind::Winget => {
            for id in packages {
                emit.emit("deps", "info", format!("Running: winget install --id {id}"));
                let out = Command::new("winget")
                    .args([
                        "install",
                        "--id",
                        id.as_str(),
                        "-e",
                        "--silent",
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                    ])
                    .stdin(Stdio::null())
                    .output()
                    .await
                    .map_err(|e| format!("winget spawn failed: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "winget install {id} failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
            }
        }
        PackageManagerKind::Choco => {
            for id in packages {
                emit.emit("deps", "info", format!("Running: choco install -y {id}"));
                let out = Command::new("choco")
                    .args(["install", "-y", id.as_str()])
                    .stdin(Stdio::null())
                    .output()
                    .await
                    .map_err(|e| format!("choco spawn failed: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "choco install {id} failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
            }
        }
        PackageManagerKind::Unknown => {
            return Err(
                "No supported package manager detected for automatic dependency installation"
                    .into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_dependency_matrix_builds_clean_plans_for_all_platforms() {
        let mac_rep = build_report_from_checks(
            "macos",
            "arm64",
            PackageManagerKind::Homebrew,
            DependencyRole::ClientBuild,
            "local",
            |_| (false, None),
        );
        assert!(!mac_rep.all_satisfied);
        assert!(mac_rep
            .install_commands
            .iter()
            .any(|c| c.starts_with("brew install ") && c.contains("qt") && c.contains("sdl2_ttf")));
        assert!(mac_rep
            .manual_steps
            .iter()
            .any(|m| m.contains("xcode-select --install")));

        let linux_rep = build_report_from_checks(
            "linux",
            "x86_64",
            PackageManagerKind::Apt,
            DependencyRole::HostVirtual,
            "local",
            |_| (false, None),
        );
        assert!(!linux_rep.all_satisfied);
        assert!(linux_rep
            .install_commands
            .iter()
            .any(|c| c.contains("xserver-xorg-video-dummy")
                && c.contains("pipewire-pulse")
                && c.contains("pcmanfm-qt")));

        let win_rep = build_report_from_checks(
            "windows",
            "x86_64",
            PackageManagerKind::Winget,
            DependencyRole::HostWindows,
            "local",
            |id| (id == "powershell", None),
        );
        assert!(!win_rep.all_satisfied);
        assert!(win_rep
            .install_commands
            .iter()
            .any(|c| c.contains("Microsoft.VCRedist.2015+.x64")));
    }

    #[test]
    fn package_allowlist_and_remote_cmd_reject_unsafe_tokens() {
        assert!(verify_allowlisted_package("xserver-xorg-video-dummy").is_ok());
        assert!(verify_allowlisted_package("openssl@3").is_ok());
        assert!(verify_allowlisted_package("-evil").is_err());
        assert!(verify_allowlisted_package("pkg;rm -rf /").is_err());
        assert!(verify_allowlisted_package("pkg$(id)").is_err());

        let cmd = build_remote_sudo_install_cmd(
            PackageManagerKind::Apt,
            &["curl".into(), "xauth".into()],
        )
        .unwrap();
        assert!(cmd
            .contains("sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y 'curl' 'xauth'"));
    }
}
