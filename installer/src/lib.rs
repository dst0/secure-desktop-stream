//! Cross-platform hardened installer, dependency manager, orchestrator, and uninstaller.

pub mod archive;
pub mod cli;
pub mod config_gen;
pub mod deps;
pub mod installer_ops;
pub mod native_gui;
pub mod platform;
pub mod probe;
pub mod tui;
pub mod ui_state;
pub mod uninstall;
pub mod validation;
