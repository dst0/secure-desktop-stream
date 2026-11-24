use clap::Parser;
use sds_installer::cli::{run_cli, Cli};
use sds_installer::native_gui::configure_software_renderer_env;
use std::process::ExitCode;

fn main() -> ExitCode {
    configure_software_renderer_env();
    run_cli(Cli::parse())
}
