#![allow(unused)]
mod cli;
mod enforce;
mod events;
#[cfg(unix)]
mod exec;
mod policy;
#[cfg(unix)]
mod pty;
#[cfg(unix)]
mod report;
#[cfg(unix)]
mod signal;
#[cfg(unix)]
mod tracer;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    #[cfg(unix)]
    {
        match exec::run(&cli) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("bulx: {e:#}");
                ExitCode::from(1)
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = cli;
        eprintln!("bulx: this platform is not supported yet");
        ExitCode::from(1)
    }
}
