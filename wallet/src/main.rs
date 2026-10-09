mod memory;
mod native;

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    if let Err(error) = memory::harden_process_memory() {
        eprintln!("wallet: warning: process memory hardening failed: {error}");
    }
    match native::run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wallet: {error}");
            ExitCode::FAILURE
        }
    }
}
