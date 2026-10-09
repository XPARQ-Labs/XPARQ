mod miner;
mod nat;
mod node;
mod peer;
mod snapshot;
mod storage;
mod sync;

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    match node::run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("node: {error}");
            ExitCode::FAILURE
        }
    }
}
