mod native;

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    match native::run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wallet: {error}");
            ExitCode::FAILURE
        }
    }
}
