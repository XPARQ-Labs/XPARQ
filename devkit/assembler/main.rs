use std::{collections::BTreeMap, env, fs};
use xparq_devkit::{assemble, validate};
fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" {
        println!(
            "xparq-devkit assemble SOURCE -o OUTPUT [-D NAME=VALUE]...\nxparq-devkit check BYTECODE\nAssembler targets XPVM v4; check accepts kernel-supported versions."
        );
        return Ok(());
    }
    let input = args.get(1).ok_or("missing input path")?;
    let code = match args[0].as_str() {
        "check" if args.len() == 2 => fs::read(input).map_err(|e| e.to_string())?,
        "assemble" => {
            let mut output = None;
            let mut definitions = BTreeMap::new();
            let mut i = 2;
            while i < args.len() {
                let value = args.get(i + 1).ok_or("option requires a value")?;
                match args[i].as_str() {
                    "-o" if output.is_none() => output = Some(value),
                    "-D" => {
                        let (key, val) = value
                            .split_once('=')
                            .ok_or("definition must be NAME=VALUE")?;
                        if key.is_empty()
                            || definitions
                                .insert(key.to_string(), val.to_string())
                                .is_some()
                        {
                            return Err("empty or duplicate definition".into());
                        }
                    }
                    _ => return Err(format!("unknown or duplicate option {}", args[i])),
                }
                i += 2;
            }
            let output = output.ok_or("missing -o OUTPUT")?;
            if std::path::Path::new(input) == std::path::Path::new(output) {
                return Err("output must differ from source".into());
            }
            let source = fs::read_to_string(input).map_err(|e| e.to_string())?;
            let code = assemble(&source, &definitions)?;
            fs::write(output, &code).map_err(|e| e.to_string())?;
            code
        }
        _ => return Err("unknown command or unexpected arguments; use --help".into()),
    };
    let limits = validate(&code)?;
    println!(
        "XPVM v{}: {} bytes, {} instructions, stack {}, memory {} pages; structural validation passed",
        code[4],
        code.len(),
        limits.instruction_count,
        limits.max_stack,
        limits.memory_pages
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("devkit: {error}");
        std::process::exit(1);
    }
}
