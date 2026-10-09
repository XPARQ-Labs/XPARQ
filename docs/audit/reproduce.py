#!/usr/bin/env python3
"""Reproduce audit findings without RPC, signing keys, or chain mutations.

Run: python3 docs/audit/reproduce.py (requires rustc).
Extracts production functions verbatim and replaces dependencies with stubs.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def function(path, name, end):
    source = (ROOT / path).read_text()
    start = source.index(f"pub(super) fn {name}(")
    return source[start:source.index(end, start)].replace("pub(super) fn", "fn", 1)


parser = function("runtime/src/node/rpc.rs", "read_http_request", "pub(super) fn write_http_response")
fetch = function("wallet/src/native/rpc.rs", "fetch_account", "pub(super) fn http_get_json")
vm_source = (ROOT / "kernel/src/program/vm.rs").read_text()
vm_start = vm_source.index("pub fn validate_code(")
vm_validator = vm_source[vm_start:vm_source.index("/// The VM proposes", vm_start)]
vm_constants = "\n".join(
    line for line in vm_source.splitlines()
    if line.startswith(("pub const ", "const HEADER_LEN:"))
)
constants = (ROOT / "runtime/src/node/mod.rs").read_text().splitlines()
constants = "\n".join(line for line in constants if line.startswith("const MAX_RPC_HEADER_SIZE:") or line.startswith("const MAX_STORED_TRANSACTION_SIZE:"))
limit_source = (ROOT / "kernel/src/program/mod.rs").read_text().splitlines()
limit_source = "\n".join(line for line in limit_source if line.startswith("pub const MAX_PROGRAM_INVOCATION_SIZE:"))
constants = constants.replace("kernel::program::MAX_PROGRAM_INVOCATION_SIZE", "MAX_PROGRAM_INVOCATION_SIZE")

harness = r'''
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
struct HttpRequest { headers: String, body: Vec<u8> }
struct AccountResponse {
    utxos: Vec<u8>,
    next_utxo_offset: Option<usize>,
    next_utxo_cursor: Option<String>,
}
static CALLS: AtomicUsize = AtomicUsize::new(0);
#[derive(Debug)]
struct ValidatedCode {
    entry: u32, max_stack: u16, memory_pages: u16,
    instruction_count: u32, instruction_fuel: u64,
}
#[derive(Debug)]
enum CodeError {
    InvalidHeader, UnsupportedVersion, InvalidLimit, InvalidEntry,
    InvalidInstruction, MissingReturn,
}
fn http_get_json(_rpc: &str, _route: &str) -> Result<AccountResponse, String> {
    let call = CALLS.fetch_add(1, Ordering::SeqCst) + 1;
    // Bound the reproducer itself; production has no repeated-cursor guard.
    if call > 5 { return Err("mock stopped after five repeated pages".into()); }
    Ok(AccountResponse {
        utxos: vec![1], next_utxo_offset: Some(1),
        next_utxo_cursor: Some("unchanged-cursor".into()),
    })
}
'''
harness += constants + "\n" + limit_source + "\n" + vm_constants + "\n" + vm_validator + parser + fetch
harness += r'''
fn main() {
    // Keep depth <=2: initial PUSH 0; 27,000 times PUSH 0, ADD; RETURN.
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend_from_slice(&0i64.to_le_bytes());
    for _ in 0..27_000 {
        code.push(1);
        code.extend_from_slice(&0i64.to_le_bytes());
        code.push(2);
    }
    code.push(3);
    let validated = validate_code(&code).expect("valid XPVM bytecode");
    assert!(code.len() > MAX_STORED_TRANSACTION_SIZE);
    assert!(code.len() <= 1_048_576);
    assert!(validated.instruction_fuel <= MAX_CALL_FUEL);
    let request = format!(
        "POST /program/deploy/quote HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        code.len()
    );
    let error = read_http_request(&mut std::io::Cursor::new(request.into_bytes()))
        .err().expect("RPC rejects declared length before reading the body");
    assert!(error.contains("transaction size limit"), "{error}");
    println!("A-02: valid XPVM code ({} bytes, {} fuel) exceeds RPC body limit.",
        code.len(), validated.instruction_fuel);

    let error = fetch_account("mock", "synthetic-address").err().unwrap();
    assert!(error.starts_with("mock stopped"));
    assert_eq!(CALLS.load(Ordering::SeqCst), 6);
    println!("A-03: repeated cursor accepted five times; only the mock stopped the loop.");
}
'''

with tempfile.TemporaryDirectory(prefix="xparq-audit-") as directory:
    source = Path(directory) / "reproduce.rs"
    binary = Path(directory) / "reproduce"
    source.write_text(harness)
    subprocess.run(["rustc", "--edition=2024", "-Awarnings", str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
