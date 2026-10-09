//! XPVM v4 assembler. Kernel validation remains the bytecode authority.
use kernel::program::{vm, vm_app};
use std::collections::BTreeMap;

pub fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected an even number of hexadecimal digits".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn validate(code: &[u8]) -> Result<vm::ValidatedCode, String> {
    if code.len() > kernel::program::MAX_PROGRAM_CODE_SIZE {
        return Err("code exceeds deployment limit".into());
    }
    vm::validate_code(code).map_err(|e| format!("kernel rejected bytecode: {e:?}"))
}

/// Labels are body-relative instruction offsets; entry is always zero in v4.
pub fn assemble(source: &str, definitions: &BTreeMap<String, String>) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let mut stack = 64u16;
    let mut pages = 1u16;
    let mut labels = BTreeMap::new();
    let mut jumps = Vec::new();
    let mut started = false;
    for (index, raw) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let result = (|| -> Result<(), String> {
            if let Some(label) = line.strip_suffix(':') {
                if label.is_empty()
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    return Err("invalid label".into());
                }
                if labels
                    .insert(label.to_string(), body.len() as u32)
                    .is_some()
                {
                    return Err(format!("duplicate label {label}"));
                }
                return Ok(());
            }
            let (name, operand) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let operand = operand.trim();
            let operand = if let Some(key) = operand.strip_prefix('$') {
                definitions
                    .get(key)
                    .ok_or_else(|| format!("undefined parameter {key}"))?
                    .as_str()
            } else {
                operand
            };
            if name.starts_with('.') {
                if started {
                    return Err("header directives must precede instructions".into());
                }
                match name {
                    ".version" if operand == "4" => (),
                    ".stack" => stack = operand.parse().map_err(|_| "invalid stack limit")?,
                    ".memory" => pages = operand.parse().map_err(|_| "invalid memory pages")?,
                    _ => return Err(format!("unknown directive or unsupported version: {name}")),
                }
                return Ok(());
            }
            started = true;
            match name {
                "u128.const" => {
                    let value: u128 = if let Some(hex) = operand.strip_prefix("0x") {
                        u128::from_str_radix(hex, 16)
                    } else {
                        operand.parse()
                    }
                    .map_err(|_| "invalid u128 constant")?;
                    body.push(0x01);
                    body.extend(value.to_le_bytes());
                }
                "bytes.const" | "bytes.text" => {
                    let bytes = if name == "bytes.text" {
                        operand.as_bytes().to_vec()
                    } else {
                        decode_hex(operand)?
                    };
                    if bytes.len() > vm_app::MAX_DATA_BYTES {
                        return Err("byte constant exceeds VM limit".into());
                    }
                    body.push(0x10);
                    body.extend((bytes.len() as u16).to_le_bytes());
                    body.extend(bytes);
                }
                "owner.const" => {
                    let id = operand
                        .parse::<kernel::crypto::ProgramId>()
                        .map_err(|_| "expected 64-hex ProgramId")?;
                    body.push(0x11);
                    body.push(0);
                    body.extend(id.as_bytes());
                }
                "jump" | "jump.zero" => {
                    if operand.is_empty() {
                        return Err("jump needs a label".into());
                    }
                    body.push(if name == "jump" { 0x20 } else { 0x21 });
                    jumps.push((body.len(), operand.to_string(), line_number));
                    body.extend([0; 4]);
                }
                _ => {
                    let opcode = match name {
                        "nop" => 0x00,
                        "add" => 0x02,
                        "return" => 0x03,
                        "scalar.get" => 0x04,
                        "scalar.set" => 0x05,
                        "caller" => 0x12,
                        "self" => 0x13,
                        "signer" => 0x14,
                        "data" => 0x15,
                        "dup" => 0x16,
                        "drop" => 0x17,
                        "swap" => 0x18,
                        "equal" => 0x19,
                        "assert" => 0x22,
                        "revert" => 0x23,
                        "sub" => 0x24,
                        "mul" => 0x25,
                        "div" => 0x26,
                        "less" => 0x27,
                        "less.equal" => 0x28,
                        "integer.decode" => 0x29,
                        "integer.encode" => 0x2a,
                        "bytes.concat" => 0x2b,
                        "storage.get" => 0x30,
                        "storage.set" => 0x31,
                        "storage.delete" => 0x32,
                        "owner.encode" => 0x33,
                        "owner.decode" => 0x34,
                        "bytes.slice" => 0x35,
                        "bytes.length" => 0x36,
                        "bytes.hash" => 0x37,
                        "coin.transfer" => 0x40,
                        "asset.transfer" => 0x41,
                        "asset.mint" => 0x42,
                        "program.call" => 0x43,
                        "incoming.coin" => 0x44,
                        "asset.register" => 0x45,
                        "asset.balance" => 0x46,
                        "coin.balance" => 0x47,
                        "program.call.value" => 0x48,
                        "height" => 0x49,
                        "deployer" => 0x4a,
                        "asset.burn" => 0x4b,
                        _ => return Err(format!("unknown instruction {name}")),
                    };
                    if !operand.is_empty() {
                        return Err(format!("{name} takes no immediate operand"));
                    }
                    body.push(opcode);
                }
            }
            if body.len() + 13 > vm_app::MAX_CODE_BYTES {
                return Err("code exceeds VM v4 limit".into());
            }
            Ok(())
        })();
        result.map_err(|e| format!("line {line_number}: {e}"))?;
    }
    for (position, label, line) in jumps {
        let offset = labels
            .get(&label)
            .ok_or_else(|| format!("line {line}: undefined label {label}"))?;
        body[position..position + 4].copy_from_slice(&offset.to_le_bytes());
    }
    let mut code = vm::MAGIC.to_vec();
    code.push(vm::APPLICATION_VERSION);
    code.extend(stack.to_le_bytes());
    code.extend(pages.to_le_bytes());
    code.extend(0u32.to_le_bytes());
    code.extend(body);
    validate(&code)?;
    Ok(code)
}
