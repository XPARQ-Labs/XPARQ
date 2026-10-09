//! Application bytecode decoding, jump boundaries, and resource-limit validation.

use super::{MAX_CODE_BYTES, MAX_DATA_BYTES, MAX_INSTRUCTIONS};
use crate::{
    common::Owner,
    program::vm::{self, CodeError, ValidatedCode},
};
use borsh::BorshDeserialize;
use std::collections::BTreeMap;

pub(super) const HEADER: usize = 13;

#[derive(Clone)]
pub(super) struct Instruction {
    pub(super) op: u8,
    pub(super) immediate: Vec<u8>,
    pub(super) next: usize,
}
pub(super) fn instructions(code: &[u8]) -> Result<BTreeMap<usize, Instruction>, CodeError> {
    if code.len() < HEADER || code[..4] != vm::MAGIC || code[4] != vm::APPLICATION_VERSION {
        return Err(CodeError::InvalidHeader);
    }
    if code.len() > MAX_CODE_BYTES {
        return Err(CodeError::InvalidLimit);
    }
    let mut pc = HEADER;
    let mut decoded = BTreeMap::new();
    let mut has_return = false;
    while pc < code.len() {
        if decoded.len() >= MAX_INSTRUCTIONS {
            return Err(CodeError::InvalidLimit);
        }
        let start = pc;
        let op = code[pc];
        pc += 1;
        let n = match op {
            0x01 => 16,
            0x11 => 33,
            0x20 | 0x21 => 4,
            0x10 => {
                let prefix = code.get(pc..pc + 2).ok_or(CodeError::InvalidInstruction)?;
                pc += 2;
                let len = u16::from_le_bytes(prefix.try_into().unwrap()) as usize;
                if len > MAX_DATA_BYTES {
                    return Err(CodeError::InvalidLimit);
                }
                len
            }
            0x00 | 0x02..=0x05 | 0x12..=0x19 | 0x22..=0x2b | 0x30..=0x37 | 0x40..=0x4b => 0,
            _ => return Err(CodeError::InvalidInstruction),
        };
        let immediate = code
            .get(pc..pc + n)
            .ok_or(CodeError::InvalidInstruction)?
            .to_vec();
        pc += n;
        if op == 0x11 {
            Owner::try_from_slice(&immediate).map_err(|_| CodeError::InvalidInstruction)?;
        }
        has_return |= op == 0x03;
        decoded.insert(
            start,
            Instruction {
                op,
                immediate,
                next: pc,
            },
        );
    }
    for i in decoded.values().filter(|i| i.op == 0x20 || i.op == 0x21) {
        let target = HEADER
            .checked_add(u32::from_le_bytes(i.immediate[..].try_into().unwrap()) as usize)
            .ok_or(CodeError::InvalidEntry)?;
        if !decoded.contains_key(&target) {
            return Err(CodeError::InvalidEntry);
        }
    }
    if !has_return {
        return Err(CodeError::MissingReturn);
    }
    Ok(decoded)
}
pub fn validate_code(code: &[u8]) -> Result<ValidatedCode, CodeError> {
    let decoded = instructions(code)?;
    let stack = u16::from_le_bytes([code[5], code[6]]);
    let pages = u16::from_le_bytes([code[7], code[8]]);
    if stack == 0 || stack > vm::MAX_STACK_ITEMS || pages == 0 || pages > vm::MAX_MEMORY_PAGES {
        return Err(CodeError::InvalidLimit);
    }
    let entry = u32::from_le_bytes(code[9..13].try_into().unwrap());
    if entry != 0 || !decoded.contains_key(&HEADER) {
        return Err(CodeError::InvalidEntry);
    }
    Ok(ValidatedCode {
        entry,
        max_stack: stack,
        memory_pages: pages,
        instruction_count: decoded.len() as u32,
        instruction_fuel: 0,
    })
}
