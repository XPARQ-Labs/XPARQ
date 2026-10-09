//! Scalar bytecode validation, version routing, stack bounds, and fuel counting.

use super::{
    APPLICATION_VERSION, ASSET_ISSUANCE_VERSION, ASSET_MINT_COST, ASSET_REGISTER_COST, CodeError,
    HEADER_LEN, INSTRUCTION_COST, MAGIC, MAX_MEMORY_PAGES, MAX_STACK_ITEMS, MintAssetRequest,
    MintAssetTarget, STATE_READ_COST, STATE_WRITE_COST, TRANSFER_COST, TransferRequest, VERSION,
    ValidatedCode, decode_register_request,
};
use crate::monetary::asset::AssetContract;
use borsh::BorshDeserialize;

/// Format: magic[4], version[1], stack_limit[2 LE], memory_pages[2 LE],
/// entry_offset[4 LE], then opcodes. Instructions: nop(00), i64.const(01+8 LE),
/// i64.add(02), return(03), state.get(04), state.set(05). State access is
/// limited to the program's own fixed-size i64 slot; there are no branches.
pub fn validate_code(code: &[u8]) -> Result<ValidatedCode, CodeError> {
    if code.get(4) == Some(&APPLICATION_VERSION) {
        return crate::program::vm_app::validate_code(code);
    }
    if code.len() < HEADER_LEN || code[..4] != MAGIC {
        return Err(CodeError::InvalidHeader);
    }
    if !matches!(code[4], VERSION | 2 | ASSET_ISSUANCE_VERSION) {
        return Err(CodeError::UnsupportedVersion);
    }
    let max_stack = u16::from_le_bytes([code[5], code[6]]);
    let memory_pages = u16::from_le_bytes([code[7], code[8]]);
    if max_stack == 0 || max_stack > MAX_STACK_ITEMS || memory_pages > MAX_MEMORY_PAGES {
        return Err(CodeError::InvalidLimit);
    }
    let entry = u32::from_le_bytes(
        code[9..13]
            .try_into()
            .map_err(|_| CodeError::InvalidHeader)?,
    );
    let body = &code[HEADER_LEN..];
    let mut offset = 0usize;
    let mut boundaries = Vec::new();
    let mut depth = 0u16;
    let mut count = 0u32;
    let mut instruction_fuel = 0u64;
    let mut returned = false;
    let mut coin_transfer_seen = false;
    let mut asset_transfer_seen = false;
    let mut asset_register_seen = false;
    let mut asset_mint_seen = false;
    while offset < body.len() {
        boundaries.push(offset);
        let opcode = body[offset];
        offset += 1;
        count = count.checked_add(1).ok_or(CodeError::InvalidInstruction)?;
        let cost = match opcode {
            0x04 => STATE_READ_COST,
            0x05 => STATE_WRITE_COST,
            0x06 | 0x07 => TRANSFER_COST,
            0x08 => ASSET_REGISTER_COST,
            0x09 => ASSET_MINT_COST,
            _ => INSTRUCTION_COST,
        };
        instruction_fuel = instruction_fuel
            .checked_add(cost)
            .ok_or(CodeError::InvalidLimit)?;
        match opcode {
            0x00 => {}
            0x01 => {
                if body.len().saturating_sub(offset) < 8 {
                    return Err(CodeError::InvalidInstruction);
                }
                offset += 8;
                depth = depth.checked_add(1).ok_or(CodeError::InvalidLimit)?;
                if depth > max_stack {
                    return Err(CodeError::InvalidLimit);
                }
            }
            0x02 => {
                if depth < 2 {
                    return Err(CodeError::InvalidInstruction);
                }
                depth -= 1;
            }
            0x04 => {
                depth = depth.checked_add(1).ok_or(CodeError::InvalidLimit)?;
                if depth > max_stack {
                    return Err(CodeError::InvalidLimit);
                }
            }
            0x05 => {
                if depth == 0 {
                    return Err(CodeError::InvalidInstruction);
                }
                depth -= 1;
            }
            0x06 | 0x07 => {
                if code[4] < 2 {
                    return Err(CodeError::InvalidInstruction);
                }
                let seen = if opcode == 0x06 {
                    &mut coin_transfer_seen
                } else {
                    &mut asset_transfer_seen
                };
                if *seen {
                    return Err(CodeError::InvalidInstruction);
                }
                *seen = true;
                let mut bytes = &body[offset..];
                if opcode == 0x07 {
                    AssetContract::deserialize(&mut bytes)
                        .map_err(|_| CodeError::InvalidInstruction)?;
                }
                let request = TransferRequest::deserialize(&mut bytes)
                    .map_err(|_| CodeError::InvalidInstruction)?;
                if request.amount == 0 {
                    return Err(CodeError::InvalidInstruction);
                }
                offset = body.len() - bytes.len();
            }
            0x08 => {
                if code[4] != ASSET_ISSUANCE_VERSION || asset_register_seen || asset_mint_seen {
                    return Err(CodeError::InvalidInstruction);
                }
                let mut bytes = &body[offset..];
                decode_register_request(&mut bytes)?;
                offset = body.len() - bytes.len();
                asset_register_seen = true;
            }
            0x09 => {
                if code[4] != ASSET_ISSUANCE_VERSION || asset_mint_seen {
                    return Err(CodeError::InvalidInstruction);
                }
                let mut bytes = &body[offset..];
                let request = MintAssetRequest::deserialize(&mut bytes)
                    .map_err(|_| CodeError::InvalidInstruction)?;
                if request.amount.is_zero()
                    || (request.asset == MintAssetTarget::Registered && !asset_register_seen)
                {
                    return Err(CodeError::InvalidInstruction);
                }
                offset = body.len() - bytes.len();
                asset_mint_seen = true;
            }
            0x03 => {
                if depth != 1 || offset != body.len() {
                    return Err(CodeError::InvalidInstruction);
                }
                returned = true;
            }
            _ => return Err(CodeError::InvalidInstruction),
        }
        if returned {
            break;
        }
    }
    if !returned {
        return Err(CodeError::MissingReturn);
    }
    if entry != 0 || !boundaries.contains(&0) {
        return Err(CodeError::InvalidEntry);
    }
    Ok(ValidatedCode {
        entry,
        max_stack,
        memory_pages,
        instruction_count: count,
        instruction_fuel,
    })
}
