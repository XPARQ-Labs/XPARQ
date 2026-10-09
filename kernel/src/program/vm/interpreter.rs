//! Deterministic scalar XPVM v1-v3 execution and monetary proposals.

use super::{
    APPLICATION_VERSION, ExecutionError, ExecutionResult, HEADER_LEN, MEMORY_PAGE_COST,
    MintAssetRequest, TransferRequest, VmEffect, decode_register_request, validate_code,
};
use crate::{
    monetary::asset::AssetContract,
    program::{ProgramId, ProgramRegistry},
};
use borsh::BorshDeserialize;

/// Resolve deployed code from the canonical registry before interpreting it.
pub fn execute_registered(
    registry: &ProgramRegistry,
    id: ProgramId,
    fuel_limit: u64,
) -> Result<ExecutionResult, ExecutionError> {
    let record = registry
        .program(&id)
        .ok_or(ExecutionError::UnknownProgram)?;
    execute_code_with_state(&record.code, record.state_value, fuel_limit)
}

/// Execute validated XPVM code with an explicit fuel ceiling. The
/// interpreter owns its stack; execution has no mutable ledger access.
pub fn execute_code(code: &[u8], fuel_limit: u64) -> Result<ExecutionResult, ExecutionError> {
    execute_code_with_state(code, 0, fuel_limit)
}

fn execute_code_with_state(
    code: &[u8],
    initial_state: i64,
    fuel_limit: u64,
) -> Result<ExecutionResult, ExecutionError> {
    if code.get(4) == Some(&APPLICATION_VERSION) {
        return Err(ExecutionError::InvalidOperand); // Application execution requires an authenticated kernel context.
    }
    let validated = validate_code(code).map_err(ExecutionError::InvalidCode)?;
    let memory_cost = u64::from(validated.memory_pages) * MEMORY_PAGE_COST;
    let fuel_used = memory_cost
        .checked_add(validated.instruction_fuel)
        .ok_or(ExecutionError::OutOfFuel)?;
    if fuel_used > fuel_limit {
        return Err(ExecutionError::OutOfFuel);
    }

    let mut stack = Vec::with_capacity(usize::from(validated.max_stack));
    let mut state_value = initial_state;
    let mut proposed_effect = None;
    let mut coin_transfer = None;
    let mut asset_transfer = None;
    let mut asset_register = None;
    let mut asset_mint = None;
    let mut cursor = HEADER_LEN;
    loop {
        let opcode = code[cursor];
        cursor += 1;
        match opcode {
            0x00 => {}
            0x01 => {
                let value = i64::from_le_bytes(
                    code[cursor..cursor + 8]
                        .try_into()
                        .expect("validated i64 constant"),
                );
                cursor += 8;
                stack.push(value);
            }
            0x02 => {
                let right = stack.pop().expect("validated stack depth");
                let left = stack.pop().expect("validated stack depth");
                stack.push(
                    left.checked_add(right)
                        .ok_or(ExecutionError::ArithmeticOverflow)?,
                );
            }
            0x04 => stack.push(state_value),
            0x05 => {
                state_value = stack.pop().expect("validated state write");
                proposed_effect = Some(VmEffect::ProgramState(state_value));
            }
            0x06 => {
                let mut bytes = &code[cursor..];
                coin_transfer =
                    Some(TransferRequest::deserialize(&mut bytes).expect("validated transfer"));
                cursor = code.len() - bytes.len();
            }
            0x07 => {
                let mut bytes = &code[cursor..];
                let asset = AssetContract::deserialize(&mut bytes).expect("validated asset");
                let request = TransferRequest::deserialize(&mut bytes).expect("validated transfer");
                asset_transfer = Some((asset, request));
                cursor = code.len() - bytes.len();
            }
            0x08 => {
                let mut bytes = &code[cursor..];
                asset_register =
                    Some(decode_register_request(&mut bytes).expect("validated register"));
                cursor = code.len() - bytes.len();
            }
            0x09 => {
                let mut bytes = &code[cursor..];
                asset_mint =
                    Some(MintAssetRequest::deserialize(&mut bytes).expect("validated mint"));
                cursor = code.len() - bytes.len();
            }
            0x03 => {
                return Ok(ExecutionResult {
                    value: stack.pop().expect("validated return value"),
                    fuel_used,
                    proposed_effect,
                    coin_transfer,
                    asset_transfer,
                    asset_register,
                    asset_mint,
                });
            }
            _ => unreachable!("validated opcode"),
        }
    }
}
