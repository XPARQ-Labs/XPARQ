//! Deterministic XPVM bytecode contract, interpreter, and metering.

use crate::program::{ProgramId, ProgramRegistry};
use crate::{
    common::Owner,
    monetary::asset::{ASSET_NAME_MAX_LEN, AssetContract, Unit, validate_asset_name},
};
use borsh::{BorshDeserialize, BorshSerialize};

pub const MAGIC: [u8; 4] = *b"XPVM";
pub const VERSION: u8 = 1;
pub const APPLICATION_VERSION: u8 = 4;
pub const ASSET_ISSUANCE_VERSION: u8 = 3;
pub const MAX_STACK_ITEMS: u16 = 256;
pub const MAX_MEMORY_PAGES: u16 = 16;
pub const PAGE_BYTES: usize = 65_536;
pub const MAX_CALL_FUEL: u64 = 65_536;
const HEADER_LEN: usize = 13;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedCode {
    pub entry: u32,
    pub max_stack: u16,
    pub memory_pages: u16,
    pub instruction_count: u32,
    pub instruction_fuel: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeError {
    InvalidHeader,
    UnsupportedVersion,
    InvalidLimit,
    InvalidEntry,
    InvalidInstruction,
    MissingReturn,
}

/// State and transfer instructions have explicit deterministic costs.
/// Monetary changes are proposals checked and applied by the kernel.
pub const INSTRUCTION_COST: u64 = 1;
pub const MEMORY_PAGE_COST: u64 = 1;
pub const STATE_READ_COST: u64 = 2;
pub const STATE_WRITE_COST: u64 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    pub value: i64,
    pub fuel_used: u64,
    pub proposed_effect: Option<VmEffect>,
    pub coin_transfer: Option<TransferRequest>,
    pub asset_transfer: Option<(AssetContract, TransferRequest)>,
    pub asset_register: Option<RegisterAssetRequest>,
    pub asset_mint: Option<MintAssetRequest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    InvalidCode(CodeError),
    UnknownProgram,
    OutOfFuel,
    ArithmeticOverflow,
    InvalidOperand,
    Reverted,
    ResourceLimit,
    ReentrantCall,
    SettlementFailed,
}

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

/// Format: magic[4], version[1], stack_limit[2 LE], memory_pages[2 LE],
/// entry_offset[4 LE], then opcodes. Instructions: nop(00), i64.const(01+8 LE),
/// i64.add(02), return(03), state.get(04), state.set(05). State access is
/// limited to the program's own fixed-size i64 slot; there are no branches.
pub fn validate_code(code: &[u8]) -> Result<ValidatedCode, CodeError> {
    if code.get(4) == Some(&APPLICATION_VERSION) {
        return super::vm_app::validate_code(code);
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

/// The VM proposes a change to its own fixed-size state slot. The kernel applies
/// the proposal only after successful execution and journals the old value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmEffect {
    ProgramState(i64),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_canonical_bounded_code() {
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend_from_slice(&7u64.to_le_bytes());
        code.push(3);
        assert_eq!(validate_code(&code).unwrap().instruction_count, 2);
        code[4] = 5;
        assert_eq!(validate_code(&code), Err(CodeError::UnsupportedVersion));
    }

    #[test]
    fn transfer_instructions_are_bounded_metered_and_versioned() {
        let request = TransferRequest {
            recipient: Owner::Program(crypto::ProgramId::ZERO),
            amount: 3,
        };
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[2, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(6);
        code.extend(borsh::to_vec(&request).unwrap());
        code.push(1);
        code.extend_from_slice(&0i64.to_le_bytes());
        code.push(3);
        let result = execute_code(&code, 22).unwrap();
        assert_eq!(result.coin_transfer, Some(request));
        assert_eq!(result.fuel_used, 22);
        assert_eq!(execute_code(&code, 21), Err(ExecutionError::OutOfFuel));
        let mut duplicate = code[..code.len() - 10].to_vec();
        duplicate.push(6);
        duplicate.extend(borsh::to_vec(&request).unwrap());
        duplicate.extend_from_slice(&code[code.len() - 10..]);
        assert_eq!(
            validate_code(&duplicate),
            Err(CodeError::InvalidInstruction)
        );
        for length in 14..54 {
            assert!(validate_code(&code[..length]).is_err());
        }
        code[4] = 1;
        assert_eq!(validate_code(&code), Err(CodeError::InvalidInstruction));
        code[4] = 2;
        code[47..55].fill(0);
        assert_eq!(validate_code(&code), Err(CodeError::InvalidInstruction));
    }

    fn issuance_code(register: &RegisterAssetRequest, mint: &MintAssetRequest) -> Vec<u8> {
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(8);
        code.extend(borsh::to_vec(register).unwrap());
        code.push(9);
        code.extend(borsh::to_vec(mint).unwrap());
        code.push(1);
        code.extend_from_slice(&0i64.to_le_bytes());
        code.push(3);
        code
    }

    #[test]
    fn issuance_is_versioned_bounded_validated_and_metered() {
        let register = RegisterAssetRequest {
            name: "LAUNCH".into(),
            max_supply: Unit::from_units(u128::MAX),
            initial_mint: Unit::from_units(1),
            nonce: 1,
            skip_if_exists: true,
        };
        let mint = MintAssetRequest {
            asset: MintAssetTarget::Registered,
            recipient: Owner::Program(crypto::ProgramId::ZERO),
            amount: Unit::from_units(u64::MAX as u128 + 1),
        };
        let code = issuance_code(&register, &mint);
        let fuel = ASSET_REGISTER_COST + ASSET_MINT_COST + 2;
        let result = execute_code(&code, fuel).unwrap();
        assert_eq!(result.asset_register, Some(register.clone()));
        assert_eq!(result.asset_mint, Some(mint));
        assert_eq!(result.fuel_used, fuel);
        assert_eq!(
            execute_code(&code, fuel - 1),
            Err(ExecutionError::OutOfFuel)
        );
        for version in [1, 2, 5] {
            let mut invalid = code.clone();
            invalid[4] = version;
            assert!(validate_code(&invalid).is_err());
        }
        for length in 0..code.len() {
            assert!(validate_code(&code[..length]).is_err());
        }
        for bad in [
            RegisterAssetRequest {
                name: "X".repeat(65),
                ..register.clone()
            },
            RegisterAssetRequest {
                name: " leading".into(),
                ..register.clone()
            },
            RegisterAssetRequest {
                initial_mint: Unit::ZERO,
                ..register.clone()
            },
            RegisterAssetRequest {
                max_supply: Unit::ZERO,
                ..register.clone()
            },
            RegisterAssetRequest {
                max_supply: Unit::from_units(1),
                initial_mint: Unit::from_units(2),
                ..register.clone()
            },
        ] {
            assert_eq!(
                validate_code(&issuance_code(&bad, &mint)),
                Err(CodeError::InvalidInstruction)
            );
        }
        assert!(
            validate_code(&issuance_code(
                &register,
                &MintAssetRequest {
                    amount: Unit::ZERO,
                    ..mint
                }
            ))
            .is_err()
        );
        let register_len = 1 + borsh::to_vec(&register).unwrap().len();
        let mint_start = HEADER_LEN + register_len;
        let mint_end = mint_start + 1 + borsh::to_vec(&mint).unwrap().len();
        for range in [HEADER_LEN..mint_start, mint_start..mint_end] {
            let mut duplicate = code.clone();
            duplicate.splice(range.end..range.end, code[range].iter().copied());
            assert!(validate_code(&duplicate).is_err());
        }
        let mut no_register = code.clone();
        no_register.drain(HEADER_LEN..mint_start);
        assert!(validate_code(&no_register).is_err());
        let mut huge_name = code.clone();
        huge_name[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_code(&huge_name).is_err());
        let mut invalid_bool = code.clone();
        invalid_bool[mint_start - 1] = 2;
        assert!(validate_code(&invalid_bool).is_err());
        let mut invalid_target = code.clone();
        invalid_target[mint_start + 1] = 2;
        assert!(validate_code(&invalid_target).is_err());
    }

    #[test]
    fn execution_is_metered_and_deterministic() {
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 2, 0, 1, 0, 0, 0, 0, 0]);
        for value in [7i64, 9] {
            code.push(1);
            code.extend_from_slice(&value.to_le_bytes());
        }
        code.extend_from_slice(&[2, 3]);
        assert_eq!(execute_code(&code, 4), Err(ExecutionError::OutOfFuel));
        assert_eq!(
            execute_code(&code, 5),
            Ok(ExecutionResult {
                value: 16,
                fuel_used: 5,
                proposed_effect: None,
                coin_transfer: None,
                asset_transfer: None,
                asset_register: None,
                asset_mint: None,
            })
        );
        assert_eq!(execute_code(&code, 5), execute_code(&code, 5));
    }

    #[test]
    fn arithmetic_overflow_traps_without_effects() {
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 0, 0]);
        for value in [i64::MAX, 1] {
            code.push(1);
            code.extend_from_slice(&value.to_le_bytes());
        }
        code.extend_from_slice(&[2, 3]);
        assert_eq!(
            execute_code(&code, 4),
            Err(ExecutionError::ArithmeticOverflow)
        );
    }

    #[test]
    fn registered_code_executes_and_missing_id_fails() {
        use crate::{
            common::Height,
            program::{DeployProgram, deploy_program},
        };
        let mut registry = ProgramRegistry::default();
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend_from_slice(&42i64.to_le_bytes());
        code.push(3);
        let (id, _) = deploy_program(
            &mut registry,
            DeployProgram {
                owner: crypto::ProgramId::ZERO,
                nonce: 1,
                code: code.into(),
            },
            Height(1),
        )
        .unwrap();
        assert_eq!(execute_registered(&registry, id, 2).unwrap().value, 42);
        assert_eq!(
            execute_registered(&registry, ProgramId::from_bytes([0; crypto::HASH_SIZE]), 2),
            Err(ExecutionError::UnknownProgram)
        );
    }

    #[test]
    fn program_state_proposal_is_metered_and_rollback_restores_value() {
        use crate::{
            common::Height,
            ledger::{LedgerState, StateRollbackJournal},
            program::{DeployProgram, ProgramJournal, deploy_program},
        };
        let mut state = LedgerState::default();
        let code = include_bytes!("../../../examples/counter/counter.xpvm").to_vec();
        let (id, _) = deploy_program(
            &mut state.programs,
            DeployProgram {
                owner: crypto::ProgramId::ZERO,
                nonce: 1,
                code: code.into(),
            },
            Height(1),
        )
        .unwrap();
        assert_eq!(
            execute_registered(&state.programs, id, 11),
            Err(ExecutionError::OutOfFuel)
        );
        let first = execute_registered(&state.programs, id, 12).unwrap();
        assert_eq!(
            (first.value, first.fuel_used, first.proposed_effect),
            (1, 12, Some(VmEffect::ProgramState(1)))
        );
        assert_eq!(state.programs.program(&id).unwrap().state_value, 0);
        let Some(VmEffect::ProgramState(value)) = first.proposed_effect else {
            panic!("missing state proposal")
        };
        let previous = state.programs.set_state(id, value).unwrap();
        let updated = state.clone();
        assert_eq!(
            execute_registered(&state.programs, id, 12)
                .unwrap()
                .proposed_effect,
            Some(VmEffect::ProgramState(2))
        );
        let restored = <ProgramRegistry as borsh::BorshDeserialize>::try_from_slice(
            &borsh::to_vec(&state.programs).unwrap(),
        )
        .unwrap();
        assert_eq!(execute_registered(&restored, id, 12).unwrap().value, 2);
        let mut overflow = state.programs.clone();
        overflow.set_state(id, i64::MAX).unwrap();
        let unchanged = overflow.clone();
        assert_eq!(
            execute_registered(&overflow, id, 12),
            Err(ExecutionError::ArithmeticOverflow)
        );
        assert_eq!(overflow, unchanged);
        state
            .rollback_state(StateRollbackJournal {
                coin: None,
                program: Some(ProgramJournal::State {
                    program_id: id,
                    previous,
                }),
                extension: None,
            })
            .unwrap();
        assert_eq!(state.programs.program(&id).unwrap().state_value, 0);
        assert_ne!(state, updated);
    }
}

/// Version 2 permits one coin and one asset transfer per execution. Recipients
/// and positive amounts are embedded in deployed code, never chosen by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransferRequest {
    pub recipient: Owner,
    pub amount: u64,
}
pub const TRANSFER_COST: u64 = 20;

/// Version 3 registration binds creator and mint authority to the executing program.
/// Initial supply goes to that program. Repeated registration may explicitly be
/// skipped; it never issues the initial supply again.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterAssetRequest {
    pub name: String,
    pub max_supply: Unit,
    pub initial_mint: Unit,
    pub nonce: u64,
    pub skip_if_exists: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum MintAssetTarget {
    Existing(AssetContract),
    /// The asset resolved by the preceding registration instruction. Avoids
    /// embedding an asset ID that depends on this program's own code hash.
    Registered,
}

/// Nonce is selected by the kernel from canonical asset state, never from caller data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MintAssetRequest {
    pub asset: MintAssetTarget,
    pub recipient: Owner,
    pub amount: Unit,
}

pub const ASSET_REGISTER_COST: u64 = 40;
pub const ASSET_MINT_COST: u64 = 20;

pub(crate) fn decode_register_request(
    bytes: &mut &[u8],
) -> Result<RegisterAssetRequest, CodeError> {
    // Bound the string before Borsh allocates it, including when called outside deployment.
    let length = bytes.get(..4).ok_or(CodeError::InvalidInstruction)?;
    let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
    if length == 0 || length > ASSET_NAME_MAX_LEN {
        return Err(CodeError::InvalidInstruction);
    }
    let request =
        RegisterAssetRequest::deserialize(bytes).map_err(|_| CodeError::InvalidInstruction)?;
    validate_asset_name(&request.name).map_err(|_| CodeError::InvalidInstruction)?;
    if request.max_supply.is_zero()
        || request.initial_mint.is_zero()
        || request.initial_mint > request.max_supply
    {
        return Err(CodeError::InvalidInstruction);
    }
    Ok(request)
}

impl ExecutionResult {
    pub fn has_monetary_effects(&self) -> bool {
        self.coin_transfer.is_some()
            || self.asset_transfer.is_some()
            || self.asset_register.is_some()
            || self.asset_mint.is_some()
    }
}
