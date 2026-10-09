//! Bytecode compatibility, deterministic execution, fuel, and rollback regressions.

use crate::{
    common::Owner,
    monetary::asset::Unit,
    program::{ProgramId, ProgramRegistry},
};

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
    let code = include_bytes!("../../../../examples/counter/counter.xpvm").to_vec();
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
