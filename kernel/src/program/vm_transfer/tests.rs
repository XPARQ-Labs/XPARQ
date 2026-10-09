//! Settlement ownership, supply, quote, and atomic rollback regressions.

use crate::{
    common::Owner,
    ledger::{CoinUtxo, LedgerState},
    monetary::{
        asset::{AssetOutput, Unit},
        coin::{CoinShare, Zeno},
    },
    program::{
        ProgramId,
        system::asset_program::type_::{Mint, Transfer},
        vm::MintAssetTarget,
    },
};

use super::*;
use crate::{
    common::{ChainContext, Height},
    consensus::{ProtocolBurn, StateTransitionWeight},
    monetary::{
        asset::{AssetContract, Metadata},
        coin::CoinOutput,
    },
    operation::BlockOperation,
    program::{
        AccountAuthorization, AuthorizedProgramInvocation, CoinCharges, CoinTransition,
        DeployProgram, program_invocation_commitment,
        system::{
            asset_program::{opcode::AssetOpcode, type_::Register},
            script::call::{ProgramCall, SystemProgramId},
        },
    },
};
use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

fn code(asset: AssetContract, recipient: Owner) -> Vec<u8> {
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[2, 2, 0, 0, 0, 0, 0, 0, 0]);
    code.push(6);
    code.extend(
        borsh::to_vec(&super::super::vm::TransferRequest {
            recipient,
            amount: 7,
        })
        .unwrap(),
    );
    code.push(7);
    code.extend(borsh::to_vec(&asset).unwrap());
    code.extend(
        borsh::to_vec(&super::super::vm::TransferRequest {
            recipient,
            amount: 5,
        })
        .unwrap(),
    );
    code.extend_from_slice(&[4, 1]);
    code.extend_from_slice(&1i64.to_le_bytes());
    code.extend_from_slice(&[2, 5, 4, 3]);
    code
}

fn signed(
    state: &LedgerState,
    seed: &SigningSeed,
    chain: ChainContext,
    call: ProgramCall,
    extra: Vec<CoinOutput>,
) -> AuthorizedProgramInvocation {
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let (input, value) = state
        .utxos
        .coins()
        .filter(|(_, v)| v.owner == Owner::Program(signer))
        .max_by_key(|(_, v)| v.amount)
        .unwrap();
    let amount = value.amount.as_zeno();
    let sent = extra.iter().map(|o| o.amount.as_zeno()).sum::<u64>();
    let make = |burn: u64| {
        let mut outputs = extra.clone();
        outputs.push(CoinOutput::new(
            signer,
            Zeno::from_zeno(amount - sent - burn - 1),
        ));
        let payment = CoinTransition::coin_with_charges(
            signer,
            vec![input],
            outputs,
            CoinCharges::new(Zeno::ONE),
        )
        .unwrap();
        let commitment = program_invocation_commitment(signer, &call, &payment, chain).unwrap();
        AuthorizedProgramInvocation {
            signer,
            call: call.clone(),
            payment,
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(commitment.as_bytes()),
            },
        }
    };
    let provisional = make(0);
    let mut growth =
        crate::program::program_created_state_weight(&provisional, chain, &state.extensions)
            .unwrap();
    let mut transfer = TransferQuote::default();
    let mut fuel = 0;
    if let crate::program::system::script::execute::DecodedProgramCall::Vm(raw) =
        crate::program::system::script::execute::decode_program(&call).unwrap()
    {
        let id = ProgramId::from_bytes(raw);
        let result = crate::program::vm::execute_registered(
            &state.programs,
            id,
            crate::program::vm::MAX_CALL_FUEL,
        )
        .unwrap();
        fuel = result.fuel_used;
        let commitment =
            program_invocation_commitment(signer, &call, &provisional.payment, chain).unwrap();
        transfer = quote(
            state,
            id,
            &result,
            commitment,
            crate::program::application::Applications::default().executor(),
        )
        .unwrap();
        growth += transfer.created_state_weight;
    }
    let size = crypto::canonical_bytes(&BlockOperation::ProgramCall(Box::new(provisional)))
        .unwrap()
        .len() as u64;
    let burn = ProtocolBurn::for_program_call(
        StateTransitionWeight {
            created_coin_utxos: extra.len() as u64 + 2 + transfer.created_coin_utxos,
            consumed_coin_utxos: 1 + transfer.consumed_coin_utxos,
            created_state_weight: growth,
        },
        size,
    )
    .unwrap()
    .total()
    .unwrap()
    .as_zeno()
        + fuel;
    make(burn)
}

fn fixture() -> (
    LedgerState,
    SigningSeed,
    ChainContext,
    ProgramId,
    AssetContract,
    crypto::ProgramId,
) {
    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x71; 32]));
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let receiver = crypto::ProgramId([0x72; 32]);
    let chain = ChainContext::new([0x73; 32]);
    let metadata = Metadata::new(
        "VAULT".into(),
        Unit::from_units(100),
        Owner::Program(signer),
        Owner::Program(signer),
    )
    .unwrap();
    let asset = AssetContract::derive(&metadata, 1).unwrap();
    let mut state = LedgerState::default();
    let (id, _) = crate::program::deploy_program(
        &mut state.programs,
        DeployProgram {
            owner: signer,
            nonce: 1,
            code: code(asset, Owner::Program(receiver)).into(),
        },
        Height(1),
    )
    .unwrap();
    let initial = Zeno::from_zeno(10_000_000);
    state
        .utxos
        .insert_coin(
            CoinShare::from_bytes([1; 32]),
            CoinUtxo {
                amount: initial,
                owner: Owner::Program(signer),
            },
        )
        .unwrap();
    state.coin.total_mined = initial;
    let register = ProgramCall {
        program: SystemProgramId::ASSET,
        opcode: AssetOpcode::Register as u8,
        payload: borsh::to_vec(&Register {
            name: "VAULT".into(),
            max_supply: Unit::from_units(100),
            initial_mint: Unit::from_units(15),
            mint_authority: Owner::Program(signer),
            nonce: 1,
        })
        .unwrap(),
    };
    state
        .apply_program_call(
            signed(&state, &seed, chain, register, vec![]),
            signer,
            chain,
            2,
        )
        .unwrap();
    let inputs = state.extensions.assets.shares().keys().copied().collect();
    let deposit = ProgramCall {
        program: SystemProgramId::ASSET,
        opcode: AssetOpcode::Transfer as u8,
        payload: borsh::to_vec(&Transfer {
            asset,
            inputs,
            outputs: vec![AssetOutput::new(Owner::Program(id), Unit::from_units(15))],
        })
        .unwrap(),
    };
    state
        .apply_program_call(
            signed(
                &state,
                &seed,
                chain,
                deposit,
                vec![CoinOutput::to_owner(
                    Owner::Program(id),
                    Zeno::from_zeno(20),
                )],
            ),
            signer,
            chain,
            3,
        )
        .unwrap();
    (state, seed, chain, id, asset, receiver)
}

#[test]
fn deployed_contract_receives_sends_both_values_and_rolls_back() {
    let (mut state, seed, chain, id, asset, receiver) = fixture();
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let before = state.clone();
    let restored =
        <LedgerState as borsh::BorshDeserialize>::try_from_slice(&borsh::to_vec(&state).unwrap())
            .unwrap();
    assert_eq!(restored, state);
    let call = ProgramCall {
        program: SystemProgramId::VM,
        opcode: 0,
        payload: id.as_bytes().to_vec(),
    };
    let journal = state
        .apply_program_call(signed(&state, &seed, chain, call, vec![]), signer, chain, 4)
        .unwrap();
    assert_eq!(
        state
            .utxos
            .coins()
            .filter(|(_, v)| v.owner == Owner::Program(receiver))
            .map(|(_, v)| v.amount.as_zeno())
            .sum::<u64>(),
        7
    );
    assert_eq!(
        state
            .utxos
            .coins()
            .filter(|(_, v)| v.owner == Owner::Program(id))
            .map(|(_, v)| v.amount.as_zeno())
            .sum::<u64>(),
        13
    );
    assert_eq!(
        state
            .extensions
            .assets
            .shares()
            .values()
            .filter(|v| v.owner == Owner::Program(receiver) && v.asset == asset)
            .map(|v| v.amount.as_units())
            .sum::<u128>(),
        5
    );
    assert_eq!(
        state
            .extensions
            .assets
            .shares()
            .values()
            .filter(|v| v.owner == Owner::Program(id))
            .map(|v| v.amount.as_units())
            .sum::<u128>(),
        10
    );
    assert_eq!(state.programs.program(&id).unwrap().state_value, 1);
    state.validate_supply_invariants().unwrap();
    state.rollback_state(journal).unwrap();
    assert_eq!(state, before);
}

#[test]
fn direct_signer_cannot_spend_contract_coin_and_failed_asset_settlement_is_atomic() {
    let (mut state, seed, chain, id, _, _) = fixture();
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let input = state
        .utxos
        .coins()
        .find(|(_, v)| v.owner == Owner::Program(id))
        .unwrap()
        .0;
    let payment = CoinTransition::coin(
        signer,
        vec![input],
        vec![CoinOutput::new(signer, Zeno::ONE)],
    )
    .unwrap();
    let call = crate::program::system::coin_program::transfer_call();
    let commitment = program_invocation_commitment(signer, &call, &payment, chain).unwrap();
    let tx = AuthorizedProgramInvocation {
        signer,
        call,
        payment,
        authorization: AccountAuthorization {
            salt: [0; 32],
            public_key: seed.public_key(),
            signature: seed.sign(commitment.as_bytes()),
        },
    };
    let before = state.clone();
    assert!(state.apply_program_call(tx, signer, chain, 4).is_err());
    assert_eq!(state, before);
    // An account signature cannot spend the contract's asset shares either.
    let mut asset_tx = signed(
        &state,
        &seed,
        chain,
        crate::program::system::coin_program::transfer_call(),
        vec![],
    );
    let (share, value) = state.extensions.assets.shares().iter().next().unwrap();
    asset_tx.call = ProgramCall {
        program: SystemProgramId::ASSET,
        opcode: AssetOpcode::Transfer as u8,
        payload: borsh::to_vec(&Transfer {
            asset: value.asset,
            inputs: vec![*share],
            outputs: vec![AssetOutput::new(Owner::Program(signer), value.amount)],
        })
        .unwrap(),
    };
    let commitment =
        program_invocation_commitment(signer, &asset_tx.call, &asset_tx.payment, chain).unwrap();
    asset_tx.authorization.signature = seed.sign(commitment.as_bytes());
    assert!(
        state
            .apply_program_call(asset_tx, signer, chain, 4)
            .is_err()
    );
    assert_eq!(state, before);
    let call = ProgramCall {
        program: SystemProgramId::VM,
        opcode: 0,
        payload: id.as_bytes().to_vec(),
    };
    let tx = signed(&state, &seed, chain, call, vec![]);
    // Make the asset leg impossible while leaving the coin leg funded.
    let mut staged = state.clone();
    staged.extensions.assets = borsh::from_slice(
        &borsh::to_vec(&(
            staged.extensions.assets.records(),
            std::collections::BTreeMap::<
                crate::monetary::asset::Share,
                crate::monetary::asset::AssetShare,
            >::new(),
        ))
        .unwrap(),
    )
    .unwrap();
    let before = staged.clone();
    assert!(staged.apply_program_call(tx, signer, chain, 4).is_err());
    assert_eq!(staged, before);
}

fn issuance_program(
    state: &mut LedgerState,
    owner: crypto::ProgramId,
    register: Option<crate::program::vm::RegisterAssetRequest>,
    mint: Option<crate::program::vm::MintAssetRequest>,
) -> ProgramId {
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[3, 1, 0, 0, 0, 0, 0, 0, 0]);
    if let Some(request) = register {
        code.push(8);
        code.extend(borsh::to_vec(&request).unwrap());
    }
    if let Some(request) = mint {
        code.push(9);
        code.extend(borsh::to_vec(&request).unwrap());
    }
    code.push(1);
    code.extend_from_slice(&0i64.to_le_bytes());
    code.push(3);
    crate::program::deploy_program(
        &mut state.programs,
        DeployProgram {
            owner,
            nonce: 2,
            code: code.into(),
        },
        Height(4),
    )
    .unwrap()
    .0
}

fn invocation(id: ProgramId) -> ProgramCall {
    ProgramCall {
        program: SystemProgramId::VM,
        opcode: 0,
        payload: id.as_bytes().to_vec(),
    }
}

// An authenticated call whose payment is intentionally unrelated to the VM
// quote lets rejection tests exercise paths for which quoting already fails.
fn unquoted(
    state: &LedgerState,
    seed: &SigningSeed,
    chain: ChainContext,
    call: ProgramCall,
) -> AuthorizedProgramInvocation {
    let mut tx = signed(
        state,
        seed,
        chain,
        crate::program::system::coin_program::transfer_call(),
        vec![],
    );
    tx.call = call;
    let commitment =
        program_invocation_commitment(tx.signer, &tx.call, &tx.payment, chain).unwrap();
    tx.authorization.signature = seed.sign(commitment.as_bytes());
    tx
}

#[test]
fn contract_registers_mints_repeatedly_and_rolls_back_all_asset_changes() {
    use crate::program::vm::{MintAssetRequest, RegisterAssetRequest};
    let (mut state, seed, chain, _, _, receiver) = fixture();
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let id = issuance_program(
        &mut state,
        signer,
        Some(RegisterAssetRequest {
            name: "LAUNCH".into(),
            max_supply: Unit::from_units(11),
            initial_mint: Unit::from_units(1),
            nonce: 9,
            skip_if_exists: true,
        }),
        Some(MintAssetRequest {
            asset: MintAssetTarget::Registered,
            recipient: Owner::Program(receiver),
            amount: Unit::from_units(5),
        }),
    );
    let actor = Owner::Program(id);
    let asset = AssetContract::derive(
        &Metadata::new("LAUNCH".into(), Unit::from_units(11), actor, actor).unwrap(),
        9,
    )
    .unwrap();
    let before = state.clone();
    let caller_balance = |s: &LedgerState| {
        s.utxos
            .coins()
            .filter(|(_, v)| v.owner == Owner::Program(signer))
            .map(|(_, v)| v.amount.as_zeno())
            .sum::<u64>()
    };
    let tx = signed(&state, &seed, chain, invocation(id), vec![]);
    let result = crate::program::vm::execute_registered(
        &state.programs,
        id,
        crate::program::vm::MAX_CALL_FUEL,
    )
    .unwrap();
    let commitment = program_invocation_commitment(signer, &tx.call, &tx.payment, chain).unwrap();
    let preview_before = state.clone();
    let first_quote = quote(
        &state,
        id,
        &result,
        commitment,
        crate::program::application::Applications::default().executor(),
    )
    .unwrap();
    assert!(first_quote.created_state_weight > 0);
    assert_eq!(state, preview_before);
    let input_total = tx
        .payment
        .coin_parts()
        .unwrap()
        .0
        .iter()
        .map(|id| state.utxos.coin(id).unwrap().amount.as_zeno())
        .sum::<u64>();
    let output_total = tx
        .payment
        .coin_parts()
        .unwrap()
        .1
        .iter()
        .map(|v| v.amount.as_zeno())
        .sum::<u64>();
    let journal = state.apply_program_call(tx, receiver, chain, 5).unwrap();
    assert_eq!(
        caller_balance(&before) - caller_balance(&state),
        input_total - output_total
    );
    let record = state.extensions.assets.records().get(&asset).unwrap();
    assert_eq!(record.metadata.creator, actor);
    assert_eq!(record.metadata.mint_authority, actor);
    assert_eq!(
        (
            record.supply.as_units(),
            record.total_minted.as_units(),
            record.mint_nonce
        ),
        (6, 6, 1)
    );
    let balance = |s: &LedgerState, owner| {
        s.extensions
            .assets
            .shares()
            .values()
            .filter(|v| v.asset == asset && v.owner == owner)
            .map(|v| v.amount.as_units())
            .sum::<u128>()
    };
    assert_eq!(balance(&state, actor), 1);
    assert_eq!(balance(&state, Owner::Program(receiver)), 5);
    assert_eq!(
        state
            .utxos
            .coins()
            .filter(|(_, v)| v.owner == actor)
            .count(),
        0
    );
    state.validate_supply_invariants().unwrap();
    let after_first = state.clone();
    let tx = signed(&state, &seed, chain, invocation(id), vec![]);
    let commitment = program_invocation_commitment(signer, &tx.call, &tx.payment, chain).unwrap();
    let second_quote = quote(
        &state,
        id,
        &result,
        commitment,
        crate::program::application::Applications::default().executor(),
    )
    .unwrap();
    assert!(second_quote.created_state_weight < first_quote.created_state_weight);
    let second_journal = state.apply_program_call(tx, receiver, chain, 6).unwrap();
    let record = state.extensions.assets.records().get(&asset).unwrap();
    assert_eq!(
        (
            record.supply.as_units(),
            record.total_minted.as_units(),
            record.mint_nonce
        ),
        (11, 11, 2)
    );
    assert_eq!(balance(&state, actor), 1); // Initial mint is never repeated.
    assert_eq!(balance(&state, Owner::Program(receiver)), 10);
    let after_second = state.clone();
    let failed = unquoted(&state, &seed, chain, invocation(id));
    assert!(
        state
            .apply_program_call(failed, receiver, chain, 7)
            .is_err()
    );
    assert_eq!(state, after_second);
    state.validate_supply_invariants().unwrap();
    let restored =
        <LedgerState as borsh::BorshDeserialize>::try_from_slice(&borsh::to_vec(&state).unwrap())
            .unwrap();
    assert_eq!(restored, state);
    state.rollback_state(second_journal).unwrap();
    assert_eq!(state, after_first);
    state.rollback_state(journal).unwrap();
    assert_eq!(state, before);
}

#[test]
fn invalid_payment_and_direct_signer_mint_cannot_change_program_asset() {
    use crate::program::vm::{MintAssetRequest, RegisterAssetRequest};
    let (mut state, seed, chain, _, _, receiver) = fixture();
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let id = issuance_program(
        &mut state,
        signer,
        Some(RegisterAssetRequest {
            name: "OWNED".into(),
            max_supply: Unit::from_units(100),
            initial_mint: Unit::from_units(1),
            nonce: 1,
            skip_if_exists: false,
        }),
        Some(MintAssetRequest {
            asset: MintAssetTarget::Registered,
            recipient: Owner::Program(receiver),
            amount: Unit::from_units(2),
        }),
    );
    let before = state.clone();
    let mut tx = signed(&state, &seed, chain, invocation(id), vec![]);
    // Use a validly signed but underpaid transaction; registration and mint must not leak.
    tx.payment = unquoted(&state, &seed, chain, invocation(id)).payment;
    let commitment = program_invocation_commitment(signer, &tx.call, &tx.payment, chain).unwrap();
    tx.authorization.signature = seed.sign(commitment.as_bytes());
    assert!(state.apply_program_call(tx, receiver, chain, 5).is_err());
    assert_eq!(state, before);
    let tx = signed(&state, &seed, chain, invocation(id), vec![]);
    state.apply_program_call(tx, receiver, chain, 5).unwrap();
    let actor = Owner::Program(id);
    let asset = AssetContract::derive(
        &Metadata::new("OWNED".into(), Unit::from_units(100), actor, actor).unwrap(),
        1,
    )
    .unwrap();
    let registered = state.clone();
    let mint_call = ProgramCall {
        program: SystemProgramId::ASSET,
        opcode: AssetOpcode::Mint as u8,
        payload: borsh::to_vec(&Mint {
            asset,
            nonce: 2,
            recipient: Owner::Program(signer),
            amount: Unit::from_units(1),
        })
        .unwrap(),
    };
    let tx = unquoted(&state, &seed, chain, mint_call);
    assert!(state.apply_program_call(tx, receiver, chain, 6).is_err());
    assert_eq!(state, registered);
    // Strict registration rejects repeats and never issues the initial supply twice.
    let tx = unquoted(&state, &seed, chain, invocation(id));
    assert!(state.apply_program_call(tx, receiver, chain, 6).is_err());
    assert_eq!(state, registered);
}

#[test]
fn mint_existing_asset_requires_program_authority_and_accepts_implicit_recipient() {
    use crate::program::vm::MintAssetRequest;
    let (mut state, seed, chain, _, asset, receiver) = fixture();
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let id = issuance_program(
        &mut state,
        signer,
        None,
        Some(MintAssetRequest {
            asset: MintAssetTarget::Existing(asset),
            recipient: Owner::Program(receiver),
            amount: Unit::from_units(2),
        }),
    );
    let before = state.clone();
    let tx = unquoted(&state, &seed, chain, invocation(id));
    assert!(state.apply_program_call(tx, receiver, chain, 5).is_err());
    assert_eq!(state, before); // Asset authority belongs to signer, not this program.
    let metadata = Metadata::new(
        "EXTERNAL".into(),
        Unit::from_units(100),
        Owner::Program(signer),
        Owner::Program(id),
    )
    .unwrap();
    let asset = AssetContract::derive(&metadata, 7).unwrap();
    let registration = ProgramCall {
        program: SystemProgramId::ASSET,
        opcode: AssetOpcode::Register as u8,
        payload: borsh::to_vec(&Register {
            name: "EXTERNAL".into(),
            max_supply: Unit::from_units(100),
            initial_mint: Unit::from_units(1),
            mint_authority: Owner::Program(id),
            nonce: 7,
        })
        .unwrap(),
    };
    let tx = signed(&state, &seed, chain, registration, vec![]);
    state.apply_program_call(tx, receiver, chain, 5).unwrap();
    // Exercise the same settled proposal against external, program-authorized state.
    let mut result = crate::program::vm::execute_registered(
        &state.programs,
        id,
        crate::program::vm::MAX_CALL_FUEL,
    )
    .unwrap();
    result.asset_mint.as_mut().unwrap().asset = MintAssetTarget::Existing(asset);
    let commitment = program_invocation_commitment(
        signer,
        &invocation(id),
        &signed(
            &state,
            &seed,
            chain,
            crate::program::system::coin_program::transfer_call(),
            vec![],
        )
        .payment,
        chain,
    )
    .unwrap();
    let before = state.clone();
    let (_, journal) = settle(
        &mut state,
        id,
        &result,
        commitment,
        crate::program::application::Applications::default().executor(),
    )
    .unwrap();
    assert_eq!(
        state
            .extensions
            .assets
            .records()
            .get(&asset)
            .unwrap()
            .mint_nonce,
        1
    );
    state.validate_supply_invariants().unwrap();
    state.extensions.assets.rollback(journal.unwrap());
    assert_eq!(state, before);
    result.asset_mint.as_mut().unwrap().recipient =
        Owner::Program(ProgramId::from_bytes([0x99; 32]));
    assert!(
        quote(
            &state,
            id,
            &result,
            commitment,
            crate::program::application::Applications::default().executor()
        )
        .is_ok()
    );
    assert_eq!(state, before);
}

#[test]
fn program_can_mint_u128_amounts_to_another_deployed_program() {
    use crate::program::vm::{MintAssetRequest, RegisterAssetRequest};
    let (mut state, seed, chain, recipient, _, miner) = fixture();
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let amount = Unit::from_units(u64::MAX as u128 + 1);
    let id = issuance_program(
        &mut state,
        signer,
        Some(RegisterAssetRequest {
            name: "BIG".into(),
            max_supply: Unit::from_units(u128::MAX),
            initial_mint: Unit::from_units(1),
            nonce: 1,
            skip_if_exists: true,
        }),
        Some(MintAssetRequest {
            asset: MintAssetTarget::Registered,
            recipient: Owner::Program(recipient),
            amount,
        }),
    );
    let before = state.clone();
    let tx = signed(&state, &seed, chain, invocation(id), vec![]);
    let journal = state.apply_program_call(tx, miner, chain, 5).unwrap();
    let actor = Owner::Program(id);
    let asset = AssetContract::derive(
        &Metadata::new("BIG".into(), Unit::from_units(u128::MAX), actor, actor).unwrap(),
        1,
    )
    .unwrap();
    let record = state.extensions.assets.records().get(&asset).unwrap();
    assert_eq!(record.supply.as_units(), amount.as_units() + 1);
    assert_eq!(
        state
            .extensions
            .assets
            .shares()
            .values()
            .filter(|v| v.asset == asset && v.owner == Owner::Program(recipient))
            .map(|v| v.amount.as_units())
            .sum::<u128>(),
        amount.as_units()
    );
    state.validate_supply_invariants().unwrap();
    state.rollback_state(journal).unwrap();
    assert_eq!(state, before);
}

#[test]
fn failed_first_mint_discards_registration_and_payment() {
    use crate::program::vm::{MintAssetRequest, RegisterAssetRequest};
    let (mut state, seed, chain, _, _, receiver) = fixture();
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let id = issuance_program(
        &mut state,
        signer,
        Some(RegisterAssetRequest {
            name: "FULL".into(),
            max_supply: Unit::from_units(u128::MAX),
            initial_mint: Unit::from_units(u128::MAX),
            nonce: 1,
            skip_if_exists: true,
        }),
        Some(MintAssetRequest {
            asset: MintAssetTarget::Registered,
            recipient: Owner::Program(receiver),
            amount: Unit::from_units(1),
        }),
    );
    let before = state.clone();
    let tx = unquoted(&state, &seed, chain, invocation(id));
    let commitment = program_invocation_commitment(signer, &tx.call, &tx.payment, chain).unwrap();
    let result = crate::program::vm::execute_registered(
        &state.programs,
        id,
        crate::program::vm::MAX_CALL_FUEL,
    )
    .unwrap();
    assert!(
        quote(
            &state,
            id,
            &result,
            commitment,
            crate::program::application::Applications::default().executor()
        )
        .is_err()
    );
    assert_eq!(state, before);
    assert!(state.apply_program_call(tx, receiver, chain, 5).is_err());
    assert_eq!(state, before);
}
