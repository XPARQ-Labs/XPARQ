use super::*;
use crate::{
    common::{ChainContext, Height},
    consensus::{ProtocolBurn, StateTransitionWeight},
    monetary::coin::CoinOutput,
    operation::BlockOperation,
    program::{
        AccountAuthorization, CoinCharges, CoinTransition, DeployProgram,
        program_invocation_commitment,
        system::script::call::{ProgramCall, SystemProgramId},
    },
};
use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

fn code(body: Vec<u8>) -> Vec<u8> {
    let mut v = b"XPVM".to_vec();
    v.extend([4, 16, 0, 1, 0, 0, 0, 0, 0]);
    v.extend(body);
    v
}
fn int(body: &mut Vec<u8>, n: u128) {
    body.push(1);
    body.extend(n.to_le_bytes());
}
fn bytes(body: &mut Vec<u8>, v: &[u8]) {
    body.push(0x10);
    body.extend((v.len() as u16).to_le_bytes());
    body.extend(v);
}
fn owner(body: &mut Vec<u8>, v: Owner) {
    body.push(0x11);
    body.extend(canonical_bytes(&v).unwrap());
}
fn end(body: &mut Vec<u8>, n: u128) {
    int(body, n);
    body.push(3);
}
fn deploy(state: &mut LedgerState, seed: &SigningSeed, body: Vec<u8>, nonce: u64) -> ProgramId {
    super::super::deploy_program(
        &mut state.programs,
        DeployProgram {
            owner: program_id_from_public_key(&seed.public_key()).unwrap(),
            nonce,
            code: code(body).into(),
        },
        Height(1),
    )
    .unwrap()
    .0
}
fn fund(state: &mut LedgerState, owner: Owner, n: u64, tag: u8) {
    state.coin.total_mined = state
        .coin
        .total_mined
        .checked_add(Zeno::from_zeno(n))
        .unwrap();
    state
        .utxos
        .insert_coin(
            CoinShare::from_bytes([tag; 32]),
            crate::ledger::CoinUtxo {
                owner,
                amount: Zeno::from_zeno(n),
            },
        )
        .unwrap();
}
fn fixture() -> (LedgerState, SigningSeed, ChainContext) {
    let mut state = LedgerState::default();
    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([6; 32]));
    fund(
        &mut state,
        Owner::Program(program_id_from_public_key(&seed.public_key()).unwrap()),
        10_000_000,
        1,
    );
    (state, seed, crate::genesis::chain_context().unwrap())
}
fn call(id: ProgramId, data: &[u8]) -> ProgramCall {
    let mut payload = id.into_bytes().to_vec();
    payload.extend(data);
    ProgramCall {
        program: SystemProgramId::VM,
        opcode: 1,
        payload,
    }
}
fn signed(
    state: &LedgerState,
    seed: &SigningSeed,
    chain: ChainContext,
    call: ProgramCall,
    deposit: u64,
) -> AuthorizedProgramInvocation {
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let (input, value) = state
        .utxos
        .coins()
        .filter(|(_, v)| v.owner == Owner::Program(signer))
        .max_by_key(|(_, v)| v.amount)
        .unwrap();
    let make = |burn: u64| {
        let mut outputs = vec![CoinOutput::new(
            signer,
            Zeno::from_zeno(value.amount.as_zeno() - deposit - burn - 1),
        )];
        if deposit > 0 {
            outputs.push(CoinOutput::to_owner(
                Owner::Program(call_input(&call).unwrap().0),
                Zeno::from_zeno(deposit),
            ));
        }
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
    let mut burn = 0;
    for _ in 0..8 {
        let tx = make(burn);
        let commitment = program_invocation_commitment(signer, &call, &tx.payment, chain).unwrap();
        let result = preview(
            state,
            &tx,
            2,
            commitment,
            super::super::application::Applications::default().executor(),
        )
        .unwrap();
        // Independent encoding oracle for the sparse growth calculation.
        let before = canonical_bytes(&(&state.programs, &state.extensions))
            .unwrap()
            .len();
        let mut staged = state.clone();
        apply(
            &mut staged,
            &tx,
            2,
            commitment,
            super::super::application::Applications::default().executor(),
        )
        .unwrap();
        let after = canonical_bytes(&(&staged.programs, &staged.extensions))
            .unwrap()
            .len();
        assert_eq!(
            result.quote.created_state_weight,
            after.saturating_sub(before) as u64
        );
        let size = canonical_bytes(&BlockOperation::ProgramCall(Box::new(tx.clone())))
            .unwrap()
            .len() as u64;
        let required = ProtocolBurn::for_program_call(
            StateTransitionWeight {
                created_coin_utxos: tx.payment.outputs.len() as u64
                    + 1
                    + result.quote.created_coin_utxos,
                consumed_coin_utxos: 1 + result.quote.consumed_coin_utxos,
                created_state_weight: result.quote.created_state_weight,
            },
            size,
        )
        .unwrap()
        .total()
        .unwrap()
        .as_zeno()
            + result.fuel_used;
        if burn == required {
            return tx;
        }
        burn = required;
    }
    panic!("quote did not converge");
}
fn dummy(
    state: &LedgerState,
    seed: &SigningSeed,
    chain: ChainContext,
    call: ProgramCall,
) -> AuthorizedProgramInvocation {
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let (input, value) = state
        .utxos
        .coins()
        .find(|(_, v)| v.owner == Owner::Program(signer))
        .unwrap();
    let payment = CoinTransition::coin_with_charges(
        signer,
        vec![input],
        vec![CoinOutput::new(
            signer,
            Zeno::from_zeno(value.amount.as_zeno() - 1),
        )],
        CoinCharges::new(Zeno::ONE),
    )
    .unwrap();
    let commitment = program_invocation_commitment(signer, &call, &payment, chain).unwrap();
    AuthorizedProgramInvocation {
        signer,
        call,
        payment,
        authorization: AccountAuthorization {
            salt: [0; 32],
            public_key: seed.public_key(),
            signature: seed.sign(commitment.as_bytes()),
        },
    }
}
fn balance(state: &LedgerState, owner: Owner) -> u64 {
    state
        .utxos
        .coins()
        .filter(|(_, v)| v.owner == owner)
        .map(|(_, v)| v.amount.as_zeno())
        .sum()
}

#[test]
fn vault_deposit_and_dynamic_withdraw_are_bound_to_signed_caller_and_atomic() {
    let (mut state, seed, chain) = fixture();
    let alice = Owner::Program(program_id_from_public_key(&seed.public_key()).unwrap());
    let mut body = vec![0x15, 0x36];
    int(&mut body, 0);
    body.push(0x19);
    body.push(0x21);
    let jump = body.len();
    body.extend([0; 4]);
    // Deposit: key = caller encoding; balance += authenticated incoming coin amount.
    body.extend([0x12, 0x33, 0x16, 0x30, 0x29, 0x44, 0x02, 0x2a, 0x31]);
    end(&mut body, 0);
    let withdraw = body.len() as u32;
    body[jump..jump + 4].copy_from_slice(&withdraw.to_le_bytes());
    body.extend([
        0x12, 0x33, 0x16, 0x30, 0x29, 0x15, 0x29, 0x24, 0x2a, 0x31, 0x12, 0x15, 0x29, 0x40,
    ]);
    end(&mut body, 0);
    let vault = deploy(&mut state, &seed, body, 1);
    let initial = state.clone();
    let deposit = signed(&state, &seed, chain, call(vault, &[]), 100);
    let journal = state
        .apply_program_call(deposit, ProgramId::ZERO, chain, 1)
        .unwrap();
    assert_eq!(balance(&state, Owner::Program(vault)), 100);
    let key = canonical_bytes(&alice).unwrap();
    assert_eq!(
        state.programs.program(&vault).unwrap().storage[&key],
        100u128.to_le_bytes()
    );
    let deposited = state.clone();
    let withdrawal = signed(&state, &seed, chain, call(vault, &30u128.to_le_bytes()), 0);
    let second = state
        .apply_program_call(withdrawal.clone(), ProgramId::ZERO, chain, 2)
        .unwrap();
    assert_eq!(balance(&state, Owner::Program(vault)), 70);
    assert_eq!(
        state.programs.program(&vault).unwrap().storage[&key],
        70u128.to_le_bytes()
    );
    state.validate_supply_invariants().unwrap();
    let restored = LedgerState::try_from_slice(&canonical_bytes(&state).unwrap()).unwrap();
    assert_eq!(restored, state);
    state.rollback_state(second).unwrap();
    assert_eq!(state, deposited);
    // Exact burn underpayment rolls back both mapping and transfers.
    let mut underpaid = withdrawal;
    underpaid.payment.outputs[0].amount = underpaid.payment.outputs[0]
        .amount
        .checked_add(Zeno::ONE)
        .unwrap();
    let commitment =
        program_invocation_commitment(underpaid.signer, &underpaid.call, &underpaid.payment, chain)
            .unwrap();
    underpaid.authorization.signature = seed.sign(commitment.as_bytes());
    assert!(
        state
            .apply_program_call(underpaid, ProgramId::ZERO, chain, 2)
            .is_err()
    );
    assert_eq!(state, deposited);
    let too_much = dummy(&state, &seed, chain, call(vault, &101u128.to_le_bytes()));
    assert!(
        state
            .apply_program_call(too_much, ProgramId::ZERO, chain, 2)
            .is_err()
    );
    assert_eq!(state, deposited);
    state.rollback_state(journal).unwrap();
    assert_eq!(state, initial);
}

#[test]
fn nested_program_controller_cannot_be_forged_and_transient_outputs_rollback() {
    let (mut state, seed, chain) = fixture();
    let alice = Owner::Program(program_id_from_public_key(&seed.public_key()).unwrap());
    let mut child = vec![0x12];
    bytes(&mut child, b"controller");
    child.extend([0x30, 0x34, 0x19, 0x22, 0x12]);
    int(&mut child, 9);
    child.push(0x40);
    end(&mut child, 7);
    let child = deploy(&mut state, &seed, child, 1);
    let mut parent = Vec::new();
    owner(&mut parent, Owner::Program(child));
    bytes(&mut parent, &[]);
    parent.extend([0x43, 0x17, 0x12]);
    int(&mut parent, 9);
    parent.push(0x40);
    end(&mut parent, 7);
    let parent = deploy(&mut state, &seed, parent, 2);
    state
        .programs
        .set_storage(
            child,
            b"controller".to_vec(),
            Some(canonical_bytes(&Owner::Program(parent)).unwrap()),
        )
        .unwrap();
    fund(&mut state, Owner::Program(child), 9, 2);
    let before = state.clone();
    let direct = dummy(&state, &seed, chain, call(child, &[]));
    let commitment =
        program_invocation_commitment(direct.signer, &direct.call, &direct.payment, chain).unwrap();
    assert!(matches!(
        preview(
            &state,
            &direct,
            2,
            commitment,
            super::super::application::Applications::default().executor()
        ),
        Err(ExecutionError::Reverted)
    ));
    let tx = signed(&state, &seed, chain, call(parent, &[]), 0);
    let commitment =
        program_invocation_commitment(tx.signer, &tx.call, &tx.payment, chain).unwrap();
    let quote = preview(
        &state,
        &tx,
        2,
        commitment,
        super::super::application::Applications::default().executor(),
    )
    .unwrap();
    assert_eq!(quote.value, 7);
    assert_eq!(quote.quote.created_coin_utxos, 1);
    assert_eq!(quote.quote.consumed_coin_utxos, 1);
    let journal = state
        .apply_program_call(tx, ProgramId::ZERO, chain, 2)
        .unwrap();
    assert_eq!(balance(&state, Owner::Program(child)), 0);
    assert_eq!(balance(&state, Owner::Program(parent)), 0);
    assert!(balance(&state, alice) > 0);
    state.validate_supply_invariants().unwrap();
    state.rollback_state(journal).unwrap();
    assert_eq!(state, before);
}

#[test]
fn traps_bound_execution_and_revert_after_child_effects() {
    let (mut state, seed, chain) = fixture();
    let mut child = Vec::new();
    bytes(&mut child, b"k");
    bytes(&mut child, b"v");
    child.push(0x31);
    end(&mut child, 0);
    let child = deploy(&mut state, &seed, child, 1);
    let mut parent = Vec::new();
    owner(&mut parent, Owner::Program(child));
    bytes(&mut parent, &[]);
    parent.extend([0x43, 0x17, 0x23]);
    end(&mut parent, 0);
    let parent = deploy(&mut state, &seed, parent, 2);
    let before = state.clone();
    assert!(
        state
            .apply_program_call(
                dummy(&state, &seed, chain, call(parent, &[])),
                ProgramId::ZERO,
                chain,
                2
            )
            .is_err()
    );
    assert_eq!(state, before);
    for (nonce, body, error) in [
        (
            3,
            {
                let mut b = vec![0x20];
                b.extend(0u32.to_le_bytes());
                end(&mut b, 0);
                b
            },
            ExecutionError::OutOfFuel,
        ),
        (
            4,
            {
                let mut b = vec![0x13];
                bytes(&mut b, &[]);
                b.push(0x43);
                b.push(3);
                b
            },
            ExecutionError::ReentrantCall,
        ),
        (5, vec![3], ExecutionError::InvalidOperand),
        (
            6,
            {
                let mut b = Vec::new();
                bytes(&mut b, &[7; 129]);
                bytes(&mut b, b"v");
                b.push(0x31);
                end(&mut b, 0);
                b
            },
            ExecutionError::InvalidOperand,
        ),
    ] {
        let id = deploy(&mut state, &seed, body, nonce);
        let tx = dummy(&state, &seed, chain, call(id, &[]));
        let commitment =
            program_invocation_commitment(tx.signer, &tx.call, &tx.payment, chain).unwrap();
        let before = state.clone();
        assert!(
            matches!(preview(&state,&tx,2,commitment,super::super::application::Applications::default().executor()),Err(e) if e==error)
        );
        assert_eq!(state, before);
    }
}

#[test]
fn malformed_bytecode_storage_and_call_data_are_rejected() {
    let mut body = vec![0x20];
    body.extend(1u32.to_le_bytes());
    end(&mut body, 0);
    assert!(validate_code(&code(body)).is_err());
    let mut body = Vec::new();
    bytes(&mut body, &[1, 2]);
    end(&mut body, 0);
    let valid = code(body);
    for len in 0..valid.len() {
        assert!(validate_code(&valid[..len]).is_err());
    }
    let id = ProgramId::from_bytes([7; 32]);
    assert!(call_input(&call(id, &vec![0; MAX_DATA_BYTES + 1])).is_err());
    let mut reader = &u32::MAX.to_le_bytes()[..];
    assert!(read_storage(&mut reader).is_err());
    let mut bytes = 1u32.to_le_bytes().to_vec();
    bytes.extend(u32::MAX.to_le_bytes());
    assert!(read_storage(&mut &bytes[..]).is_err());
}

#[test]
fn dynamic_asset_registration_mint_and_u128_transfer_obey_kernel_authority() {
    let (mut state, seed, chain) = fixture();
    let mut receiver = vec![0x15];
    int(&mut receiver, 1);
    receiver.push(0x4b);
    end(&mut receiver, 0);
    let receiver = deploy(&mut state, &seed, receiver, 1);
    let big = u128::from(u64::MAX) + 7;
    let request = vm::RegisterAssetRequest {
        name: "DYNAMIC".into(),
        max_supply: Unit::from_units(big + 1),
        initial_mint: Unit::from_units(1),
        nonce: 7,
        skip_if_exists: true,
    };
    let mut body = vec![0x15, 0x45, 0x16, 0x13];
    int(&mut body, big);
    body.extend([0x42, 0x16]);
    owner(&mut body, Owner::Program(receiver));
    int(&mut body, big);
    body.extend([0x41, 0x17]);
    end(&mut body, 0);
    let issuer = deploy(&mut state, &seed, body, 2);
    let before = state.clone();
    let input = canonical_bytes(&request).unwrap();
    let tx = signed(&state, &seed, chain, call(issuer, &input), 0);
    let journal = state
        .apply_program_call(tx, ProgramId::ZERO, chain, 2)
        .unwrap();
    let actor = Owner::Program(issuer);
    let metadata =
        crate::monetary::asset::Metadata::new("DYNAMIC".into(), request.max_supply, actor, actor)
            .unwrap();
    let asset = AssetContract::derive(&metadata, 7).unwrap();
    assert_eq!(
        state.extensions.assets.records()[&asset]
            .metadata
            .mint_authority,
        actor
    );
    assert_eq!(
        state
            .extensions
            .assets
            .shares()
            .values()
            .filter(|v| v.owner == Owner::Program(receiver))
            .map(|v| v.amount.as_units())
            .sum::<u128>(),
        big
    );
    assert_eq!(
        state
            .extensions
            .assets
            .shares()
            .values()
            .filter(|v| v.owner == actor)
            .map(|v| v.amount.as_units())
            .sum::<u128>(),
        1
    );
    state.validate_supply_invariants().unwrap();
    let burn_tx = signed(
        &state,
        &seed,
        chain,
        call(receiver, &canonical_bytes(&asset).unwrap()),
        0,
    );
    let burn_journal = state
        .apply_program_call(burn_tx, ProgramId::ZERO, chain, 3)
        .unwrap();
    assert_eq!(
        state.extensions.assets.records()[&asset]
            .total_burned
            .as_units(),
        1
    );
    state.validate_supply_invariants().unwrap();
    let capped = state.clone();
    assert!(
        state
            .apply_program_call(
                dummy(&state, &seed, chain, call(issuer, &input)),
                ProgramId::ZERO,
                chain,
                3
            )
            .is_err()
    );
    assert_eq!(state, capped);
    let mut wrong = Vec::new();
    bytes(&mut wrong, &canonical_bytes(&asset).unwrap());
    wrong.push(0x12);
    int(&mut wrong, 1);
    wrong.push(0x42);
    end(&mut wrong, 0);
    let wrong = deploy(&mut state, &seed, wrong, 3);
    let unchanged = state.clone();
    assert!(
        state
            .apply_program_call(
                dummy(&state, &seed, chain, call(wrong, &[])),
                ProgramId::ZERO,
                chain,
                3
            )
            .is_err()
    );
    assert_eq!(state, unchanged);
    super::super::rollback_program(
        &mut state.programs,
        ProgramJournal::Deploy { program_id: wrong },
    )
    .unwrap();
    state.rollback_state(burn_journal).unwrap();
    state.rollback_state(journal).unwrap();
    assert_eq!(state, before);
}

#[test]
fn value_calls_credit_only_actual_transfer_and_bound_depth_and_call_count() {
    let (mut state, seed, chain) = fixture();
    let mut child = Vec::new();
    bytes(&mut child, b"deposit");
    child.extend([0x44, 0x2a, 0x31]);
    end(&mut child, 0);
    let child = deploy(&mut state, &seed, child, 1);
    let mut parent = Vec::new();
    owner(&mut parent, Owner::Program(child));
    bytes(&mut parent, &[]);
    int(&mut parent, 17);
    parent.extend([0x48, 0x17]);
    end(&mut parent, 0);
    let parent = deploy(&mut state, &seed, parent, 2);
    fund(&mut state, Owner::Program(parent), 17, 4);
    let before = state.clone();
    let tx = signed(&state, &seed, chain, call(parent, &[]), 0);
    let journal = state
        .apply_program_call(tx, ProgramId::ZERO, chain, 2)
        .unwrap();
    assert_eq!(balance(&state, Owner::Program(child)), 17);
    assert_eq!(
        state.programs.program(&child).unwrap().storage[b"deposit".as_slice()],
        17u128.to_le_bytes()
    );
    state.rollback_state(journal).unwrap();
    assert_eq!(state, before);
    let mut leaf = Vec::new();
    end(&mut leaf, 0);
    let mut target = deploy(&mut state, &seed, leaf, 3);
    for nonce in 4..=11 {
        let mut b = Vec::new();
        owner(&mut b, Owner::Program(target));
        bytes(&mut b, &[]);
        b.push(0x43);
        b.push(3);
        target = deploy(&mut state, &seed, b, nonce);
    }
    let tx = dummy(&state, &seed, chain, call(target, &[]));
    let c = program_invocation_commitment(tx.signer, &tx.call, &tx.payment, chain).unwrap();
    assert!(matches!(
        preview(
            &state,
            &tx,
            2,
            c,
            super::super::application::Applications::default().executor()
        ),
        Err(ExecutionError::ResourceLimit)
    ));
    let mut many = Vec::new();
    for _ in 0..MAX_CALLS {
        owner(&mut many, Owner::Program(child));
        bytes(&mut many, &[]);
        many.extend([0x43, 0x17]);
    }
    end(&mut many, 0);
    let many = deploy(&mut state, &seed, many, 12);
    let tx = dummy(&state, &seed, chain, call(many, &[]));
    let c = program_invocation_commitment(tx.signer, &tx.call, &tx.payment, chain).unwrap();
    let before = state.clone();
    assert!(matches!(
        preview(
            &state,
            &tx,
            2,
            c,
            super::super::application::Applications::default().executor()
        ),
        Err(ExecutionError::ResourceLimit)
    ));
    assert_eq!(state, before);
}

#[test]
fn indexed_accounts_include_existing_and_new_coins_when_loaded_before_or_after_transfer() {
    for preload in [false, true] {
        let (mut state, seed, chain) = fixture();
        let child = deploy(&mut state, &seed, vec![0x47, 3], 1);
        let mut parent = Vec::new();
        if preload {
            owner(&mut parent, Owner::Program(child));
            bytes(&mut parent, &[]);
            parent.extend([0x43, 0x17]);
        }
        owner(&mut parent, Owner::Program(child));
        bytes(&mut parent, &[]);
        int(&mut parent, 17);
        parent.extend([0x48, 3]);
        let parent = deploy(&mut state, &seed, parent, 2);
        fund(&mut state, Owner::Program(child), 7, 3);
        fund(&mut state, Owner::Program(parent), 17, 4);
        let before = state.clone();
        let tx = signed(&state, &seed, chain, call(parent, &[]), 0);
        let commitment =
            program_invocation_commitment(tx.signer, &tx.call, &tx.payment, chain).unwrap();
        let result = preview(
            &state,
            &tx,
            2,
            commitment,
            super::super::application::Applications::default().executor(),
        )
        .unwrap();
        assert_eq!(result.value, 24);
        assert_eq!(state, before);
        let journal = state
            .apply_program_call(tx, ProgramId::ZERO, chain, 2)
            .unwrap();
        assert_eq!(
            state
                .utxos
                .coins_by_owner(Owner::Program(child))
                .map(|(_, coin)| coin.amount.as_zeno())
                .sum::<u64>(),
            24
        );
        assert_eq!(
            state.utxos.coins_by_owner(Owner::Program(parent)).count(),
            0
        );
        state.rollback_state(journal).unwrap();
        assert_eq!(state, before);
    }
}

#[test]
fn application_state_survives_block_replay_snapshot_and_reorg() {
    use crate::{
        block::{Block, Emission},
        common::Nonce,
        ledger::{Ledger, LedgerSnapshot},
        operation::AuthorizedDeployProgram,
    };
    fn commit(ledger: &mut Ledger, miner: ProgramId, operations: Vec<BlockOperation>) -> Block {
        let height = Height(ledger.tip_height().unwrap().0 + 1);
        let mut block = Block::from_protocol_operations(
            height,
            ledger.tip_hash().unwrap(),
            crate::consensus::expected_next_difficulty(&ledger.chain).unwrap(),
            Nonce(0),
            Some(Emission::new(
                miner,
                crate::consensus::expected_emission_for_height(height),
            )),
            operations,
        )
        .unwrap();
        let (root, weight) = ledger.preview_block_commitments(&block).unwrap();
        block.set_state_root(root);
        block.set_block_weight(weight);
        let checked =
            crate::consensus::validate_candidate_for_apply(&block, &ledger.chain).unwrap();
        crate::consensus::ApplyBlockState::commit_validated_block(ledger, checked).unwrap();
        block
    }
    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([7; 32]));
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let chain = crate::genesis::chain_context().unwrap();
    let mut ledger = crate::genesis::genesis_ledger().unwrap();
    commit(&mut ledger, signer, vec![]);
    let mut body = vec![0x12, 0x4a, 0x19, 0x22];
    bytes(&mut body, b"height");
    body.extend([0x49, 0x2a, 0x31, 0x49, 0x03]);
    let (input, value) = ledger.state.utxos.coins().next().unwrap();
    let amount = value.amount.as_zeno();
    let deploy = DeployProgram {
        owner: signer,
        nonce: 1,
        code: code(body).into(),
    };
    let mut tx = AuthorizedDeployProgram {
        deploy,
        payment: CoinTransition::coin_with_charges(
            signer,
            vec![input],
            vec![CoinOutput::new(signer, Zeno::ONE)],
            CoinCharges::new(Zeno::ONE),
        )
        .unwrap(),
        authorization: AccountAuthorization {
            salt: [0; 32],
            public_key: seed.public_key(),
            signature: seed.sign(b"draft"),
        },
    };
    let (id, burn) = crate::consensus::quote_deploy_burn(&tx, Height(2), &ledger.state).unwrap();
    tx.payment.outputs[0].amount = Zeno::from_zeno(amount - burn.as_zeno() - 1);
    let c = tx.commitment(chain).unwrap();
    tx.authorization.signature = seed.sign(c.as_bytes());
    commit(
        &mut ledger,
        signer,
        vec![BlockOperation::DeployProgram(Box::new(tx))],
    );
    let parent = ledger.clone();
    let tx = signed(&ledger.state, &seed, chain, call(id, &[]), 0);
    let block = commit(
        &mut ledger,
        signer,
        vec![BlockOperation::ProgramCall(Box::new(tx))],
    );
    assert_eq!(
        ledger.state.programs.program(&id).unwrap().storage[b"height".as_slice()],
        3u128.to_le_bytes()
    );
    let snapshot =
        LedgerSnapshot::try_from_slice(&canonical_bytes(&ledger.snapshot()).unwrap()).unwrap();
    let blocks = ledger.chain.blocks().cloned().collect::<Vec<_>>();
    let mut restored = Ledger::from_snapshot(snapshot, &blocks).unwrap();
    assert_eq!(restored, ledger);
    restored.rollback_tip().unwrap();
    assert_eq!(restored, parent);
    let checked = crate::consensus::validate_candidate_for_apply(&block, &restored.chain).unwrap();
    crate::consensus::ApplyBlockState::commit_validated_block(&mut restored, checked).unwrap();
    assert_eq!(restored, ledger);
    restored.rollback_tip().unwrap();
    commit(&mut restored, signer, vec![]);
    assert!(
        restored
            .state
            .programs
            .program(&id)
            .unwrap()
            .storage
            .is_empty()
    );
    restored.rollback_tip().unwrap();
    assert_eq!(restored, parent);
}

#[test]
fn storage_and_action_limits_and_journal_decoding_are_bounded() {
    let mut storage = Storage::new();
    for n in 0..247u16 {
        let mut key = vec![0; MAX_KEY_BYTES];
        key[..2].copy_from_slice(&n.to_be_bytes());
        storage.insert(key, vec![1; MAX_DATA_BYTES]);
    }
    assert!(valid_storage(&storage));
    let mut key = vec![0; MAX_KEY_BYTES];
    key[..2].copy_from_slice(&247u16.to_be_bytes());
    storage.insert(key, vec![1; MAX_DATA_BYTES]);
    assert!(!valid_storage(&storage));
    assert!(read_storage(&mut &canonical_bytes(&storage).unwrap()[..]).is_err());
    let mut journal = vec![2];
    journal.extend(u32::MAX.to_le_bytes());
    assert!(ProgramJournal::try_from_slice(&journal).is_err());
    let mut journal = vec![2];
    journal.extend(0u32.to_le_bytes());
    journal.extend(1u32.to_le_bytes());
    journal.extend([0; 32]);
    journal.extend(u32::MAX.to_le_bytes());
    assert!(ProgramJournal::try_from_slice(&journal).is_err());
    let (mut state, seed, chain) = fixture();
    let mut body = Vec::new();
    for _ in 0..=MAX_ACTIONS {
        bytes(&mut body, b"key");
        bytes(&mut body, b"value");
        body.push(0x31);
    }
    end(&mut body, 0);
    let id = deploy(&mut state, &seed, body, 1);
    let before = state.clone();
    let tx = dummy(&state, &seed, chain, call(id, &[]));
    let c = program_invocation_commitment(tx.signer, &tx.call, &tx.payment, chain).unwrap();
    assert!(matches!(
        preview(
            &state,
            &tx,
            2,
            c,
            super::super::application::Applications::default().executor()
        ),
        Err(ExecutionError::ResourceLimit)
    ));
    assert_eq!(state, before);
}
