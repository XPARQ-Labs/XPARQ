use kernel::{
    common::{ChainContext, Owner},
    consensus::{ProtocolBurn, StateTransitionWeight},
    crypto::{
        AccountSignatureScheme, ProgramId, SigningSeed, canonical_bytes, canonical_decode,
        program_id_from_public_key,
    },
    ledger::{CoinUtxo, LedgerState, StateError},
    monetary::coin::{CoinOutput, CoinShare, Zeno},
    operation::BlockOperation,
    program::{
        AccountAuthorization, AuthorizedProgramInvocation, CoinCharges, CoinTransition,
        application::{ApplicationExecutor, AssetHost, NoApplications},
        program_created_state_weight_with_applications, program_invocation_commitment,
        system::{
            asset_program::{
                asset::{AssetError, Unit},
                opcode::AssetOpcode,
                type_::{AssetCall, Mint, Register},
            },
            coin_program::{CoinHost, TransferError},
            script::call::{ProgramCall, SystemProgramId},
        },
    },
};

fn seed() -> SigningSeed {
    SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([21; 32]))
}

fn funded() -> LedgerState {
    let owner = program_id_from_public_key(&seed().public_key()).unwrap();
    let amount = Zeno::from_zeno(10_000_000);
    let coins = std::collections::BTreeMap::from([(
        CoinShare::from_bytes([1; 32]),
        CoinUtxo {
            owner: kernel::common::Owner::Program(owner),
            amount,
        },
    )]);
    LedgerState {
        utxos: canonical_decode(&canonical_bytes(&(coins, amount)).unwrap()).unwrap(),
        coin: kernel::ledger::CoinRecord {
            total_mined: amount,
            total_burned: Zeno::ZERO,
        },
        ..LedgerState::default()
    }
}

fn invocation(state: &LedgerState, call: ProgramCall) -> AuthorizedProgramInvocation {
    let seed = seed();
    let signer = program_id_from_public_key(&seed.public_key()).unwrap();
    let chain = ChainContext::new([7; 32]);
    let (input, coin) = state
        .utxos
        .coins()
        .find(|(_, coin)| coin.owner == kernel::common::Owner::Program(signer))
        .unwrap();
    let fee = Zeno::ONE;
    let build = |burn: u64| {
        let payment = CoinTransition::coin_with_charges(
            signer,
            vec![input],
            vec![CoinOutput::new(
                signer,
                Zeno::from_zeno(coin.amount.as_zeno() - 1 - burn),
            )],
            CoinCharges::new(fee),
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
    let draft = build(0);
    let weight = program_created_state_weight_with_applications(
        &draft,
        chain,
        &state.extensions,
        &extension::SystemApplications,
    )
    .unwrap();
    let size = canonical_bytes(&BlockOperation::ProgramCall(Box::new(draft)))
        .unwrap()
        .len() as u64;
    let burn = ProtocolBurn::for_program_call(
        StateTransitionWeight {
            created_coin_utxos: 2,
            consumed_coin_utxos: 1,
            created_state_weight: weight,
        },
        size,
    )
    .unwrap()
    .total()
    .unwrap()
    .as_zeno();
    build(burn)
}

#[derive(Clone, Copy)]
enum BadApplication {
    Omit,
    RedirectCoin,
    SubstituteAsset,
    FailAfterAsset,
    DoubleAsset,
}

impl ApplicationExecutor for BadApplication {
    fn execute_coin(
        &self,
        host: &mut dyn CoinHost<Error = StateError>,
        inputs: &[CoinShare],
        outputs: &[(Owner, u64)],
        miner: ProgramId,
        fee: u64,
    ) -> Result<(), TransferError<StateError>> {
        if matches!(self, Self::Omit) {
            return Ok(());
        }
        let mut outputs = outputs.to_vec();
        if matches!(self, Self::RedirectCoin) {
            outputs[0].0 = Owner::Program(ProgramId::ZERO);
        }
        extension::coin_program::execute_transfer(host, inputs, &outputs, miner, fee)
    }
    fn execute_asset(&self, call: &AssetCall, host: &mut dyn AssetHost) -> Result<(), AssetError> {
        if matches!(self, Self::SubstituteAsset) {
            let AssetCall::Register(call) = call else {
                panic!()
            };
            let mut replacement = call.clone();
            replacement.name = "SUBSTITUTED".into();
            return host.register(&replacement);
        }
        extension::asset_program::execute(call, host)?;
        if matches!(self, Self::DoubleAsset) {
            extension::asset_program::execute(call, host)?;
        }
        if matches!(self, Self::FailAfterAsset) {
            return Err(AssetError::InvalidProgram);
        }
        Ok(())
    }
}

fn register_call() -> ProgramCall {
    let owner = program_id_from_public_key(&seed().public_key()).unwrap();
    ProgramCall {
        program: SystemProgramId::ASSET,
        opcode: AssetOpcode::Register as u8,
        payload: canonical_bytes(&Register {
            name: "BOUNDARY".into(),
            max_supply: Unit::from_units(100),
            initial_mint: Unit::from_units(10),
            mint_authority: kernel::common::Owner::Program(owner),
            nonce: 1,
        })
        .unwrap(),
    }
}

#[test]
fn extension_execution_obeys_signed_coin_effects_and_missing_apps_fail_closed() {
    for executor in [
        &NoApplications as &dyn ApplicationExecutor,
        &BadApplication::Omit,
        &BadApplication::RedirectCoin,
    ] {
        let mut state = funded();
        let before = state.clone();
        let tx = invocation(&state, extension::coin_program::transfer_call());
        assert!(
            state
                .apply_program_call_with_applications(
                    tx,
                    ProgramId::ZERO,
                    ChainContext::new([7; 32]),
                    1,
                    executor
                )
                .is_err()
        );
        assert_eq!(state, before);
    }
    let mut state = funded();
    let tx = invocation(&state, extension::coin_program::transfer_call());
    state
        .apply_program_call_with_applications(
            tx,
            ProgramId::ZERO,
            ChainContext::new([7; 32]),
            1,
            &extension::SystemApplications,
        )
        .unwrap();
    state.validate_supply_invariants().unwrap();
}

#[test]
fn asset_substitution_or_application_failure_cannot_change_state() {
    for executor in [
        BadApplication::SubstituteAsset,
        BadApplication::FailAfterAsset,
        BadApplication::DoubleAsset,
    ] {
        let mut state = funded();
        let before = state.clone();
        let tx = invocation(&state, register_call());
        assert!(
            state
                .apply_program_call_with_applications(
                    tx,
                    ProgramId::ZERO,
                    ChainContext::new([7; 32]),
                    1,
                    &executor
                )
                .is_err()
        );
        assert_eq!(state, before);
    }
}

#[test]
fn tampered_authorizations_and_payments_leave_the_complete_state_unchanged() {
    let initial = funded();
    let tx = invocation(&initial, register_call());
    let chain = ChainContext::new([7; 32]);
    let mut variants = Vec::new();
    let mut changed = tx.clone();
    changed.payment.outputs[0].output = kernel::common::Owner::Program(ProgramId::ZERO);
    variants.push((changed, chain));
    let mut changed = tx.clone();
    changed.payment.inputs.push(changed.payment.inputs[0]);
    variants.push((changed, chain));
    let mut changed = tx.clone();
    changed.payment.inputs[0] = CoinShare::from_bytes([9; 32]);
    variants.push((changed, chain));
    let mut changed = tx.clone();
    changed.payment.outputs[0].amount = Zeno::ZERO;
    variants.push((changed, chain));
    let mut changed = tx.clone();
    changed.payment.charges.miner_fee = Zeno::from_zeno(u64::MAX);
    variants.push((changed, chain));
    let mut changed = tx.clone();
    let mut register: Register = canonical_decode(&changed.call.payload).unwrap();
    register.initial_mint = Unit::from_units(20);
    changed.call.payload = canonical_bytes(&register).unwrap();
    variants.push((changed, chain));
    let mut changed = tx.clone();
    changed.authorization.signature = seed().sign(&[0; 32]);
    variants.push((changed, chain));
    variants.push((tx.clone(), ChainContext::new([8; 32])));

    // A valid attacker signature still cannot spend an input owned by another key.
    let attacker = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([22; 32]));
    let mut changed = tx;
    changed.signer = program_id_from_public_key(&attacker.public_key()).unwrap();
    changed.payment.signer = changed.signer;
    let commitment =
        program_invocation_commitment(changed.signer, &changed.call, &changed.payment, chain)
            .unwrap();
    changed.authorization = AccountAuthorization {
        salt: [0; 32],
        public_key: attacker.public_key(),
        signature: attacker.sign(commitment.as_bytes()),
    };
    variants.push((changed, chain));

    for (index, (changed, context)) in variants.into_iter().enumerate() {
        let mut state = initial.clone();
        assert!(
            state
                .apply_program_call_with_applications(
                    changed,
                    ProgramId::ZERO,
                    context,
                    1,
                    &extension::SystemApplications,
                )
                .is_err(),
            "tamper case {index} was accepted"
        );
        assert_eq!(state, initial, "tamper case {index} mutated state");
        state.audit_coin_supply().unwrap();
        state.validate_supply_invariants().unwrap();
    }
}

#[test]
fn signed_asset_replay_is_rejected_without_changing_committed_state() {
    let mut state = funded();
    let tx = invocation(&state, register_call());
    let chain = ChainContext::new([7; 32]);
    state
        .apply_program_call_with_applications(
            tx.clone(),
            ProgramId::ZERO,
            chain,
            1,
            &extension::SystemApplications,
        )
        .unwrap();
    state.audit_coin_supply().unwrap();
    state.validate_supply_invariants().unwrap();
    let committed = state.clone();
    assert!(
        state
            .apply_program_call_with_applications(
                tx,
                ProgramId::ZERO,
                chain,
                2,
                &extension::SystemApplications,
            )
            .is_err()
    );
    assert_eq!(state, committed);
    state.audit_coin_supply().unwrap();
    state.validate_supply_invariants().unwrap();
}

#[test]
fn extension_register_and_mint_use_kernel_supply_and_ownership_checks() {
    let mut state = funded();
    let chain = ChainContext::new([7; 32]);
    let owner = program_id_from_public_key(&seed().public_key()).unwrap();
    let register = invocation(&state, register_call());
    state
        .apply_program_call_with_applications(
            register,
            ProgramId::ZERO,
            chain,
            1,
            &extension::SystemApplications,
        )
        .unwrap();
    let asset = *state.extensions.assets.records().keys().next().unwrap();
    let mint = ProgramCall {
        program: SystemProgramId::ASSET,
        opcode: AssetOpcode::Mint as u8,
        payload: canonical_bytes(&Mint {
            asset,
            nonce: 1,
            recipient: kernel::common::Owner::Program(owner),
            amount: Unit::from_units(5),
        })
        .unwrap(),
    };
    let tx = invocation(&state, mint.clone());
    state
        .apply_program_call_with_applications(
            tx,
            ProgramId::ZERO,
            chain,
            2,
            &extension::SystemApplications,
        )
        .unwrap();
    assert_eq!(
        state.extensions.assets.records()[&asset].supply,
        Unit::from_units(15)
    );
    state.validate_supply_invariants().unwrap();
    // Reusing the same mint nonce must be rejected during application preview.
    let mut stale = mint;
    stale.payload = canonical_bytes(&Mint {
        asset,
        nonce: 1,
        recipient: kernel::common::Owner::Program(owner),
        amount: Unit::from_units(5),
    })
    .unwrap();
    let before = state.clone();
    let payment = CoinTransition::coin_with_charges(
        owner,
        vec![
            state
                .utxos
                .coins()
                .find(|(_, c)| c.owner == kernel::common::Owner::Program(owner))
                .unwrap()
                .0,
        ],
        vec![CoinOutput::new(owner, Zeno::ONE)],
        CoinCharges::new(Zeno::ONE),
    )
    .unwrap();
    let commitment = program_invocation_commitment(owner, &stale, &payment, chain).unwrap();
    let seed = seed();
    let tx = AuthorizedProgramInvocation {
        signer: owner,
        call: stale,
        payment,
        authorization: AccountAuthorization {
            salt: [0; 32],
            public_key: seed.public_key(),
            signature: seed.sign(commitment.as_bytes()),
        },
    };
    assert!(
        state
            .apply_program_call_with_applications(
                tx,
                ProgramId::ZERO,
                chain,
                3,
                &extension::SystemApplications
            )
            .is_err()
    );
    assert_eq!(state, before);
}
