//! Atomic execution, supply, snapshot, replay, and rollback regression tests.

use super::accounting::validate_block_accounting;
use super::execution::BlockTransitionPoint;
use crate::ledger::utxo::ExecutionContext;
use crate::{ledger::CoinUtxo, monetary::coin::CoinShare, program::CoinTransition};
use borsh::BorshDeserialize;
use crypto::canonical_bytes;

use super::*;

use crate::{
    blockchain::{Block, Emission},
    common::Nonce,
    consensus::{
        ConsensusError, expected_emission_for_height, expected_next_difficulty,
        initial_block_emission, validate_candidate_for_apply,
    },
    genesis,
};

fn ledger_bytes(ledger: &Ledger) -> Vec<u8> {
    borsh::to_vec(ledger).expect("ledger must serialize canonically")
}

#[test]
fn signed_deploy_commits_registry_and_rolls_back_atomically() {
    use crate::{
        consensus::quote_deploy_burn,
        monetary::coin::CoinOutput,
        operation::{AuthorizedDeployProgram, BlockOperation},
        program::{AccountAuthorization, CoinCharges, DeployProgram},
    };
    use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x71; 32]));
    let owner = program_id_from_public_key(&seed.public_key()).unwrap();
    let mut ledger = genesis::genesis_ledger().unwrap();
    commit_empty_block(&mut ledger, owner);
    let before = ledger_bytes(&ledger);
    let chain = genesis::chain_context().unwrap();
    let height = Height(2);
    let (input, coin) = ledger.state.utxos.coins().next().unwrap();
    let fee = Zeno::from_zeno(1_000);
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend_from_slice(&7u64.to_le_bytes());
    code.push(3);
    let deploy = DeployProgram {
        owner,
        nonce: 1,
        code: code.into(),
    };
    let draft_payment = CoinTransition::coin_with_charges(
        owner,
        vec![input],
        vec![CoinOutput::new(owner, Zeno::ONE)],
        CoinCharges::new(fee),
    )
    .unwrap();
    let draft = AuthorizedDeployProgram {
        deploy: deploy.clone(),
        payment: draft_payment,
        authorization: AccountAuthorization {
            salt: [0; 32],
            public_key: seed.public_key(),
            signature: seed.sign(b"deploy-size-fixture"),
        },
    };
    let (program_id, burn) = quote_deploy_burn(&draft, height, &ledger.state).unwrap();
    let amount = coin
        .amount
        .checked_sub(fee)
        .unwrap()
        .checked_sub(burn)
        .unwrap();
    let payment = CoinTransition::coin_with_charges(
        owner,
        vec![input],
        vec![CoinOutput::new(owner, amount)],
        CoinCharges::new(fee),
    )
    .unwrap();
    let mut signed = AuthorizedDeployProgram { payment, ..draft };
    let commitment = signed.commitment(chain).unwrap();
    signed.authorization.signature = seed.sign(commitment.as_bytes());

    let mut invalid = signed.clone();
    invalid.deploy.nonce = 2;
    assert!(crate::consensus::validate_deploy(invalid, chain, height, &ledger.state).is_err());
    assert!(
        crate::consensus::validate_deploy(
            signed.clone(),
            crate::common::ChainContext::new([0x44; 32]),
            height,
            &ledger.state
        )
        .is_err()
    );

    let mut block = Block::from_protocol_operations(
        height,
        ledger.tip_hash().unwrap(),
        expected_next_difficulty(&ledger.chain).unwrap(),
        Nonce(0),
        Some(Emission::new(owner, expected_emission_for_height(height))),
        vec![BlockOperation::DeployProgram(Box::new(signed))],
    )
    .unwrap();
    let (root, weight) = ledger.preview_block_commitments(&block).unwrap();
    block.set_state_root(root);
    block.set_block_weight(weight);
    ledger
        .apply_validated_block(validate_candidate_for_apply(&block, &ledger.chain).unwrap())
        .unwrap();
    assert!(ledger.state.programs.contains(&program_id));
    assert_eq!(ledger.state_root().unwrap(), root);
    assert_eq!(
        ledger.state.programs.program(&program_id).unwrap().owner,
        owner
    );
    assert_eq!(ledger.rollback_tip().unwrap(), block);
    assert_eq!(ledger_bytes(&ledger), before);
    assert_eq!(ledger.state.programs.len(), 0);
}

#[test]

fn unexpected_coin_supply_delta_is_rejected() {
    let mut state = LedgerState::default();

    state
        .utxos
        .insert_coin(
            CoinShare::from_bytes([0x44; crypto::HASH_SIZE]),
            CoinUtxo {
                amount: Zeno::from_zeno(109),

                owner: crate::common::Owner::Program(crypto::ProgramId(
                    [0x55; crypto::PROGRAM_ID_SIZE],
                )),
            },
        )
        .unwrap();

    assert!(matches!(
        validate_block_accounting(
            Zeno::from_zeno(100),
            &state,
            Zeno::from_zeno(10),
            Zeno::from_zeno(2),
        ),
        Err(LedgerError::BlockAccountingMismatch)
    ));
}

#[test]

fn block_with_forged_extra_coin_is_rejected_even_if_supply_record_matches() {
    let ledger = genesis::genesis_ledger().unwrap();

    let before = ledger_bytes(&ledger);

    let block =
        empty_height_one_candidate(&ledger, crypto::ProgramId([0x56; crypto::PROGRAM_ID_SIZE]));

    let result = ledger.execute_block_with_checkpoint(&block, |point, state| {
        if point == BlockTransitionPoint::BeforeAccountingCheck {
            let (id, coin) = state.utxos.coins().next().unwrap();

            let forged = CoinUtxo {
                amount: coin.amount.checked_add(Zeno::ONE).unwrap(),

                ..*coin
            };

            state.utxos.consume_coin(&id).unwrap();

            state.utxos.insert_coin(id, forged).unwrap();

            state.coin.total_mined = state.coin.total_mined.checked_add(Zeno::ONE).unwrap();

            assert!(state.validate_supply_invariants().is_ok());
        }

        Ok(())
    });

    assert!(matches!(result, Err(LedgerError::BlockAccountingMismatch)));

    assert_eq!(ledger_bytes(&ledger), before);
}

#[test]
fn pruned_snapshot_requires_a_complete_contiguous_journal_suffix() {
    let mut ledger = genesis::genesis_ledger().unwrap();
    for _ in 0..3 {
        commit_empty_block(&mut ledger, crypto::ProgramId::ZERO);
    }
    let blocks = ledger.chain.blocks().cloned().collect::<Vec<_>>();
    let full = ledger.snapshot();
    let root = ledger.state_root().unwrap();
    ledger.prune_rollback_journals_before(Height(2));
    assert_eq!(ledger.state_root().unwrap(), root);
    let compact = ledger.snapshot();
    let mut restored = Ledger::from_snapshot(compact.clone(), &blocks).unwrap();
    assert!(restored.can_rollback_to(Height(1)));
    assert!(!restored.can_rollback_to(Height(0)));
    restored.rollback_tip().unwrap();
    restored.rollback_tip().unwrap();
    let unchanged = ledger_bytes(&restored);
    assert!(matches!(
        restored.rollback_tip().unwrap_err(),
        LedgerError::MissingRollbackJournal
    ));
    assert_eq!(ledger_bytes(&restored), unchanged);
    let mut hole = full;
    hole.journals.remove(&Height(2));
    let mut missing_tip = compact.clone();
    missing_tip.journals.remove(&Height(3));
    let mut extra = compact.clone();
    extra.journals.insert(Height(9), vec![]);
    let mut wrong_count = compact.clone();
    wrong_count.journals.get_mut(&Height(2)).unwrap().clear();
    let mut empty = compact;
    empty.journals.clear();
    for invalid in [hole, missing_tip, extra, wrong_count, empty] {
        assert!(matches!(
            Ledger::from_snapshot(invalid, &blocks).unwrap_err(),
            LedgerError::MissingRollbackJournal
        ));
    }
}

fn empty_next_candidate(ledger: &Ledger, miner: crypto::ProgramId) -> Block {
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );

    let previous = ledger.tip_hash().expect("canonical tip");

    let target_bits = expected_next_difficulty(&ledger.chain).expect("next target bits");

    let subsidy = expected_emission_for_height(height);

    Block::from_protocol_operations(
        height,
        previous,
        target_bits,
        Nonce(0),
        Some(Emission::new(miner, subsidy)),
        vec![],
    )
    .expect("empty candidate")
}

fn commit_empty_block(ledger: &mut Ledger, miner: crypto::ProgramId) -> Block {
    let mut block = empty_next_candidate(ledger, miner);

    let (state_root, block_weight) = ledger
        .preview_block_commitments(&block)
        .expect("preview commitments");

    block.set_state_root(state_root);

    block.set_block_weight(block_weight);

    let validated = validate_candidate_for_apply(&block, &ledger.chain).expect("valid candidate");

    ledger
        .apply_validated_block(validated)
        .expect("commit block");

    block
}

fn empty_height_one_candidate(ledger: &Ledger, miner: crypto::ProgramId) -> Block {
    let previous = ledger.tip_hash().expect("genesis tip");

    let target_bits = expected_next_difficulty(&ledger.chain).expect("next target bits");

    Block::from_protocol_operations(
        Height(1),
        previous,
        target_bits,
        Nonce(0),
        Some(Emission::new(miner, initial_block_emission())),
        vec![],
    )
    .expect("height-one candidate")
}

#[test]

fn invalid_state_root_after_staging_does_not_mutate_ledger() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    let miner = crypto::ProgramId([0x41; crypto::PROGRAM_ID_SIZE]);

    let before = ledger_bytes(&ledger);

    let before_tip = ledger.tip_hash();

    let block = empty_height_one_candidate(&ledger, miner);

    let validated = validate_candidate_for_apply(&block, &ledger.chain)
        .expect("candidate must pass pre-application consensus");

    assert!(matches!(
        ledger.apply_validated_block(validated),
        Err(LedgerError::InvalidStateRoot)
    ));

    assert_eq!(ledger_bytes(&ledger), before);

    assert_eq!(ledger.tip_hash(), before_tip);

    assert_eq!(ledger.tip_height(), Some(Height(0)));
}

#[test]

fn committed_block_then_rollback_restores_entire_ledger_byte_for_byte() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    let miner = crypto::ProgramId([0x42; crypto::PROGRAM_ID_SIZE]);

    let before = ledger_bytes(&ledger);

    let before_tip = ledger.tip_hash();

    let mut block = empty_height_one_candidate(&ledger, miner);

    let (state_root, block_weight) = ledger
        .preview_block_commitments(&block)
        .expect("preview commitments");

    block.set_state_root(state_root);

    block.set_block_weight(block_weight);

    let validated = validate_candidate_for_apply(&block, &ledger.chain).expect("valid candidate");

    ledger
        .apply_validated_block(validated)
        .expect("commit block");

    assert_eq!(ledger.tip_height(), Some(Height(1)));

    assert_ne!(ledger_bytes(&ledger), before);

    let removed = ledger.rollback_tip().expect("rollback tip");

    assert_eq!(removed, block);

    assert_eq!(ledger.tip_hash(), before_tip);

    assert_eq!(ledger.tip_height(), Some(Height(0)));

    assert_eq!(ledger_bytes(&ledger), before);
}

#[test]

fn tampered_active_state_rejects_next_block_and_rollback_without_mutation() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    commit_empty_block(
        &mut ledger,
        crypto::ProgramId([0x81; crypto::PROGRAM_ID_SIZE]),
    );

    let (coin_id, coin) = ledger.state.utxos.coins().next().expect("emission coin");

    let mut altered = *coin;

    altered.owner =
        crate::common::Owner::Program(crypto::ProgramId([0x82; crypto::PROGRAM_ID_SIZE]));

    ledger.state.utxos.consume_coin(&coin_id).unwrap();

    ledger.state.utxos.insert_coin(coin_id, altered).unwrap();

    assert!(ledger.state.validate_supply_invariants().is_ok());

    let before = ledger_bytes(&ledger);

    let next = empty_next_candidate(&ledger, crypto::ProgramId([0x83; crypto::PROGRAM_ID_SIZE]));

    assert!(matches!(
        ledger.preview_block_commitments(&next),
        Err(LedgerError::InvalidPriorStateRoot)
    ));

    assert!(matches!(
        ledger.rollback_tip(),
        Err(LedgerError::InvalidPriorStateRoot)
    ));

    assert_eq!(ledger_bytes(&ledger), before);
}

#[test]

fn rollback_rejects_journal_that_preserves_supply_but_changes_parent_root() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    commit_empty_block(
        &mut ledger,
        crypto::ProgramId([0x84; crypto::PROGRAM_ID_SIZE]),
    );

    let journal = &mut ledger
        .journals
        .get_mut(&Height(1))
        .expect("height-one journal")[0]
        .coin
        .as_mut()
        .expect("emission journal");

    journal.mined = journal.mined.checked_sub(Zeno::ONE).unwrap();

    journal.burned = journal.burned.checked_sub(Zeno::ONE).unwrap();

    let before = ledger_bytes(&ledger);

    assert!(matches!(
        ledger.rollback_tip(),
        Err(LedgerError::InvalidRollbackStateRoot)
    ));

    assert_eq!(ledger_bytes(&ledger), before);

    assert_eq!(ledger.tip_height(), Some(Height(1)));
}

#[test]

fn rollback_to_non_genesis_parent_checks_parent_root() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    commit_empty_block(
        &mut ledger,
        crypto::ProgramId([0x85; crypto::PROGRAM_ID_SIZE]),
    );

    commit_empty_block(
        &mut ledger,
        crypto::ProgramId([0x86; crypto::PROGRAM_ID_SIZE]),
    );

    let journal = &mut ledger
        .journals
        .get_mut(&Height(2))
        .expect("height-two journal")[0]
        .coin
        .as_mut()
        .expect("emission journal");

    journal.mined = journal.mined.checked_sub(Zeno::ONE).unwrap();

    journal.burned = journal.burned.checked_sub(Zeno::ONE).unwrap();

    let before = ledger_bytes(&ledger);

    assert!(matches!(
        ledger.rollback_tip(),
        Err(LedgerError::InvalidRollbackStateRoot)
    ));

    assert_eq!(ledger_bytes(&ledger), before);

    assert_eq!(ledger.tip_height(), Some(Height(2)));
}

#[test]

fn rolling_back_genesis_restores_empty_state_root() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    let genesis = ledger.chain.block(&Height(0)).unwrap().clone();

    assert_eq!(ledger.rollback_tip().unwrap(), genesis);

    assert_eq!(ledger.tip_height(), None);

    assert_eq!(ledger.state_root().unwrap(), StateRoot::ZERO);
}

#[test]

fn failure_after_emission_creation_does_not_change_canonical_ledger() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    let mut baseline = ledger.clone();

    let miner = crypto::ProgramId([0x91; crypto::PROGRAM_ID_SIZE]);

    let block = empty_next_candidate(&ledger, miner);

    let before = ledger_bytes(&ledger);

    assert!(matches!(
        ledger.execute_block_with_checkpoint(&block, |point, _| {
            if point == BlockTransitionPoint::EmissionCreated {
                Err(LedgerError::InvalidStateRoot)
            } else {
                Ok(())
            }
        }),
        Err(LedgerError::InvalidStateRoot)
    ));

    assert_eq!(ledger_bytes(&ledger), before);

    commit_empty_block(&mut ledger, miner);

    commit_empty_block(&mut baseline, miner);

    assert_eq!(ledger_bytes(&ledger), ledger_bytes(&baseline));
}

#[test]

fn two_committed_blocks_then_two_rollbacks_restore_genesis_byte_for_byte() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    let genesis_bytes = ledger_bytes(&ledger);

    let genesis_tip = ledger.tip_hash();

    let miner_one = crypto::ProgramId([0x51; crypto::PROGRAM_ID_SIZE]);

    let miner_two = crypto::ProgramId([0x52; crypto::PROGRAM_ID_SIZE]);

    let block_one = commit_empty_block(&mut ledger, miner_one);

    assert_eq!(ledger.tip_height(), Some(Height(1)));

    let height_one_bytes = ledger_bytes(&ledger);

    let height_one_tip = ledger.tip_hash();

    let block_two = commit_empty_block(&mut ledger, miner_two);

    assert_eq!(ledger.tip_height(), Some(Height(2)));

    assert_ne!(ledger_bytes(&ledger), height_one_bytes);

    let removed_two = ledger.rollback_tip().expect("rollback height two");

    assert_eq!(removed_two, block_two);

    assert_eq!(ledger.tip_height(), Some(Height(1)));

    assert_eq!(ledger.tip_hash(), height_one_tip);

    assert_eq!(ledger_bytes(&ledger), height_one_bytes);

    let removed_one = ledger.rollback_tip().expect("rollback height one");

    assert_eq!(removed_one, block_one);

    assert_eq!(ledger.tip_height(), Some(Height(0)));

    assert_eq!(ledger.tip_hash(), genesis_tip);

    assert_eq!(ledger_bytes(&ledger), genesis_bytes);
}

#[test]

fn failed_second_block_does_not_mutate_committed_first_block() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    let miner_one = crypto::ProgramId([0x61; crypto::PROGRAM_ID_SIZE]);

    let miner_two = crypto::ProgramId([0x62; crypto::PROGRAM_ID_SIZE]);

    let block_one = commit_empty_block(&mut ledger, miner_one);

    assert_eq!(ledger.tip_height(), Some(Height(1)));

    let before = ledger_bytes(&ledger);

    let before_tip = ledger.tip_hash();

    let block_two = empty_next_candidate(&ledger, miner_two);

    let validated = validate_candidate_for_apply(&block_two, &ledger.chain)
        .expect("candidate must pass pre-application consensus");

    assert!(matches!(
        ledger.apply_validated_block(validated),
        Err(LedgerError::InvalidStateRoot)
    ));

    assert_eq!(ledger.tip_height(), Some(Height(1)));

    assert_eq!(ledger.tip_hash(), before_tip);

    assert_eq!(ledger_bytes(&ledger), before);

    let removed = ledger.rollback_tip().expect("height-one rollback");

    assert_eq!(removed, block_one);

    assert_eq!(ledger.tip_height(), Some(Height(0)));
}

#[test]

fn invalid_block_weight_after_staging_does_not_mutate_ledger() {
    let mut ledger = genesis::genesis_ledger().expect("genesis ledger");

    let miner = crypto::ProgramId([0x71; crypto::PROGRAM_ID_SIZE]);

    let before = ledger_bytes(&ledger);

    let before_tip = ledger.tip_hash();

    let mut block = empty_next_candidate(&ledger, miner);

    let (state_root, block_weight) = ledger
        .preview_block_commitments(&block)
        .expect("preview commitments");

    block.set_state_root(state_root);

    //

    // Keep the weight structurally plausible, but make it

    // different from the canonical execution weight.

    //

    block.set_block_weight(
        block_weight
            .checked_add(1)
            .expect("fixture block weight overflow"),
    );

    //

    // The malformed weight is still large enough to satisfy

    // block-local structural validation.

    //

    let validated = validate_candidate_for_apply(&block, &ledger.chain)
        .expect("candidate must pass pre-application consensus");

    assert!(matches!(
        ledger.apply_validated_block(validated),
        Err(LedgerError::InvalidBlockWeight)
    ));

    assert_eq!(ledger_bytes(&ledger), before);

    assert_eq!(ledger.tip_hash(), before_tip);

    assert_eq!(ledger.tip_height(), Some(Height(0)));
}

#[test]

fn invalid_next_height_is_rejected_without_mutating_ledger() {
    let ledger = genesis::genesis_ledger().expect("genesis ledger");

    let miner = crypto::ProgramId([0x72; crypto::PROGRAM_ID_SIZE]);

    let before = ledger_bytes(&ledger);

    let before_tip = ledger.tip_hash();

    let mut block = empty_next_candidate(&ledger, miner);

    //

    // Genesis tip is height 0, therefore the only valid

    // next block is height 1.

    //

    block.height = Height(2);

    assert!(matches!(
        validate_candidate_for_apply(&block, &ledger.chain,),
        Err(ConsensusError::InvalidHeight)
    ));

    assert_eq!(ledger_bytes(&ledger), before);

    assert_eq!(ledger.tip_hash(), before_tip);

    assert_eq!(ledger.tip_height(), Some(Height(0)));
}

#[test]

fn invalid_previous_hash_is_rejected_without_mutating_ledger() {
    let ledger = genesis::genesis_ledger().expect("genesis ledger");

    let miner = crypto::ProgramId([0x73; crypto::PROGRAM_ID_SIZE]);

    let before = ledger_bytes(&ledger);

    let before_tip = ledger.tip_hash();

    let mut block = empty_next_candidate(&ledger, miner);

    let mut wrong_previous = ledger.tip_hash().expect("genesis tip").0;

    wrong_previous[0] ^= 0xff;

    block.header.previous_hash = crypto::PreviousHash(wrong_previous);

    assert!(matches!(
        validate_candidate_for_apply(&block, &ledger.chain,),
        Err(ConsensusError::InvalidPreviousHash)
    ));

    assert_eq!(ledger_bytes(&ledger), before);

    assert_eq!(ledger.tip_hash(), before_tip);

    assert_eq!(ledger.tip_height(), Some(Height(0)));
}

#[test]

fn program_block_snapshot_replay_and_reorg_restore_exact_state() {
    use crate::consensus::{ProtocolBurn, StateTransitionWeight};

    use crate::monetary::coin::CoinOutput;

    use crate::program::{
        AccountAuthorization, AuthorizedProgramEnvelope, AuthorizedProgramInvocation,
        CoinTransition, program_invocation_commitment,
    };

    use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

    use crate::program::system::{
        asset_program::{
            asset::Unit as ExtUnit,
            opcode::AssetOpcode,
            type_::{AssetCall, Register},
        },
        script::call::{ProgramCall, SystemProgramId},
    };

    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([24; 32]));

    let signer = program_id_from_public_key(&seed.public_key()).unwrap();

    let miner = crypto::ProgramId([0x82; crypto::PROGRAM_ID_SIZE]);

    let mut ledger = genesis::genesis_ledger().unwrap();

    commit_empty_block(&mut ledger, signer);

    let parent = ledger.clone();

    let chain = ledger.chain_context.unwrap();

    let (input, coin) = ledger.state.utxos.coins().next().unwrap();

    let amount = coin.amount;

    let register = Register {
        name: "ATOMIC".into(),

        max_supply: ExtUnit::from_units(100),

        initial_mint: ExtUnit::from_units(10),

        mint_authority: crate::common::Owner::Program(signer),

        nonce: 1,
    };

    let call = ProgramCall {
        program: SystemProgramId::ASSET,

        opcode: AssetOpcode::Register as u8,

        payload: borsh::to_vec(&register).unwrap(),
    };

    let sign = |output| {
        let payment =
            CoinTransition::coin(signer, vec![input], vec![CoinOutput::new(signer, output)])
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

    let dummy = sign(Zeno::ONE);

    let mut preview = ledger.state.extensions.clone();

    preview
        .assets
        .apply(
            &AssetCall::Register(register),
            ExecutionContext {
                actor: crate::common::Owner::Program(signer),

                commitment: [9; 32],
            },
        )
        .unwrap();

    let growth = (canonical_bytes(&preview).unwrap().len()
        - canonical_bytes(&ledger.state.extensions).unwrap().len()) as u64;

    let size = canonical_bytes(&AuthorizedProgramEnvelope::Program(Box::new(dummy)))
        .unwrap()
        .len() as u64;

    let burn = ProtocolBurn::for_program_call(
        StateTransitionWeight {
            created_coin_utxos: 1,

            consumed_coin_utxos: 1,

            created_state_weight: growth,
        },
        size,
    )
    .unwrap()
    .total()
    .unwrap();

    let tx = AuthorizedProgramEnvelope::Program(Box::new(sign(amount.checked_sub(burn).unwrap())));

    let candidate = |transactions: Vec<AuthorizedProgramEnvelope>| {
        Block::from_protocol_operations(
            Height(2),
            parent.tip_hash().unwrap(),
            expected_next_difficulty(&parent.chain).unwrap(),
            Nonce(0),
            Some(Emission::new(
                miner,
                expected_emission_for_height(Height(2)),
            )),
            transactions.into_iter().map(Into::into).collect(),
        )
        .unwrap()
    };

    let mut block = candidate(vec![tx.clone()]);

    assert!(ledger.execute_block(&block).is_ok());

    let bad = candidate(vec![tx.clone(), tx]);

    assert!(ledger.execute_block(&bad).is_err());

    assert_eq!(ledger, parent);

    let executed = ledger.execute_block(&block).unwrap();

    block.set_state_root(executed.state_root);

    block.set_block_weight(executed.block_weight);

    let validated = validate_candidate_for_apply(&block, &ledger.chain).unwrap();

    ledger.apply_validated_block(validated).unwrap();

    assert_eq!(ledger.state.extensions.assets.records().len(), 1);

    assert_eq!(
        ledger.program_call_protocol_burns(Height(2)).unwrap(),
        vec![burn]
    );

    let bytes = ledger_bytes(&ledger);

    let restored = Ledger::from_snapshot(
        LedgerSnapshot::try_from_slice(&borsh::to_vec(&ledger.snapshot()).unwrap()).unwrap(),
        &ledger.chain.blocks().cloned().collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(ledger_bytes(&restored), bytes);

    assert_eq!(restored, ledger);

    let blocks = ledger.chain.blocks().cloned().collect::<Vec<_>>();

    let snapshot =
        LedgerSnapshot::try_from_slice(&borsh::to_vec(&ledger.snapshot()).unwrap()).unwrap();

    let mut invalid_snapshot = snapshot.clone();
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend_from_slice(&7_u64.to_le_bytes());
    code.push(3);
    crate::program::deploy_program(
        &mut invalid_snapshot.state.programs,
        crate::program::DeployProgram {
            owner: signer,
            nonce: 1,
            code: code.into(),
        },
        Height(ledger.tip_height().unwrap().0 + 1),
    )
    .unwrap();
    assert!(matches!(
        Ledger::from_snapshot(invalid_snapshot, &blocks),
        Err(LedgerError::InvalidProgramState)
    ));

    let mut recovered = Ledger::from_snapshot(snapshot, &blocks).unwrap();

    assert_eq!(recovered, ledger);

    let mut corrupt = recovered.clone();

    corrupt.journals.get_mut(&Height(2)).unwrap()[1]
        .coin
        .as_mut()
        .unwrap()
        .created_coin_ids
        .push(CoinShare::from_bytes([0xfa; crypto::HASH_SIZE]));

    let before = ledger_bytes(&corrupt);

    assert!(corrupt.rollback_tip().is_err());

    assert_eq!(ledger_bytes(&corrupt), before);

    recovered.rollback_tip().unwrap();

    assert_eq!(recovered, parent);

    let mut replay = parent.clone();

    replay
        .apply_validated_block(validate_candidate_for_apply(&block, &parent.chain).unwrap())
        .unwrap();

    assert_eq!(replay, ledger);

    replay.rollback_tip().unwrap();

    commit_empty_block(&mut replay, miner);

    assert!(replay.state.extensions.assets.records().is_empty());

    replay.rollback_tip().unwrap();

    assert_eq!(replay, parent);
}

#[test]

fn active_program_lifecycle_replays_and_rolls_back_every_opcode() {
    use crate::{
        consensus::{ProtocolBurn, StateTransitionWeight},
        monetary::coin::CoinOutput,
        program::{
            AccountAuthorization, AuthorizedProgramEnvelope, AuthorizedProgramInvocation,
            CoinCharges, program_invocation_commitment,
        },
    };

    use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

    use crate::program::system::{
        asset_program::{
            asset::{AssetOutput, Unit as ExtUnit},
            opcode::AssetOpcode,
            type_::{AssetCall, Burn, Mint, Register, Transfer},
        },
        script::call::{ProgramCall, SystemProgramId},
    };

    fn commit_call(ledger: &mut Ledger, seed: &SigningSeed, call: AssetCall) {
        let signer = program_id_from_public_key(&seed.public_key()).unwrap();

        let chain = ledger.chain_context.unwrap();

        let (opcode, payload) = match &call {
            AssetCall::Register(v) => (AssetOpcode::Register, borsh::to_vec(v).unwrap()),

            AssetCall::Mint(v) => (AssetOpcode::Mint, borsh::to_vec(v).unwrap()),

            AssetCall::Transfer(v) => (AssetOpcode::Transfer, borsh::to_vec(v).unwrap()),

            AssetCall::Burn(v) => (AssetOpcode::Burn, borsh::to_vec(v).unwrap()),
        };

        let mut preview = ledger.state.extensions.clone();

        preview
            .assets
            .apply(
                &call,
                ExecutionContext {
                    actor: crate::common::Owner::Program(signer),

                    commitment: [11; 32],
                },
            )
            .unwrap();

        let growth = canonical_bytes(&preview)
            .unwrap()
            .len()
            .saturating_sub(canonical_bytes(&ledger.state.extensions).unwrap().len())
            as u64;

        let call = ProgramCall {
            program: SystemProgramId::ASSET,

            opcode: opcode as u8,

            payload,
        };

        let (input, coin) = ledger
            .state
            .utxos
            .coins()
            .filter(|(_, v)| v.owner == crate::common::Owner::Program(signer))
            .max_by_key(|(_, v)| v.amount)
            .unwrap();

        let amount = coin.amount;

        let sign = |output| {
            let payment = CoinTransition::coin_with_charges(
                signer,
                vec![input],
                vec![CoinOutput::new(signer, output)],
                CoinCharges::new(Zeno::ONE),
            )
            .unwrap();

            let commitment = program_invocation_commitment(signer, &call, &payment, chain).unwrap();

            AuthorizedProgramEnvelope::Program(Box::new(AuthorizedProgramInvocation {
                signer,

                call: call.clone(),

                payment,

                authorization: AccountAuthorization {
                    salt: [0; 32],
                    public_key: seed.public_key(),

                    signature: seed.sign(commitment.as_bytes()),
                },
            }))
        };

        let size = canonical_bytes(&sign(Zeno::ONE)).unwrap().len() as u64;

        let burn = ProtocolBurn::for_program_call(
            StateTransitionWeight {
                created_coin_utxos: 2,

                consumed_coin_utxos: 1,

                created_state_weight: growth,
            },
            size,
        )
        .unwrap()
        .total()
        .unwrap();

        let tx = sign(
            amount
                .checked_sub(burn)
                .unwrap()
                .checked_sub(Zeno::ONE)
                .unwrap(),
        );

        let height = Height(ledger.tip_height().unwrap().0 + 1);

        let mut block = Block::from_protocol_operations(
            height,
            ledger.tip_hash().unwrap(),
            expected_next_difficulty(&ledger.chain).unwrap(),
            Nonce(0),
            Some(Emission::new(signer, expected_emission_for_height(height))),
            vec![tx.into()],
        )
        .unwrap();

        let (root, weight) = ledger.preview_block_commitments(&block).unwrap();

        block.set_state_root(root);

        block.set_block_weight(weight);

        ledger
            .apply_validated_block(validate_candidate_for_apply(&block, &ledger.chain).unwrap())
            .unwrap();

        let blocks = ledger.chain.blocks().cloned().collect::<Vec<_>>();

        let snapshot =
            LedgerSnapshot::try_from_slice(&borsh::to_vec(&ledger.snapshot()).unwrap()).unwrap();

        *ledger = Ledger::from_snapshot(snapshot, &blocks).unwrap();
    }

    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([25; 32]));

    let signer = program_id_from_public_key(&seed.public_key()).unwrap();

    let mut ledger = genesis::genesis_ledger().unwrap();

    commit_empty_block(&mut ledger, signer);

    let mut checkpoints = vec![ledger.clone()];

    commit_call(
        &mut ledger,
        &seed,
        AssetCall::Register(Register {
            name: "LIFECYCLE".into(),

            max_supply: ExtUnit::from_units(100),

            initial_mint: ExtUnit::from_units(40),

            mint_authority: crate::common::Owner::Program(signer),

            nonce: 1,
        }),
    );

    checkpoints.push(ledger.clone());

    let asset = *ledger
        .state
        .extensions
        .assets
        .records()
        .keys()
        .next()
        .unwrap();

    commit_call(
        &mut ledger,
        &seed,
        AssetCall::Mint(Mint {
            asset,

            nonce: 1,

            recipient: crate::common::Owner::Program(signer),

            amount: ExtUnit::from_units(20),
        }),
    );

    checkpoints.push(ledger.clone());

    let inputs = ledger
        .state
        .extensions
        .assets
        .shares()
        .keys()
        .copied()
        .collect();

    commit_call(
        &mut ledger,
        &seed,
        AssetCall::Transfer(Transfer {
            asset,

            inputs,

            outputs: vec![AssetOutput::new(
                crate::common::Owner::Program(signer),
                ExtUnit::from_units(60),
            )],
        }),
    );

    checkpoints.push(ledger.clone());

    let inputs = ledger
        .state
        .extensions
        .assets
        .shares()
        .keys()
        .copied()
        .collect();

    commit_call(
        &mut ledger,
        &seed,
        AssetCall::Burn(Burn {
            asset,

            inputs,

            amount: ExtUnit::from_units(10),

            output: ExtUnit::from_units(50),
        }),
    );

    assert_eq!(
        ledger.state.extensions.assets.records()[&asset].supply,
        ExtUnit::from_units(50)
    );

    let mut replay = genesis::genesis_ledger().unwrap();

    for block in ledger.chain.blocks().skip(1) {
        replay
            .apply_validated_block(validate_candidate_for_apply(block, &replay.chain).unwrap())
            .unwrap();
    }

    assert_eq!(replay, ledger);

    for checkpoint in checkpoints.into_iter().rev() {
        replay.rollback_tip().unwrap();

        assert_eq!(replay, checkpoint);
    }
}
