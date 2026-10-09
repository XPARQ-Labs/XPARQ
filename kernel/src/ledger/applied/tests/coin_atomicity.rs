//! Coin mutation failure injection and journal validation regressions.

use super::coin::TransitionPoint;
use crate::{
    ledger::{CoinRollbackJournal, CoinUtxo, LedgerState, StateError},
    monetary::coin::{CoinShare, Zeno},
    program::{AuthorizationCommitment, CoinTransition},
};
use crypto::ProgramId;

use crate::{monetary::coin::CoinOutput, program::CoinCharges};

use crypto::HASH_SIZE;

fn program_id(byte: u8) -> ProgramId {
    ProgramId([byte; crypto::PROGRAM_ID_SIZE])
}

#[test]

fn coin_coin_failure_after_each_mutation_restores_state_and_retry_root() {
    let owner = program_id(1);

    let input = CoinShare::from_bytes([3; crypto::HASH_SIZE]);

    let mut original = LedgerState::default();

    original.coin.total_mined = Zeno::from_zeno(100);

    original
        .utxos
        .insert_coin(
            input,
            CoinUtxo {
                amount: Zeno::from_zeno(100),

                owner: crate::common::Owner::Program(owner),
            },
        )
        .unwrap();

    let intent = CoinTransition::coin_with_charges(
        owner,
        vec![input],
        vec![CoinOutput::new(program_id(2), Zeno::from_zeno(70))],
        CoinCharges::new(Zeno::from_zeno(10)),
    )
    .unwrap();

    let commitment = AuthorizationCommitment::from_bytes([4; HASH_SIZE]);

    let mut expected = original.clone();

    expected
        .execute_coin_program(&intent, commitment, program_id(9))
        .unwrap();

    let expected_bytes = borsh::to_vec(&expected).unwrap();

    for point in [
        TransitionPoint::CoinInputConsumed,
        TransitionPoint::CoinOutputCreated,
        TransitionPoint::MinerFeeCreated,
        TransitionPoint::ProtocolBurnRecorded,
    ] {
        let mut state = original.clone();

        assert!(matches!(
            state.execute_coin_program_with_checkpoint(
                &intent,
                commitment,
                program_id(9),
                |seen| if seen == point {
                    Err(StateError::InvalidTransition)
                } else {
                    Ok(())
                },
            ),
            Err(StateError::InvalidTransition)
        ));

        assert_eq!(state, original, "failure at {point:?}");

        state
            .execute_coin_program(&intent, commitment, program_id(9))
            .unwrap();

        assert_eq!(borsh::to_vec(&state).unwrap(), expected_bytes);
    }
}

#[test]

fn burn_accounting_and_invalid_rollback_journal_fail_without_partial_mutation() {
    let mut state = LedgerState::default();

    let mut journal = CoinRollbackJournal {
        burned: Zeno::from_zeno(u64::MAX),

        ..CoinRollbackJournal::default()
    };

    assert!(matches!(
        state.record_protocol_burn(Zeno::ONE, &mut journal),
        Err(StateError::BurnOverflow)
    ));

    assert_eq!(state.coin.total_burned, Zeno::ZERO);

    assert_eq!(journal.burned, Zeno::from_zeno(u64::MAX));

    state.coin.total_mined = Zeno::from_zeno(100);

    state.coin.total_burned = Zeno::from_zeno(5);

    let before = state.clone();

    let corrupt = CoinRollbackJournal {
        created_coin_ids: vec![CoinShare::from_bytes([9; crypto::HASH_SIZE])],

        mined: Zeno::from_zeno(10),

        burned: Zeno::ONE,

        ..CoinRollbackJournal::default()
    };

    assert!(matches!(
        state.rollback_coin(corrupt),
        Err(StateError::InvalidTransition)
    ));

    assert_eq!(state, before);
}
