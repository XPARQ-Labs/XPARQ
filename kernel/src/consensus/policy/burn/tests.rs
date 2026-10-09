use super::*;
use crate::{
    block::{Emission, block_bytes, block_header_bytes},
    common::{Nonce, Owner},
    ledger::CoinUtxo,
    monetary::coin::CoinShare,
    program::ProgramId,
};
use crate::{blockchain::Block, common::Height};
use crypto::{Hash, canonical_bytes};

#[test]
fn archival_and_utxo_weights_match_actual_borsh_encoding() {
    let block = Block::from_protocol_operations(
        Height(1),
        Hash::ZERO,
        crate::consensus::TARGET_BITS_START,
        Nonce(0),
        Some(Emission::new(ProgramId::ZERO, Zeno::from_zeno(1))),
        vec![],
    )
    .unwrap();
    assert_eq!(
        block_header_bytes(&block.header).unwrap().len(),
        BLOCK_HEADER_ARCHIVAL_BYTES
    );
    assert_eq!(
        block_bytes(&block).unwrap().len() as u64,
        EMPTY_BLOCK_ARCHIVAL_BYTES
    );
    assert_eq!(EMPTY_BLOCK_ARCHIVAL_BYTES, 165);
    for owner in [
        Owner::Program(ProgramId::ZERO),
        Owner::Program(ProgramId::from_bytes([0; HASH_SIZE])),
    ] {
        let entry = (
            CoinShare::from_bytes([0; CoinShare::SIZE]),
            CoinUtxo {
                amount: Zeno::ONE,
                owner,
            },
        );
        assert_eq!(
            canonical_bytes(&entry).unwrap().len() as u64,
            COIN_UTXO_STATE_WEIGHT
        );
    }
    assert_eq!(COIN_UTXO_STATE_WEIGHT, 73);
    assert_eq!(
        MINER_PROTOCOL_BURN.as_zeno(),
        (EMPTY_BLOCK_ARCHIVAL_BYTES + COIN_UTXO_STATE_WEIGHT) * STATE_BURN_RATE_ZENO_PER_BYTE
    );
    assert_eq!(
        MINER_PROTOCOL_BURN,
        EMPTY_BLOCK_ARCHIVAL_BURN
            .checked_add(EMISSION_UTXO_STATE_GROWTH_BURN)
            .unwrap()
    );
}

#[test]
fn burn_charges_actual_bytes_and_only_positive_net_state_growth() {
    let growth = StateTransitionWeight {
        created_coin_utxos: 3,
        consumed_coin_utxos: 1,
        created_state_weight: 100,
    };
    let burn = ProtocolBurn::for_program_call(growth, 1_000).unwrap();
    assert_eq!(
        burn.archival.as_zeno(),
        1_000 * STATE_BURN_RATE_ZENO_PER_BYTE
    );
    assert_eq!(
        burn.state_growth.as_zeno(),
        (2 * COIN_UTXO_STATE_WEIGHT + 100) * STATE_BURN_RATE_ZENO_PER_BYTE
    );
    let shrinking = StateTransitionWeight {
        created_coin_utxos: 1,
        consumed_coin_utxos: 3,
        created_state_weight: 0,
    };
    let burn = ProtocolBurn::for_program_call(shrinking, 1_000).unwrap();
    assert_eq!(burn.state_growth, Zeno::ZERO);
    assert_eq!(burn.total(), Ok(burn.archival)); // Consolidation cannot erase history cost.
    assert!(
        validate_exact_burn(Zeno::from_zeno(burn.archival.as_zeno() - 1), burn.archival).is_err()
    );
    assert!(
        validate_exact_burn(Zeno::from_zeno(burn.archival.as_zeno() + 1), burn.archival).is_err()
    );
}

#[test]
fn burn_rejects_weight_and_total_overflow_instead_of_wrapping() {
    assert_eq!(
        StateTransitionWeight {
            created_coin_utxos: u64::MAX,
            consumed_coin_utxos: 0,
            created_state_weight: 0
        }
        .state_growth_burn(),
        Err(BurnError::WeightOverflow)
    );
    assert_eq!(
        StateTransitionWeight {
            created_coin_utxos: 1,
            consumed_coin_utxos: 0,
            created_state_weight: u64::MAX
        }
        .state_growth_burn(),
        Err(BurnError::WeightOverflow)
    );
    let burn = ProtocolBurn {
        archival: Zeno::from_zeno(u64::MAX),
        state_growth: Zeno::ONE,
    };
    assert_eq!(burn.total(), Err(BurnError::ZenoOverflow));
    // The maximum size charge can fit at 1 zeno/byte, but adding any state
    // growth must still fail checked arithmetic.
    if STATE_BURN_RATE_ZENO_PER_BYTE == 1 {
        let burn = ProtocolBurn::for_program_call(
            StateTransitionWeight {
                created_state_weight: 1,
                ..Default::default()
            },
            u64::MAX,
        )
        .unwrap();
        assert_eq!(burn.total(), Err(BurnError::ZenoOverflow));
    } else {
        assert_eq!(
            ProtocolBurn::for_program_call(StateTransitionWeight::default(), u64::MAX),
            Err(BurnError::ZenoOverflow)
        );
    }
}
