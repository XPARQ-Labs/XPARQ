//! Asset supply, indexes, sparse journals, encoding, and rollback regressions.

use crate::{
    monetary::asset::{AssetError, Metadata},
    program::system::asset_program::type_::AssetCall,
};
use crypto::ProgramId;
use std::collections::{BTreeMap, BTreeSet};

use super::*;

use crate::program::system::asset_program::{
    asset::AssetOutput,
    type_::{Burn, Mint, Register, Transfer},
};

fn supply_fixture() -> crate::ledger::LedgerState {
    let mut state = crate::ledger::LedgerState::default();
    let owner = Owner::Program(ProgramId([61; 32]));
    state
        .extensions
        .assets
        .apply(
            &AssetCall::Register(Register {
                name: "SupplyCache".into(),
                max_supply: Unit::from_units(100),
                initial_mint: Unit::from_units(10),
                mint_authority: owner,
                nonce: 1,
            }),
            ExecutionContext {
                actor: owner,
                commitment: [1; 32],
            },
        )
        .unwrap();
    state
}

fn assert_incremental_totals(state: &crate::ledger::LedgerState) {
    let key = state
        .extensions
        .assets
        .supply_snapshot()
        .expect("tracked roots");
    let mut totals = BTreeMap::new();
    for share in state.extensions.assets.shares.values() {
        let entry = totals.entry(share.asset).or_insert(Unit::ZERO);
        *entry = entry.checked_add(share.amount).unwrap();
    }
    assert_eq!(
        key.totals
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect::<BTreeMap<_, _>>(),
        totals
    );
}

#[test]
fn incremental_supply_tracks_pending_multi_asset_operations_failure_and_reverse_journals() {
    let mut state = supply_fixture();
    state.validate_supply_invariants().unwrap();
    let original = state.clone();
    let owner = Owner::Program(ProgramId([61; 32]));
    let first = *state.extensions.assets.records.keys().next().unwrap();
    let context = |tag| ExecutionContext {
        actor: owner,
        commitment: [tag; 32],
    };
    let mut journals = Vec::new();
    journals.push(
        state
            .extensions
            .assets
            .apply(
                &AssetCall::Register(Register {
                    name: "SecondAsset".into(),
                    max_supply: Unit::from_units(u128::MAX),
                    initial_mint: Unit::from_units(u128::MAX),
                    mint_authority: owner,
                    nonce: 2,
                }),
                context(2),
            )
            .unwrap(),
    );
    let second = *state
        .extensions
        .assets
        .records
        .keys()
        .find(|id| **id != first)
        .unwrap();
    let input = Share::derive(second, [2; 32], 0);
    // Two outputs at the u128 boundary exercise subtract-before-add summaries.
    journals.push(
        state
            .extensions
            .assets
            .apply(
                &AssetCall::Transfer(Transfer {
                    asset: second,
                    inputs: vec![input],
                    outputs: vec![
                        AssetOutput::new(owner, Unit::from_units(u128::MAX - 1)),
                        AssetOutput::new(owner, Unit::from_units(1)),
                    ],
                }),
                context(3),
            )
            .unwrap(),
    );
    journals.push(
        state
            .extensions
            .assets
            .apply(
                &AssetCall::Mint(Mint {
                    asset: first,
                    amount: Unit::from_units(5),
                    recipient: owner,
                    nonce: 1,
                }),
                context(4),
            )
            .unwrap(),
    );
    let input = Share::derive(first, [1; 32], 0);
    // Output collides after the old input has been consumed; all summaries must restore.
    let before_error = state.clone();
    assert_eq!(
        state.extensions.assets.apply(
            &AssetCall::Transfer(Transfer {
                asset: first,
                inputs: vec![input],
                outputs: vec![AssetOutput::new(owner, Unit::from_units(10))],
            }),
            context(4)
        ),
        Err(AssetError::ShareAlreadyExists)
    );
    assert_eq!(state, before_error);
    assert_incremental_totals(&state);
    assert_eq!(
        state
            .extensions
            .assets
            .supply_snapshot()
            .unwrap()
            .dirty
            .len(),
        2
    );
    state.validate_supply_invariants().unwrap();
    assert!(state.extensions.assets.cached_supply_valid());
    assert!(original.extensions.assets.cached_supply_valid());
    let input = Share::derive(second, [3; 32], 1);
    journals.push(
        state
            .extensions
            .assets
            .apply(
                &AssetCall::Burn(Burn {
                    asset: second,
                    inputs: vec![input],
                    amount: Unit::from_units(1),
                    output: Unit::ZERO,
                }),
                context(5),
            )
            .unwrap(),
    );
    assert_incremental_totals(&state);
    state.validate_supply_invariants().unwrap();
    state.audit_supply_invariants().unwrap();
    for journal in journals.into_iter().rev() {
        state.extensions.assets.rollback(journal);
        assert_incremental_totals(&state);
        state.validate_supply_invariants().unwrap();
        state.audit_supply_invariants().unwrap();
    }
    assert_eq!(state, original);
    assert_eq!(
        borsh::to_vec(&state).unwrap(),
        borsh::to_vec(&original).unwrap()
    );
}

#[test]
fn incremental_summary_missing_or_stale_falls_back_and_never_skips_untracked_changes() {
    let mut state = supply_fixture();
    state.validate_supply_invariants().unwrap();
    let owner = Owner::Program(ProgramId([61; 32]));
    let asset = *state.extensions.assets.records.keys().next().unwrap();
    let call = AssetCall::Mint(Mint {
        asset,
        amount: Unit::from_units(1),
        recipient: owner,
        nonce: 1,
    });
    state
        .extensions
        .assets
        .apply(
            &call,
            ExecutionContext {
                actor: owner,
                commitment: [2; 32],
            },
        )
        .unwrap();
    assert_incremental_totals(&state);
    // A raw record mutation is outside the tracked operation path.
    state
        .extensions
        .assets
        .records
        .get_mut(&asset)
        .unwrap()
        .supply = Unit::from_units(10);
    assert!(state.extensions.assets.supply_snapshot().is_none());
    assert!(matches!(
        state.validate_supply_invariants(),
        Err(crate::ledger::LedgerError::AssetSupplyMismatch)
    ));
    assert!(state.extensions.assets.supply_snapshot().is_none());
    state
        .extensions
        .assets
        .apply(
            &AssetCall::Mint(Mint {
                asset,
                amount: Unit::from_units(1),
                recipient: owner,
                nonce: 2,
            }),
            ExecutionContext {
                actor: owner,
                commitment: [3; 32],
            },
        )
        .unwrap();
    // A successful later call cannot bless a stale baseline or hide earlier corruption.
    assert!(state.extensions.assets.supply_snapshot().is_none());
    assert!(matches!(
        state.validate_supply_invariants(),
        Err(crate::ledger::LedgerError::AssetSupplyMismatch)
    ));
    let restored =
        crate::ledger::LedgerState::try_from_slice(&borsh::to_vec(&state).unwrap()).unwrap();
    assert!(restored.extensions.assets.supply_snapshot().is_none());
    assert!(restored.audit_supply_invariants().is_err());
}

#[test]
fn incremental_validation_rejects_incorrect_tracked_accounting_without_clearing_pending() {
    use crate::ledger::LedgerError;
    for case in 0..3 {
        let mut state = supply_fixture();
        state.validate_supply_invariants().unwrap();
        let assets = &mut state.extensions.assets;
        let asset = *assets.records.keys().next().unwrap();
        let prior = assets.supply_snapshot();
        let journal = AssetJournal {
            records: vec![(asset, assets.records.get(&asset).cloned())],
            shares: vec![],
        };
        match case {
            0 => assets.records.get_mut(&asset).unwrap().supply = Unit::from_units(9),
            1 => assets.records.get_mut(&asset).unwrap().metadata.name = " invalid ".into(),
            _ => {
                assets.records.remove(&asset);
            }
        }
        // Simulate an incorrect kernel accounting update on the tracked path.
        assets.advance_supply_summary(prior, &journal);
        for _ in 0..2 {
            let result = state.validate_supply_invariants();
            assert!(matches!(
                (case, result),
                (0, Err(LedgerError::AssetSupplyMismatch))
                    | (1, Err(LedgerError::InvalidAssetState))
                    | (2, Err(LedgerError::UnknownAssetShare))
            ));
            assert_eq!(
                state
                    .extensions
                    .assets
                    .supply_snapshot()
                    .unwrap()
                    .dirty
                    .len(),
                1
            );
            assert!(state.audit_supply_invariants().is_err());
        }
    }
}

#[test]
fn successful_supply_cache_rejects_changed_invalid_records_and_shares() {
    use crate::ledger::LedgerError;
    let original = supply_fixture();
    let encoded = borsh::to_vec(&original).unwrap();
    assert!(!original.extensions.assets.cached_supply_valid());
    original.validate_supply_invariants().unwrap();
    assert!(original.extensions.assets.cached_supply_valid());
    assert_eq!(borsh::to_vec(&original).unwrap(), encoded);
    for case in 0..8 {
        let mut fork = original.clone();
        assert!(fork.extensions.assets.cached_supply_valid());
        let assets = &mut fork.extensions.assets;
        let asset = *assets.records.keys().next().unwrap();
        let input = *assets.shares.keys().next().unwrap();
        let share = *assets.shares.get(&input).unwrap();
        match case {
            0 => assets.put_share(
                input,
                AssetShare::new(asset, Unit::from_units(9), share.owner),
            ),
            1 => assets.put_share(input, AssetShare::new(asset, Unit::ZERO, share.owner)),
            2 => assets.put_share(
                input,
                AssetShare::new(
                    AssetContract::from_bytes([99; 32]),
                    share.amount,
                    share.owner,
                ),
            ),
            3 => assets.records.get_mut(&asset).unwrap().metadata.name = " bad name ".into(),
            4 => assets.records.get_mut(&asset).unwrap().total_minted = Unit::from_units(101),
            5 => {
                assets.records.remove(&asset);
            }
            6 => assets.put_share(
                Share::from_bytes([99; 32]),
                AssetShare::new(asset, Unit::from_units(u128::MAX), share.owner),
            ),
            _ => assets.records.get_mut(&asset).unwrap().supply = Unit::from_units(9),
        }
        assert!(!assets.cached_supply_valid());
        for _ in 0..2 {
            let error = fork.validate_supply_invariants().unwrap_err();
            match case {
                1 | 3 => assert!(matches!(error, LedgerError::InvalidAssetState)),
                2 | 5 => assert!(matches!(error, LedgerError::UnknownAssetShare)),
                6 => assert!(matches!(error, LedgerError::SupplyOverflow)),
                _ => assert!(matches!(error, LedgerError::AssetSupplyMismatch)),
            }
            assert!(!fork.extensions.assets.cached_supply_valid());
        }
        let restored =
            crate::ledger::LedgerState::try_from_slice(&borsh::to_vec(&fork).unwrap()).unwrap();
        assert!(!restored.extensions.assets.cached_supply_valid());
        assert!(restored.audit_supply_invariants().is_err());
        assert!(original.extensions.assets.cached_supply_valid());
        original.validate_supply_invariants().unwrap();
    }
}

#[test]
fn supply_cache_keeps_coin_checks_and_audits_valid_forks_and_rollback() {
    use crate::{
        ledger::{CoinUtxo, LedgerError},
        monetary::coin::{CoinShare, Zeno},
    };
    let original = supply_fixture();
    original.validate_supply_invariants().unwrap();
    let mut fork = original.clone();
    let owner = Owner::Program(ProgramId([61; 32]));
    fork.utxos
        .insert_coin(
            CoinShare::from_bytes([1; 32]),
            CoinUtxo {
                amount: Zeno::ONE,
                owner,
            },
        )
        .unwrap();
    assert!(fork.extensions.assets.cached_supply_valid());
    assert!(matches!(
        fork.validate_supply_invariants(),
        Err(LedgerError::CoinSupplyMismatch)
    ));
    fork.coin.total_mined = Zeno::ONE;
    fork.validate_supply_invariants().unwrap();
    fork.audit_supply_invariants().unwrap();
    let asset = *fork.extensions.assets.records.keys().next().unwrap();
    let input = *fork.extensions.assets.shares.keys().next().unwrap();
    let journal = fork
        .extensions
        .assets
        .apply(
            &AssetCall::Transfer(Transfer {
                asset,
                inputs: vec![input],
                outputs: vec![AssetOutput::new(owner, Unit::from_units(10))],
            }),
            ExecutionContext {
                actor: owner,
                commitment: [2; 32],
            },
        )
        .unwrap();
    assert!(!fork.extensions.assets.cached_supply_valid());
    fork.validate_supply_invariants().unwrap();
    assert!(fork.extensions.assets.cached_supply_valid());
    assert!(original.extensions.assets.cached_supply_valid());
    original.validate_supply_invariants().unwrap();
    fork.extensions.assets.rollback(journal);
    assert!(!fork.extensions.assets.cached_supply_valid());
    fork.audit_supply_invariants().unwrap();
    assert_eq!(fork.extensions.assets, original.extensions.assets);
    let restored =
        crate::ledger::LedgerState::try_from_slice(&borsh::to_vec(&fork).unwrap()).unwrap();
    assert!(!restored.extensions.assets.cached_supply_valid());
    restored.audit_supply_invariants().unwrap();
    std::thread::scope(|scope| {
        for state in [&original, &fork] {
            scope.spawn(move || {
                for _ in 0..32 {
                    state.validate_supply_invariants().unwrap();
                }
            });
        }
    });
}

#[test]
fn deep_audit_and_snapshot_restore_ignore_even_forged_internal_memo() {
    use crate::ledger::{Ledger, LedgerError};
    let mut ledger = crate::genesis::genesis_ledger().unwrap();
    ledger.state.extensions.assets = supply_fixture().extensions.assets;
    let asset = *ledger
        .state
        .extensions
        .assets
        .records
        .keys()
        .next()
        .unwrap();
    ledger
        .state
        .extensions
        .assets
        .records
        .get_mut(&asset)
        .unwrap()
        .supply = Unit::from_units(9);
    // Intentionally forge a kernel-internal memo. Applications and encoded
    // snapshots have no access to this setter or these private cache fields.
    ledger
        .state
        .extensions
        .assets
        .remember_valid_supply(BTreeMap::new());
    assert!(ledger.state.extensions.assets.cached_supply_valid());
    assert!(matches!(
        ledger.state.audit_asset_supply(),
        Err(LedgerError::AssetSupplyMismatch)
    ));
    assert!(matches!(
        ledger.state.audit_supply_invariants(),
        Err(LedgerError::AssetSupplyMismatch)
    ));
    let blocks: Vec<_> = ledger.chain.blocks().cloned().collect();
    assert!(matches!(
        Ledger::from_snapshot(ledger.snapshot(), &blocks),
        Err(LedgerError::AssetSupplyMismatch)
    ));
}

#[test]
#[ignore = "manual changed-asset supply benchmark; use release mode and --nocapture"]
fn benchmark_incremental_changed_asset_supply() {
    use std::{
        hint::black_box,
        time::{Duration, Instant},
    };
    let mut state = supply_fixture();
    let owner = Owner::Program(ProgramId([61; 32]));
    let asset = *state.extensions.assets.records.keys().next().unwrap();
    let entries = 100_000u64;
    let input = *state.extensions.assets.shares.keys().next().unwrap();
    state.extensions.assets.remove_share(&input);
    state
        .extensions
        .assets
        .records
        .get_mut(&asset)
        .unwrap()
        .supply = Unit::from_units(entries.into());
    state
        .extensions
        .assets
        .records
        .get_mut(&asset)
        .unwrap()
        .total_minted = Unit::from_units(entries.into());
    state
        .extensions
        .assets
        .records
        .get_mut(&asset)
        .unwrap()
        .metadata
        .max_supply = Unit::from_units(entries.into());
    for key in 0..entries {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&key.to_le_bytes());
        state.extensions.assets.put_share(
            Share::from_bytes(bytes),
            AssetShare::new(asset, Unit::from_units(1), owner),
        );
    }
    state.audit_supply_invariants().unwrap();
    let mut input = Share::from_bytes([0; 32]);
    let rounds = 128u64;
    let mut full = Duration::ZERO;
    let mut incremental = Duration::ZERO;
    let mut apply = Duration::ZERO;
    for round in 0..rounds {
        let mut commitment = [9; 32];
        commitment[..8].copy_from_slice(&round.to_le_bytes());
        let call = AssetCall::Transfer(Transfer {
            asset,
            inputs: vec![input],
            outputs: vec![AssetOutput::new(owner, Unit::from_units(1))],
        });
        let start = Instant::now();
        state
            .extensions
            .assets
            .apply(
                &call,
                ExecutionContext {
                    actor: owner,
                    commitment,
                },
            )
            .unwrap();
        apply += start.elapsed();
        assert_eq!(
            state
                .extensions
                .assets
                .supply_snapshot()
                .unwrap()
                .dirty
                .len(),
            1
        );
        let start = Instant::now();
        black_box(&state).validate_supply_invariants().unwrap();
        incremental += start.elapsed();
        let start = Instant::now();
        black_box(&state).audit_supply_invariants().unwrap();
        full += start.elapsed();
        input = Share::derive(asset, commitment, 0);
    }
    assert_incremental_totals(&state);
    let restored =
        crate::ledger::LedgerState::try_from_slice(&borsh::to_vec(&state).unwrap()).unwrap();
    assert!(restored.extensions.assets.supply_snapshot().is_none());
    restored.audit_supply_invariants().unwrap();
    println!(
        "shares={entries} changed_asset_checks={rounds} full_audit_ms={:.3} incremental_ms={:.3} tracked_apply_ms={:.3}",
        full.as_secs_f64() * 1000.0,
        incremental.as_secs_f64() * 1000.0,
        apply.as_secs_f64() * 1000.0
    );
}

#[test]
#[ignore = "manual repeated supply-audit benchmark; use release mode and --nocapture"]
fn benchmark_unchanged_asset_supply_cache() {
    use std::{hint::black_box, time::Instant};
    let mut state = crate::ledger::LedgerState::default();
    let owner = Owner::Program(ProgramId([62; 32]));
    let entries = 100_000u64;
    state
        .extensions
        .assets
        .apply(
            &AssetCall::Register(Register {
                name: "SupplyBench".into(),
                max_supply: Unit::from_units(u128::from(entries)),
                initial_mint: Unit::from_units(u128::from(entries)),
                mint_authority: owner,
                nonce: 1,
            }),
            ExecutionContext {
                actor: owner,
                commitment: [1; 32],
            },
        )
        .unwrap();
    let asset = *state.extensions.assets.records.keys().next().unwrap();
    let input = *state.extensions.assets.shares.keys().next().unwrap();
    state.extensions.assets.remove_share(&input);
    for key in 0..entries {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&key.to_le_bytes());
        state.extensions.assets.put_share(
            Share::from_bytes(bytes),
            AssetShare::new(asset, Unit::from_units(1), owner),
        );
    }
    let before = borsh::to_vec(&state).unwrap();
    state.validate_supply_invariants().unwrap();
    let rounds = 128;
    let start = Instant::now();
    for _ in 0..rounds {
        black_box(&state).audit_asset_supply().unwrap();
    }
    let full = start.elapsed();
    let start = Instant::now();
    for _ in 0..rounds {
        black_box(&state).validate_supply_invariants().unwrap();
    }
    let cached = start.elapsed();
    assert_eq!(borsh::to_vec(&state).unwrap(), before);
    state.audit_supply_invariants().unwrap();
    let input = *state.extensions.assets.shares.keys().next().unwrap();
    state
        .extensions
        .assets
        .put_share(input, AssetShare::new(asset, Unit::ZERO, owner));
    assert!(!state.extensions.assets.cached_supply_valid());
    assert!(matches!(
        state.validate_supply_invariants(),
        Err(crate::ledger::LedgerError::InvalidAssetState)
    ));
    println!(
        "asset_shares={entries} unchanged_supply_checks={rounds} full_scan_ms={:.3} validated_roots_ms={:.3}",
        full.as_secs_f64() * 1000.0,
        cached.as_secs_f64() * 1000.0
    );
}

// Historical clone-and-diff implementation, retained only as a test oracle.
fn legacy_apply(
    state: &mut AssetState,
    call: &AssetCall,
    context: ExecutionContext,
) -> Result<AssetJournal, AssetError> {
    let mut next = AssetState {
        records: state
            .records
            .iter()
            .map(|(&key, value)| (key, value.clone()))
            .collect(),
        shares: state
            .shares
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect(),
        by_owner: state
            .by_owner
            .iter()
            .map(|(&owner, assets)| {
                (
                    owner,
                    assets
                        .iter()
                        .map(|(&asset, ids)| (asset, ids.keys().map(|&id| (id, ())).collect()))
                        .collect(),
                )
            })
            .collect(),
        supply_cache: SupplyAuditCache::default(),
    };
    next.apply_monetary_operation(call, context)?;
    let record_keys: BTreeSet<_> = state
        .records
        .keys()
        .chain(next.records.keys())
        .copied()
        .collect();
    let share_keys: BTreeSet<_> = state
        .shares
        .keys()
        .chain(next.shares.keys())
        .copied()
        .collect();
    let journal = AssetJournal {
        records: record_keys
            .into_iter()
            .filter(|key| state.records.get(key) != next.records.get(key))
            .map(|key| (key, state.records.get(&key).cloned()))
            .collect(),
        shares: share_keys
            .into_iter()
            .filter(|key| state.shares.get(key) != next.shares.get(key))
            .map(|key| (key, state.shares.get(&key).copied()))
            .collect(),
    };
    *state = next;
    Ok(journal)
}

#[test]
fn cloned_asset_tables_detach_independently_and_keep_original_and_rollback() {
    let owner = Owner::Program(ProgramId([51; HASH_SIZE]));
    let context = |tag| ExecutionContext {
        actor: owner,
        commitment: [tag; HASH_SIZE],
    };
    let mut original = AssetState::default();
    original
        .apply(
            &AssetCall::Register(Register {
                name: "CopyOnWrite".into(),
                max_supply: Unit::from_units(100),
                initial_mint: Unit::from_units(10),
                mint_authority: owner,
                nonce: 1,
            }),
            context(1),
        )
        .unwrap();
    let encoded = borsh::to_vec(&original).unwrap();
    let asset = *original.records.keys().next().unwrap();
    let input = *original.shares.keys().next().unwrap();
    let mut staged = original.clone();
    assert!(original.records.shares_root(&staged.records));
    assert!(original.shares.shares_root(&staged.shares));
    assert!(original.by_owner.shares_root(&staged.by_owner));
    let mint = AssetCall::Mint(Mint {
        asset,
        nonce: 1,
        recipient: owner,
        amount: Unit::from_units(1),
    });
    let mut foreign = context(2);
    foreign.actor = Owner::Program(ProgramId([52; HASH_SIZE]));
    assert_eq!(staged.apply(&mint, foreign), Err(AssetError::Unauthorized));
    assert!(original.records.shares_root(&staged.records));
    assert!(original.shares.shares_root(&staged.shares));
    assert!(original.by_owner.shares_root(&staged.by_owner));
    let transfer = AssetCall::Transfer(Transfer {
        asset,
        inputs: vec![input],
        outputs: vec![AssetOutput::new(owner, Unit::from_units(10))],
    });
    let journal = staged.apply(&transfer, context(3)).unwrap();
    assert!(original.records.shares_root(&staged.records));
    assert!(!original.shares.shares_root(&staged.shares));
    assert!(!original.by_owner.shares_root(&staged.by_owner));
    staged.rollback(journal);
    assert_eq!(staged, original);
    let journal = staged.apply(&mint, context(4)).unwrap();
    assert!(!original.records.shares_root(&staged.records));
    assert_eq!(borsh::to_vec(&original).unwrap(), encoded);
    staged.rollback(journal);
    assert_eq!(staged, original);
    assert_owner_index(&staged);
}

fn assert_sparse_matches_full(state: &AssetState, call: &AssetCall, context: ExecutionContext) {
    let before = borsh::to_vec(state).unwrap().len() as i128;
    let mut legacy = state.clone();
    let old = legacy_apply(&mut legacy, call, context).unwrap();
    let mut sparse = state.clone();
    let journal = sparse.apply(call, context).unwrap();
    assert_eq!(sparse, legacy);
    assert_eq!(
        borsh::to_vec(&journal).unwrap(),
        borsh::to_vec(&old).unwrap()
    );
    let delta = borsh::to_vec(&legacy).unwrap().len() as i128 - before;
    assert_eq!(journal.canonical_delta(&sparse).unwrap(), delta);
    let mut view = state.operation_view(call, context).unwrap();
    let preview = view.apply(call, context).unwrap();
    assert_eq!(preview, journal);
    assert_eq!(preview.canonical_delta(&view).unwrap(), delta);
}

fn assert_owner_index(state: &AssetState) {
    let mut expected: BTreeMap<Owner, BTreeMap<AssetContract, BTreeSet<Share>>> = BTreeMap::new();
    for (&id, share) in state.shares.iter() {
        expected
            .entry(share.owner)
            .or_default()
            .entry(share.asset)
            .or_default()
            .insert(id);
    }
    let actual: BTreeMap<_, BTreeMap<_, BTreeSet<_>>> = state
        .by_owner
        .iter()
        .map(|(&owner, assets)| {
            (
                owner,
                assets
                    .iter()
                    .map(|(&asset, ids)| (asset, ids.keys().copied().collect()))
                    .collect(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
    for (&owner, assets) in &expected {
        let indexed: BTreeMap<_, _> = state
            .shares_by_owner(owner)
            .map(|(id, share)| (id, *share))
            .collect();
        let scanned: BTreeMap<_, _> = state
            .shares
            .iter()
            .filter(|(_, share)| share.owner == owner)
            .map(|(&id, share)| (id, *share))
            .collect();
        assert_eq!(indexed, scanned);
        for &asset in assets.keys() {
            let indexed: Vec<_> = state
                .shares_by_owner_asset(owner, asset)
                .map(|(id, share)| (id, *share))
                .collect();
            let scanned: Vec<_> = state
                .shares
                .iter()
                .filter(|(_, share)| share.owner == owner && share.asset == asset)
                .map(|(&id, share)| (id, *share))
                .collect();
            assert_eq!(indexed, scanned);
        }
    }
    let encoded = borsh::to_vec(state).unwrap();
    assert_eq!(
        encoded,
        borsh::to_vec(&(&state.records, &state.shares)).unwrap()
    );
    assert_eq!(AssetState::try_from_slice(&encoded).unwrap(), *state);
}

#[test]
fn sparse_transfer_collision_restores_consumed_inputs_and_created_outputs() {
    let owner = Owner::Program(ProgramId([41; HASH_SIZE]));
    let mut state = AssetState::default();
    let register = AssetCall::Register(Register {
        name: "Sparse".into(),
        max_supply: Unit::from_units(100),
        initial_mint: Unit::from_units(10),
        mint_authority: owner,
        nonce: 1,
    });
    let context = ExecutionContext {
        actor: owner,
        commitment: [1; HASH_SIZE],
    };
    assert_sparse_matches_full(&state, &register, context);
    state.apply(&register, context).unwrap();
    let asset = *state.records.keys().next().unwrap();
    let input = *state.shares.keys().next().unwrap();
    let context = ExecutionContext {
        actor: owner,
        commitment: [2; HASH_SIZE],
    };
    let collision = Share::derive(asset, context.commitment, 1);
    state.put_share(
        collision,
        AssetShare::new(asset, Unit::from_units(7), owner),
    );
    let record = state.records.get_mut(&asset).unwrap();
    record.supply = Unit::from_units(17);
    record.total_minted = Unit::from_units(17);
    let call = AssetCall::Transfer(Transfer {
        asset,
        inputs: vec![input],
        outputs: vec![
            AssetOutput::new(owner, Unit::from_units(4)),
            AssetOutput::new(owner, Unit::from_units(6)),
        ],
    });
    let before = state.clone();
    assert_eq!(
        state.apply(&call, context),
        Err(AssetError::ShareAlreadyExists)
    );
    assert_eq!(state, before);
    let mut view = state.operation_view(&call, context).unwrap();
    let view_before = view.clone();
    assert_eq!(
        view.apply(&call, context),
        Err(AssetError::ShareAlreadyExists)
    );
    assert_eq!(view, view_before);
}

#[test]
fn owner_index_separates_assets_and_owners_and_removes_empty_buckets() {
    let alice = Owner::Program(ProgramId([1; 32]));
    let bob = Owner::Program(ProgramId([2; 32]));
    let mut state = AssetState::default();
    let initial = state.clone();
    let mut journals = Vec::new();
    for (owner, name, tag) in [(alice, "A", 1), (bob, "B", 2)] {
        journals.push(
            state
                .apply(
                    &AssetCall::Register(Register {
                        name: name.into(),
                        max_supply: Unit::from_units(100),
                        initial_mint: Unit::from_units(10),
                        mint_authority: owner,
                        nonce: 1,
                    }),
                    ExecutionContext {
                        actor: owner,
                        commitment: [tag; 32],
                    },
                )
                .unwrap(),
        );
        assert_owner_index(&state);
    }
    let a = state
        .records
        .iter()
        .find(|(_, r)| r.metadata.creator == alice)
        .unwrap()
        .0
        .to_owned();
    let b = state
        .records
        .iter()
        .find(|(_, r)| r.metadata.creator == bob)
        .unwrap()
        .0
        .to_owned();
    journals.push(
        state
            .apply(
                &AssetCall::Mint(Mint {
                    asset: b,
                    recipient: alice,
                    amount: Unit::from_units(5),
                    nonce: 1,
                }),
                ExecutionContext {
                    actor: bob,
                    commitment: [3; 32],
                },
            )
            .unwrap(),
    );
    assert_owner_index(&state);
    assert_eq!(state.shares_by_owner(alice).count(), 2);
    let input = state.shares_by_owner_asset(alice, a).next().unwrap().0;
    journals.push(
        state
            .apply(
                &AssetCall::Transfer(Transfer {
                    asset: a,
                    inputs: vec![input],
                    outputs: vec![AssetOutput::new(bob, Unit::from_units(10))],
                }),
                ExecutionContext {
                    actor: alice,
                    commitment: [4; 32],
                },
            )
            .unwrap(),
    );
    assert_owner_index(&state);
    assert_eq!(state.shares_by_owner_asset(alice, a).count(), 0);
    let input = state.shares_by_owner_asset(alice, b).next().unwrap().0;
    journals.push(
        state
            .apply(
                &AssetCall::Burn(Burn {
                    asset: b,
                    inputs: vec![input],
                    amount: Unit::from_units(5),
                    output: Unit::ZERO,
                }),
                ExecutionContext {
                    actor: alice,
                    commitment: [5; 32],
                },
            )
            .unwrap(),
    );
    assert_owner_index(&state);
    assert!(!state.by_owner.contains_key(&alice));
    assert_eq!(state.shares_by_owner(alice).count(), 0);
    for journal in journals.into_iter().rev() {
        state.rollback(journal);
        assert_owner_index(&state);
    }
    assert_eq!(state, initial);
}

#[test]
#[ignore = "manual clone microbenchmark; use release mode and --nocapture"]
fn benchmark_asset_clone_and_sparse_journal() {
    use std::{hint::black_box, time::Instant};
    let owner = Owner::Program(ProgramId([41; HASH_SIZE]));
    let mut base = AssetState::default();
    let context = ExecutionContext {
        actor: owner,
        commitment: [1; HASH_SIZE],
    };
    base.apply(
        &AssetCall::Register(Register {
            name: "Bench".into(),
            max_supply: Unit::from_units(1_000_000),
            initial_mint: Unit::from_units(1),
            mint_authority: owner,
            nonce: 1,
        }),
        context,
    )
    .unwrap();
    let asset = *base.records.keys().next().unwrap();
    for index in 0..20_000 {
        base.put_share(
            Share::derive(asset, [7; HASH_SIZE], index),
            AssetShare::new(asset, Unit::from_units(1), owner),
        );
    }
    let record = base.records.get_mut(&asset).unwrap();
    record.supply = Unit::from_units(20_001);
    record.total_minted = Unit::from_units(20_001);
    let calls: Vec<_> = (1..=128u64)
        .map(|nonce| {
            let mut commitment = [0; HASH_SIZE];
            commitment[..8].copy_from_slice(&nonce.to_le_bytes());
            (
                AssetCall::Mint(Mint {
                    asset,
                    recipient: owner,
                    amount: Unit::from_units(1),
                    nonce,
                }),
                ExecutionContext {
                    actor: owner,
                    commitment,
                },
            )
        })
        .collect();
    let mut old = base.clone();
    let mut sparse = base;
    let start = Instant::now();
    let old_journals: Vec<_> = calls
        .iter()
        .map(|(call, context)| legacy_apply(&mut old, call, *context).unwrap())
        .collect();
    let cloned = start.elapsed();
    let start = Instant::now();
    for ((call, context), expected) in calls.iter().zip(old_journals) {
        let journal = sparse.apply(call, *context).unwrap();
        assert_eq!(journal, expected);
        black_box(&sparse);
    }
    let journaled = start.elapsed();
    assert_eq!(sparse, old);
    println!(
        "shares=20000 operations=128 clone_diff_ms={:.3} sparse_journal_ms={:.3}",
        cloned.as_secs_f64() * 1000.0,
        journaled.as_secs_f64() * 1000.0
    );
}

#[test]

fn lifetime_mint_cap_cannot_be_bypassed_by_burning_and_reminting() {
    let owner = ProgramId([1; crypto::PROGRAM_ID_SIZE]);

    let context = |byte| ExecutionContext {
        actor: Owner::Program(owner),
        commitment: [byte; HASH_SIZE],
    };

    let mut state = AssetState::default();

    state
        .apply(
            &AssetCall::Register(Register {
                name: "CAP".into(),

                max_supply: Unit::from_units(100),

                initial_mint: Unit::from_units(90),

                mint_authority: Owner::Program(owner),

                nonce: 1,
            }),
            context(1),
        )
        .unwrap();

    let asset = *state.records.keys().next().unwrap();

    let input = *state.shares.keys().next().unwrap();

    state
        .apply(
            &AssetCall::Burn(Burn {
                asset,

                inputs: vec![input],

                amount: Unit::from_units(80),

                output: Unit::from_units(10),
            }),
            context(2),
        )
        .unwrap();

    let before = state.clone();

    let result = state.apply(
        &AssetCall::Mint(Mint {
            asset,

            nonce: 1,

            recipient: Owner::Program(owner),

            amount: Unit::from_units(20),
        }),
        context(3),
    );

    assert_eq!(result, Err(AssetError::SupplyOverflow));

    assert_eq!(state, before);
}

#[test]

fn transfer_collision_after_consumption_is_atomic() {
    let owner = ProgramId([1; crypto::PROGRAM_ID_SIZE]);

    let context = |byte| ExecutionContext {
        actor: Owner::Program(owner),
        commitment: [byte; HASH_SIZE],
    };

    let mut state = AssetState::default();

    state
        .apply(
            &AssetCall::Register(Register {
                name: "COLLISION".into(),

                max_supply: Unit::from_units(100),

                initial_mint: Unit::from_units(10),

                mint_authority: Owner::Program(owner),

                nonce: 1,
            }),
            context(1),
        )
        .unwrap();

    let asset = *state.records.keys().next().unwrap();

    state
        .apply(
            &AssetCall::Mint(Mint {
                asset,

                nonce: 1,

                recipient: Owner::Program(owner),

                amount: Unit::from_units(5),
            }),
            context(2),
        )
        .unwrap();

    let before = state.clone();

    let result = state.apply(
        &AssetCall::Transfer(Transfer {
            asset,

            inputs: vec![Share::derive(asset, [1; HASH_SIZE], 0)],

            outputs: vec![AssetOutput::new(
                Owner::Program(owner),
                Unit::from_units(10),
            )],
        }),
        context(2),
    );

    assert_eq!(result, Err(AssetError::ShareAlreadyExists));

    assert_eq!(state, before);
}

#[test]

fn mint_amount_and_nonce_overflow_fail_without_mutation() {
    let owner = ProgramId([1; crypto::PROGRAM_ID_SIZE]);

    let context = ExecutionContext {
        actor: Owner::Program(owner),
        commitment: [1; HASH_SIZE],
    };

    let mut state = AssetState::default();

    state
        .apply(
            &AssetCall::Register(Register {
                name: "OVERFLOW".into(),

                max_supply: Unit::from_units(u128::MAX),

                initial_mint: Unit::from_units(u128::MAX),

                mint_authority: Owner::Program(owner),

                nonce: 1,
            }),
            context,
        )
        .unwrap();

    let asset = *state.records.keys().next().unwrap();

    let before = state.clone();

    assert_eq!(
        state.apply(
            &AssetCall::Mint(Mint {
                asset,

                nonce: 1,

                recipient: Owner::Program(owner),

                amount: Unit::from_units(1),
            }),
            ExecutionContext {
                commitment: [2; HASH_SIZE],

                ..context
            }
        ),
        Err(AssetError::SupplyOverflow)
    );

    assert_eq!(state, before);

    // Synthetic exhausted counter: the next nonce must never wrap to zero.

    state.records.get_mut(&asset).unwrap().mint_nonce = u64::MAX;

    let before = state.clone();

    assert_eq!(
        state.apply(
            &AssetCall::Mint(Mint {
                asset,

                nonce: 0,

                recipient: Owner::Program(owner),

                amount: Unit::from_units(1),
            }),
            ExecutionContext {
                commitment: [2; HASH_SIZE],

                ..context
            }
        ),
        Err(AssetError::InvalidMintNonce)
    );

    assert_eq!(state, before);
}

#[test]

fn generated_asset_lifecycles_preserve_balances_supply_and_exact_rollback() {
    for seed in 1..=16u64 {
        let owners = [
            ProgramId([1; crypto::PROGRAM_ID_SIZE]),
            ProgramId([2; crypto::PROGRAM_ID_SIZE]),
        ];

        let mut state = AssetState::default();

        let initial = state.clone();

        let registration = state
            .apply(
                &AssetCall::Register(Register {
                    name: "MODEL".into(),

                    max_supply: Unit::from_units(10_000),

                    initial_mint: Unit::from_units(1_000),

                    mint_authority: Owner::Program(owners[0]),

                    nonce: seed,
                }),
                ExecutionContext {
                    actor: Owner::Program(owners[0]),
                    commitment: [0; HASH_SIZE],
                },
            )
            .unwrap();

        let asset = *state.records.keys().next().unwrap();

        let mut balances = [1_000u64, 0];

        let mut minted = 1_000u64;

        let mut burned = 0u64;

        let mut nonce = 0u64;

        let mut random = seed;

        let mut journals = vec![(initial, registration)];

        for step in 1..=64u64 {
            random ^= random << 13;

            random ^= random >> 7;

            random ^= random << 17;

            let selected = (random & 1) as usize;

            let mut commitment = [0; HASH_SIZE];

            commitment[..8].copy_from_slice(&seed.to_le_bytes());

            commitment[8..16].copy_from_slice(&step.to_le_bytes());

            let inputs = state
                .shares
                .iter()
                .filter(|(_, share)| share.owner == Owner::Program(owners[selected]))
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();

            let before = state.clone();

            let (call, signer) = if random % 3 == 0 || balances[selected] == 0 {
                let amount = random % 20 + 1;

                nonce += 1;

                minted += amount;

                balances[selected] += amount;

                (
                    AssetCall::Mint(Mint {
                        asset,

                        nonce,

                        recipient: Owner::Program(owners[selected]),

                        amount: Unit::from_units(amount.into()),
                    }),
                    owners[0],
                )
            } else if random % 3 == 1 {
                let amount = random % balances[selected] + 1;

                let change = balances[selected] - amount;

                let mut outputs = vec![AssetOutput::new(
                    Owner::Program(owners[1 - selected]),
                    Unit::from_units(amount.into()),
                )];

                if change > 0 {
                    outputs.push(AssetOutput::new(
                        Owner::Program(owners[selected]),
                        Unit::from_units(change.into()),
                    ));
                }

                balances[selected] = change;

                balances[1 - selected] += amount;

                (
                    AssetCall::Transfer(Transfer {
                        asset,

                        inputs,

                        outputs,
                    }),
                    owners[selected],
                )
            } else {
                let amount = random % balances[selected] + 1;

                balances[selected] -= amount;

                burned += amount;

                (
                    AssetCall::Burn(Burn {
                        asset,

                        inputs,

                        amount: Unit::from_units(amount.into()),

                        output: Unit::from_units(balances[selected].into()),
                    }),
                    owners[selected],
                )
            };

            assert_sparse_matches_full(
                &state,
                &call,
                ExecutionContext {
                    actor: Owner::Program(signer),
                    commitment,
                },
            );
            let journal = state
                .apply(
                    &call,
                    ExecutionContext {
                        actor: Owner::Program(signer),
                        commitment,
                    },
                )
                .unwrap();

            for (index, owner) in owners.iter().enumerate() {
                let actual: u128 = state
                    .shares
                    .values()
                    .filter(|share| share.owner == Owner::Program(*owner))
                    .map(|share| share.amount.as_units())
                    .sum();

                assert_eq!(actual, u128::from(balances[index]));
            }

            assert_eq!(
                state.records[&asset].supply.as_units(),
                u128::from(minted - burned)
            );

            assert_eq!(
                state.records[&asset].total_minted.as_units(),
                u128::from(minted)
            );

            assert_eq!(
                state.records[&asset].total_burned.as_units(),
                u128::from(burned)
            );
            assert_owner_index(&state);

            let mut ledger = crate::ledger::LedgerState::default();

            ledger.extensions.assets = state.clone();

            ledger.validate_supply_invariants().unwrap();

            journals.push((before, journal));
        }

        for (before, journal) in journals.into_iter().rev() {
            let encoded = borsh::to_vec(&journal).unwrap();

            state.rollback(AssetJournal::try_from_slice(&encoded).unwrap());
            assert_owner_index(&state);

            assert_eq!(state, before);
        }

        assert_eq!(state, AssetState::default());
    }
}

#[test]

fn lifecycle_authorization_conservation_and_rollback() {
    let owner = ProgramId::from_bytes([1; crypto::PROGRAM_ID_SIZE]);

    let receiver = ProgramId::from_bytes([2; crypto::PROGRAM_ID_SIZE]);

    let context = |signer, byte| ExecutionContext {
        actor: Owner::Program(signer),
        commitment: [byte; HASH_SIZE],
    };

    let mut state = AssetState::default();

    let register = Register {
        name: "TEST".into(),

        max_supply: Unit::from_units(100),

        initial_mint: Unit::from_units(40),

        mint_authority: Owner::Program(owner),

        nonce: 7,
    };

    let register_journal = state
        .apply(&AssetCall::Register(register.clone()), context(owner, 1))
        .unwrap();

    let metadata = Metadata::new(
        register.name,
        register.max_supply,
        Owner::Program(owner),
        Owner::Program(owner),
    )
    .unwrap();

    let asset = AssetContract::derive(&metadata, 7).unwrap();

    let first = Share::derive(asset, [1; HASH_SIZE], 0);

    let mint = AssetCall::Mint(Mint {
        asset,

        nonce: 1,

        recipient: Owner::Program(owner),

        amount: Unit::from_units(20),
    });

    let before = state.clone();

    assert_eq!(
        state.apply(&mint, context(receiver, 2)),
        Err(AssetError::Unauthorized)
    );

    assert_eq!(state, before);

    let mint_journal = state.apply(&mint, context(owner, 2)).unwrap();

    let second = Share::derive(asset, [2; HASH_SIZE], 0);

    let transfer = AssetCall::Transfer(Transfer {
        asset,

        inputs: vec![first, second],

        outputs: vec![AssetOutput::new(
            Owner::Program(receiver),
            Unit::from_units(60),
        )],
    });

    let before = state.clone();

    assert_eq!(
        state.apply(&transfer, context(receiver, 3)),
        Err(AssetError::Unauthorized)
    );

    assert_eq!(state, before);

    let journal = state.apply(&transfer, context(owner, 3)).unwrap();

    let received = Share::derive(asset, [3; HASH_SIZE], 0);

    assert_eq!(
        state.shares.get(&received).unwrap().owner,
        Owner::Program(receiver)
    );

    state.rollback(journal);

    assert_eq!(state, before);

    let transfer_journal = state.apply(&transfer, context(owner, 3)).unwrap();

    let burn = AssetCall::Burn(Burn {
        asset,

        inputs: vec![received],

        amount: Unit::from_units(10),

        output: Unit::from_units(50),
    });

    assert_eq!(
        state.apply(&burn, context(owner, 4)),
        Err(AssetError::Unauthorized)
    );

    let burn_journal = state.apply(&burn, context(receiver, 4)).unwrap();

    assert_eq!(state.records[&asset].supply, Unit::from_units(50));

    assert_eq!(state.records[&asset].total_burned, Unit::from_units(10));

    for journal in [
        burn_journal,
        transfer_journal,
        mint_journal,
        register_journal,
    ] {
        let encoded = borsh::to_vec(&journal).unwrap();

        state.rollback(AssetJournal::try_from_slice(&encoded).unwrap());
    }

    assert_eq!(state, AssetState::default());
}
