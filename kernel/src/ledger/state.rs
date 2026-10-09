//! Canonical ledger state and rollback journal types.

use super::utxo::{self, CoinUtxo};
#[cfg(test)]
use crate::ledger::utxo::ExecutionContext;

use crate::{
    monetary::coin::{CoinShare, Zeno},
    program::{ProgramJournal, ProgramRegistry},
};

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::StateRoot;
use std::sync::{Arc, Mutex};

/// Detached canonical state data; public accessors expose immutable components.
/// Decoding this type does not install it into a live `Ledger`.
///
/// ```compile_fail
/// use kernel::ledger::LedgerState;
/// use kernel::monetary::coin::Zeno;
/// let mut state = LedgerState::default();
/// state.coin.total_mined = Zeno::from_zeno(100);
/// ```
///
/// ```compile_fail
/// use kernel::ledger::LedgerState;
/// use kernel::ledger::utxo::UtxoSet;
/// let mut state = LedgerState::default();
/// *state.utxos() = UtxoSet::default();
/// ```
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pub(crate) utxos: utxo::UtxoSet,
    pub(crate) coin: CoinRecord,
    pub(crate) programs: ProgramRegistry,
    pub(crate) extensions: crate::program::system::script::state::ExtensionState,
    /// Derived memoization only; excluded from canonical bytes and equality.
    #[borsh(skip)]
    #[doc(hidden)]
    pub(crate) root_cache: StateRootCache,
}

#[derive(Clone, Default)]
pub(crate) struct StateRootCache(Arc<Mutex<Option<CachedStateRoot>>>);

struct CachedStateRoot {
    // Retained roots force later mutations to detach and prevent pointer reuse.
    utxos: utxo::UtxoSet,
    coin: CoinRecord,
    extensions: crate::program::system::script::state::ExtensionState,
    programs: ProgramRegistry,
    root: StateRoot,
}
impl PartialEq for StateRootCache {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for StateRootCache {}
impl std::fmt::Debug for StateRootCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StateRootCache")
    }
}

impl LedgerState {
    /// Hash this detached state; a root alone is not proof of valid execution.
    pub fn state_root(&self) -> Result<StateRoot, super::LedgerError> {
        self.application_state_root()
    }

    pub(crate) fn cached_state_root(&self) -> Option<StateRoot> {
        // Exhaustive destructuring forces future state fields to be considered.
        let Self {
            utxos,
            coin,
            programs,
            extensions,
            root_cache,
        } = self;
        let cache = root_cache
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let cached = cache.as_ref()?;
        (cached.utxos.same_canonical_view(utxos)
            && cached.coin == *coin
            && cached.extensions.same_canonical_view(extensions)
            && cached.programs.same_canonical_view(programs))
        .then_some(cached.root)
    }

    pub(crate) fn cache_state_root(&self, root: StateRoot) {
        let cached = CachedStateRoot {
            utxos: self.utxos.clone(),
            coin: self.coin,
            extensions: self.extensions.clone(),
            programs: self.programs.clone(),
            root,
        };
        *self
            .root_cache
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(cached);
    }
    pub const fn coin(&self) -> &CoinRecord {
        &self.coin
    }
    pub const fn programs(&self) -> &ProgramRegistry {
        &self.programs
    }
    pub const fn extensions(&self) -> &crate::program::system::script::state::ExtensionState {
        &self.extensions
    }

    pub const fn utxos(&self) -> &utxo::UtxoSet {
        &self.utxos
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoinRecord {
    pub total_mined: Zeno,
    pub total_burned: Zeno,
}

impl CoinRecord {
    pub fn supply(&self) -> Option<Zeno> {
        self.total_mined.checked_sub(self.total_burned)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinRollbackJournal {
    pub(crate) consumed_coins: Vec<(CoinShare, CoinUtxo)>,
    pub(crate) created_coin_ids: Vec<CoinShare>,
    pub(crate) mined: Zeno,
    pub(crate) burned: Zeno,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct StateRollbackJournal {
    pub(crate) coin: Option<CoinRollbackJournal>,
    pub program: Option<ProgramJournal>,
    pub extension: Option<crate::ledger::utxo::AssetJournal>,
}

impl StateRollbackJournal {
    pub const fn protocol_burn(&self) -> Zeno {
        match &self.coin {
            Some(journal) => journal.burned,
            None => Zeno::ZERO,
        }
    }
}

#[cfg(test)]
mod extension_commitment_tests {
    use super::*;
    use crate::program::system::asset_program::{
        asset::Unit,
        type_::{AssetCall, Register},
    };
    use crypto::{ProgramId, StateRoot};

    #[test]
    fn extension_state_is_committed_serialized_and_supply_checked() {
        let mut state = LedgerState::default();
        assert_eq!(state.application_state_root().unwrap(), StateRoot::ZERO);
        let call = AssetCall::Register(Register {
            name: "ROOT".into(),
            max_supply: Unit::from_units(100),
            initial_mint: Unit::from_units(10),
            mint_authority: crate::common::Owner::Program(ProgramId::ZERO),
            nonce: 1,
        });
        let journal = state
            .extensions
            .assets
            .apply(
                &call,
                ExecutionContext {
                    actor: crate::common::Owner::Program(ProgramId::ZERO),
                    commitment: [3; 32],
                },
            )
            .unwrap();
        let root = state.application_state_root().unwrap();
        assert_ne!(root, StateRoot::ZERO);
        state.validate_supply_invariants().unwrap();
        let restored = LedgerState::try_from_slice(&borsh::to_vec(&state).unwrap()).unwrap();
        assert_eq!(restored, state);
        assert_eq!(restored.application_state_root().unwrap(), root);
        let mut shares = state
            .extensions
            .assets
            .shares()
            .iter()
            .map(|(&id, &share)| (id, share))
            .collect::<std::collections::BTreeMap<_, _>>();
        shares.values_mut().next().unwrap().amount = Unit::from_units(9);
        state.extensions.assets = crate::ledger::utxo::AssetState::try_from_slice(
            &borsh::to_vec(&(state.extensions.assets.records(), shares)).unwrap(),
        )
        .unwrap();
        assert_ne!(state.application_state_root().unwrap(), root);
        assert!(state.validate_supply_invariants().is_err());
        state.extensions.assets.rollback(journal);
        assert_eq!(state, LedgerState::default());
        assert_eq!(state.application_state_root().unwrap(), StateRoot::ZERO);
    }
}

#[cfg(test)]
mod root_cache_tests {
    use super::*;
    use crate::{
        common::{Height, Owner},
        monetary::asset::{AssetOutput, Unit},
        program::system::asset_program::type_::{AssetCall, Burn, Mint, Register, Transfer},
        program::{DeployProgram, deploy_program, rollback_program},
    };
    use crypto::{HashDomain, ProgramId, canonical_bytes, domain};

    fn reference(state: &LedgerState) -> StateRoot {
        if state.extensions == Default::default()
            && state.utxos.is_empty()
            && state.programs.is_empty()
            && state.coin.total_mined.is_zero()
            && state.coin.total_burned.is_zero()
        {
            return StateRoot::ZERO;
        }
        StateRoot(
            domain(
                HashDomain::ProtocolState,
                &canonical_bytes(&(
                    &state.utxos,
                    &state.coin,
                    &state.programs,
                    &state.extensions,
                ))
                .unwrap(),
            )
            .into_bytes(),
        )
    }
    fn assert_root(state: &LedgerState) -> StateRoot {
        let expected = reference(state);
        assert_eq!(
            state.canonical_encoded_len().unwrap(),
            canonical_bytes(state).unwrap().len() as u64
        );
        assert_eq!(state.application_state_root().unwrap(), expected);
        assert_eq!(state.application_state_root().unwrap(), expected);
        if expected != StateRoot::ZERO {
            assert_eq!(state.cached_state_root(), Some(expected));
        }
        // Memoization is omitted from the historical encoding and equality.
        assert_eq!(
            canonical_bytes(state).unwrap(),
            canonical_bytes(&(
                &state.utxos,
                &state.coin,
                &state.programs,
                &state.extensions,
            ))
            .unwrap()
        );
        expected
    }
    fn funded() -> LedgerState {
        let mut state = LedgerState::default();
        state
            .utxos
            .insert_coin(
                CoinShare::from_bytes([1; 32]),
                CoinUtxo {
                    amount: Zeno::from_zeno(100),
                    owner: Owner::Program(ProgramId([1; 32])),
                },
            )
            .unwrap();
        state.coin.total_mined = Zeno::from_zeno(100);
        state
    }
    #[test]
    fn root_cache_tracks_coin_mutations_counters_and_fork_interleaving() {
        let mut state = funded();
        let original_root = assert_root(&state);
        let original_bytes = canonical_bytes(&state).unwrap();
        let original = state.clone();
        assert_eq!(state.cached_state_root(), Some(original_root));
        state
            .utxos
            .consume_coin(&CoinShare::from_bytes([1; 32]))
            .unwrap();
        assert_eq!(state.cached_state_root(), None);
        state
            .utxos
            .insert_coin(
                CoinShare::from_bytes([2; 32]),
                CoinUtxo {
                    amount: Zeno::from_zeno(100),
                    owner: Owner::Program(ProgramId([2; 32])),
                },
            )
            .unwrap();
        let changed = assert_root(&state);
        assert_ne!(changed, original_root);
        assert_eq!(original.cached_state_root(), None);
        assert_eq!(assert_root(&original), original_root);
        assert_eq!(state.cached_state_root(), None);
        assert_eq!(assert_root(&state), changed);
        for change_mined in [true, false] {
            if change_mined {
                state.coin.total_mined = Zeno::from_zeno(101);
            } else {
                state.coin.total_burned = Zeno::ONE;
            }
            assert_eq!(state.cached_state_root(), None);
            assert_ne!(assert_root(&state), changed);
        }
        assert_eq!(canonical_bytes(&original).unwrap(), original_bytes);
        let restored = LedgerState::try_from_slice(&canonical_bytes(&state).unwrap()).unwrap();
        assert_eq!(restored.cached_state_root(), None);
        assert_eq!(restored, state);
        assert_eq!(assert_root(&restored), assert_root(&state));
        // Public component replacement cannot carry a stale root through the cache.
        state.utxos = original.utxos.clone();
        state.coin = original.coin;
        assert_eq!(state.cached_state_root(), None);
        assert_eq!(assert_root(&state), original_root);
    }
    #[test]
    fn root_cache_tracks_asset_register_mint_transfer_burn_and_rollback() {
        let mut state = funded();
        let before = assert_root(&state);
        let owner = Owner::Program(ProgramId([3; 32]));
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
                        name: "RootCache".into(),
                        max_supply: Unit::from_units(100),
                        initial_mint: Unit::from_units(10),
                        mint_authority: owner,
                        nonce: 1,
                    }),
                    context(1),
                )
                .unwrap(),
        );
        assert_eq!(state.cached_state_root(), None);
        assert_ne!(assert_root(&state), before);
        let asset = *state.extensions.assets.records().keys().next().unwrap();
        journals.push(
            state
                .extensions
                .assets
                .apply(
                    &AssetCall::Mint(Mint {
                        asset,
                        amount: Unit::from_units(5),
                        recipient: owner,
                        nonce: 1,
                    }),
                    context(2),
                )
                .unwrap(),
        );
        assert_eq!(state.cached_state_root(), None);
        assert_root(&state);
        let inputs = state
            .extensions
            .assets
            .shares_by_owner_asset(owner, asset)
            .map(|(id, _)| id)
            .collect();
        journals.push(
            state
                .extensions
                .assets
                .apply(
                    &AssetCall::Transfer(Transfer {
                        asset,
                        inputs,
                        outputs: vec![AssetOutput::new(owner, Unit::from_units(15))],
                    }),
                    context(3),
                )
                .unwrap(),
        );
        assert_eq!(state.cached_state_root(), None);
        assert_root(&state);
        let input = state
            .extensions
            .assets
            .shares_by_owner_asset(owner, asset)
            .next()
            .unwrap()
            .0;
        journals.push(
            state
                .extensions
                .assets
                .apply(
                    &AssetCall::Burn(Burn {
                        asset,
                        inputs: vec![input],
                        amount: Unit::from_units(5),
                        output: Unit::from_units(10),
                    }),
                    context(4),
                )
                .unwrap(),
        );
        assert_eq!(state.cached_state_root(), None);
        assert_root(&state);
        for journal in journals.into_iter().rev() {
            state.extensions.assets.rollback(journal);
            assert_eq!(state.cached_state_root(), None);
            assert_root(&state);
        }
        assert_eq!(assert_root(&state), before);
    }
    #[test]
    fn root_cache_tracks_deployment_scalar_storage_noops_removal_and_restore() {
        let mut state = funded();
        let before = assert_root(&state);
        let mut code = b"XPVM".to_vec();
        code.extend([4, 16, 0, 1, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend(0u128.to_le_bytes());
        code.push(3);
        let (id, journal) = deploy_program(
            &mut state.programs,
            DeployProgram {
                owner: ProgramId([4; 32]),
                nonce: 1,
                code: code.into(),
            },
            Height(1),
        )
        .unwrap();
        assert_eq!(state.cached_state_root(), None);
        let deployed = assert_root(&state);
        assert_ne!(deployed, before);
        let retained = state.clone();
        assert_eq!(state.programs.set_state(id, 0), Some(0));
        state
            .programs
            .set_storage(id, b"missing".to_vec(), None)
            .unwrap();
        assert_eq!(state.cached_state_root(), Some(deployed));
        state.programs.set_state(id, 7).unwrap();
        assert_eq!(state.cached_state_root(), None);
        let scalar = assert_root(&state);
        assert_ne!(scalar, deployed);
        assert_eq!(assert_root(&retained), deployed);
        state
            .programs
            .set_storage(id, b"key".to_vec(), Some(b"value".to_vec()))
            .unwrap();
        assert_eq!(state.cached_state_root(), None);
        let stored = assert_root(&state);
        assert_ne!(stored, scalar);
        state
            .programs
            .set_storage(id, b"key".to_vec(), Some(b"value".to_vec()))
            .unwrap();
        assert_eq!(state.cached_state_root(), Some(stored));
        state
            .programs
            .set_storage(id, b"key".to_vec(), None)
            .unwrap();
        assert_eq!(state.cached_state_root(), None);
        assert_eq!(assert_root(&state), scalar);
        let restored = LedgerState::try_from_slice(&canonical_bytes(&state).unwrap()).unwrap();
        assert_eq!(restored.cached_state_root(), None);
        assert_eq!(assert_root(&restored), scalar);
        rollback_program(&mut state.programs, journal).unwrap();
        assert_eq!(state.cached_state_root(), None);
        assert_eq!(assert_root(&state), before);
        state = Default::default();
        assert_eq!(assert_root(&state), StateRoot::ZERO);
    }
    #[test]
    fn concurrent_forks_never_reuse_another_states_cached_root() {
        let first = funded();
        assert_root(&first);
        let mut second = first.clone();
        second.coin.total_mined = Zeno::from_zeno(101);
        let third = second.clone();
        std::thread::scope(|scope| {
            for state in [&first, &second, &third] {
                scope.spawn(move || {
                    for _ in 0..64 {
                        assert_eq!(state.application_state_root().unwrap(), reference(state));
                    }
                });
            }
        });
    }
    #[test]
    #[ignore = "manual cold-root benchmark; use release mode and --nocapture"]
    fn benchmark_streaming_cold_state_root() {
        use std::{hint::black_box, time::Instant};
        let mut state = LedgerState::default();
        let entries = 100_000u64;
        for key in 0..entries {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&key.to_le_bytes());
            state
                .utxos
                .insert_coin(
                    CoinShare::from_bytes(id),
                    CoinUtxo {
                        amount: Zeno::ONE,
                        owner: Owner::Program(ProgramId([5; 32])),
                    },
                )
                .unwrap();
        }
        state.coin.total_mined = Zeno::from_zeno(entries);
        let expected = reference(&state);
        assert_eq!(state.hash_canonical_state().unwrap(), expected);
        let bytes = canonical_bytes(&state).unwrap().len();
        let rounds = 32;
        // Alternate order to reduce systematic ordering bias; neither path uses the cache.
        let mut old = std::time::Duration::ZERO;
        let mut streaming = std::time::Duration::ZERO;
        for round in 0..rounds {
            for is_stream in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let start = Instant::now();
                let root = if is_stream {
                    black_box(&state).hash_canonical_state().unwrap()
                } else {
                    reference(black_box(&state))
                };
                let elapsed = start.elapsed();
                assert_eq!(black_box(root), expected);
                if is_stream {
                    streaming += elapsed;
                } else {
                    old += elapsed;
                }
            }
        }
        println!(
            "utxos={entries} cold_roots={rounds} payload_bytes={bytes} full_vec_ms={:.3} streaming_ms={:.3} hash_buffer_bytes=65536",
            old.as_secs_f64() * 1000.0,
            streaming.as_secs_f64() * 1000.0
        );
    }

    #[test]
    #[ignore = "manual repeated-root microbenchmark; use release mode and --nocapture"]
    fn benchmark_repeated_state_root_cache() {
        use std::{hint::black_box, time::Instant};
        let mut state = LedgerState::default();
        let entries = 100_000u64;
        for key in 0..entries {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&key.to_le_bytes());
            state
                .utxos
                .insert_coin(
                    CoinShare::from_bytes(id),
                    CoinUtxo {
                        amount: Zeno::ONE,
                        owner: Owner::Program(ProgramId([5; 32])),
                    },
                )
                .unwrap();
        }
        state.coin.total_mined = Zeno::from_zeno(entries);
        let expected = reference(&state);
        assert_eq!(state.application_state_root().unwrap(), expected);
        let rounds = 32;
        let start = Instant::now();
        for _ in 0..rounds {
            assert_eq!(black_box(reference(black_box(&state))), expected);
        }
        let uncached = start.elapsed();
        let start = Instant::now();
        for _ in 0..rounds {
            assert_eq!(
                black_box(black_box(&state).application_state_root().unwrap()),
                expected
            );
        }
        let cached = start.elapsed();
        state.coin.total_burned = Zeno::ONE;
        assert_eq!(state.cached_state_root(), None);
        assert_ne!(assert_root(&state), expected);
        println!(
            "utxos={entries} repeated_roots={rounds} full_serialization_hash_ms={:.3} cached_root_ms={:.3}",
            uncached.as_secs_f64() * 1000.0,
            cached.as_secs_f64() * 1000.0
        );
    }
}
