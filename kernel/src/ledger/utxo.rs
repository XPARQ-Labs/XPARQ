use std::{collections::BTreeMap, error::Error as StdError, fmt};

use crate::{common::Owner, state_map::StateMap};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::monetary::coin::{CoinShare, Zeno};

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinUtxo {
    pub amount: Zeno,
    pub owner: Owner,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize)]
pub struct UtxoSet {
    // Staged states share branches; writes detach only the affected paths.
    coins: StateMap<CoinShare, CoinUtxo>,
    total_value: Zeno,
    #[borsh(skip)]
    by_owner: StateMap<Owner, StateMap<CoinShare, ()>>,
}

impl BorshDeserialize for UtxoSet {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let coins = BTreeMap::<CoinShare, CoinUtxo>::deserialize_reader(reader)?;
        let total_value = Zeno::deserialize_reader(reader)?;
        let mut by_owner: StateMap<Owner, StateMap<CoinShare, ()>> = StateMap::default();
        for (&id, coin) in &coins {
            by_owner.entry(coin.owner).or_default().insert(id, ());
        }
        Ok(Self {
            coins: coins.into(),
            total_value,
            by_owner,
        })
    }
}

impl UtxoSet {
    pub(crate) fn canonical_encoded_len(&self) -> Result<u64, crypto::CodecError> {
        let Self {
            coins,
            total_value,
            by_owner: _,
        } = self;
        // All owners have the sole Program variant, so every entry has equal width.
        let width = crypto::canonical_length(&(
            CoinShare::from_bytes([0; crypto::HASH_SIZE]),
            CoinUtxo {
                amount: Zeno::ZERO,
                owner: Owner::Program(crypto::ProgramId::ZERO),
            },
        ))?;
        crypto::canonical_fixed_map_length(coins.len(), width)?
            .checked_add(crypto::canonical_length(total_value)?)
            .ok_or(crypto::CodecError::EncodeFailed)
    }

    pub(crate) fn same_canonical_view(&self, other: &Self) -> bool {
        let Self {
            coins,
            total_value,
            by_owner: _,
        } = self;
        coins.shares_root(&other.coins) && *total_value == other.total_value
    }
    pub fn coin(&self, id: &CoinShare) -> Option<&CoinUtxo> {
        self.coins.get(id)
    }

    pub fn total_value(&self) -> Zeno {
        self.total_value
    }

    pub(crate) fn insert_coin(&mut self, id: CoinShare, coin: CoinUtxo) -> Result<(), Error> {
        if coin.amount.is_zero() {
            return Err(Error::ZeroAmount);
        }
        if self.coins.contains_key(&id) {
            return Err(Error::CoinCollision);
        }

        let total_value = self
            .total_value
            .checked_add(coin.amount)
            .ok_or(Error::ValueOverflow)?;

        self.coins.insert(id, coin);
        self.by_owner.entry(coin.owner).or_default().insert(id, ());
        self.total_value = total_value;

        Ok(())
    }

    pub(crate) fn consume_coin(&mut self, id: &CoinShare) -> Result<CoinUtxo, Error> {
        let coin = self.coins.get(id).copied().ok_or(Error::NotFound)?;

        let total_value = self
            .total_value
            .checked_sub(coin.amount)
            .ok_or(Error::ValueUnderflow)?;

        self.coins.remove(id);
        let by_owner = &mut self.by_owner;
        if let Some(ids) = by_owner.get_mut(&coin.owner) {
            ids.remove(id);
            if ids.is_empty() {
                by_owner.remove(&coin.owner);
            }
        }
        self.total_value = total_value;

        Ok(coin)
    }

    pub fn coins(&self) -> impl Iterator<Item = (CoinShare, &CoinUtxo)> + '_ {
        self.coins.iter().map(|(&id, coin)| (id, coin))
    }

    /// Sorted candidate IDs; values and ownership are read from the canonical map.
    pub fn coins_by_owner(
        &self,
        owner: Owner,
    ) -> impl Iterator<Item = (CoinShare, &CoinUtxo)> + '_ {
        self.by_owner
            .get(&owner)
            .into_iter()
            .flat_map(|ids| ids.keys())
            .filter_map(move |id| {
                self.coins
                    .get(id)
                    .filter(|coin| coin.owner == owner)
                    .map(|coin| (*id, coin))
            })
    }

    pub fn len(&self) -> usize {
        self.coins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    ZeroAmount,
    NotFound,
    CoinCollision,
    ValueOverflow,
    ValueUnderflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroAmount => f.write_str("coin UTXO amount must be nonzero"),
            Self::NotFound => f.write_str("UTXO was not found"),
            Self::CoinCollision => f.write_str("coin UTXO ID already exists"),
            Self::ValueOverflow => f.write_str("coin UTXO total value overflowed"),
            Self::ValueUnderflow => f.write_str("coin UTXO total value underflowed"),
        }
    }
}

impl StdError for Error {}

#[cfg(test)]
mod invariant_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn coin(amount: u64) -> CoinUtxo {
        CoinUtxo {
            owner: Owner::Program(crypto::ProgramId([1; crypto::PROGRAM_ID_SIZE])),
            amount: Zeno::from_zeno(amount),
        }
    }

    fn id(value: u64) -> CoinShare {
        let mut bytes = [0; crypto::HASH_SIZE];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        CoinShare::from_bytes(bytes)
    }

    #[test]
    fn cloned_utxo_tables_share_reads_and_isolate_mutations_and_failures() {
        let mut original = UtxoSet::default();
        original.insert_coin(id(1), coin(10)).unwrap();
        let encoded = borsh::to_vec(&original).unwrap();
        let mut staged = original.clone();
        assert!(original.coins.shares_root(&staged.coins));
        assert!(original.by_owner.shares_root(&staged.by_owner));
        assert_eq!(
            staged.insert_coin(id(1), coin(5)),
            Err(Error::CoinCollision)
        );
        assert_eq!(staged.consume_coin(&id(2)), Err(Error::NotFound));
        assert!(original.coins.shares_root(&staged.coins));
        assert!(original.by_owner.shares_root(&staged.by_owner));
        staged.insert_coin(id(2), coin(7)).unwrap();
        assert!(!original.coins.shares_root(&staged.coins));
        assert!(!original.by_owner.shares_root(&staged.by_owner));
        assert_eq!(staged.consume_coin(&id(1)), Ok(coin(10)));
        assert_eq!(original.total_value(), Zeno::from_zeno(10));
        assert_eq!(staged.total_value(), Zeno::from_zeno(7));
        assert_eq!(borsh::to_vec(&original).unwrap(), encoded);
        assert_eq!(
            UtxoSet::try_from_slice(&borsh::to_vec(&staged).unwrap()).unwrap(),
            staged
        );
    }

    #[test]
    fn rejected_insertions_leave_the_map_and_cache_unchanged() {
        let mut set = UtxoSet::default();
        let empty = set.clone();
        assert_eq!(set.insert_coin(id(1), coin(0)), Err(Error::ZeroAmount));
        assert_eq!(set, empty);
        set.insert_coin(id(1), coin(u64::MAX)).unwrap();
        let before = set.clone();
        assert_eq!(set.insert_coin(id(1), coin(1)), Err(Error::CoinCollision));
        assert_eq!(set, before);
        assert_eq!(set.insert_coin(id(2), coin(1)), Err(Error::ValueOverflow));
        assert_eq!(set, before);
        assert_eq!(set.consume_coin(&id(2)), Err(Error::NotFound));
        assert_eq!(set, before);
    }

    #[test]
    fn generated_insert_consume_sequences_match_an_independent_model() {
        for seed in 1..=16u64 {
            let mut random = seed;
            let mut set = UtxoSet::default();
            let mut model = BTreeMap::new();
            for step in 0..256 {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                if random & 1 == 0 || model.is_empty() {
                    let key = id(step);
                    let mut value = coin(random % 10_000 + 1);
                    value.owner = Owner::Program(crypto::ProgramId([(random % 8 + 1) as u8; 32]));
                    set.insert_coin(key, value).unwrap();
                    model.insert(key, value);
                } else {
                    let offset = random as usize % model.len();
                    let key = *model.keys().nth(offset).unwrap();
                    assert_eq!(set.consume_coin(&key).unwrap(), model.remove(&key).unwrap());
                }
                let actual: BTreeMap<_, _> =
                    set.coins().map(|(key, value)| (key, *value)).collect();
                assert_eq!(actual, model);
                let mut expected_index: BTreeMap<Owner, BTreeSet<CoinShare>> = BTreeMap::new();
                for (&id, coin) in &model {
                    expected_index.entry(coin.owner).or_default().insert(id);
                }
                let actual_index: BTreeMap<_, BTreeSet<_>> = set
                    .by_owner
                    .iter()
                    .map(|(&owner, ids)| (owner, ids.keys().copied().collect()))
                    .collect();
                assert_eq!(actual_index, expected_index);
                for owner in (1..=9).map(|tag| Owner::Program(crypto::ProgramId([tag; 32]))) {
                    let indexed: BTreeMap<_, _> = set
                        .coins_by_owner(owner)
                        .map(|(id, coin)| (id, *coin))
                        .collect();
                    let scanned: BTreeMap<_, _> = model
                        .iter()
                        .filter(|(_, coin)| coin.owner == owner)
                        .map(|(&id, coin)| (id, *coin))
                        .collect();
                    assert_eq!(indexed, scanned);
                }
                let total: u64 = model.values().map(|value| value.amount.as_zeno()).sum();
                assert_eq!(set.total_value().as_zeno(), total);
                let encoded = borsh::to_vec(&set).unwrap();
                assert_eq!(encoded, borsh::to_vec(&(&model, set.total_value)).unwrap());
                assert_eq!(UtxoSet::try_from_slice(&encoded).unwrap(), set);
            }
        }
    }

    #[test]
    #[ignore = "manual owner lookup benchmark; use release mode and --nocapture"]
    fn benchmark_owner_lookup() {
        use std::{hint::black_box, time::Instant};
        let mut set = UtxoSet::default();
        for index in 0..100_000u64 {
            let mut owner = [0; 32];
            owner[..8].copy_from_slice(&(index % 1_000).to_le_bytes());
            set.insert_coin(
                id(index),
                CoinUtxo {
                    amount: Zeno::ONE,
                    owner: Owner::Program(crypto::ProgramId(owner)),
                },
            )
            .unwrap();
        }
        let owner = Owner::Program(crypto::ProgramId::ZERO);
        let rounds = 128;
        let start = Instant::now();
        let mut scanned = 0u64;
        for _ in 0..rounds {
            let owner = black_box(owner);
            scanned += black_box(
                set.coins()
                    .filter(|(_, coin)| coin.owner == owner)
                    .map(|(_, coin)| coin.amount.as_zeno())
                    .sum::<u64>(),
            );
        }
        let scan_time = start.elapsed();
        let start = Instant::now();
        let mut indexed = 0u64;
        for _ in 0..rounds {
            indexed += black_box(
                set.coins_by_owner(black_box(owner))
                    .map(|(_, coin)| coin.amount.as_zeno())
                    .sum::<u64>(),
            );
        }
        let index_time = start.elapsed();
        assert_eq!(indexed, scanned);
        assert_eq!(indexed, rounds * 100);
        println!(
            "utxos=100000 owned=100 queries={rounds} scan_ms={:.3} owner_index_ms={:.3}",
            scan_time.as_secs_f64() * 1000.0,
            index_time.as_secs_f64() * 1000.0
        );
    }
    #[test]
    #[ignore = "manual first-write benchmark; use release mode and --nocapture"]
    fn benchmark_utxo_first_write_paths() {
        use std::{hint::black_box, sync::Arc, time::Instant};
        for size in [20_000u64, 100_000] {
            let mut set = UtxoSet::default();
            for key in 0..size {
                set.insert_coin(id(key), coin(1)).unwrap();
            }
            // Previous implementation: whole-map COW plus whole owner index COW.
            let coins = Arc::new(
                set.coins()
                    .map(|(key, &value)| (key, value))
                    .collect::<BTreeMap<_, _>>(),
            );
            let owner = coin(1).owner;
            let index = Arc::new(BTreeMap::from([(
                owner,
                coins.keys().copied().collect::<BTreeSet<_>>(),
            )]));
            let rounds = 128;
            let input = id(size / 2);
            let output = id(size + 1);
            let start = Instant::now();
            let mut baseline = None;
            for _ in 0..rounds {
                let mut fork_coins = coins.clone();
                let mut fork_index = index.clone();
                let value = Arc::make_mut(&mut fork_coins).remove(&input).unwrap();
                Arc::make_mut(&mut fork_coins).insert(output, value);
                let ids = Arc::make_mut(&mut fork_index).get_mut(&owner).unwrap();
                ids.remove(&input);
                ids.insert(output);
                baseline = Some(black_box((fork_coins, fork_index)));
            }
            let whole_map_time = start.elapsed();
            let start = Instant::now();
            let mut result = None;
            for _ in 0..rounds {
                let mut fork = set.clone();
                let value = fork.consume_coin(&input).unwrap();
                fork.insert_coin(output, value).unwrap();
                result = Some(black_box(fork));
            }
            let path_time = start.elapsed();
            let result = result.unwrap();
            let (baseline_coins, baseline_index) = baseline.unwrap();
            assert_eq!(
                borsh::to_vec(&result).unwrap(),
                borsh::to_vec(&(baseline_coins, set.total_value)).unwrap()
            );
            assert_eq!(
                result
                    .coins_by_owner(owner)
                    .map(|(key, _)| key)
                    .collect::<BTreeSet<_>>(),
                baseline_index[&owner]
            );
            assert!(set.coin(&input).is_some());
            assert!(set.coin(&output).is_none());
            println!(
                "utxos={size} same_owner={size} clone_and_spend_rounds={rounds} whole_table_cow_ms={:.3} shared_paths_ms={:.3}",
                whole_map_time.as_secs_f64() * 1000.0,
                path_time.as_secs_f64() * 1000.0
            );
        }
    }
}
