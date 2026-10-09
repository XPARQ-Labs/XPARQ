use crypto::{HASH_SIZE, ProgramId};
use kernel::ledger::utxo::AssetState;
use kernel::{
    ledger::{CoinUtxo, LedgerError},
    monetary::coin::{CoinShare, Zeno},
};

#[test]
fn coin_utxos_must_equal_recorded_live_supply() {
    let mut state = StateFixture::default();
    let id = CoinShare::from_bytes([1; HASH_SIZE]);
    state.coin.total_mined = Zeno::from_zeno(100);
    state.coin.total_burned = Zeno::from_zeno(10);
    // Deliberately forged serialized fixtures exercise the invariant without
    // granting integration-test callers coin mutation capabilities.
    let mut coins = std::collections::BTreeMap::from([(
        id,
        CoinUtxo {
            amount: Zeno::from_zeno(90),
            owner: kernel::common::Owner::Program(ProgramId([2; crypto::PROGRAM_ID_SIZE])),
        },
    )]);
    state.utxos =
        borsh::from_slice(&borsh::to_vec(&(coins.clone(), Zeno::from_zeno(90))).unwrap()).unwrap();
    assert!(state.validate_supply_invariants().is_ok());
    coins.get_mut(&id).unwrap().amount = Zeno::from_zeno(91);
    state.utxos =
        borsh::from_slice(&borsh::to_vec(&(coins, Zeno::from_zeno(91))).unwrap()).unwrap();
    assert!(matches!(
        state.validate_supply_invariants(),
        Err(LedgerError::CoinSupplyMismatch)
    ));
}
// Corrupt serialized fixtures deliberately: production mutation stays private.
fn asset_fixture() -> StateFixture {
    use kernel::monetary::asset::{AssetContract, AssetRecord, AssetShare, Metadata, Share, Unit};
    let owner = ProgramId([3; crypto::PROGRAM_ID_SIZE]);
    let metadata = Metadata::new(
        "Guard Test".into(),
        Unit::from_units(100),
        kernel::common::Owner::Program(owner),
        kernel::common::Owner::Program(owner),
    )
    .unwrap();
    let asset = AssetContract::derive(&metadata, 1).unwrap();
    let records = std::collections::BTreeMap::from([(
        asset,
        AssetRecord {
            metadata,
            supply: Unit::from_units(10),
            total_minted: Unit::from_units(10),
            total_burned: Unit::ZERO,
            mint_nonce: 0,
        },
    )]);
    let shares = std::collections::BTreeMap::from([(
        Share::from_bytes([4; HASH_SIZE]),
        AssetShare::new(
            asset,
            Unit::from_units(10),
            kernel::common::Owner::Program(owner),
        ),
    )]);
    let assets: AssetState =
        borsh::from_slice(&borsh::to_vec(&(records, shares)).unwrap()).unwrap();
    let mut state = StateFixture::default();
    state.extensions.assets = assets;
    state
}

#[test]
fn program_shares_must_equal_recorded_supply_and_reference_known_assets() {
    use kernel::monetary::asset::{AssetContract, Unit};
    let mut state = asset_fixture();
    assert!(state.utxos.is_empty());
    assert!(state.validate_supply_invariants().is_ok());
    let records = state
        .extensions
        .assets
        .records()
        .iter()
        .map(|(&id, record)| (id, record.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut shares = state
        .extensions
        .assets
        .shares()
        .iter()
        .map(|(&id, &share)| (id, share))
        .collect::<std::collections::BTreeMap<_, _>>();
    let id = *shares.keys().next().unwrap();
    shares.get_mut(&id).unwrap().amount = Unit::from_units(11);
    state.extensions.assets =
        borsh::from_slice(&borsh::to_vec(&(&records, &shares)).unwrap()).unwrap();
    assert!(matches!(
        state.validate_supply_invariants(),
        Err(LedgerError::AssetSupplyMismatch)
    ));
    let share = shares.get_mut(&id).unwrap();
    share.amount = Unit::from_units(10);
    share.asset = AssetContract::from_bytes([8; 32]);
    state.extensions.assets =
        borsh::from_slice(&borsh::to_vec(&(records, shares)).unwrap()).unwrap();
    assert!(matches!(
        state.validate_supply_invariants(),
        Err(LedgerError::UnknownAssetShare)
    ));
}

#[test]
fn balanced_zero_asset_share_and_invalid_metadata_are_rejected() {
    use kernel::monetary::asset::{Share, Unit};
    let state = asset_fixture();
    let mut records = state
        .extensions
        .assets
        .records()
        .iter()
        .map(|(&id, record)| (id, record.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut shares = state
        .extensions
        .assets
        .shares()
        .iter()
        .map(|(&id, &share)| (id, share))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut zero_share = *shares.values().next().unwrap();
    zero_share.amount = Unit::ZERO;
    shares.insert(Share::from_bytes([5; HASH_SIZE]), zero_share);
    let mut forged = state.clone();
    forged.extensions.assets =
        borsh::from_slice(&borsh::to_vec(&(&records, &shares)).unwrap()).unwrap();
    assert!(matches!(
        forged.validate_supply_invariants(),
        Err(LedgerError::InvalidAssetState)
    ));
    shares.remove(&Share::from_bytes([5; HASH_SIZE]));
    records.values_mut().next().unwrap().metadata.name = " bad name ".into();
    forged.extensions.assets =
        borsh::from_slice(&borsh::to_vec(&(records, shares)).unwrap()).unwrap();
    assert!(matches!(
        forged.validate_supply_invariants(),
        Err(LedgerError::InvalidAssetState)
    ));
}

#[test]
fn deep_coin_audit_rejects_forged_cache_and_balanced_zero_utxo() {
    let owner = ProgramId([2; crypto::PROGRAM_ID_SIZE]);
    let id = CoinShare::from_bytes([1; HASH_SIZE]);
    let mut coins = std::collections::BTreeMap::from([(
        id,
        CoinUtxo {
            owner: kernel::common::Owner::Program(owner),
            amount: Zeno::from_zeno(90),
        },
    )]);
    let mut state = StateFixture::default();
    state.coin.total_mined = Zeno::from_zeno(100);
    state.utxos =
        borsh::from_slice(&borsh::to_vec(&(&coins, Zeno::from_zeno(100))).unwrap()).unwrap();
    // The fast check trusts the private cache; recovery must independently sum it.
    assert!(state.validate_supply_invariants().is_ok());
    assert!(matches!(
        state.audit_coin_supply(),
        Err(LedgerError::CoinSupplyMismatch)
    ));
    state.coin.total_mined = Zeno::from_zeno(90);
    coins.insert(
        CoinShare::from_bytes([2; HASH_SIZE]),
        CoinUtxo {
            owner: kernel::common::Owner::Program(owner),
            amount: Zeno::ZERO,
        },
    );
    state.utxos =
        borsh::from_slice(&borsh::to_vec(&(coins, Zeno::from_zeno(90))).unwrap()).unwrap();
    assert!(matches!(
        state.audit_coin_supply(),
        Err(LedgerError::InvalidCoinState)
    ));
}

#[test]
fn aggregate_overflow_and_impossible_accounting_are_rejected() {
    let mut state = asset_fixture();
    let mut records = state
        .extensions
        .assets
        .records()
        .iter()
        .map(|(&id, record)| (id, record.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let shares = state
        .extensions
        .assets
        .shares()
        .iter()
        .map(|(&id, &share)| (id, share))
        .collect::<std::collections::BTreeMap<_, _>>();
    let record = records.values_mut().next().unwrap();
    record.total_burned = kernel::monetary::asset::Unit::from_units(11);
    state.extensions.assets =
        borsh::from_slice(&borsh::to_vec(&(records, shares)).unwrap()).unwrap();
    assert!(matches!(
        state.validate_supply_invariants(),
        Err(LedgerError::AssetSupplyMismatch)
    ));

    let mut state = asset_fixture();
    let mut records = state
        .extensions
        .assets
        .records()
        .iter()
        .map(|(&id, record)| (id, record.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut shares = state
        .extensions
        .assets
        .shares()
        .iter()
        .map(|(&id, &share)| (id, share))
        .collect::<std::collections::BTreeMap<_, _>>();
    let asset = *records.keys().next().unwrap();
    let record = records.get_mut(&asset).unwrap();
    record.metadata.max_supply = kernel::monetary::asset::Unit::from_units(u128::MAX);
    record.total_minted = kernel::monetary::asset::Unit::from_units(u128::MAX);
    record.supply = kernel::monetary::asset::Unit::from_units(u128::MAX);
    shares.values_mut().next().unwrap().amount =
        kernel::monetary::asset::Unit::from_units(u128::MAX);
    shares.insert(
        kernel::monetary::asset::Share::from_bytes([5; HASH_SIZE]),
        kernel::monetary::asset::AssetShare::new(
            asset,
            kernel::monetary::asset::Unit::from_units(1),
            kernel::common::Owner::Program(ProgramId([3; crypto::PROGRAM_ID_SIZE])),
        ),
    );
    state.extensions.assets =
        borsh::from_slice(&borsh::to_vec(&(records, shares)).unwrap()).unwrap();
    assert!(matches!(
        state.validate_supply_invariants(),
        Err(LedgerError::SupplyOverflow)
    ));

    let owner = ProgramId([1; crypto::PROGRAM_ID_SIZE]);
    let coins = std::collections::BTreeMap::from([
        (
            CoinShare::from_bytes([1; HASH_SIZE]),
            CoinUtxo {
                owner: kernel::common::Owner::Program(owner),
                amount: Zeno::from_zeno(u64::MAX),
            },
        ),
        (
            CoinShare::from_bytes([2; HASH_SIZE]),
            CoinUtxo {
                owner: kernel::common::Owner::Program(owner),
                amount: Zeno::ONE,
            },
        ),
    ]);
    state = StateFixture::default();
    state.utxos =
        borsh::from_slice(&borsh::to_vec(&(coins, Zeno::from_zeno(u64::MAX))).unwrap()).unwrap();
    assert!(matches!(
        state.audit_coin_supply(),
        Err(LedgerError::SupplyOverflow)
    ));
}

// Deliberately untrusted serialized data for invariant tests, never a live ledger.
#[derive(Clone, Default, borsh::BorshSerialize)]
struct StateFixture {
    utxos: kernel::ledger::utxo::UtxoSet,
    coin: kernel::ledger::CoinRecord,
    programs: kernel::program::ProgramRegistry,
    extensions: kernel::program::system::script::state::ExtensionState,
}

impl StateFixture {
    fn decode(&self) -> kernel::ledger::LedgerState {
        borsh::from_slice(&borsh::to_vec(self).unwrap()).unwrap()
    }
    fn validate_supply_invariants(&self) -> Result<(), LedgerError> {
        self.decode().validate_supply_invariants()
    }
    fn audit_coin_supply(&self) -> Result<(), LedgerError> {
        self.decode().audit_coin_supply()
    }
}
