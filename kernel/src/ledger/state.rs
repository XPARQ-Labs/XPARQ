//! Canonical ledger state and rollback journal types.

use super::utxo::{self, CoinUtxo};

use crate::native::{
    asset::{AssetShare, Contract, Metadata, Share, Unit},
    coin::{XPQ, Zeno},
};

use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pub utxos: utxo::UtxoSet,
    pub coin: CoinRecord,
    pub assets: AssetState,
}

impl LedgerState {
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

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetRecord {
    pub metadata: Metadata,
    pub supply: Unit,
    pub total_minted: Unit,
    pub mint_nonce: u64,
    pub total_burned: Unit,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetState {
    pub(crate) assets: BTreeMap<Contract, AssetRecord>,
}

impl AssetState {
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    pub fn record(&self, id: Contract) -> Option<&AssetRecord> {
        self.assets.get(&id)
    }

    pub fn metadata(&self, id: Contract) -> Option<&Metadata> {
        self.record(id).map(|record| &record.metadata)
    }

    pub fn metadata_entries(&self) -> impl Iterator<Item = (Contract, &Metadata)> + '_ {
        self.assets
            .iter()
            .map(|(&id, record)| (id, &record.metadata))
    }

    pub fn supply(&self, id: Contract) -> Unit {
        self.record(id).map_or(Unit::ZERO, |record| record.supply)
    }

    pub fn total_minted(&self, id: Contract) -> Option<Unit> {
        self.record(id).map(|record| record.total_minted)
    }

    pub fn mint_nonce(&self, id: Contract) -> Option<u64> {
        self.record(id).map(|record| record.mint_nonce)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SpendRollbackJournal {
    pub(crate) consumed_coins: Vec<(XPQ, CoinUtxo)>,
    pub(crate) created_coin_ids: Vec<XPQ>,
    pub(crate) mined: Zeno,
    pub(crate) burned: Zeno,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetRollbackJournal {
    pub(crate) assets: Vec<(Contract, Option<AssetRecord>)>,
    pub(crate) utxos: Vec<(Share, Option<AssetShare>)>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct StateRollbackJournal {
    pub spend: Option<SpendRollbackJournal>,
    pub asset: Option<AssetRollbackJournal>,
}

impl StateRollbackJournal {
    pub const fn protocol_burn(&self) -> Zeno {
        match &self.spend {
            Some(journal) => journal.burned,
            None => Zeno::ZERO,
        }
    }
}
