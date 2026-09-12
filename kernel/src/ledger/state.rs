//! Canonical ledger state and rollback journal types.

use super::{account, utxo};

use crate::native::{
    asset::{AssetShare, Contract, Metadata, MintCapability, MintCapabilityId, Share, Unit},
    coin::{XPQ, Zeno},
};

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::Address;
use std::collections::BTreeMap;

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pub account_keys: account::Registry,
    pub utxos: utxo::UtxoSet,
    pub assets: AssetState,
    pub total_burned: Zeno,
    pub(crate) coin_recipients: BTreeMap<XPQ, Address>,
}

impl LedgerState {
    pub const fn utxos(&self) -> &utxo::UtxoSet {
        &self.utxos
    }

    pub fn coin_recipient(&self, id: XPQ) -> Option<Address> {
        self.coin_recipients.get(&id).copied()
    }

    pub fn share_recipient(&self, id: Share) -> Option<Address> {
        self.assets.share_recipients.get(&id).copied()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetState {
    pub(crate) metadata: BTreeMap<Contract, Metadata>,
    pub(crate) supplies: BTreeMap<Contract, Unit>,
    pub(crate) share_recipients: BTreeMap<Share, Address>,
}

impl AssetState {
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty() && self.supplies.is_empty() && self.share_recipients.is_empty()
    }
    pub fn metadata(&self, id: Contract) -> Option<&Metadata> {
        self.metadata.get(&id)
    }
    pub fn metadata_entries(&self) -> impl Iterator<Item = (Contract, &Metadata)> + '_ {
        self.metadata.iter().map(|(&id, metadata)| (id, metadata))
    }
    pub fn supply(&self, id: Contract) -> Unit {
        self.supplies.get(&id).copied().unwrap_or(Unit::ZERO)
    }
    pub fn utxo<'a>(&self, utxos: &'a utxo::UtxoSet, id: Share) -> Option<&'a AssetShare> {
        utxos.asset(&id)
    }
    pub fn utxos<'a>(
        &self,
        utxos: &'a utxo::UtxoSet,
    ) -> impl Iterator<Item = (Share, &'a AssetShare)> + 'a {
        utxos.assets()
    }

    pub fn mint_capability(
        &self,
        utxos: &utxo::UtxoSet,
        asset: Contract,
    ) -> Option<(MintCapabilityId, MintCapability)> {
        utxos
            .mint_capabilities()
            .find(|(_, capability)| capability.asset == asset)
            .map(|(id, capability)| (id, *capability))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SpendRollbackJournal {
    pub(crate) consumed_coins: Vec<(XPQ, Zeno)>,
    pub(crate) consumed_coin_recipients: Vec<(XPQ, Address)>,
    pub(crate) created_coin_ids: Vec<XPQ>,
    pub(crate) registered_accounts: Vec<Address>,
    pub(crate) burned: Zeno,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetRollbackJournal {
    pub(crate) metadata: Vec<(Contract, Option<Metadata>)>,
    pub(crate) supplies: Vec<(Contract, Option<Unit>)>,
    pub(crate) utxos: Vec<(Share, Option<AssetShare>)>,
    pub(crate) recipients: Vec<(Share, Option<Address>)>,
    pub(crate) capabilities: Vec<(MintCapabilityId, Option<MintCapability>)>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum StateRollbackJournal {
    Spend(SpendRollbackJournal),
    AssetWithPayment {
        asset: AssetRollbackJournal,
        payment: SpendRollbackJournal,
    },
    AssetSpendWithPayment {
        asset: AssetRollbackJournal,
        payment: SpendRollbackJournal,
    },
}

impl StateRollbackJournal {
    pub const fn protocol_burn(&self) -> Zeno {
        match self {
            Self::Spend(journal) => journal.burned,
            Self::AssetWithPayment { payment, .. }
            | Self::AssetSpendWithPayment { payment, .. } => payment.burned,
        }
    }
}
