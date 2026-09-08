use std::{collections::BTreeMap, error::Error as StdError, fmt};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::native::asset::{AssetShare, Share};
use crate::native::coin::{XPQ, Zeno};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub enum UtxoId {
    Coin(XPQ),
    Asset(Share),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Utxo {
    Coin(Zeno),
    Asset(AssetShare),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UtxoSet {
    entries: BTreeMap<UtxoId, Utxo>,
}

impl UtxoSet {
    pub fn coin(&self, id: &XPQ) -> Option<Zeno> {
        match self.entries.get(&UtxoId::Coin(*id)) {
            Some(Utxo::Coin(amount)) => Some(*amount),
            _ => None,
        }
    }

    pub fn insert_coin(&mut self, id: XPQ, amount: Zeno) -> Result<(), Error> {
        let key = UtxoId::Coin(id);

        if self.entries.contains_key(&key) {
            return Err(Error::CoinCollision);
        }

        self.entries.insert(key, Utxo::Coin(amount));
        Ok(())
    }

    pub fn consume_coin(&mut self, id: &XPQ) -> Result<Zeno, Error> {
        match self.entries.remove(&UtxoId::Coin(*id)) {
            Some(Utxo::Coin(amount)) => Ok(amount),
            _ => Err(Error::NotFound),
        }
    }

    pub fn coins(&self) -> impl Iterator<Item = (XPQ, Zeno)> + '_ {
        self.entries
            .iter()
            .filter_map(|(id, utxo)| match (id, utxo) {
                (UtxoId::Coin(id), Utxo::Coin(amount)) => Some((*id, *amount)),
                _ => None,
            })
    }

    pub fn asset(&self, id: &Share) -> Option<&AssetShare> {
        match self.entries.get(&UtxoId::Asset(*id)) {
            Some(Utxo::Asset(share)) => Some(share),
            _ => None,
        }
    }

    pub fn insert_asset(&mut self, id: Share, share: AssetShare) -> Result<(), Error> {
        let key = UtxoId::Asset(id);

        if self.entries.contains_key(&key) {
            return Err(Error::ShareCollision);
        }

        self.entries.insert(key, Utxo::Asset(share));
        Ok(())
    }

    pub fn consume_asset(&mut self, id: &Share) -> Result<AssetShare, Error> {
        match self.entries.remove(&UtxoId::Asset(*id)) {
            Some(Utxo::Asset(share)) => Ok(share),
            _ => Err(Error::NotFound),
        }
    }

    pub fn assets(&self) -> impl Iterator<Item = (Share, &AssetShare)> + '_ {
        self.entries
            .iter()
            .filter_map(|(id, utxo)| match (id, utxo) {
                (UtxoId::Asset(id), Utxo::Asset(share)) => Some((*id, share)),
                _ => None,
            })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotFound,
    CoinCollision,
    ShareCollision,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("UTXO was not found"),
            Self::CoinCollision => f.write_str("coin UTXO ID already exists"),
            Self::ShareCollision => f.write_str("asset share UTXO ID already exists"),
        }
    }
}

impl StdError for Error {}
