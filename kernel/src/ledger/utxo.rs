use std::{collections::BTreeMap, error::Error as StdError, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::Address;

use crate::native::{
    asset::{AssetShare, Share},
    coin::{XPQ, Zeno},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinUtxo {
    pub amount: Zeno,
    pub owner: Address,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UtxoSet {
    coins: BTreeMap<XPQ, CoinUtxo>,
    shares: BTreeMap<Share, AssetShare>,
}

impl UtxoSet {
    pub fn coin(&self, id: &XPQ) -> Option<&CoinUtxo> {
        self.coins.get(id)
    }

    pub fn insert_coin(&mut self, id: XPQ, coin: CoinUtxo) -> Result<(), Error> {
        if self.coins.contains_key(&id) {
            return Err(Error::CoinCollision);
        }
        self.coins.insert(id, coin);
        Ok(())
    }

    pub fn consume_coin(&mut self, id: &XPQ) -> Result<CoinUtxo, Error> {
        self.coins.remove(id).ok_or(Error::NotFound)
    }

    pub fn coins(&self) -> impl Iterator<Item = (XPQ, &CoinUtxo)> + '_ {
        self.coins.iter().map(|(&id, coin)| (id, coin))
    }

    pub fn asset(&self, id: &Share) -> Option<&AssetShare> {
        self.shares.get(id)
    }

    pub fn insert_asset(&mut self, id: Share, share: AssetShare) -> Result<(), Error> {
        if self.shares.contains_key(&id) {
            return Err(Error::ShareCollision);
        }
        self.shares.insert(id, share);
        Ok(())
    }

    pub fn consume_asset(&mut self, id: &Share) -> Result<AssetShare, Error> {
        self.shares.remove(id).ok_or(Error::NotFound)
    }

    pub fn assets(&self) -> impl Iterator<Item = (Share, &AssetShare)> + '_ {
        self.shares.iter().map(|(&id, share)| (id, share))
    }

    pub fn len(&self) -> usize {
        self.coins.len().saturating_add(self.shares.len())
    }

    pub fn is_empty(&self) -> bool {
        self.coins.is_empty() && self.shares.is_empty()
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
