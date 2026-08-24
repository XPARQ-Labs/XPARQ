use std::{collections::BTreeMap, error::Error, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_coin::{Coin, CoinId};
use xparq_common::Height;
use xparq_crypto::{Address, PublicKey, QCashPublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinUtxo {
    pub coin: Coin,
    pub owner: Address,
    pub spendable_height: Height,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct StoredCoinUtxo {
    amount: xparq_coin::Amount,
    owner: Address,
    spendable_height: Height,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinUtxoSet {
    utxos: BTreeMap<CoinId, StoredCoinUtxo>,
}

impl CoinUtxoSet {
    pub fn get(&self, id: &CoinId) -> Option<CoinUtxo> {
        self.utxos.get(id).map(|stored| CoinUtxo {
            coin: Coin::new(*id, stored.amount),
            owner: stored.owner,
            spendable_height: stored.spendable_height,
        })
    }

    pub fn insert(&mut self, utxo: CoinUtxo) -> Result<(), UtxoError> {
        if self.utxos.contains_key(&utxo.coin.id) {
            return Err(UtxoError::CoinIdCollision);
        }
        self.utxos.insert(
            utxo.coin.id,
            StoredCoinUtxo {
                amount: utxo.coin.amount,
                owner: utxo.owner,
                spendable_height: utxo.spendable_height,
            },
        );
        Ok(())
    }

    pub fn consume(&mut self, id: &CoinId) -> Result<CoinUtxo, UtxoError> {
        self.utxos
            .remove(id)
            .map(|stored| CoinUtxo {
                coin: Coin::new(*id, stored.amount),
                owner: stored.owner,
                spendable_height: stored.spendable_height,
            })
            .ok_or(UtxoError::UtxoNotFound)
    }

    pub fn restore(&mut self, utxo: CoinUtxo) -> Result<(), UtxoError> {
        self.insert(utxo)
    }

    pub fn iter(&self) -> impl Iterator<Item = CoinUtxo> + '_ {
        self.utxos.iter().map(|(id, stored)| CoinUtxo {
            coin: Coin::new(*id, stored.amount),
            owner: stored.owner,
            spendable_height: stored.spendable_height,
        })
    }

    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }
}

/// One available QCash output in canonical ledger state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct QCashUtxo {
    pub coin: Coin,
    pub public_key: QCashPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct StoredQCashUtxo {
    amount: xparq_coin::Amount,
    public_key: QCashPublicKey,
}

/// A UTXO set contains available outputs only. Absence means invalid input.
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct QCashUtxoSet {
    utxos: BTreeMap<CoinId, StoredQCashUtxo>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UtxoRollbackJournal {
    pub(crate) consumed_coins: Vec<CoinUtxo>,
    pub(crate) created_coin_ids: Vec<CoinId>,
    pub(crate) consumed_qcash: Vec<QCashUtxo>,
    pub(crate) created_qcash_ids: Vec<CoinId>,
    pub(crate) registered_public_keys: Vec<Address>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountKeyRegistry {
    keys: BTreeMap<Address, PublicKey>,
}

impl AccountKeyRegistry {
    pub fn get(&self, address: &Address) -> Option<&PublicKey> {
        self.keys.get(address)
    }

    pub fn register(&mut self, address: Address, public_key: PublicKey) -> Result<bool, UtxoError> {
        if let Some(existing) = self.keys.get(&address) {
            return if existing == &public_key {
                Ok(false)
            } else {
                Err(UtxoError::PublicKeyConflict)
            };
        }
        self.keys.insert(address, public_key);
        Ok(true)
    }

    pub fn remove(&mut self, address: &Address) -> Result<PublicKey, UtxoError> {
        self.keys
            .remove(address)
            .ok_or(UtxoError::PublicKeyNotFound)
    }
}

impl QCashUtxoSet {
    pub fn get(&self, id: &CoinId) -> Option<QCashUtxo> {
        self.utxos.get(id).map(|stored| QCashUtxo {
            coin: Coin::new(*id, stored.amount),
            public_key: stored.public_key,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = QCashUtxo> + '_ {
        self.utxos.iter().map(|(id, stored)| QCashUtxo {
            coin: Coin::new(*id, stored.amount),
            public_key: stored.public_key,
        })
    }

    pub fn insert(&mut self, utxo: QCashUtxo) -> Result<(), UtxoError> {
        if self.utxos.contains_key(&utxo.coin.id) {
            return Err(UtxoError::CoinIdCollision);
        }
        self.utxos.insert(
            utxo.coin.id,
            StoredQCashUtxo {
                amount: utxo.coin.amount,
                public_key: utxo.public_key,
            },
        );
        Ok(())
    }

    /// Consumes an available output. A second spend fails because the entry is gone.
    pub fn consume(&mut self, id: &CoinId) -> Result<QCashUtxo, UtxoError> {
        self.utxos
            .remove(id)
            .map(|stored| QCashUtxo {
                coin: Coin::new(*id, stored.amount),
                public_key: stored.public_key,
            })
            .ok_or(UtxoError::UtxoNotFound)
    }

    /// Restores a consumed output while rolling back its block.
    pub fn restore(&mut self, utxo: QCashUtxo) -> Result<(), UtxoError> {
        self.insert(utxo)
    }

    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtxoError {
    UtxoNotFound,
    CoinIdCollision,
    PublicKeyNotFound,
    PublicKeyConflict,
}

impl fmt::Display for UtxoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UtxoNotFound => formatter.write_str("UTXO was not found"),
            Self::CoinIdCollision => formatter.write_str("UTXO coin ID already exists"),
            Self::PublicKeyNotFound => formatter.write_str("account public key was not found"),
            Self::PublicKeyConflict => {
                formatter.write_str("account address is registered to another public key")
            }
        }
    }
}

impl Error for UtxoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_utxo_storage_does_not_duplicate_coin_id() {
        let id = CoinId::from_bytes([1; CoinId::SIZE]);
        let mut coins = CoinUtxoSet::default();
        coins
            .insert(CoinUtxo {
                coin: Coin::new(id, xparq_coin::Amount(2)),
                owner: Address([3; xparq_crypto::ADDRESS_SIZE]),
                spendable_height: Height(4),
            })
            .unwrap();
        let coin_bytes = xparq_common::canonical_bytes(&coins).unwrap();
        assert_eq!(coin_bytes.len(), 4 + 32 + 8 + 20 + 8);
        assert_eq!(
            coins.get(&id).unwrap().coin,
            Coin::new(id, xparq_coin::Amount(2))
        );

        let mut qcash = QCashUtxoSet::default();
        qcash
            .insert(QCashUtxo {
                coin: Coin::new(id, xparq_coin::Amount(5)),
                public_key: QCashPublicKey([6; xparq_crypto::QCASH_PUBLIC_KEY_SIZE]),
            })
            .unwrap();
        let qcash_bytes = xparq_common::canonical_bytes(&qcash).unwrap();
        assert_eq!(
            qcash_bytes.len(),
            4 + 32 + 8 + xparq_crypto::QCASH_PUBLIC_KEY_SIZE
        );
        assert_eq!(
            qcash.get(&id).unwrap().coin,
            Coin::new(id, xparq_coin::Amount(5))
        );
    }
}
