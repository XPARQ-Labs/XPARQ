use std::{collections::BTreeMap, error::Error as StdError, fmt};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::transaction::{VaultId, VaultOutput, VaultValue};

/// Canonical set of currently unspent Vault UTXOs.
///
/// Transaction outputs become canonical entries after the transaction
/// has passed consensus validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VaultUtxoSet {
    entries: BTreeMap<VaultId, VaultOutput>,
}

impl VaultUtxoSet {
    pub fn get(&self, id: &VaultId) -> Option<&VaultOutput> {
        self.entries.get(id)
    }

    pub fn value(&self, id: &VaultId) -> Option<&VaultValue> {
        self.entries.get(id).map(|vault| &vault.value)
    }

    pub fn contains(&self, id: &VaultId) -> bool {
        self.entries.contains_key(id)
    }

    pub fn insert(&mut self, id: VaultId, vault: VaultOutput) -> Result<(), Error> {
        if self.entries.contains_key(&id) {
            return Err(Error::Collision);
        }

        self.entries.insert(id, vault);

        Ok(())
    }

    pub fn consume(&mut self, id: &VaultId) -> Result<VaultOutput, Error> {
        self.entries.remove(id).ok_or(Error::NotFound)
    }

    pub fn iter(&self) -> impl Iterator<Item = (VaultId, &VaultOutput)> + '_ {
        self.entries.iter().map(|(id, vault)| (*id, vault))
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
    Collision,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("Vault UTXO was not found"),

            Self::Collision => formatter.write_str("Vault UTXO ID already exists"),
        }
    }
}

impl StdError for Error {}
