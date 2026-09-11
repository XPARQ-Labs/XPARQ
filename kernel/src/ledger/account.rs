use std::{collections::BTreeMap, error::Error as StdError, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, PublicKey};

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Registry {
    account: BTreeMap<Address, PublicKey>,
}

impl Registry {
    pub fn get_account(&self, address: &Address) -> Option<&PublicKey> {
        self.account.get(address)
    }

    pub fn len(&self) -> usize {
        self.account.len()
    }

    pub fn is_empty(&self) -> bool {
        self.account.is_empty()
    }

    pub fn register_account(
        &mut self,
        address: Address,
        public_key: PublicKey,
    ) -> Result<bool, Error> {
        if let Some(existing) = self.account.get(&address) {
            return if existing == &public_key {
                Ok(false)
            } else {
                Err(Error::PublicKeyConflict)
            };
        }

        self.account.insert(address, public_key);

        Ok(true)
    }

    pub fn remove_account(&mut self, address: &Address) -> Result<PublicKey, Error> {
        self.account.remove(address).ok_or(Error::PublicKeyNotFound)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    PublicKeyNotFound,
    PublicKeyConflict,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKeyNotFound => formatter.write_str("account public key was not found"),
            Self::PublicKeyConflict => {
                formatter.write_str("account address is registered to another public key")
            }
        }
    }
}

impl StdError for Error {}