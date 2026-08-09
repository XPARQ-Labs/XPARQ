use crate::crypto::{Address, PublicKey};
use crate::error::StateError;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Address authorization state.
///
/// XPQ value is deliberately absent: balances are derived exclusively from
/// the owned XPQ UTXO set.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct Account {
    pub address: Address,
    pub authorization: Option<AccountAuthorization>,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct AccountAuthorization {
    pub owner_public_key: PublicKey,
    pub auth_public_key: PublicKey,
}

impl Account {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            authorization: None,
        }
    }

    pub fn new_with_authorization(address: Address, _auth_public_key: PublicKey) -> Self {
        Self::new(address)
    }

    pub fn register_authorization(
        &mut self,
        owner_public_key: PublicKey,
        auth_public_key: PublicKey,
    ) -> Result<(), StateError> {
        if self.authorization.is_some() {
            return Err(StateError::InvalidAuthorization);
        }
        self.authorization = Some(AccountAuthorization {
            owner_public_key,
            auth_public_key,
        });
        Ok(())
    }
}
