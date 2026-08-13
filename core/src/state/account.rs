use crate::crypto::{Address, PublicKey, address_from_public_key};
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
    pub public_key: PublicKey,
}

impl Account {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            authorization: None,
        }
    }

    pub fn new_with_authorization(
        address: Address,
        public_key: PublicKey,
    ) -> Result<Self, StateError> {
        let mut account = Self::new(address);
        account.register_authorization(public_key)?;
        Ok(account)
    }

    pub fn register_authorization(&mut self, public_key: PublicKey) -> Result<(), StateError> {
        if self.authorization.is_some() {
            return Err(StateError::InvalidAuthorization);
        }
        if address_from_public_key(&public_key) != self.address {
            return Err(StateError::AddressMismatch);
        }
        self.authorization = Some(AccountAuthorization { public_key });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    #[test]
    fn new_with_authorization_registers_matching_keys() {
        let owner = generate_keypair();
        let address = address_from_public_key(&owner.public_key);

        let account = Account::new_with_authorization(address, owner.public_key).unwrap();

        assert_eq!(
            account.authorization,
            Some(AccountAuthorization {
                public_key: owner.public_key,
            })
        );
    }

    #[test]
    fn register_authorization_rejects_keys_for_another_address() {
        let owner = generate_keypair();
        let mut account = Account::new(Address([0x5a; crate::crypto::ADDRESS_SIZE]));

        assert_eq!(
            account.register_authorization(owner.public_key),
            Err(StateError::AddressMismatch)
        );
        assert!(account.authorization.is_none());
    }
}
