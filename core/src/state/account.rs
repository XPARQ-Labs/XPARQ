use crate::crypto::{Address, PublicKey, dual_address_from_public_keys};
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

    pub fn new_with_authorization(
        address: Address,
        owner_public_key: PublicKey,
        auth_public_key: PublicKey,
    ) -> Result<Self, StateError> {
        let mut account = Self::new(address);
        account.register_authorization(owner_public_key, auth_public_key)?;
        Ok(account)
    }

    pub fn register_authorization(
        &mut self,
        owner_public_key: PublicKey,
        auth_public_key: PublicKey,
    ) -> Result<(), StateError> {
        if self.authorization.is_some() {
            return Err(StateError::InvalidAuthorization);
        }
        if dual_address_from_public_keys(&owner_public_key, &auth_public_key) != self.address {
            return Err(StateError::AddressMismatch);
        }
        self.authorization = Some(AccountAuthorization {
            owner_public_key,
            auth_public_key,
        });
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
        let authorization = generate_keypair();
        let address = dual_address_from_public_keys(&owner.public_key, &authorization.public_key);

        let account =
            Account::new_with_authorization(address, owner.public_key, authorization.public_key)
                .unwrap();

        assert_eq!(
            account.authorization,
            Some(AccountAuthorization {
                owner_public_key: owner.public_key,
                auth_public_key: authorization.public_key,
            })
        );
    }

    #[test]
    fn register_authorization_rejects_keys_for_another_address() {
        let owner = generate_keypair();
        let authorization = generate_keypair();
        let mut account = Account::new(Address([0x5a; crate::crypto::ADDRESS_SIZE]));

        assert_eq!(
            account.register_authorization(owner.public_key, authorization.public_key),
            Err(StateError::AddressMismatch)
        );
        assert!(account.authorization.is_none());
    }
}
