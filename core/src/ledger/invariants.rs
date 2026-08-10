use crate::crypto::dual_address_from_public_keys;
use crate::error::{LedgerError, StateError};
use crate::ledger::{Ledger, calculate_state_root};

pub fn validate_ledger_invariants(ledger: &Ledger) -> Result<(), LedgerError> {
    ledger.validate_supply()?;

    for (address, account) in &ledger.accounts {
        if account.address != *address {
            return Err(LedgerError::InvalidState(StateError::AddressMismatch));
        }
        if let Some(authorization) = &account.authorization
            && dual_address_from_public_keys(
                &authorization.owner_public_key,
                &authorization.auth_public_key,
            ) != account.address
        {
            return Err(LedgerError::InvalidState(StateError::AddressMismatch));
        }
    }

    if ledger.state_root() != calculate_state_root(&ledger.accounts)? {
        return Err(LedgerError::InvalidStateRoot);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Address, generate_keypair};
    use crate::state::{Account, AccountAuthorization};
    use std::collections::BTreeMap;

    #[test]
    fn rejects_deserialized_authorization_that_does_not_bind_to_account_address() {
        let owner = generate_keypair();
        let authorization = generate_keypair();
        let address = Address([0x6b; crate::crypto::ADDRESS_SIZE]);
        let serialized = crate::codec::canonical_bytes(&Account {
            address,
            authorization: Some(AccountAuthorization {
                owner_public_key: owner.public_key,
                auth_public_key: authorization.public_key,
            }),
        })
        .unwrap();
        let account: Account = crate::codec::canonical_deserialize(&serialized).unwrap();
        let mut accounts = BTreeMap::new();
        accounts.insert(address, account);
        let mut ledger = Ledger::new();
        ledger.replace_accounts(accounts).unwrap();

        assert_eq!(
            validate_ledger_invariants(&ledger),
            Err(LedgerError::InvalidState(StateError::AddressMismatch))
        );
    }
}
