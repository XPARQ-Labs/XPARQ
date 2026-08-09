use crate::error::{LedgerError, StateError};
use crate::ledger::{Ledger, calculate_state_root};

pub fn validate_ledger_invariants(ledger: &Ledger) -> Result<(), LedgerError> {
    ledger.validate_supply()?;

    for (address, account) in &ledger.accounts {
        if account.address != *address {
            return Err(LedgerError::InvalidState(StateError::AddressMismatch));
        }
    }

    if ledger.state_root() != calculate_state_root(&ledger.accounts)? {
        return Err(LedgerError::InvalidStateRoot);
    }

    Ok(())
}
