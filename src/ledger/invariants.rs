use crate::error::{LedgerError, StateError};
use crate::ledger::{Ledger, calculate_state_root};

pub fn validate_ledger_invariants(ledger: &Ledger) -> Result<(), LedgerError> {
    ledger.validate_supply()?;

    for (address, account) in &ledger.accounts {
        if account.address != *address {
            return Err(LedgerError::InvalidState(StateError::AddressMismatch));
        }

        let credit_total = account
            .credits
            .iter()
            .try_fold(0_u64, |total, credit| total.checked_add(credit.amount.0))
            .ok_or(LedgerError::SupplyOverflow)?;
        if credit_total != account.balance.0 {
            return Err(LedgerError::InvalidState(StateError::BalanceOverflow));
        }
    }

    if ledger.state_root() != calculate_state_root(&ledger.accounts)? {
        return Err(LedgerError::InvalidStateRoot);
    }

    Ok(())
}
