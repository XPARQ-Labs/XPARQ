use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    InsufficientBalance,
    InvalidNonce,
    NonceOverflow,
    InvalidAuthorization,
    AddressMismatch,
    BalanceOverflow,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::InsufficientBalance => f.write_str("account balance is insufficient"),
            StateError::InvalidNonce => {
                f.write_str("transaction nonce does not match account nonce")
            }
            StateError::NonceOverflow => f.write_str("account nonce is exhausted"),
            StateError::InvalidAuthorization => {
                f.write_str("account authorization initialization is invalid")
            }
            StateError::AddressMismatch => {
                f.write_str("transaction address does not match account address")
            }
            StateError::BalanceOverflow => f.write_str("account balance overflow"),
        }
    }
}

impl Error for StateError {}
