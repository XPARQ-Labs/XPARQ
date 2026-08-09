use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    InvalidAuthorization,
    AddressMismatch,
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::InvalidAuthorization => {
                f.write_str("account authorization initialization is invalid")
            }
            StateError::AddressMismatch => {
                f.write_str("transaction address does not match account address")
            }
        }
    }
}

impl Error for StateError {}
