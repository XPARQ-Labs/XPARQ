//! Ledger state-transition errors.

use super::{account, utxo};
use crate::native::asset::AssetError;
use std::{error::Error as StdError, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    Utxo(utxo::Error),
    Account(account::Error),
    Asset(AssetError),
    InvalidTransaction,
    OutputIndexOverflow,
    BurnOverflow,
    BurnUnderflow,
    AmountOverflow,
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utxo(error) => write!(formatter, "UTXO transition failed: {error}"),
            Self::Account(error) => write!(formatter, "account transition failed: {error}"),
            Self::Asset(error) => write!(formatter, "asset transition failed: {error}"),
            Self::InvalidTransaction => formatter.write_str("invalid transaction state transition"),
            Self::OutputIndexOverflow => formatter.write_str("transaction output index overflow"),
            Self::BurnOverflow => formatter.write_str("total burned amount overflow"),
            Self::BurnUnderflow => formatter.write_str("total burned amount underflow"),
            Self::AmountOverflow => formatter.write_str("coin amount overflow"),
        }
    }
}
impl StdError for StateError {}
impl From<utxo::Error> for StateError {
    fn from(error: utxo::Error) -> Self {
        Self::Utxo(error)
    }
}
impl From<account::Error> for StateError {
    fn from(error: account::Error) -> Self {
        Self::Account(error)
    }
}
impl From<AssetError> for StateError {
    fn from(error: AssetError) -> Self {
        Self::Asset(error)
    }
}
