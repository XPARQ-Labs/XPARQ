use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetHashParseError;

impl fmt::Display for AssetHashParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid asset hash")
    }
}

impl Error for AssetHashParseError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetError {
    InvalidProgram,
    InvalidAmount,
    AssetAlreadyExists,
    ShareAlreadyExists,
    UnknownAsset,
    UnknownObject,
    AssetMismatch,
    Unauthorized,
    InvalidNonce,
    SupplyOverflow,
    BalanceOverflow,
    InsufficientBalance,
    Encoding,
}

impl fmt::Display for AssetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for AssetError {}
