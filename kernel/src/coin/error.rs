use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinHashParseError;

impl fmt::Display for CoinHashParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("coin ID must be exactly 32 bytes encoded as hexadecimal")
    }
}

impl Error for CoinHashParseError {}
