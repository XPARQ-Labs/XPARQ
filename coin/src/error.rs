use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinIdParseError;

impl fmt::Display for CoinIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("coin ID must be exactly 32 bytes encoded as hexadecimal")
    }
}

impl Error for CoinIdParseError {}
