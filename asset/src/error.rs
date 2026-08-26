use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetIdParseError;

impl fmt::Display for AssetIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("coin ID must be exactly 32 bytes encoded as hexadecimal")
    }
}

impl Error for AssetIdParseError {}
