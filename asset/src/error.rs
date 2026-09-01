use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetHashParseError;

impl fmt::Display for AssetHashParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("asset ID must be `asset:` followed by 64 lowercase hexadecimal characters")
    }
}

impl Error for AssetHashParseError {}
