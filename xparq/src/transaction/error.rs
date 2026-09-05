use std::{error::Error, fmt};

use crate::common::CodecError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentError {
    EmptyInputs,
    EmptyOutputs,
    ZeroZeno,
    DuplicateInput,
    InvalidMinerOutput,
    InvalidBurnOutput,
    InvalidAssetCall,
    AmountOverflow,
    ValueMismatch,
    Encoding(CodecError),
}

impl fmt::Display for IntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInputs => formatter.write_str("intent has no inputs"),
            Self::EmptyOutputs => formatter.write_str("intent has no outputs"),
            Self::ZeroZeno => formatter.write_str("intent contains a zero amount"),
            Self::DuplicateInput => formatter.write_str("intent contains a duplicate coin"),
            Self::InvalidMinerOutput => {
                formatter.write_str("transform public output must target the block miner")
            }
            Self::InvalidBurnOutput => formatter.write_str("intent contains multiple burn outputs"),
            Self::InvalidAssetCall => formatter.write_str("asset call is structurally invalid"),
            Self::AmountOverflow => formatter.write_str("intent amount overflow"),
            Self::ValueMismatch => formatter.write_str("input value does not equal output value"),
            Self::Encoding(error) => write!(formatter, "intent encoding failed: {error}"),
        }
    }
}

impl Error for IntentError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionEncodingError {
    Encoding(CodecError),
}

impl fmt::Display for TransactionEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "transaction encoding failed: {error}"),
        }
    }
}

impl Error for TransactionEncodingError {}
