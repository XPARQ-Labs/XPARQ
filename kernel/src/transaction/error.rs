use std::{error::Error as StdError, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentError {
    EmptyInputs,
    EmptyOutputs,
    ZeroAmount,
    DuplicateInput,
    InvalidAssetCall,
    InvalidVault,
    Encoding,
}

impl fmt::Display for IntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInputs => formatter.write_str("intent has no inputs"),
            Self::EmptyOutputs => formatter.write_str("intent has no outputs"),
            Self::ZeroAmount => formatter.write_str("intent contains a zero amount"),
            Self::DuplicateInput => formatter.write_str("intent contains a duplicate input"),
            Self::InvalidAssetCall => formatter.write_str("asset call is structurally invalid"),
            Self::InvalidVault => formatter.write_str("vault transaction is structurally invalid"),
            Self::Encoding => formatter.write_str("intent encoding failed"),
        }
    }
}

impl StdError for IntentError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionEncodingError {
    Encoding,
}

impl fmt::Display for TransactionEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => formatter.write_str("transaction encoding failed"),
        }
    }
}

impl StdError for TransactionEncodingError {}
