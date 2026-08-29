use std::{error::Error, fmt};

use xparq_common::CodecError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentError {
    EmptyInputs,
    EmptyOutputs,
    ZeroAmount,
    DuplicateInput,
    DuplicateBearerOutput,
    InvalidMergeShape,
    InvalidSplitShape,
    InvalidMinerOutput,
    InvalidBurnOutput,
    InvalidTransformOutput,
    QCashAuthorizationCountMismatch,
    AmountOverflow,
    ValueMismatch,
    Encoding(CodecError),
}

impl fmt::Display for IntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInputs => formatter.write_str("intent has no inputs"),
            Self::EmptyOutputs => formatter.write_str("intent has no outputs"),
            Self::ZeroAmount => formatter.write_str("intent contains a zero amount"),
            Self::DuplicateInput => formatter.write_str("intent contains a duplicate coin"),
            Self::DuplicateBearerOutput => {
                formatter.write_str("intent reuses a bearer key across QCash outputs")
            }
            Self::InvalidMergeShape => {
                formatter.write_str("merge requires at least two inputs and one QCash output")
            }
            Self::InvalidSplitShape => {
                formatter.write_str("split requires one input and at least two QCash outputs")
            }
            Self::InvalidMinerOutput => {
                formatter.write_str("transform public output must target the block miner")
            }
            Self::InvalidBurnOutput => {
                formatter.write_str("intent contains multiple burn outputs")
            }
            Self::InvalidTransformOutput => formatter
                .write_str("QCash transform public outputs must target the miner or burn"),
            Self::QCashAuthorizationCountMismatch => {
                formatter.write_str("authorization count does not match QCash inputs")
            }
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
