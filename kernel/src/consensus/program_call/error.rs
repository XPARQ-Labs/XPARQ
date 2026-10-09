use crate::{consensus::BurnError, program::IntentError};
use std::{error::Error as StdError, fmt};
#[derive(Debug)]
pub enum ProgramConsensusError {
    UnknownProgram,
    Vm(crate::program::vm::ExecutionError),
    Encoding,
    InvocationTooLarge,
    Intent(IntentError),
    InvalidAuthorization,
    UtxoNotFound,
    RecipientMismatch,
    ZenoOverflow,
    ValueMismatch,
    Burn(BurnError),
}

impl fmt::Display for ProgramConsensusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProgram => formatter.write_str("deployed program was not found"),
            Self::Vm(error) => write!(formatter, "VM execution failed: {error:?}"),
            Self::Encoding => formatter.write_str("program call encoding failed"),
            Self::InvocationTooLarge => {
                formatter.write_str("program call exceeds consensus size limit")
            }
            Self::Intent(error) => write!(formatter, "invalid program call intent: {error}"),
            Self::InvalidAuthorization => {
                formatter.write_str("program call authorization is invalid")
            }
            Self::UtxoNotFound => formatter.write_str("program call input UTXO was not found"),

            Self::RecipientMismatch => {
                formatter.write_str("program call input is not committed to this signer")
            }
            Self::ZenoOverflow => formatter.write_str("program call amount overflow"),
            Self::ValueMismatch => {
                formatter.write_str("program call outputs exceed canonical input value")
            }
            Self::Burn(error) => write!(formatter, "invalid protocol burn: {error}"),
        }
    }
}

impl StdError for ProgramConsensusError {}

impl From<BurnError> for ProgramConsensusError {
    fn from(error: BurnError) -> Self {
        Self::Burn(error)
    }
}
