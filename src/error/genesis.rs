use crate::crypto::HASH_SIZE;
use crate::error::CodecError;
use crate::ledger::LedgerError;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisError {
    Ledger(LedgerError),
    Codec(CodecError),
    InvalidArtifact,
    InvalidArtifactKind,
    InvalidArtifactVersion,
    InvalidNetwork,
    InvalidPayloadHash,
    InvalidStateCommitment,
    TrustAnchorMismatch,
    HashMismatch {
        expected: [u8; HASH_SIZE],
        found: [u8; HASH_SIZE],
    },
}

impl fmt::Display for GenesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenesisError::Ledger(error) => write!(f, "genesis ledger error: {error}"),
            GenesisError::Codec(error) => write!(f, "genesis encoding error: {error}"),
            GenesisError::InvalidArtifact => f.write_str("invalid PAQUS artifact"),
            GenesisError::InvalidArtifactKind => f.write_str("invalid PAQUS artifact kind"),
            GenesisError::InvalidArtifactVersion => f.write_str("invalid PAQUS artifact version"),
            GenesisError::InvalidNetwork => f.write_str("invalid PAQUS artifact network"),
            GenesisError::InvalidPayloadHash => f.write_str("invalid PAQUS artifact payload hash"),
            GenesisError::InvalidStateCommitment => {
                f.write_str("invalid PAQUS artifact state commitment")
            }
            GenesisError::TrustAnchorMismatch => {
                f.write_str("PAQUS artifact does not match the validated trust anchor")
            }
            GenesisError::HashMismatch { expected, found } => write!(
                f,
                "canonical genesis hash mismatch: expected {expected:02x?}, found {found:02x?}"
            ),
        }
    }
}

impl Error for GenesisError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ledger(error) => Some(error),
            Self::Codec(error) => Some(error),
            _ => None,
        }
    }
}

impl From<LedgerError> for GenesisError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<CodecError> for GenesisError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}
