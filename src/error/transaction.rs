use crate::error::CodecError;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError {
    UnsupportedVersion,
    EmptyOutputs,
    ZeroAmount,
    SameSenderAndRecipient,
    TooManyOutputs,
    DuplicateRecipient,
    AmountOverflow,
    EmptyPublicKey,
    EmptySignature,
    EmptyAuthorizationPublicKey,
    EmptyAuthorizationSignature,
    UnsupportedSignatureScheme,
    InvalidWitnessEncoding,
    TransactionTooLarge,
    InvalidSignature,
    InvalidAuthorizationSignature,
    InvalidAuthorizationInitialization,
    SenderAddressMismatch,
    AuthorizationPublicKeyMismatch,
    InvalidQCashMetadata,
    InvalidQCashRecipient,
    InvalidValidityWindow,
    NotYetValid,
    ValidityExpired,
    InvalidGovernanceProposal,
    InactiveGovernanceProposal,
    DuplicateGovernanceCredential,
    InvalidGovernanceCredential,
    TooManyCredentials,
    Serialization(CodecError),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::UnsupportedVersion => {
                f.write_str("transaction version is unsupported")
            }
            TransactionError::EmptyOutputs => {
                f.write_str("transaction must contain at least one output")
            }
            TransactionError::ZeroAmount => {
                f.write_str("transaction amount must be greater than zero")
            }
            TransactionError::SameSenderAndRecipient => {
                f.write_str("sender and recipient address must be different")
            }
            TransactionError::TooManyOutputs => f.write_str("transaction has too many outputs"),
            TransactionError::DuplicateRecipient => {
                f.write_str("transaction contains a duplicate recipient")
            }
            TransactionError::AmountOverflow => f.write_str("transaction output total overflow"),
            TransactionError::EmptyPublicKey => {
                f.write_str("signed transaction public key is empty")
            }
            TransactionError::EmptySignature => {
                f.write_str("signed transaction signature is empty")
            }
            TransactionError::EmptyAuthorizationPublicKey => {
                f.write_str("signed transaction authorization public key is empty")
            }
            TransactionError::EmptyAuthorizationSignature => {
                f.write_str("signed transaction authorization signature is empty")
            }
            TransactionError::UnsupportedSignatureScheme => {
                f.write_str("signature scheme is not active at this block height")
            }
            TransactionError::InvalidWitnessEncoding => {
                f.write_str("transaction witness encoding is invalid")
            }
            TransactionError::TransactionTooLarge => {
                f.write_str("signed transaction exceeds maximum serialized size")
            }
            TransactionError::InvalidSignature => f.write_str("transaction signature is invalid"),
            TransactionError::InvalidAuthorizationSignature => {
                f.write_str("transaction authorization signature is invalid")
            }
            TransactionError::InvalidAuthorizationInitialization => {
                f.write_str("transaction authorization initialization is invalid")
            }
            TransactionError::SenderAddressMismatch => {
                f.write_str("transaction sender does not match public key address")
            }
            TransactionError::AuthorizationPublicKeyMismatch => {
                f.write_str("transaction authorization public key does not match account")
            }
            TransactionError::InvalidQCashMetadata => {
                f.write_str("transaction contains invalid QCash metadata")
            }
            TransactionError::InvalidQCashRecipient => {
                f.write_str("QCash deposit recipient is invalid")
            }
            TransactionError::InvalidValidityWindow => {
                f.write_str("transaction validity window is invalid")
            }
            TransactionError::NotYetValid => {
                f.write_str("transaction is not valid at this block height yet")
            }
            TransactionError::ValidityExpired => {
                f.write_str("transaction validity window has expired")
            }
            TransactionError::InvalidGovernanceProposal => {
                f.write_str("governance proposal is invalid")
            }
            TransactionError::InactiveGovernanceProposal => {
                f.write_str("governance proposal is not active")
            }
            TransactionError::DuplicateGovernanceCredential => {
                f.write_str("governance credential has already been used for this context")
            }
            TransactionError::InvalidGovernanceCredential => {
                f.write_str("governance credential proof is invalid")
            }
            TransactionError::TooManyCredentials => {
                f.write_str("transaction carries too many credentials")
            }
            TransactionError::Serialization(error) => {
                write!(f, "transaction encoding failed: {error}")
            }
        }
    }
}

impl Error for TransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CodecError> for TransactionError {
    fn from(error: CodecError) -> Self {
        Self::Serialization(error)
    }
}
