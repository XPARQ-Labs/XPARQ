use crate::error::CodecError;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionError {
    UnsupportedVersion,
    ZeroAmount,
    EmptyInputs,
    EmptyOutputs,
    DuplicateInput,
    SameSenderAndRecipient,
    EmptyPublicKey,
    EmptySignature,
    EmptyAuthorizationPublicKey,
    EmptyAuthorizationSignature,
    UnsupportedSignatureScheme,
    InvalidAuthorizationProofEncoding,
    TransactionTooLarge,
    InvalidSignature,
    InvalidAuthorizationSignature,
    InvalidAuthorizationInitialization,
    SenderAddressMismatch,
    AuthorizationPublicKeyMismatch,
    InvalidQCashMetadata,
    InvalidQCashRecipient,
    InvalidQCashOutputs,
    InvalidValidityWindow,
    NotYetValid,
    ValidityExpired,
    Serialization(CodecError),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransactionError::UnsupportedVersion => {
                f.write_str("transaction version is unsupported")
            }
            TransactionError::ZeroAmount => {
                f.write_str("transaction amount must be greater than zero")
            }
            TransactionError::EmptyInputs => f.write_str("transaction must contain an input"),
            TransactionError::EmptyOutputs => f.write_str("transaction must contain an output"),
            TransactionError::DuplicateInput => {
                f.write_str("transaction contains a duplicate input coin")
            }
            TransactionError::SameSenderAndRecipient => {
                f.write_str("sender and recipient address must be different")
            }
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
            TransactionError::InvalidAuthorizationProofEncoding => {
                f.write_str("transaction authorization proof encoding is invalid")
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
                f.write_str("QCash redeem recipient is invalid")
            }
            TransactionError::InvalidQCashOutputs => {
                f.write_str("QCash redeem outputs are invalid or do not conserve value")
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
