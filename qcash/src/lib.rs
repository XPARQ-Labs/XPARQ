//! Portable QCash bearer-file primitives.
//!
//! Consensus transactions and ledger state deliberately live outside this
//! crate. Secret generation and persistence policy belong to wallet callers.

mod coin;
mod file;
mod secret;

pub use coin::QCash;
pub use file::{
    MAX_QCASH_FILE_SIZE, QCASH_FILE_MAGIC, QCashFile, QCashFileError, QCashFileNameError,
    canonical_qcash_file_name, validate_qcash_file_name,
};
pub use secret::{
    FalconQCashSigningSeed, QCASH_SIGNING_SEED_SIZE, QCashBearerPublicKey, QCashBearerSignature,
    QCashSignatureScheme, QCashSigningKey, QCashSigningSeed, verify_qcash_bearer_signature,
};
