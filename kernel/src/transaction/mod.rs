//! Canonical transaction intents and direct authorization envelopes.

mod asset;
mod authorization;
mod error;
mod spend;

pub use asset::{AssetInstruction, AssetIntent};
pub use authorization::{
    AccountAuthorization, AccountIntent, AuthorizedAccountIntent, AuthorizedAssetTransaction,
    AuthorizedSpendTransaction, AuthorizedTransaction,
};
pub use error::{IntentError, TransactionEncodingError};
pub use spend::{ChainContext, Spend, SpendCommitment, SpendIntent};

/// Canonical directly authorized on-chain transaction.
pub type Transaction = AuthorizedTransaction;
