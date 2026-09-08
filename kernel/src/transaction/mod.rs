//! Canonical transaction intents, authorization envelopes, and Commit/Reveal transactions.

mod asset;
mod authorization;
mod commit;
mod error;
mod spend;

pub use asset::{AssetInstruction, AssetIntent};
pub use authorization::{
    AccountAuthorization, AccountIntent, AuthorizedAccountIntent, AuthorizedAssetTransaction,
    AuthorizedSpendTransaction, AuthorizedTransaction,
};
pub use commit::{CommitTransaction, RevealTransaction, Transaction, TransactionCommitment};
pub use error::{IntentError, TransactionEncodingError};
pub use spend::{ChainContext, Spend, SpendCommitment, SpendIntent};
