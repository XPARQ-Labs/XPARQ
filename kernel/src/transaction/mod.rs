//! Canonical transaction intents and direct authorization envelopes.

mod asset;
mod authorization;
mod error;
pub mod pool;
mod spend;

pub use asset::{AssetInstruction, AssetIntent};
pub use authorization::{
    AccountAuthorization, AccountIntent, AuthorizedAccountIntent, AuthorizedAssetTransaction,
    AuthorizedPoolTransaction, AuthorizedSpendTransaction, AuthorizedTransaction,
};
pub use error::{IntentError, TransactionEncodingError};
pub use pool::{PoolFunding, PoolInstruction, PoolIntent};
pub use spend::{ChainContext, Spend, SpendCommitment, SpendIntent};

/// Canonical directly authorized on-chain transaction.
pub type Transaction = AuthorizedTransaction;
