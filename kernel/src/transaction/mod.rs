//! Canonical transaction intents, authorization envelopes, and identifiers.

mod authorization;
mod error;
mod intent;
mod spend;

pub use authorization::{
    AccountAuthorization, AccountIntent, AuthorizedAccountIntent, AuthorizedAssetTransaction,
    AuthorizedSpendTransaction, AuthorizedTransaction,
};
pub use error::{IntentError, TransactionEncodingError};
pub use intent::{
    AssetInstruction, AssetIntent, ChainContext, CoinOutput, Recipient, SpendCommitment,
};
pub use spend::{Spend, SpendIntent};
