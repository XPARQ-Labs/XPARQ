//! Canonical transaction intents, authorization envelopes, and identifiers.

mod authorization;
mod error;
mod intent;

pub use authorization::{
    AccountAuthorization, AccountIntent, AuthorizedAccountIntent, AuthorizedAssetTransaction,
    AuthorizedExtensionTransaction, AuthorizedTransaction,
};
pub use error::{IntentError, TransactionEncodingError};
pub use intent::{
    AssetInstruction, AssetIntent, ChainContext, CoinIntent, Recipient, SpendCommitment,
    SpendOutput,
};
