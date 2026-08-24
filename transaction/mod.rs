//! Canonical transaction intents, authorization envelopes, and identifiers.

mod authorization;
mod error;
mod intent;

pub use authorization::{
    AccountAuthorization, AccountIntent, AuthorizedAccountIntent, AuthorizedQCashIntent,
    AuthorizedTransaction, QCashAuthorization,
};
pub use error::{IntentError, TransactionEncodingError};
pub use intent::{
    ChainContext, MergeIntent, OnChainSpendIntent, OutputTarget, QCashIntent, QCashOutput,
    RedeemIntent, SpendCommitment, SpendOutput, SplitIntent, WithdrawIntent,
};
