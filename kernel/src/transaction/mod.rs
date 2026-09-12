mod asset;
mod authorization;
mod error;
mod spend;
mod vutxo;

pub use asset::{AssetInstruction, AssetIntent};
pub use authorization::{
    AccountAuthorization, AccountIntent, AuthorizedAccountIntent, AuthorizedAssetTransaction,
    AuthorizedSpendTransaction, AuthorizedTransaction,
};
pub use error::{IntentError, TransactionEncodingError};
pub use spend::{ChainContext, Spend, SpendCommitment, SpendIntent};

pub type Transaction = AuthorizedTransaction;

pub use vutxo::{
    AuthorizedVaultLockTransaction, AuthorizedVaultSpendTransaction, VaultAuthorization,
    VaultEnvelope, VaultId, VaultLock, VaultLockIntent, VaultOutput, VaultSource, VaultSpendIntent,
    VaultSpendOutput, VaultValue,
};
