//! Application capabilities supplied by the node, outside canonical ledger data.

use std::sync::Arc;

use crate::common::Owner;
use crypto::ProgramId;

use super::system::{
    asset_program::{
        asset::AssetError,
        type_::{AssetCall, Burn, Mint, Register, Transfer},
    },
    coin_program::{CoinHost, TransferError},
};
use crate::{ledger::StateError, monetary::coin::CoinShare};

/// A host bound to one authenticated asset instruction. Applications cannot
/// obtain the ledger or substitute another instruction through this interface.
pub trait AssetHost {
    fn register(&mut self, call: &Register) -> Result<(), AssetError>;
    fn mint(&mut self, call: &Mint) -> Result<(), AssetError>;
    fn transfer(&mut self, call: &Transfer) -> Result<(), AssetError>;
    fn burn(&mut self, call: &Burn) -> Result<(), AssetError>;
}

/// Runtime installs the protocol's deterministic application implementation.
/// Both preview and commit use this same implementation.
pub trait ApplicationExecutor: Send + Sync {
    fn execute_coin(
        &self,
        host: &mut dyn CoinHost<Error = StateError>,
        inputs: &[CoinShare],
        outputs: &[(Owner, u64)],
        miner: ProgramId,
        miner_fee: u64,
    ) -> Result<(), TransferError<StateError>>;

    fn execute_asset(&self, call: &AssetCall, host: &mut dyn AssetHost) -> Result<(), AssetError>;
}

#[derive(Clone)]
pub struct Applications(pub(crate) Arc<dyn ApplicationExecutor>);

impl Applications {
    pub fn new(executor: impl ApplicationExecutor + 'static) -> Self {
        Self(Arc::new(executor))
    }

    pub fn executor(&self) -> &dyn ApplicationExecutor {
        self.0.as_ref()
    }
}

impl std::fmt::Debug for Applications {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Applications(runtime capability)")
    }
}

/// A bare kernel fails closed until the node installs its applications.
pub struct NoApplications;

impl ApplicationExecutor for NoApplications {
    fn execute_coin(
        &self,
        _: &mut dyn CoinHost<Error = StateError>,
        _: &[CoinShare],
        _: &[(Owner, u64)],
        _: ProgramId,
        _: u64,
    ) -> Result<(), TransferError<StateError>> {
        Err(TransferError::Host(StateError::InvalidTransition))
    }

    fn execute_asset(&self, _: &AssetCall, _: &mut dyn AssetHost) -> Result<(), AssetError> {
        Err(AssetError::InvalidProgram)
    }
}

impl Default for Applications {
    fn default() -> Self {
        #[cfg(test)]
        {
            Self::new(test_executor::TestApplications)
        }
        #[cfg(not(test))]
        {
            Self::new(NoApplications)
        }
    }
}

#[cfg(test)]
mod test_executor;
