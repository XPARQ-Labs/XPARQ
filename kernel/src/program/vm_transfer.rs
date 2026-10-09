//! Kernel-owned settlement of monetary proposals from deployed code.
//!
//! Settlement applies coin effects before asset registration, minting, and
//! transfer. These internal routines require disposable or atomic staging state:
//! the caller must discard that state if any settlement step fails.

use crate::ledger::utxo::AssetJournal;
use crate::{
    common::Owner,
    ledger::{CoinRollbackJournal, LedgerState, StateError},
    monetary::coin::CoinShare,
    program::{
        AuthorizationCommitment, ProgramId, application::ApplicationExecutor, vm::ExecutionResult,
    },
};

mod asset;
mod coin;
mod quote;

pub use quote::quote;

pub const MAX_TRANSFER_INPUTS: usize = 256;

pub(crate) fn settle(
    state: &mut LedgerState,
    id: ProgramId,
    result: &ExecutionResult,
    commitment: AuthorizationCommitment,
    applications: &dyn ApplicationExecutor,
) -> Result<(CoinRollbackJournal, Option<AssetJournal>), StateError> {
    settle_with_inputs(state, id, result, commitment, applications, None)
}

pub(crate) fn settle_with_inputs(
    state: &mut LedgerState,
    id: ProgramId,
    result: &ExecutionResult,
    commitment: AuthorizationCommitment,
    applications: &dyn ApplicationExecutor,
    selected: Option<&[CoinShare]>,
) -> Result<(CoinRollbackJournal, Option<AssetJournal>), StateError> {
    let actor = Owner::Program(id);
    let bytes = crypto::canonical_bytes(&(b"xparq:vm-transfer:v2", id, commitment))
        .map_err(|_| StateError::InvalidTransition)?;
    let origin = crypto::domain(crypto::HashDomain::AssetIntent, &bytes).into_bytes();
    let coin = coin::settle(state, actor, result, origin, selected)?;
    let asset = asset::settle(state, id, result, commitment, applications, origin)?;
    Ok((coin, asset))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferQuote {
    pub created_coin_utxos: u64,
    pub consumed_coin_utxos: u64,
    pub created_state_weight: u64,
}

#[cfg(test)]
mod tests;
