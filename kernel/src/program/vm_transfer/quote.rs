//! Read-only settlement quote using the same checked staging routines.

use super::{TransferQuote, settle};
use crate::{
    ledger::{LedgerState, StateError},
    program::{
        AuthorizationCommitment, ProgramId, application::ApplicationExecutor, vm::ExecutionResult,
    },
};

/// Read-only settlement preview. The commit path uses the same checked routine.
pub fn quote(
    state: &LedgerState,
    id: ProgramId,
    result: &ExecutionResult,
    commitment: AuthorizationCommitment,
    applications: &dyn ApplicationExecutor,
) -> Result<TransferQuote, StateError> {
    if !result.has_monetary_effects() {
        return Ok(TransferQuote::default());
    }
    let mut staged = state.clone();
    let before = crypto::canonical_bytes(&state.extensions)
        .map_err(|_| StateError::InvalidTransition)?
        .len();
    let (coin, _) = settle(&mut staged, id, result, commitment, applications)?;
    let after = crypto::canonical_bytes(&staged.extensions)
        .map_err(|_| StateError::InvalidTransition)?
        .len();
    Ok(TransferQuote {
        created_coin_utxos: coin.created_coin_ids.len() as u64,
        consumed_coin_utxos: coin.consumed_coins.len() as u64,
        created_state_weight: after.saturating_sub(before) as u64,
    })
}
