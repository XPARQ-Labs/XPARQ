use super::{ProgramConsensusError, ProgramStateView};
use crate::{
    common::Owner,
    consensus::{BurnError, created_coin_output_count},
    monetary::coin::{CoinOutput, CoinShare, Zeno},
    program::{AuthorizedProgramInvocation, IntentError},
};
use crypto::ProgramId;
use std::collections::BTreeSet;

pub(crate) fn count_coin_outputs(
    outputs: &[CoinOutput],
    miner_fee: Zeno,
) -> Result<u64, ProgramConsensusError> {
    created_coin_output_count(outputs)?
        .checked_add(u64::from(!miner_fee.is_zero()))
        .ok_or(ProgramConsensusError::Burn(BurnError::WeightOverflow))
}

/// Ownership/conservation validation for a signed read-only quote; exact burn is computed afterwards.
pub fn validate_coin_inputs_for_quote(
    tx: &AuthorizedProgramInvocation,
    state: &impl ProgramStateView,
) -> Result<(), ProgramConsensusError> {
    tx.validate_structure()
        .map_err(ProgramConsensusError::Intent)?;
    let (inputs, outputs) = tx
        .payment
        .coin_parts()
        .ok_or(ProgramConsensusError::Intent(IntentError::InvalidAssetCall))?;
    validate_coin_inputs(
        inputs,
        outputs,
        tx.payment.charges.miner_fee,
        tx.signer,
        state,
    )
    .map(|_| ())
}

pub(crate) fn validate_coin_inputs(
    inputs: &[CoinShare],
    outputs: &[CoinOutput],
    miner_fee: Zeno,
    signer: ProgramId,
    state: &impl ProgramStateView,
) -> Result<Zeno, ProgramConsensusError> {
    ensure_unique_coin_ids(inputs.iter().copied())?;
    // A registered contract must execute its own policy; a matching key proof
    // must never turn it into an implicit signature-policy account.
    if state.registry().is_some_and(|r| r.contains(&(signer))) {
        return Err(ProgramConsensusError::InvalidAuthorization);
    }
    let mut input_total = Zeno::ZERO;

    for id in inputs {
        let input = state.coin(*id).ok_or(ProgramConsensusError::UtxoNotFound)?;

        if input.owner != Owner::Program(signer) {
            return Err(ProgramConsensusError::RecipientMismatch);
        }

        input_total = input_total
            .checked_add(input.amount)
            .ok_or(ProgramConsensusError::ZenoOverflow)?;
    }

    let output_total = outputs.iter().try_fold(Zeno::ZERO, |sum, output| {
        sum.checked_add(output.amount)
            .ok_or(ProgramConsensusError::ZenoOverflow)
    })?;

    input_total
        .checked_sub(output_total)
        .and_then(|value| value.checked_sub(miner_fee))
        .ok_or(ProgramConsensusError::ValueMismatch)
}

fn ensure_unique_coin_ids(
    ids: impl IntoIterator<Item = CoinShare>,
) -> Result<(), ProgramConsensusError> {
    let mut unique = BTreeSet::new();

    if ids.into_iter().any(|id| !unique.insert(id)) {
        return Err(ProgramConsensusError::Intent(IntentError::DuplicateInput));
    }

    Ok(())
}
