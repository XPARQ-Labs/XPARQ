//! Program-owned coin selection, change outputs, and rollback journal construction.

use super::MAX_TRANSFER_INPUTS;
use crate::{
    common::Owner,
    ledger::{CoinRollbackJournal, CoinUtxo, LedgerState, StateError},
    monetary::coin::{CoinShare, Zeno},
    program::vm::ExecutionResult,
};

/// Mutates caller-owned staging state; discard that state on any error.
pub(super) fn settle(
    state: &mut LedgerState,
    actor: Owner,
    result: &ExecutionResult,
    origin: [u8; crypto::HASH_SIZE],
    selected: Option<&[CoinShare]>,
) -> Result<CoinRollbackJournal, StateError> {
    let mut coin = CoinRollbackJournal::default();
    if let Some(request) = result.coin_transfer {
        let mut total = Zeno::ZERO;
        let mut inputs = Vec::new();
        let candidates = if let Some(ids) = selected {
            if ids.len() > MAX_TRANSFER_INPUTS {
                return Err(StateError::InvalidTransition);
            }
            ids.iter()
                .map(|share| {
                    let value = state
                        .utxos
                        .coin(share)
                        .ok_or(StateError::InvalidTransition)?;
                    if value.owner != actor {
                        return Err(StateError::InvalidTransition);
                    }
                    Ok((*share, *value))
                })
                .collect::<Result<Vec<_>, StateError>>()?
        } else {
            state
                .utxos
                .coins_by_owner(actor)
                .take(MAX_TRANSFER_INPUTS)
                .map(|(share, value)| (share, *value))
                .collect()
        };
        for (share, value) in candidates {
            inputs.push((share, value));
            total = total
                .checked_add(value.amount)
                .ok_or(StateError::AmountOverflow)?;
            if total.as_zeno() >= request.amount {
                break;
            }
        }
        let change = total
            .checked_sub(Zeno::from_zeno(request.amount))
            .ok_or(StateError::InvalidTransition)?;
        for (share, value) in inputs {
            state.utxos.consume_coin(&share)?;
            coin.consumed_coins.push((share, value));
        }
        let mut outputs = vec![(request.recipient, Zeno::from_zeno(request.amount))];
        if !change.is_zero() {
            outputs.push((actor, change));
        }
        for (index, (owner, amount)) in outputs.into_iter().enumerate() {
            let share = CoinShare::from_output(&origin, index as u32);
            state.utxos.insert_coin(share, CoinUtxo { owner, amount })?;
            coin.created_coin_ids.push(share);
        }
    }
    Ok(coin)
}
