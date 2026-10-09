//! Signed root input, disposable previews, and execution receipts.

use super::{AppliedVm, MAX_DATA_BYTES, engine::Engine};
use crate::{
    common::Owner,
    ledger::{CoinRollbackJournal, LedgerState},
    monetary::coin::Zeno,
    program::{
        AuthorizationCommitment, AuthorizedProgramInvocation, ProgramId, ProgramJournal,
        application::ApplicationExecutor,
        vm::{self, CodeError, ExecutionError},
    },
};
use std::collections::{BTreeMap, BTreeSet};

/// Root identity and deposits are derived from the signed envelope, never calldata.
/// Used only on a disposable preview or the kernel's atomic staging state.
pub(crate) fn apply(
    state: &mut LedgerState,
    tx: &AuthorizedProgramInvocation,
    height: u64,
    commitment: AuthorizationCommitment,
    apps: &dyn ApplicationExecutor,
) -> Result<AppliedVm, ExecutionError> {
    let (id, data) = call_input(&tx.call).map_err(|_| ExecutionError::InvalidOperand)?;
    let deposit = tx
        .payment
        .coin_parts()
        .ok_or(ExecutionError::InvalidOperand)?
        .1
        .iter()
        .filter(|o| o.output == Owner::Program(id))
        .try_fold(0u64, |sum, o| sum.checked_add(o.amount.as_zeno()))
        .ok_or(ExecutionError::ArithmeticOverflow)?;
    let mut engine = Engine {
        state,
        apps,
        signer: tx.signer,
        height,
        commitment,
        fuel: vm::MAX_CALL_FUEL,
        calls: 0,
        actions: 0,
        active: Vec::new(),
        accounts_ready: BTreeSet::new(),
        coins: BTreeMap::new(),
        assets: BTreeMap::new(),
        consumed: BTreeMap::new(),
        created: BTreeSet::new(),
        asset: None,
        states: BTreeMap::new(),
        storage: BTreeMap::new(),
    };
    let value = engine.call(id, Owner::Program(tx.signer), data, deposit)?;
    let mut delta = if let Some(journal) = engine.asset.as_ref() {
        journal
            .canonical_delta(&engine.state.extensions.assets)
            .map_err(|_| ExecutionError::SettlementFailed)?
    } else {
        0
    };
    for ((id, key), previous) in &engine.storage {
        let record = engine
            .state
            .programs
            .program(id)
            .ok_or(ExecutionError::UnknownProgram)?;
        let width = |value: Option<&Vec<u8>>| value.map_or(0, |v| 8 + key.len() + v.len()) as i128;
        delta = delta
            .checked_add(width(record.storage.get(key)) - width(previous.as_ref()))
            .ok_or(ExecutionError::ArithmeticOverflow)?;
    }
    let quote = crate::program::vm_transfer::TransferQuote {
        created_coin_utxos: engine.created.len() as u64,
        consumed_coin_utxos: engine.consumed.len() as u64,
        created_state_weight: u64::try_from(delta.max(0))
            .map_err(|_| ExecutionError::ResourceLimit)?,
    };
    let program = if engine.states.is_empty() && engine.storage.is_empty() {
        None
    } else if engine.states.len() == 1 && engine.storage.is_empty() {
        let (program_id, previous) = engine.states.into_iter().next().unwrap();
        Some(ProgramJournal::State {
            program_id,
            previous,
        })
    } else {
        Some(ProgramJournal::Calls {
            states: engine.states.into_iter().collect(),
            storage: engine
                .storage
                .into_iter()
                .map(|((id, key), v)| (id, key, v))
                .collect(),
        })
    };
    Ok(AppliedVm {
        value,
        fuel_used: vm::MAX_CALL_FUEL - engine.fuel,
        quote,
        coin: CoinRollbackJournal {
            consumed_coins: engine.consumed.into_iter().collect(),
            created_coin_ids: engine.created.into_iter().collect(),
            burned: Zeno::ZERO,
            mined: Zeno::ZERO,
        },
        asset: engine.asset,
        program,
    })
}

pub fn preview(
    state: &LedgerState,
    tx: &AuthorizedProgramInvocation,
    height: u64,
    commitment: AuthorizationCommitment,
    apps: &dyn ApplicationExecutor,
) -> Result<AppliedVm, ExecutionError> {
    let (id, data) = call_input(&tx.call).map_err(|_| ExecutionError::InvalidOperand)?;
    let record = state
        .programs
        .program(&id)
        .ok_or(ExecutionError::UnknownProgram)?;
    if record.code[4] != vm::APPLICATION_VERSION {
        if !data.is_empty() {
            return Err(ExecutionError::InvalidOperand);
        }
        let result = vm::execute_registered(&state.programs, id, vm::MAX_CALL_FUEL)?;
        if !result.has_monetary_effects() {
            // Retain the historical scalar-only quote path without cloning global state.
            return Ok(AppliedVm {
                value: result.value as u128,
                fuel_used: result.fuel_used,
                quote: Default::default(),
                coin: Default::default(),
                asset: None,
                program: None,
            });
        }
    }
    let mut staged = state.clone();
    apply(&mut staged, tx, height, commitment, apps)
}
/// Opcode 0 keeps the historical ID-only envelope. Opcode 1 adds up to 4096 data bytes.
pub fn call_input(
    call: &crate::program::system::script::call::ProgramCall,
) -> Result<(ProgramId, &[u8]), CodeError> {
    use crate::program::system::script::call::SystemProgramId;
    if call.program != SystemProgramId::VM
        || !matches!(call.opcode, 0 | 1)
        || call.payload.len() < 32
        || call.payload.len() > 32 + MAX_DATA_BYTES
        || (call.opcode == 0 && call.payload.len() != 32)
    {
        return Err(CodeError::InvalidInstruction);
    }
    Ok((
        ProgramId::from_bytes(call.payload[..32].try_into().unwrap()),
        &call.payload[32..],
    ))
}
