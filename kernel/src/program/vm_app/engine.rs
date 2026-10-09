//! Invocation state, shared resource budgets, and authenticated call frames.

use super::{MAX_ACTIONS, MAX_CALL_DEPTH, MAX_CALLS, MAX_DATA_BYTES};
use crate::ledger::utxo::AssetJournal;
use crate::{
    common::Owner,
    ledger::LedgerState,
    monetary::{asset::AssetContract, coin::CoinShare},
    program::{
        AuthorizationCommitment, ProgramId,
        application::ApplicationExecutor,
        vm::{self, ExecutionError},
    },
};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
};

mod interpreter;
mod settlement;

type CoinAccount = (u64, BTreeSet<(Reverse<u64>, CoinShare)>);
type AssetAccount = (
    u128,
    BTreeSet<(Reverse<u128>, crate::monetary::asset::Share)>,
);

pub(super) struct Engine<'a> {
    pub(super) state: &'a mut LedgerState,
    pub(super) apps: &'a dyn ApplicationExecutor,
    pub(super) signer: ProgramId,
    pub(super) height: u64,
    pub(super) commitment: AuthorizationCommitment,
    pub(super) fuel: u64,
    pub(super) calls: usize,
    pub(super) actions: usize,
    pub(super) active: Vec<ProgramId>,
    pub(super) accounts_ready: BTreeSet<ProgramId>,
    // Per-invocation lookup cache, rebuilt from canonical state. Never serialized.
    pub(super) coins: BTreeMap<ProgramId, CoinAccount>,
    pub(super) assets: BTreeMap<(ProgramId, AssetContract), AssetAccount>,
    pub(super) consumed: BTreeMap<CoinShare, crate::ledger::CoinUtxo>,
    pub(super) created: BTreeSet<CoinShare>,
    pub(super) asset: Option<AssetJournal>,
    pub(super) states: BTreeMap<ProgramId, i64>,
    pub(super) storage: BTreeMap<(ProgramId, Vec<u8>), Option<Vec<u8>>>,
}

impl Engine<'_> {
    fn charge(&mut self, n: u64) -> Result<(), ExecutionError> {
        self.fuel = self.fuel.checked_sub(n).ok_or(ExecutionError::OutOfFuel)?;
        Ok(())
    }
    fn action(&mut self) -> Result<(), ExecutionError> {
        self.actions += 1;
        if self.actions > MAX_ACTIONS {
            Err(ExecutionError::ResourceLimit)
        } else {
            Ok(())
        }
    }
    pub(super) fn call(
        &mut self,
        id: ProgramId,
        caller: Owner,
        data: &[u8],
        deposit: u64,
    ) -> Result<u128, ExecutionError> {
        if data.len() > MAX_DATA_BYTES
            || self.active.len() >= MAX_CALL_DEPTH
            || self.calls >= MAX_CALLS
        {
            return Err(ExecutionError::ResourceLimit);
        }
        if self.active.contains(&id) {
            return Err(ExecutionError::ReentrantCall);
        }
        let record = self
            .state
            .programs
            .program(&id)
            .ok_or(ExecutionError::UnknownProgram)?;
        let code = record.code.clone();
        self.calls += 1;
        self.active.push(id);
        let result = if code[4] != vm::APPLICATION_VERSION {
            if !data.is_empty() {
                return Err(ExecutionError::InvalidOperand);
            }
            let result = vm::execute_registered(&self.state.programs, id, self.fuel)?;
            self.charge(result.fuel_used)?;
            let root = self.active.len() == 1;
            if result.has_monetary_effects() {
                self.settle(id, &result, root)?;
            }
            if let Some(vm::VmEffect::ProgramState(value)) = result.proposed_effect {
                let before = self
                    .state
                    .programs
                    .set_state(id, value)
                    .ok_or(ExecutionError::UnknownProgram)?;
                self.states.entry(id).or_insert(before);
            }
            Ok(result.value as u128)
        } else {
            self.interpret(id, caller, data, deposit, &code)
        };
        self.active.pop();
        result
    }
}
