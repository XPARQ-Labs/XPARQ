//! Deterministic account selection, monetary effects, and merged rollback journals.

use super::Engine;
use crate::ledger::utxo::AssetJournal;
use crate::ledger::utxo::ExecutionContext;
use crate::{
    common::Owner,
    monetary::asset::{AssetContract, AssetOutput, Unit},
    program::{
        AuthorizationCommitment, ProgramId,
        system::asset_program::type_::{AssetCall, Burn, Transfer},
        vm::{self, ExecutionError},
    },
};
use crypto::canonical_bytes;
use std::cmp::Reverse;

impl Engine<'_> {
    pub(super) fn ensure_accounts(&mut self, id: ProgramId) -> Result<(), ExecutionError> {
        if self.accounts_ready.contains(&id) {
            return Ok(());
        }
        for (share, value) in self.state.utxos.coins_by_owner(Owner::Program(id)) {
            let account = self.coins.entry(id).or_default();
            account.0 = account
                .0
                .checked_add(value.amount.as_zeno())
                .ok_or(ExecutionError::ArithmeticOverflow)?;
            account.1.insert((Reverse(value.amount.as_zeno()), share));
        }
        for (share, value) in self
            .state
            .extensions
            .assets
            .shares_by_owner(Owner::Program(id))
        {
            let account = self.assets.entry((id, value.asset)).or_default();
            account.0 = account
                .0
                .checked_add(value.amount.as_units())
                .ok_or(ExecutionError::ArithmeticOverflow)?;
            account.1.insert((Reverse(value.amount.as_units()), share));
        }
        self.accounts_ready.insert(id);
        Ok(())
    }
    pub(super) fn merge_asset(&mut self, journal: AssetJournal) -> Result<(), ExecutionError> {
        for (share, previous) in journal.share_changes() {
            if let Some(value) = previous
                && self.accounts_ready.contains(&value.owner.program())
            {
                let id = value.owner.program();
                let account = self.assets.entry((id, value.asset)).or_default();
                account.0 = account
                    .0
                    .checked_sub(value.amount.as_units())
                    .ok_or(ExecutionError::SettlementFailed)?;
                account.1.remove(&(Reverse(value.amount.as_units()), share));
            }
            if let Some(value) = self.state.extensions.assets.shares().get(&share)
                && self.accounts_ready.contains(&value.owner.program())
            {
                let id = value.owner.program();
                let account = self.assets.entry((id, value.asset)).or_default();
                account.0 = account
                    .0
                    .checked_add(value.amount.as_units())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                account.1.insert((Reverse(value.amount.as_units()), share));
            }
        }
        self.asset = Some(match self.asset.take() {
            Some(previous) => previous.merge(journal),
            None => journal,
        });
        Ok(())
    }
    pub(super) fn settle(
        &mut self,
        id: ProgramId,
        result: &vm::ExecutionResult,
        legacy_root: bool,
    ) -> Result<(), ExecutionError> {
        self.ensure_accounts(id)?;
        let mut selected = Vec::new();
        if let Some(request) = result.coin_transfer {
            let mut total = 0u64;
            // v4 selects largest amounts first, then share ID. Fee changes alter newly created IDs,
            // but cannot alter selected amounts/counts and make quotes oscillate.
            let candidates = if legacy_root {
                self.state
                    .utxos
                    .coins_by_owner(Owner::Program(id))
                    .take(crate::program::vm_transfer::MAX_TRANSFER_INPUTS)
                    .map(|(share, _)| share)
                    .collect::<Vec<_>>()
            } else {
                self.coins
                    .get(&id)
                    .map(|v| {
                        v.1.iter()
                            .take(crate::program::vm_transfer::MAX_TRANSFER_INPUTS)
                            .map(|(_, share)| *share)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            for share in candidates {
                let value = self
                    .state
                    .utxos
                    .coin(&share)
                    .ok_or(ExecutionError::SettlementFailed)?;
                selected.push(share);
                total = total
                    .checked_add(value.amount.as_zeno())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                if total >= request.amount {
                    break;
                }
            }
            if !legacy_root {
                self.charge(selected.len() as u64)?;
            }
        }
        self.action()?;
        let commitment = if legacy_root {
            self.commitment
        } else {
            let bytes =
                canonical_bytes(&(b"xparq:vm-effects:v4", self.commitment, self.actions as u64))
                    .map_err(|_| ExecutionError::SettlementFailed)?;
            AuthorizationCommitment::from_bytes(
                crypto::domain(crypto::HashDomain::AssetIntent, &bytes).into_bytes(),
            )
        };
        let (coin, asset) = crate::program::vm_transfer::settle_with_inputs(
            self.state,
            id,
            result,
            commitment,
            self.apps,
            Some(&selected),
        )
        .map_err(|_| ExecutionError::SettlementFailed)?;
        for (share, value) in coin.consumed_coins {
            if self.accounts_ready.contains(&value.owner.program()) {
                let id = value.owner.program();
                let account = self.coins.entry(id).or_default();
                account.0 = account
                    .0
                    .checked_sub(value.amount.as_zeno())
                    .ok_or(ExecutionError::SettlementFailed)?;
                account.1.remove(&(Reverse(value.amount.as_zeno()), share));
            }
            if !self.created.remove(&share) {
                self.consumed.entry(share).or_insert(value);
            }
        }
        for share in coin.created_coin_ids {
            let value = self
                .state
                .utxos
                .coin(&share)
                .ok_or(ExecutionError::SettlementFailed)?;
            if self.accounts_ready.contains(&value.owner.program()) {
                let id = value.owner.program();
                let account = self.coins.entry(id).or_default();
                account.0 = account
                    .0
                    .checked_add(value.amount.as_zeno())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                account.1.insert((Reverse(value.amount.as_zeno()), share));
            }
            self.created.insert(share);
        }
        if let Some(asset) = asset {
            self.merge_asset(asset)?;
        }
        Ok(())
    }
    pub(super) fn transfer_asset(
        &mut self,
        id: ProgramId,
        asset: AssetContract,
        recipient: Owner,
        amount: u128,
    ) -> Result<(), ExecutionError> {
        self.ensure_accounts(id)?;
        if amount == 0 {
            return Err(ExecutionError::InvalidOperand);
        }
        self.action()?;
        let actor = Owner::Program(id);
        let mut inputs = Vec::new();
        let mut total = 0u128;
        if let Some(account) = self.assets.get(&(id, asset)) {
            for (_, share) in account
                .1
                .iter()
                .take(crate::program::vm_transfer::MAX_TRANSFER_INPUTS)
            {
                let value = self
                    .state
                    .extensions
                    .assets
                    .shares()
                    .get(share)
                    .ok_or(ExecutionError::SettlementFailed)?;
                inputs.push(*share);
                total = total
                    .checked_add(value.amount.as_units())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                if total >= amount {
                    break;
                }
            }
        }
        self.charge(inputs.len() as u64)?;
        let change = total
            .checked_sub(amount)
            .ok_or(ExecutionError::SettlementFailed)?;
        let mut outputs = vec![AssetOutput::new(recipient, Unit::from_units(amount))];
        if change != 0 {
            outputs.push(AssetOutput::new(actor, Unit::from_units(change)));
        }
        let bytes = canonical_bytes(&(
            b"xparq:vm-asset-transfer:v4",
            self.commitment,
            self.actions as u64,
        ))
        .map_err(|_| ExecutionError::SettlementFailed)?;
        let journal = crate::program::asset_host::execute_asset(
            self.apps,
            &mut self.state.extensions.assets,
            &AssetCall::Transfer(Transfer {
                asset,
                inputs,
                outputs,
            }),
            ExecutionContext {
                actor,
                commitment: crypto::domain(crypto::HashDomain::AssetIntent, &bytes).into_bytes(),
            },
        )
        .map_err(|_| ExecutionError::SettlementFailed)?;
        self.merge_asset(journal)?;
        Ok(())
    }
    pub(super) fn burn_asset(
        &mut self,
        id: ProgramId,
        asset: AssetContract,
        amount: u128,
    ) -> Result<(), ExecutionError> {
        self.ensure_accounts(id)?;
        if amount == 0 {
            return Err(ExecutionError::InvalidOperand);
        }
        self.action()?;
        let mut inputs = Vec::new();
        let mut total = 0u128;
        if let Some(account) = self.assets.get(&(id, asset)) {
            for (_, share) in account
                .1
                .iter()
                .take(crate::program::vm_transfer::MAX_TRANSFER_INPUTS)
            {
                let value = self
                    .state
                    .extensions
                    .assets
                    .shares()
                    .get(share)
                    .ok_or(ExecutionError::SettlementFailed)?;
                inputs.push(*share);
                total = total
                    .checked_add(value.amount.as_units())
                    .ok_or(ExecutionError::ArithmeticOverflow)?;
                if total >= amount {
                    break;
                }
            }
        }
        self.charge(inputs.len() as u64)?;
        let output = total
            .checked_sub(amount)
            .ok_or(ExecutionError::SettlementFailed)?;
        let bytes = canonical_bytes(&(
            b"xparq:vm-asset-burn:v4",
            self.commitment,
            self.actions as u64,
        ))
        .map_err(|_| ExecutionError::SettlementFailed)?;
        let journal = crate::program::asset_host::execute_asset(
            self.apps,
            &mut self.state.extensions.assets,
            &AssetCall::Burn(Burn {
                asset,
                inputs,
                amount: Unit::from_units(amount),
                output: Unit::from_units(output),
            }),
            ExecutionContext {
                actor: Owner::Program(id),
                commitment: crypto::domain(crypto::HashDomain::AssetIntent, &bytes).into_bytes(),
            },
        )
        .map_err(|_| ExecutionError::SettlementFailed)?;
        self.merge_asset(journal)
    }
}
