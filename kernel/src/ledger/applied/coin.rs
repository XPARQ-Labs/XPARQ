//! Restricted coin host execution, protocol burn, and failed-transition recovery.

use crate::{
    common::Owner,
    ledger::{CoinRollbackJournal, CoinUtxo, LedgerState, StateError},
    monetary::coin::{CoinShare, Zeno},
    program::{AuthorizationCommitment, CoinTransition},
};
use crypto::ProgramId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]

pub(super) enum TransitionPoint {
    CoinInputConsumed,

    CoinOutputCreated,

    MinerFeeCreated,

    ProtocolBurnRecorded,
}

impl LedgerState {
    #[cfg(test)]
    pub(super) fn execute_coin_program(
        &mut self,

        intent: &CoinTransition,

        commitment: AuthorizationCommitment,

        block_miner: ProgramId,
    ) -> Result<CoinRollbackJournal, StateError> {
        self.execute_coin_program_with_applications(
            intent,
            commitment,
            block_miner,
            crate::program::application::Applications::default().executor(),
        )
    }

    pub(super) fn execute_coin_program_with_applications(
        &mut self,
        intent: &CoinTransition,
        commitment: AuthorizationCommitment,
        block_miner: ProgramId,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<CoinRollbackJournal, StateError> {
        self.execute_coin_program_with_checkpoint_and_applications(
            intent,
            commitment,
            block_miner,
            |_| Ok(()),
            applications,
        )
    }

    #[cfg(test)]
    pub(super) fn execute_coin_program_with_checkpoint(
        &mut self,

        intent: &CoinTransition,

        commitment: AuthorizationCommitment,

        block_miner: ProgramId,

        checkpoint: impl FnMut(TransitionPoint) -> Result<(), StateError>,
    ) -> Result<CoinRollbackJournal, StateError> {
        self.execute_coin_program_with_checkpoint_and_applications(
            intent,
            commitment,
            block_miner,
            checkpoint,
            crate::program::application::Applications::default().executor(),
        )
    }

    fn execute_coin_program_with_checkpoint_and_applications(
        &mut self,
        intent: &CoinTransition,
        commitment: AuthorizationCommitment,
        block_miner: ProgramId,
        mut checkpoint: impl FnMut(TransitionPoint) -> Result<(), StateError>,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<CoinRollbackJournal, StateError> {
        let mut journal = CoinRollbackJournal::default();

        let result = (|| {
            let (inputs, outputs) = intent.coin_parts().ok_or(StateError::InvalidTransition)?;

            let outputs: Vec<_> = outputs
                .iter()
                .map(|output| (output.output, output.amount.as_zeno()))
                .collect();

            let input_total = inputs.iter().try_fold(0u64, |total, id| {
                let amount = self
                    .utxos
                    .coin(id)
                    .ok_or(StateError::InvalidTransition)?
                    .amount
                    .as_zeno();
                total.checked_add(amount).ok_or(StateError::AmountOverflow)
            })?;
            let output_total = outputs
                .iter()
                .try_fold(intent.charges.miner_fee.as_zeno(), |total, (_, amount)| {
                    total.checked_add(*amount).ok_or(StateError::AmountOverflow)
                })?;
            let expected_burn = input_total
                .checked_sub(output_total)
                .ok_or(StateError::InvalidTransition)?;
            let allowed_inputs = inputs.iter().copied().collect();
            let mut host = KernelCoinHost {
                allowed_inputs: &allowed_inputs,
                outputs: &outputs,
                miner: block_miner,
                miner_fee: intent.charges.miner_fee.as_zeno(),
                expected_burn,
                state: self,

                journal: &mut journal,

                commitment,

                output_count: outputs.len(),

                checkpoint: &mut checkpoint,
            };

            applications
                .execute_coin(
                    &mut host,
                    inputs,
                    &outputs,
                    block_miner,
                    intent.charges.miner_fee.as_zeno(),
                )
                .map_err(|error| match error {
                    crate::program::system::coin_program::TransferError::Host(error) => error,

                    crate::program::system::coin_program::TransferError::InvalidBalance => {
                        StateError::InvalidTransition
                    }

                    crate::program::system::coin_program::TransferError::AmountOverflow => {
                        StateError::AmountOverflow
                    }

                    crate::program::system::coin_program::TransferError::OutputIndexOverflow => {
                        StateError::OutputIndexOverflow
                    }
                })?;

            if journal.consumed_coins.len() != inputs.len()
                || journal.created_coin_ids.len()
                    != outputs.len() + usize::from(!intent.charges.miner_fee.is_zero())
                || journal.burned.as_zeno() != expected_burn
            {
                return Err(StateError::InvalidTransition);
            }
            Ok(())
        })();

        self.finish_coin_transition(journal, result)
    }
}

/// Private adapter: only Program execution requests coin mutations. Consensus
/// has already checked signatures, ownership, charges and input uniqueness.
struct KernelCoinHost<'a, F> {
    allowed_inputs: &'a std::collections::BTreeSet<CoinShare>,
    outputs: &'a [(Owner, u64)],
    miner: ProgramId,
    miner_fee: u64,
    expected_burn: u64,
    state: &'a mut LedgerState,

    journal: &'a mut CoinRollbackJournal,

    commitment: AuthorizationCommitment,

    output_count: usize,

    checkpoint: &'a mut F,
}

impl<F: FnMut(TransitionPoint) -> Result<(), StateError>>
    crate::program::system::coin_program::CoinHost for KernelCoinHost<'_, F>
{
    type Error = StateError;

    fn input_amount(&self, id: &CoinShare) -> Result<u64, StateError> {
        if !self.allowed_inputs.contains(id) {
            return Err(StateError::InvalidTransition);
        }
        self.state
            .utxos
            .coin(id)
            .map(|coin| coin.amount.as_zeno())
            .ok_or(StateError::InvalidTransition)
    }

    fn consume(&mut self, id: CoinShare) -> Result<(), StateError> {
        if !self.allowed_inputs.contains(&id) {
            return Err(StateError::InvalidTransition);
        }
        let coin = self.state.utxos.consume_coin(&id)?;

        self.journal.consumed_coins.push((id, coin));

        (self.checkpoint)(TransitionPoint::CoinInputConsumed)
    }

    fn create(&mut self, index: u32, owner: Owner, amount: u64) -> Result<(), StateError> {
        let expected = if let Some(output) = self.outputs.get(index as usize) {
            *output
        } else if index as usize == self.outputs.len() && self.miner_fee != 0 {
            (Owner::Program(self.miner), self.miner_fee)
        } else {
            return Err(StateError::InvalidTransition);
        };
        if expected != (owner, amount) {
            return Err(StateError::InvalidTransition);
        }
        let id = CoinShare::from_output(self.commitment.as_bytes(), index);

        self.state.utxos.insert_coin(
            id,
            CoinUtxo {
                amount: Zeno::from_zeno(amount),

                owner,
            },
        )?;

        self.journal.created_coin_ids.push(id);

        (self.checkpoint)(if index as usize == self.output_count {
            TransitionPoint::MinerFeeCreated
        } else {
            TransitionPoint::CoinOutputCreated
        })
    }

    fn burn(&mut self, amount: u64) -> Result<(), StateError> {
        if amount != self.expected_burn || !self.journal.burned.is_zero() {
            return Err(StateError::InvalidTransition);
        }
        self.state
            .record_protocol_burn(Zeno::from_zeno(amount), self.journal)?;

        (self.checkpoint)(TransitionPoint::ProtocolBurnRecorded)
    }
}

impl LedgerState {
    pub(crate) fn record_protocol_burn(
        &mut self,

        burned: Zeno,

        journal: &mut CoinRollbackJournal,
    ) -> Result<(), StateError> {
        let total_burned = self
            .coin
            .total_burned
            .checked_add(burned)
            .ok_or(StateError::BurnOverflow)?;

        let journal_burned = journal
            .burned
            .checked_add(burned)
            .ok_or(StateError::BurnOverflow)?;

        self.coin.total_burned = total_burned;

        journal.burned = journal_burned;

        Ok(())
    }

    fn finish_coin_transition(
        &mut self,

        journal: CoinRollbackJournal,

        result: Result<(), StateError>,
    ) -> Result<CoinRollbackJournal, StateError> {
        match result {
            Ok(()) => Ok(journal),

            Err(error) => {
                self.rollback_coin(journal)?;

                Err(error)
            }
        }
    }
}
