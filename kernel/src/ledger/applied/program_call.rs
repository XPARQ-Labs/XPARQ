//! Validated program-call dispatch, staged settlement, and atomic commit.

use crate::{
    common::Owner,
    ledger::{CoinRollbackJournal, LedgerError, LedgerState, StateError, StateRollbackJournal},
};
use crypto::ProgramId;

impl LedgerState {
    /// Validation and both state transitions run on a clone, committed only on success.
    pub fn apply_program_call(
        &mut self,

        transaction: crate::program::AuthorizedProgramInvocation,

        miner: ProgramId,

        chain: crate::common::ChainContext,

        height: u64,
    ) -> Result<StateRollbackJournal, LedgerError> {
        self.apply_program_call_with_applications(
            transaction,
            miner,
            chain,
            height,
            crate::program::application::Applications::default().executor(),
        )
    }

    pub fn apply_program_call_with_applications(
        &mut self,
        transaction: crate::program::AuthorizedProgramInvocation,
        miner: ProgramId,
        chain: crate::common::ChainContext,
        height: u64,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<StateRollbackJournal, LedgerError> {
        let prepared = crate::consensus::program_call::validate_program_call_with_applications(
            transaction,
            chain,
            height,
            self,
            applications,
        )?;

        self.apply_prepared_program_call(prepared, miner, chain, applications)
    }

    pub(crate) fn apply_prepared_program_call(
        &mut self,
        prepared: crate::program::PreparedProgramInvocation,
        miner: ProgramId,
        chain: crate::common::ChainContext,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<StateRollbackJournal, LedgerError> {
        let mut staged = self.clone();
        let journal = staged.apply_prepared_program_call_in_staged_state(
            prepared,
            miner,
            chain,
            applications,
        )?;
        *self = staged;
        Ok(journal)
    }

    /// The caller must discard this private staging state on any error.
    pub(crate) fn apply_prepared_program_call_in_staged_state(
        &mut self,
        prepared: crate::program::PreparedProgramInvocation,
        miner: ProgramId,
        chain: crate::common::ChainContext,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<StateRollbackJournal, LedgerError> {
        let height = prepared.height;
        let tx = prepared.invocation;

        let commitment =
            crate::program::program_invocation_commitment(tx.signer, &tx.call, &tx.payment, chain)
                .map_err(crate::consensus::ProgramConsensusError::Intent)?;

        let mut vm_coin = CoinRollbackJournal::default();
        let (journal, program_journal) =
            match crate::program::system::script::execute::decode_program(&tx.call)
                .map_err(|_| StateError::InvalidTransition)?
            {
                crate::program::system::script::execute::DecodedProgramCall::XpqTransfer => {
                    (None, None)
                }

                crate::program::system::script::execute::DecodedProgramCall::Vm(id) => {
                    let _ = id;
                    let result =
                        crate::program::vm_app::apply(self, &tx, height, commitment, applications)
                            .map_err(|_| StateError::InvalidTransition)?;
                    vm_coin = result.coin;
                    (result.asset, result.program)
                }

                crate::program::system::script::execute::DecodedProgramCall::Asset(call) => {
                    let bytes = crypto::canonical_bytes(&(
                        chain.genesis_hash,
                        tx.signer,
                        &tx.call,
                        &tx.payment,
                    ))?;

                    let journal = crate::program::asset_host::execute_asset(
                        applications,
                        &mut self.extensions.assets,
                        &call,
                        crate::ledger::utxo::ExecutionContext {
                            actor: Owner::Program(tx.signer),

                            commitment: crypto::domain(crypto::HashDomain::AssetIntent, &bytes)
                                .into_bytes(),
                        },
                    )
                    .map_err(|_| StateError::InvalidTransition)?;

                    (Some(journal), None)
                }
            };

        let mut coin = self.execute_coin_program_with_applications(
            &tx.payment,
            commitment,
            miner,
            applications,
        )?;

        coin.consumed_coins.append(&mut vm_coin.consumed_coins);
        coin.created_coin_ids.append(&mut vm_coin.created_coin_ids);

        self.validate_supply_invariants()?;

        Ok(StateRollbackJournal {
            coin: Some(coin),

            program: program_journal,

            extension: journal,
        })
    }
}
