//! Validated program deployment, staged payment, and atomic commit.

use crate::ledger::{LedgerError, LedgerState, StateError, StateRollbackJournal};
use crypto::ProgramId;

impl LedgerState {
    /// Atomic application of an authenticated program deployment.
    pub fn apply_deploy(
        &mut self,
        signed: crate::operation::AuthorizedDeployProgram,
        miner: ProgramId,
        chain: crate::common::ChainContext,
        height: crate::common::Height,
    ) -> Result<StateRollbackJournal, LedgerError> {
        self.apply_deploy_with_applications(
            signed,
            miner,
            chain,
            height,
            crate::program::application::Applications::default().executor(),
        )
    }

    pub fn apply_deploy_with_applications(
        &mut self,
        signed: crate::operation::AuthorizedDeployProgram,
        miner: ProgramId,
        chain: crate::common::ChainContext,
        height: crate::common::Height,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<StateRollbackJournal, LedgerError> {
        let prepared = crate::consensus::validate_deploy(signed, chain, height, self)?;
        self.apply_prepared_deploy(prepared, miner, applications)
    }

    pub(crate) fn apply_prepared_deploy(
        &mut self,
        prepared: crate::consensus::PreparedDeploy,
        miner: ProgramId,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<StateRollbackJournal, LedgerError> {
        let mut staged = self.clone();
        let journal =
            staged.apply_prepared_deploy_in_staged_state(prepared, miner, applications)?;
        *self = staged;
        Ok(journal)
    }

    /// The caller must discard this private staging state on any error.
    pub(crate) fn apply_prepared_deploy_in_staged_state(
        &mut self,
        prepared: crate::consensus::PreparedDeploy,
        miner: ProgramId,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<StateRollbackJournal, LedgerError> {
        let coin = self.execute_coin_program_with_applications(
            &prepared.signed.payment,
            prepared.commitment,
            miner,
            applications,
        )?;
        let (id, program) = crate::program::deploy_program(
            &mut self.programs,
            prepared.signed.deploy,
            prepared.height,
        )
        .map_err(|_| StateError::InvalidTransition)?;
        if id != prepared.program_id {
            return Err(StateError::InvalidTransition.into());
        }
        self.validate_supply_invariants()?;
        Ok(StateRollbackJournal {
            coin: Some(coin),
            program: Some(program),
            extension: None,
        })
    }
}
