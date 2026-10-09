use crate::{
    common::Owner,
    ledger::{CoinRollbackJournal, CoinUtxo, LedgerState, StateError, StateRollbackJournal},
    monetary::coin::{CoinShare, Zeno},
    program::{AuthorizationCommitment, CoinTransition},
};

use crypto::ProgramId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]

enum TransitionPoint {
    CoinInputConsumed,

    CoinOutputCreated,

    MinerFeeCreated,

    ProtocolBurnRecorded,
}

#[cfg(test)]
mod vm_state_call_tests {
    use super::*;
    use crate::program::system::script::call::{ProgramCall, SystemProgramId};
    use crate::{
        common::{ChainContext, Height},
        consensus::{ProtocolBurn, StateTransitionWeight},
        monetary::coin::CoinOutput,
        operation::BlockOperation,
        program::{
            AccountAuthorization, AuthorizedProgramInvocation, CoinCharges, DeployProgram,
            program_invocation_commitment,
        },
    };
    use crypto::{
        AccountSignatureScheme, SigningSeed, canonical_bytes, program_id_from_public_key,
    };

    #[test]
    fn vm_state_call_updates_root_and_rolls_back_with_coin_payment() {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x53; 32]));
        let owner = program_id_from_public_key(&seed.public_key()).unwrap();
        let chain = ChainContext::new([0x91; crypto::HASH_SIZE]);
        let mut state = LedgerState::default();
        let input = CoinShare::from_bytes([0x23; crypto::HASH_SIZE]);
        let amount = Zeno::from_zeno(1_000_000);
        state
            .utxos
            .insert_coin(
                input,
                CoinUtxo {
                    amount,
                    owner: crate::common::Owner::Program(owner),
                },
            )
            .unwrap();
        state.coin.total_mined = amount;
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 0, 0]);
        code.push(0x04);
        code.push(0x01);
        code.extend_from_slice(&1i64.to_le_bytes());
        code.extend_from_slice(&[0x02, 0x05, 0x04, 0x03]);
        let (id, _) = crate::program::deploy_program(
            &mut state.programs,
            DeployProgram {
                owner,
                nonce: 1,
                code: code.into(),
            },
            Height(1),
        )
        .unwrap();
        let before = state.clone();
        let before_root = state.application_state_root().unwrap();
        let call = ProgramCall {
            program: SystemProgramId::VM,
            opcode: 0,
            payload: id.as_bytes().to_vec(),
        };
        let sign = |burn: u64| {
            let payment = CoinTransition::coin_with_charges(
                owner,
                vec![input],
                vec![CoinOutput::new(
                    owner,
                    Zeno::from_zeno(amount.as_zeno() - burn - 1),
                )],
                CoinCharges::new(Zeno::ONE),
            )
            .unwrap();
            let commitment = program_invocation_commitment(owner, &call, &payment, chain).unwrap();
            AuthorizedProgramInvocation {
                signer: owner,
                call: call.clone(),
                payment,
                authorization: AccountAuthorization {
                    salt: [0; 32],
                    public_key: seed.public_key(),
                    signature: seed.sign(commitment.as_bytes()),
                },
            }
        };
        let size = canonical_bytes(&BlockOperation::ProgramCall(Box::new(sign(0))))
            .unwrap()
            .len() as u64;
        let base = ProtocolBurn::for_program_call(
            StateTransitionWeight {
                created_coin_utxos: 2,
                consumed_coin_utxos: 1,
                created_state_weight: 0,
            },
            size,
        )
        .unwrap()
        .total()
        .unwrap()
        .as_zeno();
        let journal = state
            .apply_program_call(sign(base + 12), owner, chain, 2)
            .unwrap();
        assert_eq!(state.programs.program(&id).unwrap().state_value, 1);
        assert_ne!(state.application_state_root().unwrap(), before_root);
        state.rollback_state(journal).unwrap();
        assert_eq!(state, before);
        assert_eq!(state.application_state_root().unwrap(), before_root);
    }
}

//

// XPQ Program execution through a restricted coin host

//

impl LedgerState {
    #[cfg(test)]
    fn execute_coin_program(
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

    fn execute_coin_program_with_applications(
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
    fn execute_coin_program_with_checkpoint(
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
    pub(crate) fn rollback_state(
        &mut self,

        journal: StateRollbackJournal,
    ) -> Result<(), StateError> {
        let mut staged = self.clone();

        if let Some(program) = journal.program {
            crate::program::rollback_program(&mut staged.programs, program)
                .map_err(|_| StateError::InvalidTransition)?;
        }

        if let Some(extension) = journal.extension {
            staged.extensions.assets.rollback(extension);
        }

        if let Some(coin) = journal.coin {
            staged.rollback_coin(coin)?;
        }

        *self = staged;

        Ok(())
    }

    pub(crate) fn rollback_coin(&mut self, journal: CoinRollbackJournal) -> Result<(), StateError> {
        let total_mined = self
            .coin
            .total_mined
            .checked_sub(journal.mined)
            .ok_or(StateError::AmountOverflow)?;

        let total_burned = self
            .coin
            .total_burned
            .checked_sub(journal.burned)
            .ok_or(StateError::BurnUnderflow)?;

        let mut created = std::collections::BTreeSet::new();

        for id in &journal.created_coin_ids {
            if !created.insert(*id) || self.utxos.coin(id).is_none() {
                return Err(StateError::InvalidTransition);
            }
        }

        let mut consumed = std::collections::BTreeSet::new();

        for (id, _) in &journal.consumed_coins {
            if !consumed.insert(*id) || (self.utxos.coin(id).is_some() && !created.contains(id)) {
                return Err(StateError::InvalidTransition);
            }
        }

        self.coin.total_mined = total_mined;

        self.coin.total_burned = total_burned;

        for id in journal.created_coin_ids {
            self.utxos.consume_coin(&id)?;
        }

        for (id, coin) in journal.consumed_coins {
            self.utxos.insert_coin(id, coin)?;
        }

        Ok(())
    }

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

impl LedgerState {
    /// Atomic execution of an authenticated program call.
    pub fn apply_deploy(
        &mut self,
        signed: crate::operation::AuthorizedDeployProgram,
        miner: ProgramId,
        chain: crate::common::ChainContext,
        height: crate::common::Height,
    ) -> Result<StateRollbackJournal, super::LedgerError> {
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
    ) -> Result<StateRollbackJournal, super::LedgerError> {
        let prepared = crate::consensus::validate_deploy(signed, chain, height, self)?;
        self.apply_prepared_deploy(prepared, miner, applications)
    }

    pub(crate) fn apply_prepared_deploy(
        &mut self,
        prepared: crate::consensus::PreparedDeploy,
        miner: ProgramId,
        applications: &dyn crate::program::application::ApplicationExecutor,
    ) -> Result<StateRollbackJournal, super::LedgerError> {
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
    ) -> Result<StateRollbackJournal, super::LedgerError> {
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

    /// Validation and both state transitions run on a clone, committed only on success.
    pub fn apply_program_call(
        &mut self,

        transaction: crate::program::AuthorizedProgramInvocation,

        miner: ProgramId,

        chain: crate::common::ChainContext,

        height: u64,
    ) -> Result<StateRollbackJournal, super::LedgerError> {
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
    ) -> Result<StateRollbackJournal, super::LedgerError> {
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
    ) -> Result<StateRollbackJournal, super::LedgerError> {
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
    ) -> Result<StateRollbackJournal, super::LedgerError> {
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
                        crate::program::system::asset_program::state::ExecutionContext {
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

#[cfg(test)]
mod coin_atomicity_tests {

    use super::*;

    use crate::{monetary::coin::CoinOutput, program::CoinCharges};

    use crypto::HASH_SIZE;

    fn program_id(byte: u8) -> ProgramId {
        ProgramId([byte; crypto::PROGRAM_ID_SIZE])
    }

    #[test]

    fn coin_coin_failure_after_each_mutation_restores_state_and_retry_root() {
        let owner = program_id(1);

        let input = CoinShare::from_bytes([3; crypto::HASH_SIZE]);

        let mut original = LedgerState::default();

        original.coin.total_mined = Zeno::from_zeno(100);

        original
            .utxos
            .insert_coin(
                input,
                CoinUtxo {
                    amount: Zeno::from_zeno(100),

                    owner: crate::common::Owner::Program(owner),
                },
            )
            .unwrap();

        let intent = CoinTransition::coin_with_charges(
            owner,
            vec![input],
            vec![CoinOutput::new(program_id(2), Zeno::from_zeno(70))],
            CoinCharges::new(Zeno::from_zeno(10)),
        )
        .unwrap();

        let commitment = AuthorizationCommitment::from_bytes([4; HASH_SIZE]);

        let mut expected = original.clone();

        expected
            .execute_coin_program(&intent, commitment, program_id(9))
            .unwrap();

        let expected_bytes = borsh::to_vec(&expected).unwrap();

        for point in [
            TransitionPoint::CoinInputConsumed,
            TransitionPoint::CoinOutputCreated,
            TransitionPoint::MinerFeeCreated,
            TransitionPoint::ProtocolBurnRecorded,
        ] {
            let mut state = original.clone();

            assert!(matches!(
                state.execute_coin_program_with_checkpoint(
                    &intent,
                    commitment,
                    program_id(9),
                    |seen| if seen == point {
                        Err(StateError::InvalidTransition)
                    } else {
                        Ok(())
                    },
                ),
                Err(StateError::InvalidTransition)
            ));

            assert_eq!(state, original, "failure at {point:?}");

            state
                .execute_coin_program(&intent, commitment, program_id(9))
                .unwrap();

            assert_eq!(borsh::to_vec(&state).unwrap(), expected_bytes);
        }
    }

    #[test]

    fn burn_accounting_and_invalid_rollback_journal_fail_without_partial_mutation() {
        let mut state = LedgerState::default();

        let mut journal = CoinRollbackJournal {
            burned: Zeno::from_zeno(u64::MAX),

            ..CoinRollbackJournal::default()
        };

        assert!(matches!(
            state.record_protocol_burn(Zeno::ONE, &mut journal),
            Err(StateError::BurnOverflow)
        ));

        assert_eq!(state.coin.total_burned, Zeno::ZERO);

        assert_eq!(journal.burned, Zeno::from_zeno(u64::MAX));

        state.coin.total_mined = Zeno::from_zeno(100);

        state.coin.total_burned = Zeno::from_zeno(5);

        let before = state.clone();

        let corrupt = CoinRollbackJournal {
            created_coin_ids: vec![CoinShare::from_bytes([9; crypto::HASH_SIZE])],

            mined: Zeno::from_zeno(10),

            burned: Zeno::ONE,

            ..CoinRollbackJournal::default()
        };

        assert!(matches!(
            state.rollback_coin(corrupt),
            Err(StateError::InvalidTransition)
        ));

        assert_eq!(state, before);
    }
}
