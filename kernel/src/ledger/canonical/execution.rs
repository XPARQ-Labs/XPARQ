//! Staged block execution, commitment previews, and canonical commit.

use super::accounting::{coin_utxo_total, expected_coin_burn, validate_block_accounting};
use super::{Ledger, LedgerError};
use crate::{
    blockchain::{Block, Chain},
    common::Owner,
    consensus::{ApplyBlockState, ValidatedBlock, validate_deploy, validate_emission},
    ledger::{CoinRollbackJournal, CoinUtxo, LedgerState, StateError, StateRollbackJournal},
    monetary::coin::{CoinShare, Zeno},
};
use crypto::StateRoot;

pub(super) struct ExecutedBlock {
    pub(super) state: LedgerState,

    pub(super) journals: Vec<StateRollbackJournal>,

    pub(super) state_root: StateRoot,

    pub(super) block_weight: u32,

    pub(super) chain_context: crate::common::ChainContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]

pub(super) enum BlockTransitionPoint {
    EmissionCreated,

    BeforeAccountingCheck,
}

impl Ledger {
    pub fn preview_block_state_root(&self, block: &Block) -> Result<StateRoot, LedgerError> {
        self.preview_block_commitments(block).map(|(root, _)| root)
    }

    pub fn preview_block_commitments(
        &self,

        block: &Block,
    ) -> Result<(StateRoot, u32), LedgerError> {
        let executed = self.execute_block(block)?;

        Ok((executed.state_root, executed.block_weight))
    }

    pub(super) fn execute_block(&self, block: &Block) -> Result<ExecutedBlock, LedgerError> {
        self.execute_block_with_checkpoint(block, |_, _| Ok(()))
    }

    pub(super) fn execute_block_with_checkpoint(
        &self,

        block: &Block,

        mut checkpoint: impl FnMut(BlockTransitionPoint, &mut LedgerState) -> Result<(), LedgerError>,
    ) -> Result<ExecutedBlock, LedgerError> {
        self.chain.validate_next_block(block)?;

        match self.chain.tip_height() {
            Some(height) => {
                let tip = self.chain.block(&height).ok_or(LedgerError::EmptyChain)?;

                if self.state_root()? != tip.state_root() {
                    return Err(LedgerError::InvalidPriorStateRoot);
                }
            }

            None if self.state_root()? != StateRoot::ZERO => {
                return Err(LedgerError::InvalidPriorStateRoot);
            }

            None => {}
        }

        let mut state = self.state.clone();

        let coin_supply_before = coin_utxo_total(&state)?;

        let mut validated_subsidy = Zeno::ZERO;

        let mut expected_burns = Zeno::ZERO;

        let mut journals = Vec::new();

        let block_weight =
            u32::try_from(block.weight()?).map_err(|_| LedgerError::InvalidBlockWeight)?;

        let height = block.height();

        let chain_context = match self.chain_context {
            Some(context) => context,

            None if block.is_genesis() => {
                crate::common::ChainContext::new(block.hash()?.into_bytes())
            }

            None => return Err(LedgerError::EmptyChain),
        };

        if !block.is_genesis() {
            let emission = validate_emission(block)?;

            validated_subsidy = emission.subsidy();

            expected_burns = emission.protocol_burn();

            let id = CoinShare::from_emission(&emission.origin().0);

            state.utxos.insert_coin(
                id,
                CoinUtxo {
                    amount: emission.miner_emission(),

                    owner: Owner::Program(emission.recipient()),
                },
            )?;

            checkpoint(BlockTransitionPoint::EmissionCreated, &mut state)?;

            state.coin.total_mined = state
                .coin
                .total_mined
                .checked_add(emission.subsidy())
                .ok_or(StateError::AmountOverflow)?;

            let mut coin = CoinRollbackJournal {
                created_coin_ids: vec![id],

                mined: emission.subsidy(),

                ..CoinRollbackJournal::default()
            };

            state.record_protocol_burn(emission.protocol_burn(), &mut coin)?;

            journals.push(StateRollbackJournal {
                coin: Some(coin),
                program: None,
                extension: None,
            });
        }

        for operation in block.operations() {
            match operation {
                crate::operation::BlockOperation::ProgramCall(tx) => {
                    let prepared =
                        crate::consensus::program_call::validate_program_call_with_applications(
                            (**tx).clone(),
                            chain_context,
                            height.0,
                            &state,
                            self.applications.executor(),
                        )?;

                    let coin = &prepared.invocation.payment;

                    let burn = expected_coin_burn(&state, coin)?;

                    expected_burns = expected_burns
                        .checked_add(burn)
                        .ok_or(LedgerError::SupplyOverflow)?;

                    journals.push(
                        state
                            .apply_prepared_program_call_in_staged_state(
                                prepared,
                                block.miner_program_id(),
                                chain_context,
                                self.applications.executor(),
                            )
                            .map_err(|_| StateError::InvalidTransition)?,
                    );
                }

                crate::operation::BlockOperation::DeployProgram(signed) => {
                    let prepared =
                        validate_deploy((**signed).clone(), chain_context, height, &state)?;
                    let burn = expected_coin_burn(&state, &prepared.signed.payment)?;
                    expected_burns = expected_burns
                        .checked_add(burn)
                        .ok_or(LedgerError::SupplyOverflow)?;
                    journals.push(state.apply_prepared_deploy_in_staged_state(
                        prepared,
                        block.miner_program_id(),
                        self.applications.executor(),
                    )?);
                }
            }
        }

        checkpoint(BlockTransitionPoint::BeforeAccountingCheck, &mut state)?;

        validate_block_accounting(
            coin_supply_before,
            &state,
            validated_subsidy,
            expected_burns,
        )?;

        state.validate_supply_invariants()?;

        let state_root = state.application_state_root()?;

        Ok(ExecutedBlock {
            state,

            journals,

            state_root,

            block_weight,

            chain_context,
        })
    }

    pub(super) fn apply_validated_block(
        &mut self,
        validated: ValidatedBlock,
    ) -> Result<(), LedgerError> {
        let block = validated.block();

        let height = block.height();

        let executed = self.execute_block(block)?;

        if executed.block_weight != block.block_weight() {
            return Err(LedgerError::InvalidBlockWeight);
        }

        if block.state_root() != executed.state_root {
            return Err(LedgerError::InvalidStateRoot);
        }

        // All fallible insertion checks precede mutation. Execution stays staged,
        // but committing one block no longer clones the entire chain history.
        self.chain.insert_block(block.clone())?;

        self.state = executed.state;

        self.chain_context = Some(executed.chain_context);

        self.journals.insert(height, executed.journals);

        Ok(())
    }
}

impl ApplyBlockState for Ledger {
    type Error = LedgerError;

    fn consensus_chain(&self) -> &Chain {
        &self.chain
    }

    fn commit_validated_block(&mut self, block: ValidatedBlock) -> Result<(), Self::Error> {
        self.apply_validated_block(block)
    }
}
