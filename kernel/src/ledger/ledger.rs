use std::{collections::BTreeMap, error::Error as StdError, fmt};

use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{BlockHash, HashDomain, StateRoot, canonical_bytes, domain};

use crate::{
    blockchain::{Block, Chain, ChainError},
    common::Height,
    consensus::{
        ApplyBlockState, CoinInputState, ConsensusError, EmissionError, TransactionConsensusError,
        TransactionStateView, ValidatedBlock, validate_emission, validate_transaction,
    },
    ledger::{CoinUtxo, LedgerState, SpendRollbackJournal, StateError, StateRollbackJournal},
    native::coin::XPQ,
};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub chain: Chain,
    pub state: LedgerState,

    journals: BTreeMap<Height, Vec<StateRollbackJournal>>,

    chain_context: Option<crate::common::ChainContext>,
}

struct ExecutedBlock {
    state: LedgerState,
    journals: Vec<StateRollbackJournal>,
    state_root: StateRoot,
    block_weight: u32,
    chain_context: crate::common::ChainContext,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tip_height(&self) -> Option<Height> {
        self.chain.tip_height()
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.chain.tip_hash()
    }

    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    pub fn state_root(&self) -> Result<StateRoot, LedgerError> {
        self.state.application_state_root()
    }

    pub fn transaction_protocol_burns(
        &self,
        height: Height,
    ) -> Option<Vec<crate::native::coin::Zeno>> {
        let block = self.chain.block(&height)?;
        let journals = self.journals.get(&height)?;
        let offset = usize::from(block.emission().is_some());
        let transaction_journals = journals.get(offset..)?;
        if transaction_journals.len() != block.transactions().len() {
            return None;
        }
        Some(
            transaction_journals
                .iter()
                .map(StateRollbackJournal::protocol_burn)
                .collect(),
        )
    }

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

    fn execute_block(&self, block: &Block) -> Result<ExecutedBlock, LedgerError> {
        let mut state = self.state.clone();
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
            let id = XPQ::from_emission_origin(&emission.origin().0);
            state.utxos.insert_coin(
                id,
                CoinUtxo {
                    amount: emission.miner_emission(),
                    owner: block.miner_address(),
                },
            )?;
            state.coin.total_mined = state
                 .coin
                 .total_mined
                 .checked_add(emission.subsidy())
                 .ok_or(StateError::AmountOverflow)?;

            let mut spend = SpendRollbackJournal {
                created_coin_ids: vec![id],
                ..SpendRollbackJournal::default()
            };
            state.record_protocol_burn(emission.protocol_burn(), &mut spend)?;
            journals.push(StateRollbackJournal {
                spend: Some(spend),
                asset: None,
            });
        }

        for transaction in block.transactions() {
            let validated =
                validate_transaction(transaction.clone(), chain_context, height.0, &state)?;
            journals.push(state.apply_validated_transaction(
                &validated,
                block.miner_address(),
                chain_context,
            )?);
        }

        let state_root = state.application_state_root()?;
        Ok(ExecutedBlock {
            state,
            journals,
            state_root,
            block_weight,
            chain_context,
        })
    }

    pub fn rollback_tip(&mut self) -> Result<Block, LedgerError> {
        let height = self.chain.tip_height().ok_or(LedgerError::EmptyChain)?;

        let hash = self.chain.tip_hash().ok_or(LedgerError::EmptyChain)?;

        let journals = self
            .journals
            .get(&height)
            .cloned()
            .ok_or(LedgerError::MissingRollbackJournal)?;

        let mut staged_state = self.state.clone();

        for journal in journals.into_iter().rev() {
            staged_state.rollback_state(journal)?;
        }

        let mut staged_chain = self.chain.clone();

        let block = staged_chain.remove_tip(hash)?;

        self.state = staged_state;

        self.chain = staged_chain;

        self.journals.remove(&height);

        if self.chain.tip_height().is_none() {
            self.chain_context = None;
        }

        Ok(block)
    }

    fn apply_validated_block(&mut self, validated: ValidatedBlock) -> Result<(), LedgerError> {
        let block = validated.block();
        let height = block.height();
        let executed = self.execute_block(block)?;

        if executed.block_weight != block.block_weight() {
            return Err(LedgerError::InvalidBlockWeight);
        }
        if block.state_root() != executed.state_root {
            return Err(LedgerError::InvalidStateRoot);
        }
        let mut staged_chain = self.chain.clone();
        staged_chain.insert_block(block.clone())?;
        self.state = executed.state;
        self.chain = staged_chain;
        self.chain_context = Some(executed.chain_context);
        self.journals.insert(height, executed.journals);
        Ok(())
    }
}

//
// Consensus state interface
//

impl ApplyBlockState for Ledger {
    type Error = LedgerError;

    fn consensus_chain(&self) -> &Chain {
        &self.chain
    }

    fn commit_validated_block(&mut self, block: ValidatedBlock) -> Result<(), Self::Error> {
        self.apply_validated_block(block)
    }
}

//
// Transaction state view
//

impl TransactionStateView for LedgerState {
    fn coin(&self, id: XPQ) -> Option<CoinInputState> {
        self.utxos.coin(&id).map(|coin| CoinInputState {
            amount: coin.amount,
            owner: coin.owner,
        })
    }

    fn asset_share(
        &self,
        id: crate::native::asset::Share,
    ) -> Option<crate::native::asset::AssetShare> {
        self.utxos.asset(&id).copied()
    }

    fn asset_spend_created_state_weight(
        &self,
        intent: &crate::transaction::SpendIntent,
    ) -> Result<u64, crate::native::asset::AssetError> {
        let (asset, inputs, outputs) = intent
            .asset_parts()
            .ok_or(crate::native::asset::AssetError::InvalidProgram)?;

        self.assets
            .account_transfer_created_state_weight(&self.utxos, asset, inputs, outputs)
    }

    fn asset_transition_created_state_weight(
        &self,
        call: &crate::transaction::AssetIntent,
        genesis_hash: [u8; 32],
    ) -> Result<u64, crate::native::asset::AssetError> {
        self.assets
            .validate_transition(&self.utxos, call, genesis_hash)?;

        call.created_state_weight()
    }
}

//
// Canonical application state root
//

impl LedgerState {
    pub(crate) fn application_state_root(&self) -> Result<StateRoot, LedgerError> {
        if self.assets.is_empty() && self.utxos.is_empty() && self.coin.total_mined.is_zero() && self.coin.total_burned.is_zero() {
            return Ok(StateRoot::ZERO);
        }

        let state = canonical_bytes(&(&self.utxos, &self.coin, &self.assets))?;

        Ok(StateRoot(
            domain(HashDomain::ProtocolState, &state).into_bytes(),
        ))
    }
}

//
// Ledger errors
//

#[derive(Debug)]
pub enum LedgerError {
    Consensus(ConsensusError),

    Transaction(TransactionConsensusError),

    State(StateError),

    Chain(ChainError),

    Emission(EmissionError),

    EmptyChain,

    MissingParentEmission,

    MissingRollbackJournal,

    InvalidStateRoot,

    InvalidBlockWeight,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(error) => {
                write!(formatter, "consensus validation failed: {error}")
            }

            Self::Transaction(error) => {
                write!(formatter, "transaction validation failed: {error}")
            }

            Self::State(error) => {
                write!(formatter, "ledger state transition failed: {error}")
            }

            Self::Chain(error) => {
                write!(formatter, "chain transition failed: {error}")
            }

            Self::Emission(error) => {
                write!(formatter, "emission validation failed: {error}")
            }

            Self::EmptyChain => formatter.write_str("ledger chain is empty"),

            Self::MissingParentEmission => formatter.write_str("parent emission is missing"),

            Self::MissingRollbackJournal => formatter.write_str("rollback journal is missing"),

            Self::InvalidStateRoot => formatter.write_str("block state root does not match ledger"),

            Self::InvalidBlockWeight => {
                formatter.write_str("block execution weight does not match ledger")
            }
        }
    }
}

impl StdError for LedgerError {}

impl From<ConsensusError> for LedgerError {
    fn from(error: ConsensusError) -> Self {
        Self::Consensus(error)
    }
}

impl From<TransactionConsensusError> for LedgerError {
    fn from(error: TransactionConsensusError) -> Self {
        Self::Transaction(error)
    }
}

impl From<EmissionError> for LedgerError {
    fn from(error: EmissionError) -> Self {
        Self::Emission(error)
    }
}

impl From<StateError> for LedgerError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<crate::ledger::utxo::Error> for LedgerError {
    fn from(error: crate::ledger::utxo::Error) -> Self {
        Self::State(StateError::Utxo(error))
    }
}

impl From<ChainError> for LedgerError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl From<crypto::CodecError> for LedgerError {
    fn from(_error: crypto::CodecError) -> Self {
        Self::Consensus(ConsensusError::Serialization)
    }
}
