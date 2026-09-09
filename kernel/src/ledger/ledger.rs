use std::{collections::BTreeMap, error::Error as StdError, fmt};

use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{Address, BlockHash, HashDomain, PublicKey, StateRoot, canonical_bytes, domain};

use crate::blockchain::{Block, Chain, ChainError, Height};

use crate::native::coin::XPQ;

use crate::consensus::{
    ApplyBlockState, CoinInputState, ConsensusError, EmissionError, TransactionConsensusError,
    TransactionStateView, ValidatedBlock, initial_block_emission, validate_emission,
    validate_transaction,
};

use crate::ledger::{LedgerState, SpendRollbackJournal, StateError, StateRollbackJournal};

//
// Ledger
//

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub chain: Chain,
    pub state: LedgerState,

    journals: BTreeMap<Height, Vec<StateRollbackJournal>>,

    chain_context: Option<crate::transaction::ChainContext>,
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
        let mut staged = self.state.clone();

        let block_weight =
            u64::try_from(block.weight()?).map_err(|_| LedgerError::InvalidBlockWeight)?;

        let height = block.height();

        let chain_context = self.chain_context.ok_or(LedgerError::EmptyChain)?;

        let parent_emission = if height.0 <= 1 {
            initial_block_emission()
        } else {
            self.chain
                .block(&Height(height.0 - 1))
                .and_then(Block::emission)
                .map(|emission| emission.subsidy)
                .ok_or(LedgerError::MissingParentEmission)?
        };

        let emission = validate_emission(block, parent_emission, |height| {
            self.chain.header(&height).map(|header| header.block_weight)
        })?;

        //
        // Emission creates one XPQ UTXO.
        //
        // The ownerless UTXO value is paired with its canonical origin index.
        //
        let id = XPQ::from_emission_origin(&emission.origin().0);

        staged.utxos.insert_coin(id, emission.miner_emission())?;
        staged.coin_recipients.insert(id, block.miner_address());

        let mut emission_journal = SpendRollbackJournal {
            created_coin_ids: vec![id],
            ..SpendRollbackJournal::default()
        };

        staged.record_protocol_burn(emission.protocol_burn(), &mut emission_journal)?;

        //
        // Validate and execute transactions against staged state.
        //
        for transaction in block.transactions() {
            let validated =
                validate_transaction(transaction.clone(), chain_context, height.0, &staged)?;

            staged.apply_validated_transaction(
                &validated,
                height,
                block.miner_address(),
                chain_context,
            )?;
        }

        let block_weight =
            u32::try_from(block_weight).map_err(|_| LedgerError::InvalidBlockWeight)?;

        Ok((staged.application_state_root()?, block_weight))
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

        let miner = block.miner_address();

        let chain_context = match self.chain_context {
            Some(chain_context) => chain_context,

            None => {
                let genesis = self.chain.block(&Height(0)).unwrap_or(block);

                crate::transaction::ChainContext::new(genesis.hash()?.into_bytes())
            }
        };

        let mut staged_state = self.state.clone();

        let expected_block_weight =
            u64::try_from(block.weight()?).map_err(|_| LedgerError::InvalidBlockWeight)?;

        let mut block_journals = Vec::new();

        //
        // Apply block emission.
        //
        if let Some(emission) = validated.emission() {
            let id = XPQ::from_emission_origin(&emission.origin().0);

            staged_state
                .utxos
                .insert_coin(id, emission.miner_emission())?;
            staged_state.coin_recipients.insert(id, miner);

            let mut journal = SpendRollbackJournal {
                created_coin_ids: vec![id],
                ..SpendRollbackJournal::default()
            };

            staged_state.record_protocol_burn(emission.protocol_burn(), &mut journal)?;

            block_journals.push(StateRollbackJournal::Spend(journal));
        }

        //
        // Execute validated transactions.
        //
        for transaction in block.transactions() {
            let validated_transaction =
                validate_transaction(transaction.clone(), chain_context, height.0, &staged_state)?;

            let journal = staged_state.apply_validated_transaction(
                &validated_transaction,
                height,
                miner,
                chain_context,
            )?;

            block_journals.push(journal);
        }

        //
        // Verify block weight.
        //
        if expected_block_weight != u64::from(block.block_weight()) {
            return Err(LedgerError::InvalidBlockWeight);
        }

        //
        // Verify canonical state root.
        //
        let state_root = staged_state.application_state_root()?;

        if block.state_root() != state_root {
            return Err(LedgerError::InvalidStateRoot);
        }

        //
        // Commit chain + state atomically.
        //
        let mut staged_chain = self.chain.clone();

        staged_chain.insert_block(block.clone())?;

        self.state = staged_state;

        self.chain = staged_chain;

        self.chain_context = Some(chain_context);

        self.journals.insert(height, block_journals);

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
        self.utxos.coin(&id).map(|amount| CoinInputState { amount })
    }

    fn coin_recipient(&self, id: XPQ) -> Option<Address> {
        self.coin_recipients.get(&id).copied()
    }

    fn share_recipient(&self, id: crate::native::asset::Share) -> Option<Address> {
        self.assets.share_recipients.get(&id).copied()
    }

    fn account_public_key(&self, address: Address) -> Option<PublicKey> {
        self.account_keys.get_account(&address).cloned()
    }

    fn asset_spend_created_state_weight(
        &self,
        intent: &crate::transaction::SpendIntent,
    ) -> Result<u64, crate::native::asset::AssetError> {
        let (asset, inputs, outputs) = intent
            .asset_parts()
            .ok_or(crate::native::asset::AssetError::InvalidProgram)?;

        self.assets.user_transfer_created_state_weight(
            &self.utxos,
            intent.signer,
            asset,
            inputs,
            outputs,
        )
    }

    fn asset_transition_created_state_weight(
        &self,
        call: &crate::transaction::AssetIntent,
        genesis_hash: [u8; 32],
    ) -> Result<u64, crate::native::asset::AssetError> {
        self.assets
            .validate_transition(&self.utxos, call, genesis_hash)?;

        call.created_state_weight_from_presence(self.assets.nonces.contains_key(&call.signer))
    }
}

//
// Canonical application state root
//

impl LedgerState {
    pub(crate) fn application_state_root(&self) -> Result<StateRoot, LedgerError> {
        if self.account_keys.is_empty()
            && self.assets.is_empty()
            && self.utxos.is_empty()
            && self.total_burned.is_zero()
            && self.coin_recipients.is_empty()
        {
            return Ok(StateRoot::ZERO);
        }

        let state = canonical_bytes(&(
            &self.account_keys,
            &self.utxos,
            &self.assets,
            self.total_burned,
            &self.coin_recipients,
        ))?;

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
