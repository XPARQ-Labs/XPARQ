use std::{collections::BTreeMap, error::Error, fmt};

use crate::blockchain::{Block, Chain, ChainError, Height};
use crate::coin::{Coin, CoinHash};
use crate::common::{canonical_bytes, domain_hash};
use crate::consensus::{
    ApplyBlockState, CoinInputState, ConsensusError, EmissionError, TransactionConsensusError,
    TransactionStateView, ValidatedBlock, initial_block_emission, validate_emission,
    validate_transaction,
};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, BlockHash, PublicKey, StateRoot};

use crate::ledger::{
    CoinUtxo, LedgerState, SpendStateError, StateRollbackJournal, UtxoRollbackJournal,
};

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

    pub fn preview_block_state_root(
        &self,
        block: &Block,
    ) -> Result<StateRoot, LedgerError> {
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
        let id = CoinHash::from_emission_origin(&emission.origin().0);
        staged.utxos.insert(CoinUtxo {
            coin: Coin::new(id, emission.miner_emission()),
            owner: emission.recipient(),
        })?;
        staged.record_protocol_burn(
            emission.protocol_burn(),
            &mut UtxoRollbackJournal::default(),
        )?;

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

    pub fn rollback_tip(&mut self) -> Result<crate::blockchain::Block, LedgerError> {
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
                crate::transaction::ChainContext::new(genesis.hash()?.0)
            }
        };
        let mut staged_state = self.state.clone();
        let expected_block_weight =
            u64::try_from(block.weight()?).map_err(|_| LedgerError::InvalidBlockWeight)?;
        let mut block_journals = Vec::new();
        if let Some(emission) = validated.emission() {
            let id = CoinHash::from_emission_origin(&emission.origin().0);
            staged_state.utxos.insert(CoinUtxo {
                coin: Coin::new(id, emission.miner_emission()),
                owner: emission.recipient(),
            })?;
            let mut journal = UtxoRollbackJournal {
                created_coin_ids: vec![id],
                ..UtxoRollbackJournal::default()
            };
            staged_state.record_protocol_burn(emission.protocol_burn(), &mut journal)?;
            block_journals.push(StateRollbackJournal::Utxo(journal));
        }

        for transaction in block.transactions() {
            let authorized =
                validate_transaction(transaction.clone(), chain_context, height.0, &staged_state)?;
            let journal = staged_state.apply_validated_transaction(
                &authorized,
                height,
                miner,
                chain_context,
            )?;
            block_journals.push(journal);
        }

        if expected_block_weight != u64::from(block.block_weight()) {
            return Err(LedgerError::InvalidBlockWeight);
        }

        let state_root = staged_state.application_state_root()?;
        if block.state_root() != state_root {
            return Err(LedgerError::InvalidStateRoot);
        }

        let mut staged_chain = self.chain.clone();
        staged_chain.insert_block(block.clone())?;
        self.state = staged_state;
        self.chain = staged_chain;
        self.chain_context = Some(chain_context);
        self.journals.insert(height, block_journals);
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

#[derive(Debug)]
pub enum LedgerError {
    Consensus(ConsensusError),
    Transaction(TransactionConsensusError),
    Spend(SpendStateError),
    Chain(ChainError),
    EmptyChain,
    MissingParentEmission,
    Emission(EmissionError),
    MissingRollbackJournal,
    InvalidStateRoot,
    InvalidBlockWeight,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(error) => write!(formatter, "consensus validation failed: {error}"),
            Self::Transaction(error) => write!(formatter, "transaction validation failed: {error}"),
            Self::Spend(error) => write!(formatter, "ledger transition failed: {error}"),
            Self::Chain(error) => write!(formatter, "chain transition failed: {error}"),
            Self::EmptyChain => formatter.write_str("ledger chain is empty"),
            Self::MissingParentEmission => formatter.write_str("parent emission is missing"),
            Self::Emission(error) => write!(formatter, "emission validation failed: {error}"),
            Self::MissingRollbackJournal => formatter.write_str("rollback journal is missing"),
            Self::InvalidStateRoot => {
                formatter.write_str("block state root does not match ledger")
            }
            Self::InvalidBlockWeight => {
                formatter.write_str("block execution weight does not match ledger")
            }
        }
    }
}

impl Error for LedgerError {}

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

impl From<SpendStateError> for LedgerError {
    fn from(error: SpendStateError) -> Self {
        Self::Spend(error)
    }
}

impl From<crate::ledger::UtxoError> for LedgerError {
    fn from(error: crate::ledger::UtxoError) -> Self {
        Self::Spend(SpendStateError::Utxo(error))
    }
}

impl TransactionStateView for LedgerState {
    fn coin(&self, id: CoinHash) -> Option<CoinInputState> {
        self.utxos.get(&id).map(|utxo| CoinInputState {
            amount: utxo.coin.amount,
            owner: utxo.owner,
        })
    }

    fn account_public_key(&self, address: Address) -> Option<PublicKey> {
        self.account_keys.get_account(&address).cloned()
    }

    fn asset_spend_created_state_weight(
        &self,
        intent: &crate::transaction::SpendIntent,
    ) -> Result<u64, crate::asset::AssetError> {
        let (asset, inputs, outputs) = intent
            .asset_parts()
            .ok_or(crate::asset::AssetError::InvalidProgram)?;
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
    ) -> Result<u64, crate::asset::AssetError> {
        self.assets
            .validate_transition(&self.utxos, call, genesis_hash)?;
        call.created_state_weight_from_presence(self.assets.nonces.contains_key(&call.signer))
    }

}

impl LedgerState {
    fn application_state_root(&self) -> Result<StateRoot, LedgerError> {
        if self.assets.is_empty() && self.utxos.is_empty() {
            return Ok(StateRoot::ZERO);
        }
        let state = canonical_bytes(&(&self.assets, &self.utxos))?;
        Ok(StateRoot(domain_hash(
            b"xparq:ledger-asset-and-utxo-state-v3",
            &[&state],
        )))
    }
}

impl From<ChainError> for LedgerError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl From<crate::common::CodecError> for LedgerError {
    fn from(error: crate::common::CodecError) -> Self {
        Self::Consensus(ConsensusError::Serialization(error))
    }
}
