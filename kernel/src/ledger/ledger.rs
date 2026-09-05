use std::{collections::BTreeMap, error::Error, fmt};

use crate::blockchain::{Block, Chain, ChainError, Height};
use crate::coin::{Coin, CoinHash};
use crate::common::{
    Authority, ExtensionContext, ExtensionFailure, ExtensionStateRoot, domain_hash,
};
use crate::consensus::{
    ApplyBlockState, CoinInputState, ConsensusError, EmissionError, TransactionConsensusError,
    TransactionStateView, ValidatedBlock, initial_block_emission, validate_emission,
    validate_transaction,
};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, BlockHash, PublicKey};

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

    pub fn extension_state_root(&self) -> Result<ExtensionStateRoot, LedgerError> {
        self.state.application_state_root()
    }

    pub fn preview_block_state_root(
        &self,
        block: &Block,
    ) -> Result<ExtensionStateRoot, LedgerError> {
        self.preview_block_commitments(block).map(|(root, _)| root)
    }

    pub fn preview_block_commitments(
        &self,
        block: &Block,
    ) -> Result<(ExtensionStateRoot, u32), LedgerError> {
        let mut staged = self.state.clone();
        let mut block_weight =
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
        staged.assets.utxos.insert(CoinUtxo {
            coin: Coin::new(id, emission.miner_emission()),
            owner: Authority::Address(emission.recipient()),
        })?;
        staged.record_protocol_burn(
            emission.protocol_burn(),
            &mut UtxoRollbackJournal::default(),
        )?;

        for transaction in block.transactions() {
            if let crate::transaction::AuthorizedTransaction::Extension(transaction) = transaction {
                block_weight = block_weight
                    .checked_add(staged.extension_execution_weight(&transaction.call, height.0)?)
                    .ok_or(LedgerError::InvalidBlockWeight)?;
            }
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

    pub fn preview_extension_created_state_weight(
        &self,
        call: &crate::common::ExtensionCall,
        height: Height,
    ) -> Result<u64, LedgerError> {
        self.state
            .extension_created_state_weight_checked(call, height.0)
            .map_err(extension_error)
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
        let mut expected_block_weight =
            u64::try_from(block.weight()?).map_err(|_| LedgerError::InvalidBlockWeight)?;
        let mut block_journals = Vec::new();
        if let Some(emission) = validated.emission() {
            let id = CoinHash::from_emission_origin(&emission.origin().0);
            staged_state.assets.utxos.insert(CoinUtxo {
                coin: Coin::new(id, emission.miner_emission()),
                owner: Authority::Address(emission.recipient()),
            })?;
            let mut journal = UtxoRollbackJournal {
                created_coin_ids: vec![id],
                ..UtxoRollbackJournal::default()
            };
            staged_state.record_protocol_burn(emission.protocol_burn(), &mut journal)?;
            block_journals.push(StateRollbackJournal::Utxo(journal));
        }

        for transaction in block.transactions() {
            if let crate::transaction::AuthorizedTransaction::Extension(transaction) = transaction {
                expected_block_weight = expected_block_weight
                    .checked_add(
                        staged_state.extension_execution_weight(&transaction.call, height.0)?,
                    )
                    .ok_or(LedgerError::InvalidBlockWeight)?;
            }
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

        let extension_root = staged_state.application_state_root()?;
        if block.state_root().0 != *extension_root.as_bytes() {
            return Err(LedgerError::InvalidExtensionStateRoot);
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
    InvalidExtensionStateRoot,
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
            Self::InvalidExtensionStateRoot => {
                formatter.write_str("block extension state root does not match ledger")
            }
            Self::InvalidBlockWeight => {
                formatter.write_str("block execution weight does not match ledger")
            }
        }
    }
}

fn extension_error(error: ExtensionFailure) -> LedgerError {
    LedgerError::Spend(SpendStateError::Extension(error))
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
        self.assets.utxos.get(&id).map(|utxo| CoinInputState {
            amount: utxo.coin.amount,
            owner: match utxo.owner {
                Authority::Address(address) => Some(address),
                Authority::Extension(_) => None,
            },
        })
    }

    fn account_public_key(&self, address: Address) -> Option<PublicKey> {
        self.account_keys.get_account(&address).cloned()
    }

    fn asset_transition_created_state_weight(
        &self,
        call: &crate::transaction::AssetIntent,
        genesis_hash: [u8; 32],
    ) -> Result<u64, crate::asset::AssetError> {
        self.assets.validate_transition(call, genesis_hash)?;
        call.created_state_weight_from_presence(self.assets.nonces.contains_key(&call.signer))
    }

    fn extension_created_state_weight(
        &self,
        call: &crate::common::ExtensionCall,
        height: u64,
    ) -> Result<u64, ExtensionFailure> {
        self.extension_created_state_weight_checked(call, height)
    }
}

impl LedgerState {
    fn extension_execution_weight(
        &self,
        call: &crate::common::ExtensionCall,
        height: u64,
    ) -> Result<u64, LedgerError> {
        self.extensions
            .execution_weight(
                extension::production_registry(),
                ExtensionContext {
                    height: crate::common::Height(height),
                },
                call,
            )
            .map_err(extension_error)
    }

    fn extension_created_state_weight_checked(
        &self,
        call: &crate::common::ExtensionCall,
        height: u64,
    ) -> Result<u64, ExtensionFailure> {
        let preview = self.extensions.preview_created_state_weight(
            extension::production_registry(),
            ExtensionContext {
                height: crate::common::Height(height),
            },
            call,
        )?;
        let mut total = preview.created_state_weight;
        let mut assets = self.assets.clone();
        for (effect_index, effect) in preview.effects.into_iter().enumerate() {
            let execution_nonce =
                u64::try_from(effect_index).map_err(|_| ExtensionFailure::InvalidState)?;
            match effect {
                crate::common::ExtensionEffect::MintAsset {
                    asset_id,
                    recipient,
                    amount,
                } => {
                    let asset_id = crate::asset::AssetHash::from_bytes(asset_id);
                    let recipient = Authority::Address(Address(recipient));
                    let weight = assets
                        .program_mint_created_state_weight(
                            call.extension_id(),
                            asset_id,
                            recipient,
                            crate::asset::Unit::from_units(amount),
                        )
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                    total = total
                        .checked_add(weight)
                        .ok_or(ExtensionFailure::StateEntryLimit)?;
                    assets
                        .apply_program_mint(
                            call.extension_id(),
                            asset_id,
                            recipient,
                            crate::asset::Unit::from_units(amount),
                            [0; 32],
                            execution_nonce,
                        )
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                }
                crate::common::ExtensionEffect::TransferAsset {
                    asset_id,
                    recipient,
                    amount,
                } => {
                    let asset_id = crate::asset::AssetHash::from_bytes(asset_id);
                    let recipient = Address(recipient);
                    let amount = crate::asset::Unit::from_units(amount);
                    let (inputs, outputs) = assets
                        .program_transfer_plan(call.extension_id(), asset_id, recipient, amount)
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                    let weight = assets
                        .program_transfer_created_state_weight(
                            call.extension_id(),
                            asset_id,
                            &inputs,
                            &outputs,
                        )
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                    total = total
                        .checked_add(weight)
                        .ok_or(ExtensionFailure::StateEntryLimit)?;
                    assets
                        .apply_program_transfer(
                            call.extension_id(),
                            asset_id,
                            &inputs,
                            &outputs,
                            [0; 32],
                            execution_nonce,
                        )
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                }
                crate::common::ExtensionEffect::TransferCoin { amount, .. } => {
                    let weight =
                        preview_program_coin_transfer(&mut assets, call.extension_id(), amount)?;
                    total = total
                        .checked_add(weight)
                        .ok_or(ExtensionFailure::StateEntryLimit)?;
                }
            }
        }
        Ok(total)
    }
}

impl LedgerState {
    fn application_state_root(&self) -> Result<ExtensionStateRoot, LedgerError> {
        let extension = self.extensions.state_root().map_err(extension_error)?;
        if self.assets.is_empty() {
            return Ok(extension);
        }
        let asset = self
            .assets
            .state_root()
            .map_err(|error| LedgerError::Spend(SpendStateError::Asset(error)))?;
        let mut input = [0_u8; 64];
        input[..32].copy_from_slice(&asset);
        input[32..].copy_from_slice(extension.as_bytes());
        Ok(ExtensionStateRoot::from_bytes(domain_hash(
            b"xparq:application-state-root",
            &[&input],
        )))
    }
}

fn preview_program_coin_transfer(
    assets: &mut crate::ledger::AssetState,
    program: crate::common::ExtensionHash,
    amount: u64,
) -> Result<u64, ExtensionFailure> {
    if amount == 0 {
        return Err(ExtensionFailure::InvalidState);
    }

    let owner = Authority::Extension(program);
    let mut selected = Vec::new();
    let mut held = 0_u64;
    for utxo in assets.utxos.owned_by(owner) {
        selected.push(utxo.coin.utxo);
        held = held
            .checked_add(utxo.coin.amount.as_zeno())
            .ok_or(ExtensionFailure::InvalidState)?;
        if held >= amount {
            break;
        }
    }
    if held < amount {
        return Err(ExtensionFailure::InvalidState);
    }

    let outputs = if held == amount { 1 } else { 2 };
    let change = held - amount;
    for id in &selected {
        assets
            .utxos
            .consume(id)
            .map_err(|_| ExtensionFailure::InvalidState)?;
    }
    if change != 0 {
        let change_id = selected
            .first()
            .copied()
            .ok_or(ExtensionFailure::InvalidState)?;
        assets
            .utxos
            .insert(CoinUtxo {
                coin: Coin::new(change_id, crate::coin::Zeno::from_zeno(change)),
                owner,
            })
            .map_err(|_| ExtensionFailure::InvalidState)?;
    }

    Ok(outputs * crate::consensus::COIN_UTXO_STATE_WEIGHT)
}

#[cfg(test)]
mod extension_preview_tests {
    use super::*;

    #[test]
    fn sequential_coin_effects_cannot_reuse_extension_balance() {
        let program = crate::common::ExtensionHash::derive("preview.coin.vault");
        let mut assets = crate::ledger::AssetState::default();
        assets
            .utxos
            .insert(CoinUtxo {
                coin: Coin::new(
                    CoinHash::from_bytes([0x71; 32]),
                    crate::coin::Zeno::from_zeno(10),
                ),
                owner: Authority::Extension(program),
            })
            .unwrap();

        assert!(preview_program_coin_transfer(&mut assets, program, 7).is_ok());
        assert_eq!(
            preview_program_coin_transfer(&mut assets, program, 7),
            Err(ExtensionFailure::InvalidState)
        );
    }

    #[test]
    fn ledger_rejects_unearned_execution_weight() {
        let mut block = Block::genesis().unwrap();
        block.set_block_weight(block.block_weight() + 1);
        let expected_hash = block.hash().unwrap();
        let mut ledger = Ledger::new();

        assert!(matches!(
            crate::consensus::apply_genesis(&mut ledger, block, expected_hash),
            Err(LedgerError::InvalidBlockWeight)
        ));
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
