use std::{collections::BTreeMap, error::Error, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_blockchain::{Chain, ChainError, Height};
use xparq_coin::{Coin, CoinHash};
use xparq_common::{ExtensionContext, ExtensionFailure, ExtensionStateRoot};
use xparq_consensus::{
    ApplyBlockState, CoinInputState, ConsensusError, QCashInputState, TransactionConsensusError,
    TransactionStateView, ValidatedBlock, validate_transaction,
};
use xparq_crypto::{Address, BlockHash, ProfilePublicKey};
use xparq_transaction::AuthorizedTransaction;

use crate::{
    CoinOwner, CoinUtxo, LedgerState, SpendStateError, StateRollbackJournal, UtxoRollbackJournal,
};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub chain: Chain,
    pub state: LedgerState,
    journals: BTreeMap<Height, Vec<StateRollbackJournal>>,
    chain_context: Option<xparq_transaction::ChainContext>,
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

    pub fn preview_extension_state_root(
        &self,
        transactions: &[AuthorizedTransaction],
        height: Height,
    ) -> Result<ExtensionStateRoot, LedgerError> {
        let mut staged = self.state.clone();
        for transaction in transactions {
            match transaction {
                AuthorizedTransaction::Asset(transaction) => {
                    staged
                        .assets
                        .apply(&transaction.call.intent)
                        .map_err(|error| LedgerError::Spend(SpendStateError::Asset(error)))?;
                }
                AuthorizedTransaction::Extension(transaction) => {
                    let applied = staged
                        .extensions
                        .apply(
                            xparq_extension::production_registry(),
                            ExtensionContext { height },
                            &transaction.call,
                        )
                        .map_err(extension_error)?;
                    for effect in applied.effects {
                        match effect {
                            xparq_common::ExtensionEffect::MintAsset {
                                asset_id,
                                recipient,
                                amount,
                            } => {
                                staged
                                    .assets
                                    .apply_program_mint(
                                        transaction.call.extension_id(),
                                        xparq_asset::AssetHash::from_bytes(asset_id),
                                        Address(recipient),
                                        amount,
                                    )
                                    .map_err(|error| {
                                        LedgerError::Spend(SpendStateError::Asset(error))
                                    })?;
                            }
                            xparq_common::ExtensionEffect::TransferAsset {
                                asset_id,
                                recipient,
                                amount,
                            } => {
                                staged
                                    .assets
                                    .apply_program_transfer(
                                        transaction.call.extension_id(),
                                        xparq_asset::AssetHash::from_bytes(asset_id),
                                        Address(recipient),
                                        amount,
                                    )
                                    .map_err(|error| {
                                        LedgerError::Spend(SpendStateError::Asset(error))
                                    })?;
                            }
                            xparq_common::ExtensionEffect::TransferCoin { .. } => {}
                        };
                    }
                }
                _ => {}
            }
        }
        staged.application_state_root()
    }

    pub fn preview_extension_created_state_weight(
        &self,
        call: &xparq_common::ExtensionCall,
        height: Height,
    ) -> Result<u64, LedgerError> {
        self.state
            .extension_created_state_weight_checked(call, height.0)
            .map_err(extension_error)
    }

    pub fn rollback_tip(&mut self) -> Result<xparq_blockchain::Block, LedgerError> {
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
                xparq_transaction::ChainContext::new(genesis.hash()?.0)
            }
        };
        let mut staged_state = self.state.clone();
        let mut block_journals = Vec::new();
        if let Some(emission) = validated.emission() {
            let id = CoinHash::from_emission_origin(&emission.origin().0);
            staged_state.coins.insert(CoinUtxo {
                coin: Coin::new(id, emission.miner_emission()),
                owner: emission.recipient().into(),
            })?;
            let mut journal = UtxoRollbackJournal {
                created_coin_ids: vec![id],
                ..UtxoRollbackJournal::default()
            };
            staged_state.record_protocol_burn(emission.state_burn(), &mut journal)?;
            block_journals.push(StateRollbackJournal::Utxo(journal));
        }

        for transaction in block.transactions() {
            let authorized =
                validate_transaction(transaction.clone(), chain_context, height.0, &staged_state)?;
            let journal = staged_state.apply_validated_transaction(&authorized, height, miner)?;
            block_journals.push(journal);
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
    MissingRollbackJournal,
    InvalidExtensionStateRoot,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Consensus(error) => write!(formatter, "consensus validation failed: {error}"),
            Self::Transaction(error) => write!(formatter, "transaction validation failed: {error}"),
            Self::Spend(error) => write!(formatter, "ledger transition failed: {error}"),
            Self::Chain(error) => write!(formatter, "chain transition failed: {error}"),
            Self::EmptyChain => formatter.write_str("ledger chain is empty"),
            Self::MissingRollbackJournal => formatter.write_str("rollback journal is missing"),
            Self::InvalidExtensionStateRoot => {
                formatter.write_str("block extension state root does not match ledger")
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

impl From<SpendStateError> for LedgerError {
    fn from(error: SpendStateError) -> Self {
        Self::Spend(error)
    }
}

impl From<crate::UtxoError> for LedgerError {
    fn from(error: crate::UtxoError) -> Self {
        Self::Spend(SpendStateError::Utxo(error))
    }
}

impl TransactionStateView for LedgerState {
    fn coin(&self, id: CoinHash) -> Option<CoinInputState> {
        self.coins.get(&id).map(|utxo| CoinInputState {
            amount: utxo.coin.amount,
            owner: match utxo.owner {
                CoinOwner::Account(address) => Some(address),
                CoinOwner::Extension(_) => None,
            },
        })
    }

    fn qcash(&self, id: CoinHash) -> Option<QCashInputState> {
        self.qcash.get(&id).map(|utxo| QCashInputState {
            amount: utxo.coin.amount,
            public_key: utxo.public_key,
        })
    }

    fn profile_public_key(&self, address: Address) -> Option<ProfilePublicKey> {
        self.account_keys.get_profile(&address).cloned()
    }

    fn asset_state(&self) -> Option<&xparq_asset::AssetState> {
        Some(&self.assets)
    }

    fn extension_created_state_weight(
        &self,
        call: &xparq_common::ExtensionCall,
        height: u64,
    ) -> u64 {
        self.extension_created_state_weight_checked(call, height)
            .unwrap_or(0)
    }
}

impl LedgerState {
    fn extension_created_state_weight_checked(
        &self,
        call: &xparq_common::ExtensionCall,
        height: u64,
    ) -> Result<u64, ExtensionFailure> {
        let preview = self.extensions.preview_created_state_weight(
            xparq_extension::production_registry(),
            ExtensionContext {
                height: xparq_common::Height(height),
            },
            call,
        )?;
        let mut total = preview.created_state_weight;
        let mut assets = self.assets.clone();
        for effect in preview.effects {
            match effect {
                xparq_common::ExtensionEffect::MintAsset {
                    asset_id,
                    recipient,
                    amount,
                } => {
                    let asset_id = xparq_asset::AssetHash::from_bytes(asset_id);
                    let recipient = Address(recipient);
                    let weight = assets
                        .program_mint_created_state_weight(
                            call.extension_id(),
                            asset_id,
                            recipient,
                            amount,
                        )
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                    total = total
                        .checked_add(weight)
                        .ok_or(ExtensionFailure::StateEntryLimit)?;
                    assets
                        .apply_program_mint(call.extension_id(), asset_id, recipient, amount)
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                }
                xparq_common::ExtensionEffect::TransferAsset {
                    asset_id,
                    recipient,
                    amount,
                } => {
                    let asset_id = xparq_asset::AssetHash::from_bytes(asset_id);
                    let recipient = Address(recipient);
                    let weight = assets
                        .program_transfer_created_state_weight(
                            call.extension_id(),
                            asset_id,
                            recipient,
                            amount,
                        )
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                    total = total
                        .checked_add(weight)
                        .ok_or(ExtensionFailure::StateEntryLimit)?;
                    assets
                        .apply_program_transfer(call.extension_id(), asset_id, recipient, amount)
                        .map_err(|_| ExtensionFailure::InvalidState)?;
                }
                xparq_common::ExtensionEffect::TransferCoin { amount, .. } => {
                    if amount == 0 {
                        return Err(ExtensionFailure::InvalidState);
                    }
                    let owner = crate::CoinOwner::Extension(call.extension_id());
                    let mut held = 0_u64;
                    for utxo in self.coins.owned_by(owner) {
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
                    total = total
                        .checked_add(outputs * xparq_consensus::COIN_UTXO_STATE_WEIGHT)
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
        Ok(ExtensionStateRoot::from_bytes(blake3::derive_key(
            "xparq:application-state-root",
            &input,
        )))
    }
}

impl From<ChainError> for LedgerError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl From<xparq_common::CodecError> for LedgerError {
    fn from(error: xparq_common::CodecError) -> Self {
        Self::Consensus(ConsensusError::Serialization(error))
    }
}
