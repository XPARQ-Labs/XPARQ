#[path = "pow.rs"]
mod pow;

use crate::blockchain::{Block, BlockHeight, Header, Height, MAX_BLOCK_WEIGHT};
use crate::coin::{CoinHash, Zeno};
use crate::common::canonical_bytes;
use crate::consensus::error::ConsensusError;
use crate::consensus::fork::Work;
use crate::crypto::{BlockHash, HASH_SIZE, Hash, PoWHash};
use crate::transaction::{
    AccountAuthorization, AuthorizedAccountIntent, AuthorizedTransaction, ChainContext,
    IntentError, Spend, SpendCommitment, SpendIntent,
};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, PublicKey};
use std::{collections::BTreeSet, error::Error, fmt};

use crate::consensus::state_burn::{
    ProtocolBurn, StateBurnError, StateTransitionWeight, account_key_state_weight,
    created_coin_output_count, validate_exact_burn,
};

pub fn validate_emission(
    block: &crate::blockchain::Block,
    parent_emission: Zeno,
    weight_at: impl FnMut(crate::blockchain::Height) -> Option<u32>,
) -> Result<crate::consensus::ValidatedEmission, crate::consensus::EmissionError> {
    crate::consensus::apply::authorize_emission(block, parent_emission, weight_at)
}

pub use pow::{
    POW_ALGORITHM, POW_ARGON2_ITERATIONS, POW_ARGON2_LANES, POW_ARGON2_MEMORY_KIB, calculate_work,
    calculate_work_with_memory, new_pow_memory, pow_salt, pow_seed, verify_pow,
    verify_pow_with_memory,
};

pub trait ConsensusIntent: Clone {
    fn validate_structure(&self) -> Result<(), IntentError>;
    fn commitment_for(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError>;
}

macro_rules! impl_consensus_intent {
    ($type:ty) => {
        impl ConsensusIntent for $type {
            fn validate_structure(&self) -> Result<(), IntentError> {
                self.validate()
            }

            fn commitment_for(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
                self.commitment(chain)
            }
        }
    };
}

impl_consensus_intent!(SpendIntent);

/// Structural consensus result. Authorization is intentionally not implied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyValidated<T> {
    intent: T,
    commitment: SpendCommitment,
}

impl<T> StructurallyValidated<T> {
    pub fn intent(&self) -> &T {
        &self.intent
    }

    pub const fn commitment(&self) -> SpendCommitment {
        self.commitment
    }

    pub fn into_intent(self) -> T {
        self.intent
    }
}

pub fn validate_intent<T: ConsensusIntent>(
    intent: T,
    chain: ChainContext,
) -> Result<StructurallyValidated<T>, TransactionConsensusError> {
    intent
        .validate_structure()
        .map_err(TransactionConsensusError::Intent)?;
    let commitment = intent
        .commitment_for(chain)
        .map_err(TransactionConsensusError::Intent)?;
    Ok(StructurallyValidated { intent, commitment })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationValidated<T> {
    intent: T,
    commitment: SpendCommitment,
    revealed_account_key: Option<RevealedAccountKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealedAccountKey {
    Account(PublicKey),
}

impl<T> AuthorizationValidated<T> {
    pub fn intent(&self) -> &T {
        &self.intent
    }

    pub const fn commitment(&self) -> SpendCommitment {
        self.commitment
    }

    pub const fn revealed_account_key(&self) -> Option<&RevealedAccountKey> {
        self.revealed_account_key.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// This validation-only enum is short-lived; boxing would complicate every apply path.
#[allow(clippy::large_enum_variant)]
pub enum ValidatedTransaction {
    Spend(ValidatedSpendTransaction),
    Asset(ValidatedAssetTransaction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSpendTransaction {
    pub spend: AuthorizationValidated<SpendIntent>,
    pub payment: Option<AuthorizationValidated<SpendIntent>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAssetTransaction {
    pub call: AuthorizationValidated<crate::transaction::AssetIntent>,
    pub payment: AuthorizationValidated<SpendIntent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinInputState {
    pub amount: Zeno,
    pub owner: Address,
}

/// Read-only canonical state required to validate transaction inputs.
pub trait TransactionStateView {
    fn coin(&self, id: CoinHash) -> Option<CoinInputState>;
    fn account_public_key(&self, address: Address) -> Option<PublicKey>;

    fn asset_spend_created_state_weight(
        &self,
        _intent: &SpendIntent,
    ) -> Result<u64, crate::asset::AssetError> {
        Err(crate::asset::AssetError::UnknownAsset)
    }

    fn asset_transition_created_state_weight(
        &self,
        _call: &crate::transaction::AssetIntent,
        _genesis_hash: [u8; 32],
    ) -> Result<u64, crate::asset::AssetError> {
        Err(crate::asset::AssetError::UnknownAsset)
    }

}

pub fn validate_transaction(
    transaction: AuthorizedTransaction,
    chain: ChainContext,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<ValidatedTransaction, TransactionConsensusError> {
    let canonical_transaction_weight = u64::try_from(
        canonical_bytes(&transaction)
            .map_err(TransactionConsensusError::Encoding)?
            .len(),
    )
    .map_err(|_| TransactionConsensusError::StateBurn(StateBurnError::WeightOverflow))?;
    match transaction {
        AuthorizedTransaction::Spend(transaction) => {
            let transaction = *transaction;
            let validated = validate_account_intent_authorization(
                transaction.spend,
                chain,
                current_height,
                state,
            )?;
            match &validated.intent().spend {
                Spend::Coin {
                    inputs,
                    outputs,
                    burn,
                } => {
                    if transaction.payment.is_some() {
                        return Err(TransactionConsensusError::Intent(
                            IntentError::InvalidAssetCall,
                        ));
                    }
                    validate_coin_inputs(
                        inputs,
                        validated.intent().signer,
                        &outputs
                            .iter()
                            .map(|output| output.amount)
                            .collect::<Vec<_>>(),
                        *burn,
                        state,
                    )?;
                    validate_state_burn(
                        *burn,
                        StateTransitionWeight {
                            created_coin_utxos: created_coin_output_count(outputs)?,
                            consumed_coin_utxos: u64::try_from(inputs.len())
                                .map_err(|_| StateBurnError::WeightOverflow)?,
                            created_account_key_weight: revealed_account_key_weight(
                                validated.revealed_account_key(),
                            )?,
                            ..StateTransitionWeight::default()
                        },
                        canonical_transaction_weight,
                    )?;
                    Ok(ValidatedTransaction::Spend(ValidatedSpendTransaction {
                        spend: validated,
                        payment: None,
                    }))
                }
                Spend::Asset { .. } => {
                    let payment = transaction
                        .payment
                        .ok_or(TransactionConsensusError::Intent(
                            IntentError::InvalidAssetCall,
                        ))?;
                    let payment = validate_account_intent_authorization(
                        payment,
                        chain,
                        current_height,
                        state,
                    )?;
                    let (inputs, outputs, burn) = coin_parts(payment.intent())?;
                    validate_coin_inputs(
                        inputs,
                        payment.intent().signer,
                        &outputs.iter().map(|o| o.amount).collect::<Vec<_>>(),
                        burn,
                        state,
                    )?;
                    let asset_weight = state
                        .asset_spend_created_state_weight(validated.intent())
                        .map_err(TransactionConsensusError::Asset)?;
                    let key_weight = if validated.intent().signer == payment.intent().signer
                        && validated.revealed_account_key().is_some()
                        && payment.revealed_account_key().is_some()
                    {
                        revealed_account_key_weight(validated.revealed_account_key())?
                    } else {
                        revealed_account_key_weight(validated.revealed_account_key())?
                            .checked_add(revealed_account_key_weight(
                                payment.revealed_account_key(),
                            )?)
                            .ok_or(StateBurnError::WeightOverflow)?
                    };
                    validate_state_burn(
                        burn,
                        StateTransitionWeight {
                            created_coin_utxos: created_coin_output_count(outputs)?,
                            consumed_coin_utxos: u64::try_from(inputs.len())
                                .map_err(|_| StateBurnError::WeightOverflow)?,
                            created_account_key_weight: key_weight,
                            created_state_weight: asset_weight,
                            ..StateTransitionWeight::default()
                        },
                        canonical_transaction_weight,
                    )?;
                    Ok(ValidatedTransaction::Spend(ValidatedSpendTransaction {
                        spend: validated,
                        payment: Some(payment),
                    }))
                }
            }
        }
        AuthorizedTransaction::Asset(transaction) => {
            let transaction = *transaction;
            let call =
                validate_asset_authorization(transaction.call, chain, current_height, state)?;
            let asset_created_state_weight = state
                .asset_transition_created_state_weight(call.intent(), chain.genesis_hash)
                .map_err(TransactionConsensusError::Asset)?;
            let payment = validate_account_intent_authorization(
                transaction.payment,
                chain,
                current_height,
                state,
            )?;
            let (payment_inputs, payment_outputs, payment_burn) = coin_parts(payment.intent())?;
            validate_coin_inputs(
                payment_inputs,
                payment.intent().signer,
                &payment_outputs
                    .iter()
                    .map(|output| output.amount)
                    .collect::<Vec<_>>(),
                payment_burn,
                state,
            )?;
            validate_state_burn(
                payment_burn,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(payment_outputs)?,
                    consumed_coin_utxos: u64::try_from(payment_inputs.len())
                        .map_err(|_| StateBurnError::WeightOverflow)?,
                    created_account_key_weight: revealed_asset_account_key_weight(&call, &payment)?,
                    created_state_weight: asset_created_state_weight,
                    ..StateTransitionWeight::default()
                },
                canonical_transaction_weight,
            )?;
            Ok(ValidatedTransaction::Asset(ValidatedAssetTransaction {
                call,
                payment,
            }))
        }
    }
}

fn revealed_account_key_weight(
    revealed: Option<&RevealedAccountKey>,
) -> Result<u64, TransactionConsensusError> {
    match revealed {
        Some(RevealedAccountKey::Account(public_key)) => {
            account_key_state_weight(public_key).map_err(TransactionConsensusError::StateBurn)
        }
        None => Ok(0),
    }
}

fn revealed_asset_account_key_weight(
    call: &AuthorizationValidated<crate::transaction::AssetIntent>,
    payment: &AuthorizationValidated<SpendIntent>,
) -> Result<u64, TransactionConsensusError> {
    let call_weight = revealed_account_key_weight(call.revealed_account_key())?;
    if call.intent().signer == payment.intent().signer
        && call.revealed_account_key().is_some()
        && payment.revealed_account_key().is_some()
    {
        return Ok(call_weight);
    }
    call_weight
        .checked_add(revealed_account_key_weight(payment.revealed_account_key())?)
        .ok_or(TransactionConsensusError::StateBurn(
            StateBurnError::WeightOverflow,
        ))
}

fn coin_parts(
    intent: &SpendIntent,
) -> Result<(&[CoinHash], &[crate::transaction::CoinOutput], Zeno), TransactionConsensusError> {
    intent.coin_parts().ok_or(TransactionConsensusError::Intent(
        IntentError::InvalidAssetCall,
    ))
}

fn validate_state_burn(
    burn: Zeno,
    transition: StateTransitionWeight,
    canonical_transaction_weight: u64,
) -> Result<(), TransactionConsensusError> {
    let required =
        ProtocolBurn::for_transaction(transition, canonical_transaction_weight)?.total()?;
    validate_exact_burn(burn, required)?;
    Ok(())
}

fn validate_asset_authorization(
    authorized: AuthorizedAccountIntent<crate::transaction::AssetIntent>,
    chain: ChainContext,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<AuthorizationValidated<crate::transaction::AssetIntent>, TransactionConsensusError> {
    authorized
        .intent
        .validate_structure()
        .map_err(TransactionConsensusError::Asset)?;
    let commitment = SpendCommitment::from_bytes(
        authorized
            .intent
            .commitment(chain.genesis_hash)
            .map_err(TransactionConsensusError::Asset)?,
    );
    let sender = authorized.intent.signer;
    let revealed_account_key = validate_account_authorization(
        sender,
        commitment.as_bytes(),
        authorized.authorization,
        current_height,
        state,
    )?;
    Ok(AuthorizationValidated {
        intent: authorized.intent,
        commitment,
        revealed_account_key,
    })
}

fn validate_account_intent_authorization<T>(
    authorized: AuthorizedAccountIntent<T>,
    chain: ChainContext,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<AuthorizationValidated<T>, TransactionConsensusError>
where
    T: ConsensusIntent + crate::transaction::AccountIntent,
{
    let structurally_validated = validate_intent(authorized.intent, chain)?;
    let sender = crate::transaction::AccountIntent::sender(structurally_validated.intent());
    let commitment = structurally_validated.commitment();
    let commitment_bytes = commitment.as_bytes();
    let revealed_account_key = validate_account_authorization(
        sender,
        commitment_bytes,
        authorized.authorization,
        current_height,
        state,
    )?;
    Ok(AuthorizationValidated {
        intent: structurally_validated.into_intent(),
        commitment,
        revealed_account_key,
    })
}

fn validate_account_authorization(
    sender: Address,
    commitment_bytes: &[u8],
    authorization: AccountAuthorization,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<Option<RevealedAccountKey>, TransactionConsensusError> {
    let revealed_account_key = match authorization {
        AccountAuthorization::AccountReveal {
            public_key,
            signature,
        } => {
            if !public_key.account.active_at_height(current_height) {
                return Err(TransactionConsensusError::SignatureSchemeInactive);
            }
            let registered = state.account_public_key(sender);
            let was_registered = registered.is_some();
            let public_key = match registered.as_ref() {
                Some(registered) if registered == &public_key => registered.clone(),
                None if crypto::address_from_public_key(&public_key) == sender => public_key,
                _ => return Err(TransactionConsensusError::InvalidAuthorization),
            };
            if !crypto::verify(&public_key, commitment_bytes, &signature) {
                return Err(TransactionConsensusError::InvalidAuthorization);
            }
            (!was_registered).then_some(RevealedAccountKey::Account(public_key))
        }
        AccountAuthorization::AccountKnown { account, signature } => {
            if !account.active_at_height(current_height) || signature.account != account {
                return Err(TransactionConsensusError::SignatureSchemeInactive);
            }
            let public_key = state
                .account_public_key(sender)
                .ok_or(TransactionConsensusError::InvalidAuthorization)?;
            if public_key.account != account
                || !crypto::verify(&public_key, commitment_bytes, &signature)
            {
                return Err(TransactionConsensusError::InvalidAuthorization);
            }
            None
        }
    };
    Ok(revealed_account_key)
}

fn validate_coin_inputs(
    inputs: &[CoinHash],
    owner: Address,
    outputs: &[Zeno],
    burn: Zeno,
    state: &impl TransactionStateView,
) -> Result<(), TransactionConsensusError> {
    ensure_unique_coin_ids(inputs.iter().copied())?;
    let mut input_total = Zeno::from_zeno(0);
    for id in inputs {
        let input = state
            .coin(*id)
            .ok_or(TransactionConsensusError::UtxoNotFound)?;
        if input.owner != owner {
            return Err(TransactionConsensusError::OwnerMismatch);
        }
        input_total = input_total
            .checked_add(input.amount)
            .ok_or(TransactionConsensusError::ZenoOverflow)?;
    }
    let output_total = outputs.iter().try_fold(burn, |sum, amount| {
        sum.checked_add(*amount)
            .ok_or(TransactionConsensusError::ZenoOverflow)
    })?;
    if input_total != output_total {
        return Err(TransactionConsensusError::ValueMismatch);
    }
    Ok(())
}

fn ensure_unique_coin_ids(
    ids: impl IntoIterator<Item = CoinHash>,
) -> Result<(), TransactionConsensusError> {
    let mut unique = BTreeSet::new();
    if ids.into_iter().any(|id| !unique.insert(id)) {
        return Err(TransactionConsensusError::Intent(
            IntentError::DuplicateInput,
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionConsensusError {
    Encoding(crate::common::CodecError),
    Intent(IntentError),
    InvalidAuthorization,
    SignatureSchemeInactive,
    UtxoNotFound,
    OwnerMismatch,
    InputZenoMismatch,
    ReusedBearerKey,
    ZenoOverflow,
    ValueMismatch,
    Asset(crate::asset::AssetError),
    StateBurn(StateBurnError),
}

impl fmt::Display for TransactionConsensusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "transaction encoding failed: {error}"),
            Self::Intent(error) => write!(formatter, "invalid transaction intent: {error}"),
            Self::InvalidAuthorization => {
                formatter.write_str("transaction authorization is invalid")
            }
            Self::SignatureSchemeInactive => {
                formatter.write_str("transaction signature scheme is not active at this height")
            }
            Self::UtxoNotFound => formatter.write_str("transaction input UTXO was not found"),
            Self::OwnerMismatch => {
                formatter.write_str("transaction input belongs to another owner")
            }
            Self::InputZenoMismatch => {
                formatter.write_str("transaction input amount does not match canonical state")
            }
            Self::ReusedBearerKey => formatter.write_str("transaction output key is reused"),
            Self::ZenoOverflow => formatter.write_str("transaction amount overflow"),
            Self::ValueMismatch => formatter.write_str("input value does not equal output value"),
            Self::Asset(error) => write!(formatter, "invalid native asset transaction: {error}"),
            Self::StateBurn(error) => write!(formatter, "invalid state burn: {error}"),
        }
    }
}

impl Error for TransactionConsensusError {}

impl From<StateBurnError> for TransactionConsensusError {
    fn from(error: StateBurnError) -> Self {
        Self::StateBurn(error)
    }
}

pub const MIN_DIFFICULTY: u32 = 1;
/// A 256-bit PoW output cannot represent a stricter leading-zero target.
pub const MAX_DIFFICULTY: u32 = (crate::crypto::POW_HASH_SIZE * 8) as u32;
/// Compatibility name for the height-zero difficulty. Unlike
/// [`DIFFICULTY_START`], this value belongs to the stable genesis header.
pub const GENESIS_DIFFICULTY: u32 = crate::blockchain::GENESIS_BLOCK_DIFFICULTY;
pub const DIFFICULTY_START: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusConfig {
    difficulty: u32,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            difficulty: DIFFICULTY_START,
        }
    }
}

impl ConsensusConfig {
    pub fn new(difficulty: u32) -> Self {
        Self { difficulty }
    }

    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Consensus {
    config: ConsensusConfig,
}

impl Consensus {
    pub fn new(config: ConsensusConfig) -> Result<Self, ConsensusError> {
        if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&config.difficulty) {
            return Err(ConsensusError::InvalidDifficulty);
        }

        Ok(Self { config })
    }

    pub fn with_default_config() -> Self {
        Self {
            config: ConsensusConfig::default(),
        }
    }

    pub fn with_expected_difficulty(expected_difficulty: u32) -> Result<Self, ConsensusError> {
        Self::new(ConsensusConfig::new(expected_difficulty))
    }

    pub fn config(&self) -> ConsensusConfig {
        self.config
    }

    pub fn difficulty(&self) -> u32 {
        self.config.difficulty()
    }

    pub fn validate_genesis_block(&self, block: &Block) -> Result<(), ConsensusError> {
        block.validate_structure()?;

        if block.height() != Height(0) || block.previous_hash() != Hash([0; HASH_SIZE]) {
            return Err(ConsensusError::InvalidHeight);
        }

        Ok(())
    }

    pub fn validate_next_block(
        &self,
        block: &Block,
        tip_height: Height,
        tip_hash: BlockHash,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        block.validate_structure()?;
        self.validate_next_block_linkage(block, tip_height, tip_hash)?;
        Self::validate_pow_at_difficulty(block, expected_difficulty)
    }

    pub fn validate_next_block_with_tip(
        &self,
        block: &Block,
        tip: &Block,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        block.validate_structure()?;
        self.validate_next_block_linkage(block, tip.height(), tip.hash()?)?;
        Self::validate_pow_at_difficulty(block, expected_difficulty)
    }

    pub(crate) fn validate_next_block_linkage(
        &self,
        block: &Block,
        tip_height: Height,
        tip_hash: BlockHash,
    ) -> Result<(), ConsensusError> {
        if block.height().0 != tip_height.0.saturating_add(1) {
            return Err(ConsensusError::InvalidHeight);
        }

        if block.previous_hash() != tip_hash {
            return Err(ConsensusError::InvalidPreviousHash);
        }

        Ok(())
    }

    pub fn validate_candidate_block(
        &self,
        block: &Block,
        tip: Option<(Height, BlockHash)>,
        expected_difficulty: Option<u32>,
    ) -> Result<(), ConsensusError> {
        match tip {
            Some((tip_height, tip_hash)) => self.validate_next_block(
                block,
                tip_height,
                tip_hash,
                expected_difficulty.ok_or(ConsensusError::UnexpectedDifficulty)?,
            ),
            None => self.validate_genesis_block(block),
        }
    }

    pub fn validate_pow(&self, block: &Block) -> Result<(), ConsensusError> {
        if block.difficulty() != self.difficulty() {
            return Err(ConsensusError::UnexpectedDifficulty);
        }

        self.validate_claimed_pow(block)
    }

    pub fn validate_pow_at_difficulty(
        block: &Block,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        if block.difficulty() != expected_difficulty {
            return Err(ConsensusError::UnexpectedDifficulty);
        }
        Self::with_expected_difficulty(expected_difficulty)?.validate_claimed_pow(block)
    }

    pub fn validate_proof_of_work_at_difficulty(
        block: &Block,
        expected_difficulty: u32,
    ) -> Result<(), ConsensusError> {
        Self::validate_pow_at_difficulty(block, expected_difficulty)
    }

    pub fn validate_claimed_pow(&self, block: &Block) -> Result<(), ConsensusError> {
        crate::consensus::verify_pow(&block.header, block.difficulty())
    }

    pub fn validate_proof_of_work(&self, block: &Block) -> Result<(), ConsensusError> {
        self.validate_claimed_pow(block)
    }

    pub fn validate_pow_hash(&self, hash: &PoWHash) -> Result<(), ConsensusError> {
        self.validate_pow_hash_with_difficulty(hash, self.difficulty())
    }

    pub fn validate_pow_hash_with_difficulty(
        &self,
        hash: &PoWHash,
        difficulty: u32,
    ) -> Result<(), ConsensusError> {
        if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&difficulty) {
            return Err(ConsensusError::InvalidDifficulty);
        }

        if crate::crypto::hash_meets_difficulty(hash, difficulty) {
            Ok(())
        } else {
            Err(ConsensusError::InsufficientPoW)
        }
    }

    pub fn pow_hash(&self, block: &Block) -> Result<PoWHash, ConsensusError> {
        crate::consensus::calculate_work(&block.header)
    }

    pub fn pow_hash_with_memory(
        &self,
        block: &Block,
        memory: &mut crate::crypto::PoWMemory,
    ) -> Result<PoWHash, ConsensusError> {
        crate::consensus::calculate_work_with_memory(&block.header, memory)
    }

    pub fn proof_of_work_hash(&self, block: &Block) -> Result<PoWHash, ConsensusError> {
        self.pow_hash(block)
    }

    pub fn validate_proof_of_work_hash_with_difficulty(
        &self,
        hash: &PoWHash,
        difficulty: u32,
    ) -> Result<(), ConsensusError> {
        self.validate_pow_hash_with_difficulty(hash, difficulty)
    }
}

pub const RECENT_HEADER_WINDOW: usize = crate::consensus::WBDA_WINDOW * 2;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct HeaderAtHeight {
    pub height: BlockHeight,
    pub header: Header,
}

impl HeaderAtHeight {
    pub const fn new(height: BlockHeight, header: Header) -> Self {
        Self { height, header }
    }

    pub fn hash(&self) -> Result<BlockHash, crate::consensus::error::CodecError> {
        self.header.hash()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct HeaderValidationState {
    pub height: BlockHeight,
    pub header: Header,
    pub cumulative_work: Work,
    pub cumulative_weight: u64,
    pub difficulty_anchor: HeaderAtHeight,
    pub recent_headers: Vec<HeaderAtHeight>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderChainError {
    EmptyHeaderChain,
    WrongGenesis,
    InvalidHeaderChain(crate::consensus::fork::ForkChoiceError),
    InvalidCommonAncestor,
    Serialization(crate::consensus::error::CodecError),
}

impl fmt::Display for HeaderChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyHeaderChain => "header chain is empty",
            Self::WrongGenesis => "header chain does not start at configured genesis",
            Self::InvalidHeaderChain(_) => "header chain is invalid",
            Self::InvalidCommonAncestor => "header chain common ancestor is invalid",
            Self::Serialization(_) => "header chain serialization failed",
        };
        match self {
            Self::InvalidHeaderChain(error) => write!(f, "{message}: {error}"),
            Self::Serialization(error) => write!(f, "{message}: {error}"),
            _ => f.write_str(message),
        }
    }
}

impl Error for HeaderChainError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidHeaderChain(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

pub fn verify_header_chain(
    headers: &[HeaderAtHeight],
    expected_genesis: BlockHash,
) -> Result<(BlockHash, Work), HeaderChainError> {
    let first = headers.first().ok_or(HeaderChainError::EmptyHeaderChain)?;
    if first.height.0 != 0
        || first.hash().map_err(HeaderChainError::Serialization)?.0 != expected_genesis.0
    {
        return Err(HeaderChainError::WrongGenesis);
    }
    let mut previous = first;
    let mut cumulative_work = Work::ZERO;
    let mut recent = vec![first.clone()];
    let mut pow_memory = (headers.len() > 1).then(crate::consensus::new_pow_memory);
    for current in &headers[1..] {
        if current.header.block_weight == 0
            || current.header.block_weight as usize > MAX_BLOCK_WEIGHT
        {
            return Err(HeaderChainError::InvalidHeaderChain(
                crate::consensus::fork::ForkChoiceError::InvalidHeader,
            ));
        }
        if current.height.0 != previous.height.0.saturating_add(1)
            || BlockHash(current.header.previous_hash.0)
                != previous.hash().map_err(HeaderChainError::Serialization)?
        {
            return Err(HeaderChainError::InvalidCommonAncestor);
        }
        let expected = expected_header_difficulty(previous, &recent)?;
        if current.header.difficulty != expected {
            return Err(HeaderChainError::InvalidHeaderChain(
                crate::consensus::fork::ForkChoiceError::InvalidDifficulty,
            ));
        }
        crate::consensus::verify_pow_with_memory(
            &current.header,
            expected,
            pow_memory
                .as_mut()
                .expect("non-genesis headers allocate PoW memory"),
        )
        .map_err(|error| {
            HeaderChainError::InvalidHeaderChain(
                crate::consensus::fork::ForkChoiceError::InvalidProofOfWork(error),
            )
        })?;
        cumulative_work =
            cumulative_work.saturating_add(crate::consensus::fork::block_work(expected));
        previous = current;
        recent.push(current.clone());
        if recent.len() > RECENT_HEADER_WINDOW {
            recent.remove(0);
        }
    }
    Ok((
        previous.hash().map_err(HeaderChainError::Serialization)?,
        cumulative_work,
    ))
}

fn expected_header_difficulty(
    previous: &HeaderAtHeight,
    recent: &[HeaderAtHeight],
) -> Result<u32, HeaderChainError> {
    let next_height = previous.height.0.saturating_add(1);
    crate::consensus::expected_difficulty_for_height(
        next_height,
        previous.header.difficulty,
        |height| {
            recent
                .iter()
                .find(|candidate| candidate.height.0 == height)
                .ok_or(HeaderChainError::InvalidHeaderChain(
                    crate::consensus::fork::ForkChoiceError::MissingParent,
                ))?
                .header
                .block_weight
                .try_into()
                .map_err(|_| {
                    HeaderChainError::InvalidHeaderChain(
                        crate::consensus::fork::ForkChoiceError::InvalidDifficulty,
                    )
                })
        },
    )?
    .ok_or(HeaderChainError::InvalidHeaderChain(
        crate::consensus::fork::ForkChoiceError::InvalidDifficulty,
    ))
}

pub fn header_validation_state(
    validated_headers: &[HeaderAtHeight],
    expected_genesis: BlockHash,
) -> Result<HeaderValidationState, HeaderChainError> {
    let (_, cumulative_work) = verify_header_chain(validated_headers, expected_genesis)?;
    let tip = validated_headers
        .last()
        .cloned()
        .ok_or(HeaderChainError::EmptyHeaderChain)?;
    let difficulty_anchor = validated_headers
        .get(usize::from(tip.height.0 > 0))
        .cloned()
        .ok_or(HeaderChainError::EmptyHeaderChain)?;
    let start = validated_headers.len().saturating_sub(RECENT_HEADER_WINDOW);
    Ok(HeaderValidationState {
        height: tip.height,
        header: tip.header,
        cumulative_work,
        cumulative_weight: validated_headers
            .iter()
            .skip(1)
            .fold(0_u64, |total, header| {
                total.saturating_add(u64::from(header.header.block_weight))
            }),
        difficulty_anchor,
        recent_headers: validated_headers[start..].to_vec(),
    })
}

pub fn verify_header_chain_extension(
    state: &HeaderValidationState,
    headers: &[HeaderAtHeight],
) -> Result<(BlockHash, Work), HeaderChainError> {
    let mut pow_memory = (!headers.is_empty()).then(crate::consensus::new_pow_memory);
    verify_header_chain_extension_inner(state, headers, pow_memory.as_mut())
}

pub fn verify_header_chain_extension_with_memory(
    state: &HeaderValidationState,
    headers: &[HeaderAtHeight],
    pow_memory: &mut crate::crypto::PoWMemory,
) -> Result<(BlockHash, Work), HeaderChainError> {
    verify_header_chain_extension_inner(state, headers, Some(pow_memory))
}

fn verify_header_chain_extension_inner(
    state: &HeaderValidationState,
    headers: &[HeaderAtHeight],
    mut pow_memory: Option<&mut crate::crypto::PoWMemory>,
) -> Result<(BlockHash, Work), HeaderChainError> {
    let checkpoint_hash = state
        .header
        .hash()
        .map_err(HeaderChainError::Serialization)?;
    if state.recent_headers.is_empty()
        || state.recent_headers.len() > RECENT_HEADER_WINDOW
        || state
            .recent_headers
            .last()
            .is_none_or(|tip| tip.header != state.header)
    {
        return Err(HeaderChainError::InvalidCommonAncestor);
    }
    let mut previous_height = state.height;
    let mut previous = state.header.clone();
    let mut previous_hash = checkpoint_hash;
    let mut cumulative_work = state.cumulative_work;
    let mut recent = state.recent_headers.clone();
    for chain_header in headers {
        let header = &chain_header.header;
        if header.block_weight == 0 || header.block_weight as usize > MAX_BLOCK_WEIGHT {
            return Err(HeaderChainError::InvalidHeaderChain(
                crate::consensus::fork::ForkChoiceError::InvalidHeader,
            ));
        }
        if chain_header.height.0 != previous_height.0.saturating_add(1)
            || BlockHash(header.previous_hash.0) != previous_hash
        {
            return Err(HeaderChainError::InvalidCommonAncestor);
        }
        let expected_difficulty = crate::consensus::expected_difficulty_for_height(
            chain_header.height.0,
            previous.difficulty,
            |height| {
                recent
                    .iter()
                    .find(|candidate| candidate.height.0 == height)
                    .ok_or(HeaderChainError::InvalidHeaderChain(
                        crate::consensus::fork::ForkChoiceError::MissingParent,
                    ))?
                    .header
                    .block_weight
                    .try_into()
                    .map_err(|_| {
                        HeaderChainError::InvalidHeaderChain(
                            crate::consensus::fork::ForkChoiceError::InvalidDifficulty,
                        )
                    })
            },
        )?
        .ok_or(HeaderChainError::InvalidHeaderChain(
            crate::consensus::fork::ForkChoiceError::InvalidDifficulty,
        ))?;
        if header.difficulty != expected_difficulty {
            return Err(HeaderChainError::InvalidHeaderChain(
                crate::consensus::fork::ForkChoiceError::InvalidDifficulty,
            ));
        }
        crate::consensus::verify_pow_with_memory(
            header,
            expected_difficulty,
            pow_memory
                .as_deref_mut()
                .expect("non-empty header extension supplies PoW memory"),
        )
        .map_err(|error| {
            HeaderChainError::InvalidHeaderChain(
                crate::consensus::fork::ForkChoiceError::InvalidProofOfWork(error),
            )
        })?;
        cumulative_work =
            cumulative_work.saturating_add(crate::consensus::fork::block_work(expected_difficulty));
        previous_hash = header.hash().map_err(HeaderChainError::Serialization)?;
        previous_height = chain_header.height;
        previous = header.clone();
        recent.push(chain_header.clone());
        if recent.len() > RECENT_HEADER_WINDOW {
            recent.remove(0);
        }
    }
    Ok((previous_hash, cumulative_work))
}

pub fn advance_header_validation_state(
    state: &HeaderValidationState,
    headers: &[HeaderAtHeight],
) -> Result<HeaderValidationState, HeaderChainError> {
    let (_, cumulative_work) = verify_header_chain_extension(state, headers)?;
    advanced_header_validation_state(state, headers, cumulative_work)
}

pub fn advance_header_validation_state_with_memory(
    state: &HeaderValidationState,
    headers: &[HeaderAtHeight],
    pow_memory: &mut crate::crypto::PoWMemory,
) -> Result<HeaderValidationState, HeaderChainError> {
    let (_, cumulative_work) =
        verify_header_chain_extension_with_memory(state, headers, pow_memory)?;
    advanced_header_validation_state(state, headers, cumulative_work)
}

fn advanced_header_validation_state(
    state: &HeaderValidationState,
    headers: &[HeaderAtHeight],
    cumulative_work: Work,
) -> Result<HeaderValidationState, HeaderChainError> {
    let mut recent_headers = state.recent_headers.clone();
    recent_headers.extend_from_slice(headers);
    if recent_headers.len() > RECENT_HEADER_WINDOW {
        recent_headers = recent_headers[recent_headers.len() - RECENT_HEADER_WINDOW..].to_vec();
    }
    Ok(HeaderValidationState {
        height: headers
            .last()
            .map(|header| header.height)
            .unwrap_or(state.height),
        header: headers
            .last()
            .map(|header| header.header.clone())
            .unwrap_or_else(|| state.header.clone()),
        cumulative_work,
        cumulative_weight: headers
            .iter()
            .fold(state.cumulative_weight, |total, header| {
                total.saturating_add(u64::from(header.header.block_weight))
            }),
        difficulty_anchor: state.difficulty_anchor.clone(),
        recent_headers,
    })
}
