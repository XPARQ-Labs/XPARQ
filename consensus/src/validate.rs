#[path = "pow.rs"]
mod pow;

use crate::block::{Block, BlockHeight, Header, Height, MAX_BLOCK_WEIGHT};
use crate::consensus::fork::Work;
use crate::crypto::{BlockHash, HASH_SIZE, Hash, PoWHash};
use crate::error::ConsensusError;
use borsh::{BorshDeserialize, BorshSerialize};
use std::{collections::BTreeSet, error::Error, fmt};
use xparq_coin::{Amount, CoinId};
use xparq_common::ExtensionCall;
use xparq_crypto::{Address, ProfilePublicKey, QCashPublicKey};
use xparq_transaction::{
    AccountAuthorization, AuthorizedAccountIntent, AuthorizedQCashIntent, AuthorizedTransaction,
    ChainContext, IntentError, MergeIntent, OnChainSpendIntent, QCashIntent, RedeemIntent,
    SpendCommitment, SplitIntent, WithdrawIntent,
};

use crate::state_burn::{
    StateBurnError, StateTransitionWeight, created_coin_output_count, validate_exact_burn,
};

pub fn validate_emission(
    block: &xparq_blockchain::Block,
    parent_emission: Amount,
    weight_at: impl FnMut(xparq_blockchain::Height) -> Option<u32>,
) -> Result<crate::ValidatedEmission, crate::EmissionError> {
    crate::apply::authorize_emission(block, parent_emission, weight_at)
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

impl_consensus_intent!(OnChainSpendIntent);
impl_consensus_intent!(WithdrawIntent);
impl_consensus_intent!(RedeemIntent);
impl_consensus_intent!(MergeIntent);
impl_consensus_intent!(SplitIntent);

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
    Profile(ProfilePublicKey),
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
    OnChainSpend(AuthorizationValidated<OnChainSpendIntent>),
    Withdraw(AuthorizationValidated<WithdrawIntent>),
    Redeem(AuthorizationValidated<RedeemIntent>),
    Merge(AuthorizationValidated<MergeIntent>),
    Split(AuthorizationValidated<SplitIntent>),
    Asset(ValidatedAssetTransaction),
    Extension(ValidatedExtensionTransaction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAssetTransaction {
    pub call: AuthorizationValidated<xparq_asset::AssetCall>,
    pub payment: AuthorizationValidated<OnChainSpendIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedExtensionTransaction {
    pub call: ExtensionCall,
    pub fee: AuthorizationValidated<OnChainSpendIntent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinInputState {
    pub amount: Amount,
    pub owner: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QCashInputState {
    pub amount: Amount,
    pub public_key: QCashPublicKey,
}

/// Read-only canonical state required to validate transaction inputs.
pub trait TransactionStateView {
    fn coin(&self, id: CoinId) -> Option<CoinInputState>;
    fn qcash(&self, id: CoinId) -> Option<QCashInputState>;
    fn profile_public_key(&self, address: Address) -> Option<ProfilePublicKey>;

    fn asset_state(&self) -> Option<&xparq_asset::AssetState> {
        None
    }

    fn extension_created_state_weight(&self, _call: &ExtensionCall, _height: u64) -> u64 {
        0
    }
}

pub fn validate_transaction(
    transaction: AuthorizedTransaction,
    chain: ChainContext,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<ValidatedTransaction, TransactionConsensusError> {
    match transaction {
        AuthorizedTransaction::OnChainSpend(transaction) => {
            let validated =
                validate_account_authorization(*transaction, chain, current_height, state)?;
            validate_coin_inputs(
                &validated.intent().inputs,
                validated.intent().sender,
                &validated
                    .intent()
                    .outputs
                    .iter()
                    .map(|output| output.amount)
                    .collect::<Vec<_>>(),
                state,
            )?;
            validate_state_burn(
                &validated.intent().outputs,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(&validated.intent().outputs)?,
                    ..StateTransitionWeight::default()
                },
            )?;
            Ok(ValidatedTransaction::OnChainSpend(validated))
        }
        AuthorizedTransaction::Withdraw(transaction) => {
            let validated =
                validate_account_authorization(*transaction, chain, current_height, state)?;
            let intent = validated.intent();
            let outputs = intent
                .qcash_outputs
                .iter()
                .map(|output| output.amount)
                .chain(intent.outputs.iter().map(|output| output.amount))
                .collect::<Vec<_>>();
            validate_coin_inputs(&intent.inputs, intent.sender, &outputs, state)?;
            validate_state_burn(
                &intent.outputs,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(&intent.outputs)?,
                    created_qcash_utxos: count(intent.qcash_outputs.len())?,
                    ..StateTransitionWeight::default()
                },
            )?;
            Ok(ValidatedTransaction::Withdraw(validated))
        }
        AuthorizedTransaction::Redeem(transaction) => {
            let validated = validate_bearer_authorization(*transaction, chain, state)?;
            let intent = validated.intent();
            validate_state_burn(
                &intent.outputs,
                StateTransitionWeight {
                    created_qcash_utxos: count(intent.qcash_outputs.len())?,
                    created_coin_utxos: created_coin_output_count(&intent.outputs)?,
                    ..StateTransitionWeight::default()
                },
            )?;
            Ok(ValidatedTransaction::Redeem(validated))
        }
        AuthorizedTransaction::Merge(transaction) => {
            let validated = validate_bearer_authorization(*transaction, chain, state)?;
            ensure_fresh_bearer_outputs(
                validated.intent().inputs.iter().map(|input| input.id()),
                std::iter::once(validated.intent().output.public_key),
                state,
            )?;
            validate_state_burn(
                &validated.intent().public_outputs,
                StateTransitionWeight {
                    created_qcash_utxos: 1,
                    created_coin_utxos: created_coin_output_count(
                        &validated.intent().public_outputs,
                    )?,
                    ..StateTransitionWeight::default()
                },
            )?;
            Ok(ValidatedTransaction::Merge(validated))
        }
        AuthorizedTransaction::Split(transaction) => {
            let validated = validate_bearer_authorization(*transaction, chain, state)?;
            ensure_fresh_bearer_outputs(
                std::iter::once(validated.intent().input.id()),
                validated
                    .intent()
                    .outputs
                    .iter()
                    .map(|output| output.public_key),
                state,
            )?;
            validate_state_burn(
                &validated.intent().public_outputs,
                StateTransitionWeight {
                    created_qcash_utxos: count(validated.intent().outputs.len())?,
                    created_coin_utxos: created_coin_output_count(
                        &validated.intent().public_outputs,
                    )?,
                    ..StateTransitionWeight::default()
                },
            )?;
            Ok(ValidatedTransaction::Split(validated))
        }
        AuthorizedTransaction::Asset(transaction) => {
            let transaction = *transaction;
            let asset_state = state.asset_state().ok_or(TransactionConsensusError::Asset(
                xparq_asset::AssetError::UnknownAsset,
            ))?;
            let call =
                validate_asset_authorization(transaction.call, chain, current_height, state)?;
            call.intent()
                .validate(asset_state)
                .map_err(TransactionConsensusError::Asset)?;
            let payment =
                validate_account_authorization(transaction.payment, chain, current_height, state)?;
            validate_coin_inputs(
                &payment.intent().inputs,
                payment.intent().sender,
                &payment
                    .intent()
                    .outputs
                    .iter()
                    .map(|output| output.amount)
                    .collect::<Vec<_>>(),
                state,
            )?;
            validate_state_burn(
                &payment.intent().outputs,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(&payment.intent().outputs)?,
                    extension_created_weight: call
                        .intent()
                        .created_state_weight(asset_state)
                        .map_err(TransactionConsensusError::Asset)?,
                    ..StateTransitionWeight::default()
                },
            )?;
            Ok(ValidatedTransaction::Asset(ValidatedAssetTransaction {
                call,
                payment,
            }))
        }
        AuthorizedTransaction::Extension(transaction) => {
            let transaction = *transaction;
            let fee =
                validate_account_authorization(transaction.fee, chain, current_height, state)?;
            validate_coin_inputs(
                &fee.intent().inputs,
                fee.intent().sender,
                &fee.intent()
                    .outputs
                    .iter()
                    .map(|output| output.amount)
                    .collect::<Vec<_>>(),
                state,
            )?;
            validate_state_burn(
                &fee.intent().outputs,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(&fee.intent().outputs)?,
                    extension_created_weight: state
                        .extension_created_state_weight(&transaction.call, current_height),
                    ..StateTransitionWeight::default()
                },
            )?;
            Ok(ValidatedTransaction::Extension(
                ValidatedExtensionTransaction {
                    call: transaction.call,
                    fee,
                },
            ))
        }
    }
}

fn count(value: usize) -> Result<u64, TransactionConsensusError> {
    u64::try_from(value)
        .map_err(|_| TransactionConsensusError::StateBurn(StateBurnError::WeightOverflow))
}

fn validate_state_burn(
    outputs: &[xparq_transaction::SpendOutput],
    transition: StateTransitionWeight,
) -> Result<(), TransactionConsensusError> {
    let required = transition.required_burn()?;
    validate_exact_burn(outputs, required)?;
    Ok(())
}

fn validate_asset_authorization(
    authorized: AuthorizedAccountIntent<xparq_asset::AssetCall>,
    chain: ChainContext,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<AuthorizationValidated<xparq_asset::AssetCall>, TransactionConsensusError> {
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
    let revealed_account_key = validate_profile_authorization(
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

fn validate_account_authorization<T>(
    authorized: AuthorizedAccountIntent<T>,
    chain: ChainContext,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<AuthorizationValidated<T>, TransactionConsensusError>
where
    T: ConsensusIntent + xparq_transaction::AccountIntent,
{
    let structurally_validated = validate_intent(authorized.intent, chain)?;
    let sender = xparq_transaction::AccountIntent::sender(structurally_validated.intent());
    let commitment = structurally_validated.commitment();
    let commitment_bytes = commitment.as_bytes();
    let revealed_account_key = validate_profile_authorization(
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

fn validate_profile_authorization(
    sender: Address,
    commitment_bytes: &[u8],
    authorization: AccountAuthorization,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<Option<RevealedAccountKey>, TransactionConsensusError> {
    let revealed_account_key = match authorization {
        AccountAuthorization::ProfileReveal {
            public_key,
            signature,
        } => {
            if !public_key.profile.active_at_height(current_height) {
                return Err(TransactionConsensusError::SignatureSchemeInactive);
            }
            let registered = state.profile_public_key(sender);
            let was_registered = registered.is_some();
            let public_key = match registered.as_ref() {
                Some(registered) if registered == &public_key => registered.clone(),
                None if xparq_crypto::address_from_profile_public_key(&public_key) == sender => {
                    public_key
                }
                _ => return Err(TransactionConsensusError::InvalidAuthorization),
            };
            if !xparq_crypto::profile_verify(&public_key, commitment_bytes, &signature) {
                return Err(TransactionConsensusError::InvalidAuthorization);
            }
            (!was_registered).then_some(RevealedAccountKey::Profile(public_key))
        }
        AccountAuthorization::ProfileKnown { profile, signature } => {
            if !profile.active_at_height(current_height) || signature.profile != profile {
                return Err(TransactionConsensusError::SignatureSchemeInactive);
            }
            let public_key = state
                .profile_public_key(sender)
                .ok_or(TransactionConsensusError::InvalidAuthorization)?;
            if public_key.profile != profile
                || !xparq_crypto::profile_verify(&public_key, commitment_bytes, &signature)
            {
                return Err(TransactionConsensusError::InvalidAuthorization);
            }
            None
        }
    };
    Ok(revealed_account_key)
}

fn validate_bearer_authorization<T>(
    authorized: AuthorizedQCashIntent<T>,
    chain: ChainContext,
    state: &impl TransactionStateView,
) -> Result<AuthorizationValidated<T>, TransactionConsensusError>
where
    T: ConsensusIntent + QCashIntent + BorshSerialize,
{
    let inputs = authorized.intent.qcash_inputs();
    ensure_unique_coin_ids(inputs.iter().map(|input| input.id()))?;
    if inputs.len() != authorized.authorizations.len() {
        return Err(TransactionConsensusError::InvalidAuthorization);
    }
    let structurally_validated = validate_intent(authorized.intent, chain)?;
    for (input, authorization) in inputs.iter().zip(&authorized.authorizations) {
        let input_state = state
            .qcash(input.id())
            .ok_or(TransactionConsensusError::UtxoNotFound)?;
        if input.amount() != input_state.amount {
            return Err(TransactionConsensusError::InputAmountMismatch);
        }
        if !xparq_crypto::qcash_verify(
            &input_state.public_key,
            structurally_validated.commitment().as_bytes(),
            &authorization.signature,
        ) {
            return Err(TransactionConsensusError::InvalidAuthorization);
        }
    }
    let commitment = structurally_validated.commitment();
    Ok(AuthorizationValidated {
        intent: structurally_validated.into_intent(),
        commitment,
        revealed_account_key: None,
    })
}

fn validate_coin_inputs(
    inputs: &[CoinId],
    owner: Address,
    outputs: &[Amount],
    state: &impl TransactionStateView,
) -> Result<(), TransactionConsensusError> {
    ensure_unique_coin_ids(inputs.iter().copied())?;
    let mut input_total = Amount::from_zeno(0);
    for id in inputs {
        let input = state
            .coin(*id)
            .ok_or(TransactionConsensusError::UtxoNotFound)?;
        if input.owner != owner {
            return Err(TransactionConsensusError::OwnerMismatch);
        }
        input_total = input_total
            .checked_add(input.amount)
            .ok_or(TransactionConsensusError::AmountOverflow)?;
    }
    let output_total = outputs
        .iter()
        .try_fold(Amount::from_zeno(0), |sum, amount| {
            sum.checked_add(*amount)
                .ok_or(TransactionConsensusError::AmountOverflow)
        })?;
    if input_total != output_total {
        return Err(TransactionConsensusError::ValueMismatch);
    }
    Ok(())
}

fn ensure_unique_coin_ids(
    ids: impl IntoIterator<Item = CoinId>,
) -> Result<(), TransactionConsensusError> {
    let mut unique = BTreeSet::new();
    if ids.into_iter().any(|id| !unique.insert(id)) {
        return Err(TransactionConsensusError::Intent(
            IntentError::DuplicateInput,
        ));
    }
    Ok(())
}

fn ensure_fresh_bearer_outputs(
    input_ids: impl IntoIterator<Item = CoinId>,
    output_commitments: impl IntoIterator<Item = QCashPublicKey>,
    state: &impl TransactionStateView,
) -> Result<(), TransactionConsensusError> {
    let input_commitments = input_ids
        .into_iter()
        .map(|id| {
            state
                .qcash(id)
                .map(|input| input.public_key)
                .ok_or(TransactionConsensusError::UtxoNotFound)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if output_commitments
        .into_iter()
        .any(|commitment| input_commitments.contains(&commitment))
    {
        return Err(TransactionConsensusError::ReusedBearerKey);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionConsensusError {
    Intent(IntentError),
    InvalidAuthorization,
    SignatureSchemeInactive,
    UtxoNotFound,
    OwnerMismatch,
    InputAmountMismatch,
    ReusedBearerKey,
    AmountOverflow,
    ValueMismatch,
    Asset(xparq_asset::AssetError),
    StateBurn(StateBurnError),
}

impl fmt::Display for TransactionConsensusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::InputAmountMismatch => {
                formatter.write_str("QCash input amount does not match canonical state")
            }
            Self::ReusedBearerKey => {
                formatter.write_str("QCash output must use a fresh bearer key")
            }
            Self::AmountOverflow => formatter.write_str("transaction amount overflow"),
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

#[cfg(test)]
mod transaction_tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct State {
        id: CoinId,
        public_key: QCashPublicKey,
    }

    impl TransactionStateView for State {
        fn coin(&self, _: CoinId) -> Option<CoinInputState> {
            None
        }

        fn qcash(&self, id: CoinId) -> Option<QCashInputState> {
            (id == self.id).then_some(QCashInputState {
                amount: Amount::from_zeno(3_000),
                public_key: self.public_key,
            })
        }

        fn profile_public_key(&self, _: Address) -> Option<ProfilePublicKey> {
            None
        }
    }

    #[test]
    fn qcash_transform_rejects_an_input_bearer_key_as_an_output_key() {
        let id = CoinId::from_bytes([3; CoinId::SIZE]);
        let state = State {
            id,
            public_key: QCashPublicKey([9; xparq_crypto::QCASH_PUBLIC_KEY_SIZE]),
        };
        assert_eq!(
            ensure_fresh_bearer_outputs(
                [id],
                [QCashPublicKey([9; xparq_crypto::QCASH_PUBLIC_KEY_SIZE])],
                &state,
            ),
            Err(TransactionConsensusError::ReusedBearerKey)
        );
        assert_eq!(
            ensure_fresh_bearer_outputs(
                [id],
                [QCashPublicKey([8; xparq_crypto::QCASH_PUBLIC_KEY_SIZE])],
                &state,
            ),
            Ok(())
        );
    }

    #[test]
    fn qcash_spend_requires_a_valid_input_signature() {
        let id = CoinId::from_bytes([4; CoinId::SIZE]);
        let seed = xparq_qcash::QCashSigningSeed::from_bytes([5; 32]);
        let intent = SplitIntent::new(
            xparq_qcash::QCash::new(id, Amount::from_zeno(3_000)),
            vec![
                xparq_transaction::QCashOutput::new(
                    Amount::from_zeno(500),
                    QCashPublicKey([6; xparq_crypto::QCASH_PUBLIC_KEY_SIZE]),
                ),
                xparq_transaction::QCashOutput::new(
                    Amount::from_zeno(2_500 - 2 * crate::QCASH_UTXO_STATE_WEIGHT),
                    QCashPublicKey([7; xparq_crypto::QCASH_PUBLIC_KEY_SIZE]),
                ),
            ],
            vec![xparq_transaction::SpendOutput::burn(Amount::from_zeno(
                2 * crate::QCASH_UTXO_STATE_WEIGHT,
            ))],
        )
        .unwrap();
        let chain = ChainContext::new([8; 32]);
        let commitment = intent.commitment(chain).unwrap();
        let signed = AuthorizedQCashIntent::new(
            intent,
            vec![xparq_transaction::QCashAuthorization {
                signature: seed.sign(commitment.as_bytes()),
            }],
        )
        .unwrap();
        let state = State {
            id,
            public_key: seed.public_key(),
        };
        assert!(matches!(
            validate_transaction(
                AuthorizedTransaction::Split(Box::new(signed.clone())),
                chain,
                60,
                &state,
            ),
            Ok(ValidatedTransaction::Split(_))
        ));
        let mut tampered = signed;
        tampered.intent.outputs[0].amount = Amount::from_zeno(501);
        tampered.intent.outputs[1].amount =
            Amount::from_zeno(2_499 - 2 * crate::QCASH_UTXO_STATE_WEIGHT);
        assert_eq!(
            validate_transaction(
                AuthorizedTransaction::Split(Box::new(tampered)),
                chain,
                60,
                &state,
            ),
            Err(TransactionConsensusError::InvalidAuthorization)
        );
    }

    struct FalconAccountState {
        id: CoinId,
        owner: Address,
    }

    impl TransactionStateView for FalconAccountState {
        fn coin(&self, id: CoinId) -> Option<CoinInputState> {
            (id == self.id).then_some(CoinInputState {
                amount: Amount::from_zeno(10 + crate::COIN_UTXO_STATE_WEIGHT),
                owner: self.owner,
            })
        }

        fn qcash(&self, _: CoinId) -> Option<QCashInputState> {
            None
        }

        fn profile_public_key(&self, _: Address) -> Option<ProfilePublicKey> {
            None
        }
    }

    #[test]
    fn profile_authorization_is_active_from_genesis_and_verified() {
        let signing = xparq_crypto::ProfileSigningSeed::new(
            xparq_crypto::SignatureProfile::MlDsa65,
            [26; 32],
        );
        let public_key = signing.public_key();
        let sender = xparq_crypto::address_from_profile_public_key(&public_key);
        let id = CoinId::from_bytes([27; CoinId::SIZE]);
        let intent = OnChainSpendIntent::new(
            sender,
            vec![id],
            vec![
                xparq_transaction::SpendOutput::new(sender, Amount::from_zeno(10)),
                xparq_transaction::SpendOutput::burn(Amount::from_zeno(
                    crate::COIN_UTXO_STATE_WEIGHT,
                )),
            ],
        )
        .unwrap();
        let chain = ChainContext::new([28; 32]);
        let signature = signing.sign(intent.commitment(chain).unwrap().as_bytes());
        let transaction = AuthorizedTransaction::OnChainSpend(Box::new(AuthorizedAccountIntent {
            intent,
            authorization: AccountAuthorization::ProfileReveal {
                public_key,
                signature,
            },
        }));
        let state = FalconAccountState { id, owner: sender };
        assert!(matches!(
            validate_transaction(transaction, chain, 0, &state),
            Ok(ValidatedTransaction::OnChainSpend(_))
        ));
    }
}

pub const MIN_DIFFICULTY: u32 = 1;
/// A 256-bit PoW output cannot represent a stricter leading-zero target.
pub const MAX_DIFFICULTY: u32 = (crate::crypto::POW_HASH_SIZE * 8) as u32;
/// Compatibility name for the height-zero difficulty. Unlike
/// [`DIFFICULTY_START`], this value belongs to the stable genesis header.
pub const GENESIS_DIFFICULTY: u32 = crate::block::GENESIS_BLOCK_DIFFICULTY;
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

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
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
    Serialization(crate::error::CodecError),
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
        cumulative_work = cumulative_work.saturating_add(crate::fork::block_work(expected));
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
