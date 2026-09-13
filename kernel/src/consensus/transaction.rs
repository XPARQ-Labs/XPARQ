use std::{collections::BTreeSet, error::Error as StdError, fmt};

use crypto::{Address, canonical_bytes};

use crate::{
    consensus::{
        BurnError, ProtocolBurn, StateTransitionWeight, created_coin_output_count,
        validate_exact_burn,
    },
    native::{
        asset::{AssetError, AssetShare, Share},
        coin::{CoinOutput, XPQ, Zeno},
    },
    transaction::{
        AccountAuthorization, AccountIntent, AssetInstruction, AssetIntent,
        AuthorizedAccountIntent, AuthorizedTransaction, IntentError, Spend,
        SpendCommitment, SpendIntent, Transaction as OnChainTransaction,
    },
    common::ChainContext,
};

pub trait ConsensusIntent: Clone {
    fn validate_structure(&self) -> Result<(), IntentError>;
    fn commitment_for(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError>;
}

impl ConsensusIntent for SpendIntent {
    fn validate_structure(&self) -> Result<(), IntentError> {
        self.validate()
    }

    fn commitment_for(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain)
    }
}

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
}

impl<T> AuthorizationValidated<T> {
    pub fn intent(&self) -> &T {
        &self.intent
    }

    pub const fn commitment(&self) -> SpendCommitment {
        self.commitment
    }
}

/// Validated direct on-chain transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedTransaction {
    CoinSpend(ValidatedCoinSpend),
    AssetTransfer(ValidatedAssetTransfer),
    AssetCall(ValidatedAssetCall),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCoinSpend {
    pub spend: AuthorizationValidated<SpendIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAssetTransfer {
    pub spend: AuthorizationValidated<SpendIntent>,
    pub payment: AuthorizationValidated<SpendIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAssetCall {
    pub call: AuthorizationValidated<AssetIntent>,
    pub payment: AuthorizationValidated<SpendIntent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinInputState {
    pub amount: Zeno,
    pub owner: Address,
}

pub trait TransactionStateView {
    fn coin(&self, id: XPQ) -> Option<CoinInputState>;

    fn asset_share(&self, _id: Share) -> Option<AssetShare> {
        None
    }

    fn asset_spend_created_state_weight(&self, _intent: &SpendIntent) -> Result<u64, AssetError> {
        Err(AssetError::UnknownAsset)
    }

    fn asset_transition_created_state_weight(
        &self,
        _call: &AssetIntent,
        _genesis_hash: [u8; 32],
    ) -> Result<u64, AssetError> {
        Err(AssetError::UnknownAsset)
    }
}

pub fn validate_transaction(
    transaction: OnChainTransaction,
    chain: ChainContext,
    current_height: u64,
    state: &impl TransactionStateView,
) -> Result<ValidatedTransaction, TransactionConsensusError> {
    let canonical_transaction_weight = u64::try_from(
        canonical_bytes(&transaction)
            .map_err(|_| TransactionConsensusError::Encoding)?
            .len(),
    )
    .map_err(|_| TransactionConsensusError::Burn(BurnError::WeightOverflow))?;

    validate_authorized_transaction(
        transaction,
        chain,
        current_height,
        canonical_transaction_weight,
        state,
    )
}

fn validate_authorized_transaction(
    transaction: AuthorizedTransaction,
    chain: ChainContext,
    current_height: u64,
    canonical_transaction_weight: u64,
    state: &impl TransactionStateView,
) -> Result<ValidatedTransaction, TransactionConsensusError> {
    match transaction {
        AuthorizedTransaction::Spend(transaction) => {
            let transaction = *transaction;

            let spend = validate_account_intent_authorization(
                transaction.spend,
                chain,
                current_height,
                state,
            )?;

            match &spend.intent().spend {
                Spend::Coin { inputs, outputs } => {
                    if transaction.payment.is_some() {
                        return Err(TransactionConsensusError::Intent(
                            IntentError::InvalidAssetCall,
                        ));
                    }

                    let actual_burn =
                        validate_coin_inputs(inputs, outputs, spend.intent().signer, state)?;

                    validate_required_burn(
                        actual_burn,
                        StateTransitionWeight {
                            created_coin_utxos: created_coin_output_count(outputs)?,
                            consumed_coin_utxos: count_inputs(inputs.len())?,
                            ..StateTransitionWeight::default()
                        },
                        canonical_transaction_weight,
                    )?;

                    Ok(ValidatedTransaction::CoinSpend(ValidatedCoinSpend {
                        spend,
                    }))
                }

                Spend::Asset {
                    inputs, outputs: _, ..
                } => {
                    validate_share_ownership(inputs, spend.intent().signer, state)?;

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

                    let (payment_inputs, payment_outputs) = coin_parts(payment.intent())?;

                    let actual_burn = validate_coin_inputs(
                        payment_inputs,
                        payment_outputs,
                        payment.intent().signer,
                        state,
                    )?;

                    let asset_weight = state
                        .asset_spend_created_state_weight(spend.intent())
                        .map_err(TransactionConsensusError::Asset)?;

                    validate_required_burn(
                        actual_burn,
                        StateTransitionWeight {
                            created_coin_utxos: created_coin_output_count(payment_outputs)?,
                            consumed_coin_utxos: count_inputs(payment_inputs.len())?,
                            created_state_weight: asset_weight,
                        },
                        canonical_transaction_weight,
                    )?;

                    Ok(ValidatedTransaction::AssetTransfer(
                        ValidatedAssetTransfer { spend, payment },
                    ))
                }
            }
        }

        AuthorizedTransaction::Asset(transaction) => {
            let transaction = *transaction;

            let call =
                validate_asset_authorization(transaction.call, chain, current_height, state)?;

            if let AssetInstruction::Burn { inputs, .. } = &call.intent().instruction {
                validate_share_ownership(inputs, call.intent().signer, state)?;
            }

            let asset_created_state_weight = state
                .asset_transition_created_state_weight(call.intent(), chain.genesis_hash)
                .map_err(TransactionConsensusError::Asset)?;

            let payment = validate_account_intent_authorization(
                transaction.payment,
                chain,
                current_height,
                state,
            )?;

            let (payment_inputs, payment_outputs) = coin_parts(payment.intent())?;

            let actual_burn = validate_coin_inputs(
                payment_inputs,
                payment_outputs,
                payment.intent().signer,
                state,
            )?;

            validate_required_burn(
                actual_burn,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(payment_outputs)?,
                    consumed_coin_utxos: count_inputs(payment_inputs.len())?,
                    created_state_weight: asset_created_state_weight,
                },
                canonical_transaction_weight,
            )?;

            Ok(ValidatedTransaction::AssetCall(ValidatedAssetCall {
                call,
                payment,
            }))
        }
    }
}

fn count_inputs(len: usize) -> Result<u64, TransactionConsensusError> {
    u64::try_from(len).map_err(|_| TransactionConsensusError::Burn(BurnError::WeightOverflow))
}

fn coin_parts(intent: &SpendIntent) -> Result<(&[XPQ], &[CoinOutput]), TransactionConsensusError> {
    intent.coin_parts().ok_or(TransactionConsensusError::Intent(
        IntentError::InvalidAssetCall,
    ))
}

fn validate_required_burn(
    actual: Zeno,
    transition: StateTransitionWeight,
    canonical_transaction_weight: u64,
) -> Result<(), TransactionConsensusError> {
    let required =
        ProtocolBurn::for_transaction(transition, canonical_transaction_weight)?.total()?;

    validate_exact_burn(actual, required)?;
    Ok(())
}

fn validate_asset_authorization(
    authorized: AuthorizedAccountIntent<AssetIntent>,
    chain: ChainContext,
    current_height: u64,
    _state: &impl TransactionStateView,
) -> Result<AuthorizationValidated<AssetIntent>, TransactionConsensusError> {
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

    validate_account_authorization(
        sender,
        commitment.as_bytes(),
        authorized.authorization,
        current_height,
    )?;

    Ok(AuthorizationValidated {
        intent: authorized.intent,
        commitment,
    })
}

fn validate_account_intent_authorization<T>(
    authorized: AuthorizedAccountIntent<T>,
    chain: ChainContext,
    current_height: u64,
    _state: &impl TransactionStateView,
) -> Result<AuthorizationValidated<T>, TransactionConsensusError>
where
    T: ConsensusIntent + AccountIntent,
{
    let structurally_validated = validate_intent(authorized.intent, chain)?;
    let sender = AccountIntent::sender(structurally_validated.intent());
    let commitment = structurally_validated.commitment();

    validate_account_authorization(
        sender,
        commitment.as_bytes(),
        authorized.authorization,
        current_height,
    )?;

    Ok(AuthorizationValidated {
        intent: structurally_validated.into_intent(),
        commitment,
    })
}

fn validate_account_authorization(
    sender: Address,
    commitment_bytes: &[u8],
    authorization: AccountAuthorization,
    current_height: u64,
) -> Result<(), TransactionConsensusError> {
    let AccountAuthorization {
        public_key,
        signature,
    } = authorization;
    if !public_key.account.active_at_height(current_height)
        || signature.account != public_key.account
    {
        return Err(TransactionConsensusError::SignatureSchemeInactive);
    }
    if crypto::address_from_public_key(&public_key) != sender
        || !crypto::verify(&public_key, commitment_bytes, &signature)
    {
        return Err(TransactionConsensusError::InvalidAuthorization);
    }
    Ok(())
}

fn validate_coin_inputs(
    inputs: &[XPQ],
    outputs: &[CoinOutput],
    signer: Address,
    state: &impl TransactionStateView,
) -> Result<Zeno, TransactionConsensusError> {
    ensure_unique_coin_ids(inputs.iter().copied())?;

    let mut input_total = Zeno::ZERO;

    for id in inputs {
        let input = state
            .coin(*id)
            .ok_or(TransactionConsensusError::UtxoNotFound)?;

        if input.owner != signer {
            return Err(TransactionConsensusError::RecipientMismatch);
        }

        input_total = input_total
            .checked_add(input.amount)
            .ok_or(TransactionConsensusError::ZenoOverflow)?;
    }

    let output_total = outputs.iter().try_fold(Zeno::ZERO, |sum, output| {
        sum.checked_add(output.amount)
            .ok_or(TransactionConsensusError::ZenoOverflow)
    })?;

    input_total
        .checked_sub(output_total)
        .ok_or(TransactionConsensusError::ValueMismatch)
}

fn validate_share_ownership(
    inputs: &[Share],
    signer: Address,
    state: &impl TransactionStateView,
) -> Result<(), TransactionConsensusError> {
    let mut unique = BTreeSet::new();

    for id in inputs {
        if !unique.insert(*id) {
            return Err(TransactionConsensusError::Intent(
                IntentError::DuplicateInput,
            ));
        }

        let share = state
            .asset_share(*id)
            .ok_or(TransactionConsensusError::OwnershipProofMissing)?;

        if share.owner != signer {
            return Err(TransactionConsensusError::RecipientMismatch);
        }
    }

    Ok(())
}

fn ensure_unique_coin_ids(
    ids: impl IntoIterator<Item = XPQ>,
) -> Result<(), TransactionConsensusError> {
    let mut unique = BTreeSet::new();

    if ids.into_iter().any(|id| !unique.insert(id)) {
        return Err(TransactionConsensusError::Intent(
            IntentError::DuplicateInput,
        ));
    }

    Ok(())
}

#[derive(Debug)]
pub enum TransactionConsensusError {
    Encoding,
    Intent(IntentError),
    InvalidAuthorization,
    SignatureSchemeInactive,
    UtxoNotFound,
    OwnershipProofMissing,
    RecipientMismatch,
    ZenoOverflow,
    ValueMismatch,
    Asset(AssetError),
    Burn(BurnError),
}

impl fmt::Display for TransactionConsensusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding => formatter.write_str("transaction encoding failed"),
            Self::Intent(error) => write!(formatter, "invalid transaction intent: {error}"),
            Self::InvalidAuthorization => {
                formatter.write_str("transaction authorization is invalid")
            }
            Self::SignatureSchemeInactive => {
                formatter.write_str("transaction signature scheme is not active at this height")
            }
            Self::UtxoNotFound => formatter.write_str("transaction input UTXO was not found"),
            Self::OwnershipProofMissing => {
                formatter.write_str("transaction input ownership proof is unavailable")
            }
            Self::RecipientMismatch => {
                formatter.write_str("transaction input is not committed to this signer")
            }
            Self::ZenoOverflow => formatter.write_str("transaction amount overflow"),
            Self::ValueMismatch => {
                formatter.write_str("transaction outputs exceed canonical input value")
            }
            Self::Asset(error) => write!(formatter, "invalid native asset transaction: {error}"),
            Self::Burn(error) => write!(formatter, "invalid protocol burn: {error}"),
        }
    }
}

impl StdError for TransactionConsensusError {}

impl From<BurnError> for TransactionConsensusError {
    fn from(error: BurnError) -> Self {
        Self::Burn(error)
    }
}
