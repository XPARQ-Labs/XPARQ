//! Transaction consensus: authorization, ownership, value conservation,
//! and protocol burn.

use std::{collections::BTreeSet, error::Error as StdError, fmt};

use crypto::{Address, PublicKey, canonical_bytes};

use crate::consensus::{
    BurnError, ProtocolBurn, StateTransitionWeight, account_key_state_weight,
    created_coin_output_count, validate_exact_burn,
};
use crate::native::asset::{AssetError, AssetShare, Share};
use crate::native::coin::{Output as CoinOutput, XPQ, Zeno};
use crate::native::pool::{PoolAmount, PoolError, PoolShareHash};
use crate::transaction::{
    AccountAuthorization, AccountIntent, AssetInstruction, AssetIntent, AuthorizedAccountIntent,
    AuthorizedTransaction, ChainContext, IntentError, PoolFunding, PoolInstruction, PoolIntent,
    Spend, SpendCommitment, SpendIntent, Transaction as OnChainTransaction,
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

impl ConsensusIntent for PoolIntent {
    fn validate_structure(&self) -> Result<(), IntentError> {
        self.validate_structure()
            .map_err(|_| IntentError::InvalidAssetCall)
    }
    fn commitment_for(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain.genesis_hash)
            .map(SpendCommitment::from_bytes)
            .map_err(|_| IntentError::InvalidAssetCall)
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

/// Validated direct on-chain transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedAuthorizedTransaction {
    Spend(ValidatedSpendTransaction),
    Asset(ValidatedAssetTransaction),
    Pool(ValidatedPoolTransaction),
}

pub type ValidatedTransaction = ValidatedAuthorizedTransaction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSpendTransaction {
    pub spend: AuthorizationValidated<SpendIntent>,
    pub payment: Option<AuthorizationValidated<SpendIntent>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAssetTransaction {
    pub call: AuthorizationValidated<AssetIntent>,
    pub payment: AuthorizationValidated<SpendIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPoolTransaction {
    pub call: AuthorizationValidated<PoolIntent>,
    pub payment: AuthorizationValidated<SpendIntent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinInputState {
    pub amount: Zeno,
}

/// Canonical/derived state required by transaction validation.
///
/// `coin_recipient` and `share_recipient` do NOT require owner fields in UTXO
/// state. They may be resolved by a deterministic origin index reconstructed
/// from canonical direct transactions.
pub trait TransactionStateView {
    fn coin(&self, id: XPQ) -> Option<CoinInputState>;

    fn coin_recipient(&self, id: XPQ) -> Option<Address>;

    fn share_recipient(&self, id: Share) -> Option<Address>;
    fn asset_share(&self, _id: Share) -> Option<AssetShare> {
        None
    }
    fn pool_share_owner(&self, _id: PoolShareHash) -> Option<Address> {
        None
    }
    fn validate_pool_transition(
        &self,
        _intent: &PoolIntent,
        _height: crypto::Height,
        _commitment: [u8; 32],
    ) -> Result<(), PoolError> {
        Err(PoolError::UnknownPool)
    }

    fn account_public_key(&self, address: Address) -> Option<PublicKey>;

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

/// Validate one directly authorized on-chain transaction.
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
) -> Result<ValidatedAuthorizedTransaction, TransactionConsensusError> {
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
                            created_account_key_weight: revealed_account_key_weight(
                                spend.revealed_account_key(),
                            )?,
                            ..StateTransitionWeight::default()
                        },
                        canonical_transaction_weight,
                    )?;

                    Ok(ValidatedAuthorizedTransaction::Spend(
                        ValidatedSpendTransaction {
                            spend,
                            payment: None,
                        },
                    ))
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

                    let key_weight = combined_revealed_key_weight(
                        spend.intent().signer,
                        spend.revealed_account_key(),
                        payment.intent().signer,
                        payment.revealed_account_key(),
                    )?;

                    validate_required_burn(
                        actual_burn,
                        StateTransitionWeight {
                            created_coin_utxos: created_coin_output_count(payment_outputs)?,
                            consumed_coin_utxos: count_inputs(payment_inputs.len())?,
                            created_account_key_weight: key_weight,
                            created_state_weight: asset_weight,
                        },
                        canonical_transaction_weight,
                    )?;

                    Ok(ValidatedAuthorizedTransaction::Spend(
                        ValidatedSpendTransaction {
                            spend,
                            payment: Some(payment),
                        },
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

            let key_weight = combined_revealed_key_weight(
                call.intent().signer,
                call.revealed_account_key(),
                payment.intent().signer,
                payment.revealed_account_key(),
            )?;

            validate_required_burn(
                actual_burn,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(payment_outputs)?,
                    consumed_coin_utxos: count_inputs(payment_inputs.len())?,
                    created_account_key_weight: key_weight,
                    created_state_weight: asset_created_state_weight,
                },
                canonical_transaction_weight,
            )?;

            Ok(ValidatedAuthorizedTransaction::Asset(
                ValidatedAssetTransaction { call, payment },
            ))
        }
        AuthorizedTransaction::Pool(transaction) => {
            let transaction = *transaction;
            let call = validate_account_intent_authorization(
                transaction.call,
                chain,
                current_height,
                state,
            )?;
            validate_pool_funding(call.intent(), state)?;
            if let PoolInstruction::RemoveLiquidity { share, .. } = call.intent().instruction {
                if state.pool_share_owner(share) != Some(call.intent().signer) {
                    return Err(TransactionConsensusError::RecipientMismatch);
                }
            }
            state
                .validate_pool_transition(
                    call.intent(),
                    crypto::Height(current_height),
                    call.commitment().into_bytes(),
                )
                .map_err(TransactionConsensusError::Pool)?;
            let payment = validate_account_intent_authorization(
                transaction.payment,
                chain,
                current_height,
                state,
            )?;
            let (payment_inputs, payment_outputs) = coin_parts(payment.intent())?;
            ensure_pool_payment_disjoint(call.intent(), payment_inputs)?;
            let actual_burn = validate_coin_inputs(
                payment_inputs,
                payment_outputs,
                payment.intent().signer,
                state,
            )?;
            let key_weight = combined_revealed_key_weight(
                call.intent().signer,
                call.revealed_account_key(),
                payment.intent().signer,
                payment.revealed_account_key(),
            )?;
            validate_required_burn(
                actual_burn,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(payment_outputs)?,
                    consumed_coin_utxos: count_inputs(payment_inputs.len())?,
                    created_account_key_weight: key_weight,
                    ..StateTransitionWeight::default()
                },
                canonical_transaction_weight,
            )?;
            Ok(ValidatedAuthorizedTransaction::Pool(
                ValidatedPoolTransaction { call, payment },
            ))
        }
    }
}

fn validate_pool_funding(
    intent: &PoolIntent,
    state: &impl TransactionStateView,
) -> Result<(), TransactionConsensusError> {
    let validate =
        |funding: &PoolFunding, expected: PoolAmount| -> Result<(), TransactionConsensusError> {
            let actual = match funding {
                PoolFunding::Coin { inputs } => {
                    ensure_unique_coin_ids(inputs.iter().copied())?;
                    let mut total = Zeno::ZERO;
                    for id in inputs {
                        if state.coin_recipient(*id) != Some(intent.signer) {
                            return Err(TransactionConsensusError::RecipientMismatch);
                        }
                        total = total
                            .checked_add(
                                state
                                    .coin(*id)
                                    .ok_or(TransactionConsensusError::UtxoNotFound)?
                                    .amount,
                            )
                            .ok_or(TransactionConsensusError::ZenoOverflow)?;
                    }
                    PoolAmount::from(total)
                }
                PoolFunding::Asset { asset, inputs } => {
                    validate_share_ownership(inputs, intent.signer, state)?;
                    let mut total = crate::native::asset::Unit::ZERO;
                    for id in inputs {
                        let share = state
                            .asset_share(*id)
                            .ok_or(TransactionConsensusError::UtxoNotFound)?;
                        if share.parent != *asset {
                            return Err(TransactionConsensusError::ValueMismatch);
                        }
                        total = total
                            .checked_add(share.amount)
                            .ok_or(TransactionConsensusError::ValueMismatch)?;
                    }
                    PoolAmount::from(total)
                }
            };
            if actual != expected {
                return Err(TransactionConsensusError::ValueMismatch);
            }
            Ok(())
        };
    match &intent.instruction {
        PoolInstruction::Create {
            amount_x,
            amount_y,
            funding_x,
            funding_y,
            ..
        }
        | PoolInstruction::AddLiquidity {
            amount_x,
            amount_y,
            funding_x,
            funding_y,
            ..
        } => {
            validate(funding_x, *amount_x)?;
            validate(funding_y, *amount_y)
        }
        PoolInstruction::Swap {
            amount_in, funding, ..
        } => validate(funding, *amount_in),
        PoolInstruction::RemoveLiquidity { .. } => Ok(()),
    }
}

fn ensure_pool_payment_disjoint(
    intent: &PoolIntent,
    payment_inputs: &[XPQ],
) -> Result<(), TransactionConsensusError> {
    let payment: BTreeSet<_> = payment_inputs.iter().copied().collect();
    let overlaps = |funding: &PoolFunding| match funding {
        PoolFunding::Coin { inputs } => inputs.iter().any(|id| payment.contains(id)),
        PoolFunding::Asset { .. } => false,
    };
    let duplicate = match &intent.instruction {
        PoolInstruction::Create {
            funding_x,
            funding_y,
            ..
        }
        | PoolInstruction::AddLiquidity {
            funding_x,
            funding_y,
            ..
        } => overlaps(funding_x) || overlaps(funding_y),
        PoolInstruction::Swap { funding, .. } => overlaps(funding),
        PoolInstruction::RemoveLiquidity { .. } => false,
    };
    if duplicate {
        Err(TransactionConsensusError::ValueMismatch)
    } else {
        Ok(())
    }
}

fn count_inputs(len: usize) -> Result<u64, TransactionConsensusError> {
    u64::try_from(len).map_err(|_| TransactionConsensusError::Burn(BurnError::WeightOverflow))
}

fn revealed_account_key_weight(
    revealed: Option<&RevealedAccountKey>,
) -> Result<u64, TransactionConsensusError> {
    match revealed {
        Some(RevealedAccountKey::Account(public_key)) => {
            account_key_state_weight(public_key).map_err(TransactionConsensusError::Burn)
        }
        None => Ok(0),
    }
}

fn combined_revealed_key_weight(
    first_signer: Address,
    first: Option<&RevealedAccountKey>,
    second_signer: Address,
    second: Option<&RevealedAccountKey>,
) -> Result<u64, TransactionConsensusError> {
    let first_weight = revealed_account_key_weight(first)?;

    if first_signer == second_signer && first.is_some() && second.is_some() {
        return Ok(first_weight);
    }

    first_weight
        .checked_add(revealed_account_key_weight(second)?)
        .ok_or(TransactionConsensusError::Burn(BurnError::WeightOverflow))
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
    state: &impl TransactionStateView,
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
    T: ConsensusIntent + AccountIntent,
{
    let structurally_validated = validate_intent(authorized.intent, chain)?;
    let sender = AccountIntent::sender(structurally_validated.intent());
    let commitment = structurally_validated.commitment();

    let revealed_account_key = validate_account_authorization(
        sender,
        commitment.as_bytes(),
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
    match authorization {
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

            Ok((!was_registered).then_some(RevealedAccountKey::Account(public_key)))
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

            Ok(None)
        }
    }
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

        let recipient = state
            .coin_recipient(*id)
            .ok_or(TransactionConsensusError::OwnershipProofMissing)?;

        if recipient != signer {
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

        let recipient = state
            .share_recipient(*id)
            .ok_or(TransactionConsensusError::OwnershipProofMissing)?;

        if recipient != signer {
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
    Pool(PoolError),
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
            Self::Pool(error) => write!(formatter, "invalid native pool transaction: {error}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::LedgerState;
    use crate::native::coin::Output as CoinOutput;
    use crate::native::{Pair, PoolAmount, PoolHash};
    use crate::transaction::Spend;
    use crate::transaction::{PoolFunding, PoolInstruction, PoolIntent};

    #[test]
    fn direct_spend_application_and_rollback_are_atomic() {
        let owner = Address([7; crypto::ADDRESS_SIZE]);
        let recipient = Address([9; crypto::ADDRESS_SIZE]);
        let input = XPQ::from_bytes([3; crypto::HASH_SIZE]);
        let spend_commitment = SpendCommitment::from_bytes([5; crypto::HASH_SIZE]);
        let chain = ChainContext::new([1; crypto::HASH_SIZE]);

        let mut state = LedgerState::default();
        state.utxos.insert_coin(input, Zeno::from_zeno(10)).unwrap();
        state.coin_recipients.insert(input, owner);

        let intent = SpendIntent {
            signer: owner,
            spend: Spend::Coin {
                inputs: vec![input],
                outputs: vec![CoinOutput::new(recipient, Zeno::from_zeno(9))],
            },
        };
        let transaction = ValidatedTransaction::Spend(ValidatedSpendTransaction {
            spend: AuthorizationValidated {
                intent,
                commitment: spend_commitment,
                revealed_account_key: None,
            },
            payment: None,
        });

        let journal = state
            .apply_validated_transaction(&transaction, crypto::Height(1), owner, chain)
            .unwrap();
        let output = XPQ::from_output(spend_commitment.as_bytes(), 0);
        assert_eq!(state.utxos.coin(&input), None);
        assert_eq!(state.utxos.coin(&output), Some(Zeno::from_zeno(9)));
        assert_eq!(state.coin_recipients.get(&output), Some(&recipient));
        assert_eq!(state.total_burned, Zeno::ONE);

        state.rollback_state(journal).unwrap();
        assert_eq!(state.utxos.coin(&input), Some(Zeno::from_zeno(10)));
        assert_eq!(state.coin_recipients.get(&input), Some(&owner));
        assert_eq!(state.utxos.coin(&output), None);
        assert_eq!(state.total_burned, Zeno::ZERO);
    }

    #[test]
    fn funded_pool_creation_and_rollback_are_atomic() {
        let owner = Address([7; crypto::ADDRESS_SIZE]);
        let asset = crate::native::asset::Asset::from_bytes([8; crypto::HASH_SIZE]);
        let coin_input = XPQ::from_bytes([1; crypto::HASH_SIZE]);
        let payment_input = XPQ::from_bytes([2; crypto::HASH_SIZE]);
        let asset_input = Share::from_bytes([3; crypto::HASH_SIZE]);
        let call_commitment = SpendCommitment::from_bytes([4; crypto::HASH_SIZE]);
        let payment_commitment = SpendCommitment::from_bytes([5; crypto::HASH_SIZE]);
        let chain = ChainContext::new([6; crypto::HASH_SIZE]);
        let mut state = LedgerState::default();
        state
            .utxos
            .insert_coin(coin_input, Zeno::from_zeno(100))
            .unwrap();
        state.coin_recipients.insert(coin_input, owner);
        state
            .utxos
            .insert_coin(payment_input, Zeno::from_zeno(10))
            .unwrap();
        state.coin_recipients.insert(payment_input, owner);
        state
            .utxos
            .insert_asset(
                asset_input,
                AssetShare {
                    parent: asset,
                    amount: crate::native::asset::Unit::from_units(200),
                },
            )
            .unwrap();
        state.assets.share_recipients.insert(asset_input, owner);

        let call = PoolIntent::new(
            owner,
            PoolInstruction::Create {
                asset_x: Pair::Coin,
                asset_y: Pair::Asset(asset),
                amount_x: PoolAmount::from(Zeno::from_zeno(100)),
                amount_y: PoolAmount::from(crate::native::asset::Unit::from_units(200)),
                funding_x: PoolFunding::Coin {
                    inputs: vec![coin_input],
                },
                funding_y: PoolFunding::Asset {
                    asset,
                    inputs: vec![asset_input],
                },
                fee_units: 300,
            },
        );
        let payment = SpendIntent::coin(
            owner,
            vec![payment_input],
            vec![CoinOutput::new(owner, Zeno::from_zeno(9))],
        )
        .unwrap();
        let transaction = ValidatedTransaction::Pool(ValidatedPoolTransaction {
            call: AuthorizationValidated {
                intent: call,
                commitment: call_commitment,
                revealed_account_key: None,
            },
            payment: AuthorizationValidated {
                intent: payment,
                commitment: payment_commitment,
                revealed_account_key: None,
            },
        });

        let journal = state
            .apply_validated_transaction(&transaction, crypto::Height(1), owner, chain)
            .unwrap();
        let pool_id = PoolHash::derive(Pair::Coin, Pair::Asset(asset)).unwrap();
        assert!(state.pools.pool(pool_id).is_some());
        assert!(state.utxos.coin(&coin_input).is_none());
        assert!(state.utxos.asset(&asset_input).is_none());

        state.rollback_state(journal).unwrap();
        assert!(state.pools.is_empty());
        assert_eq!(state.utxos.coin(&coin_input), Some(Zeno::from_zeno(100)));
        assert_eq!(
            state.utxos.asset(&asset_input).map(|share| share.amount),
            Some(crate::native::asset::Unit::from_units(200))
        );
        assert_eq!(state.utxos.coin(&payment_input), Some(Zeno::from_zeno(10)));
    }
}
