//! Transaction consensus: authorization, ownership, value conservation,
//! and protocol burn.

use std::{collections::BTreeSet, error::Error as StdError, fmt};

use crypto::{Address, HASH_SIZE, PublicKey, canonical_bytes, verify};

use crate::{
    consensus::{
        BurnError, ProtocolBurn, StateTransitionWeight, account_key_state_weight,
        created_coin_output_count, validate_exact_burn,
    },
    native::{
        asset::{AssetError, AssetShare, Share},
        coin::{CoinOutput, XPQ, Zeno},
    },
    transaction::{
        AccountAuthorization, AccountIntent, AssetInstruction, AssetIntent,
        AuthorizedAccountIntent, AuthorizedTransaction, AuthorizedVaultLockTransaction,
        AuthorizedVaultSpendTransaction, ChainContext, IntentError, Spend, SpendCommitment,
        SpendIntent, Transaction as OnChainTransaction, VaultAuthorization, VaultId, VaultLock,
        VaultLockIntent, VaultOutput, VaultSource, VaultSpendIntent, VaultSpendOutput, VaultValue,
    },
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

impl ConsensusIntent for VaultLockIntent {
    fn validate_structure(&self) -> Result<(), IntentError> {
        self.validate()
    }
    fn commitment_for(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain)
    }
}

impl ConsensusIntent for VaultSpendIntent {
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
    VaultLock(ValidatedVaultLockTransaction),
    VaultSpend(ValidatedVaultSpendTransaction),
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
pub struct ValidatedVaultLockTransaction {
    pub lock: AuthorizationValidated<VaultLockIntent>,
    pub payment: Option<AuthorizationValidated<SpendIntent>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedVaultSpendTransaction {
    pub spend: StructurallyValidated<VaultSpendIntent>,
    pub payment: Option<AuthorizationValidated<SpendIntent>>,
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

    fn vault(&self, _id: VaultId) -> Option<VaultOutput> {
        None
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
        AuthorizedTransaction::VaultLock(transaction) => validate_vault_lock(
            *transaction,
            chain,
            current_height,
            canonical_transaction_weight,
            state,
        ),
        AuthorizedTransaction::VaultSpend(transaction) => validate_vault_spend(
            *transaction,
            chain,
            current_height,
            canonical_transaction_weight,
            state,
        ),
    }
}

fn validate_vault_lock(
    transaction: AuthorizedVaultLockTransaction,
    chain: ChainContext,
    current_height: u64,
    canonical_weight: u64,
    state: &impl TransactionStateView,
) -> Result<ValidatedAuthorizedTransaction, TransactionConsensusError> {
    let lock =
        validate_account_intent_authorization(transaction.lock, chain, current_height, state)?;
    if lock.intent().outputs.iter().any(|output| {
        !output
            .envelope
            .kem_ciphertext()
            .kem()
            .active_at_height(current_height)
    }) {
        return Err(TransactionConsensusError::KemSchemeInactive);
    }
    let vault_weight = vault_outputs_weight(&lock.intent().outputs)?;
    match &lock.intent().source {
        VaultSource::Coin { inputs } => {
            let outputs = lock
                .intent()
                .outputs
                .iter()
                .map(|o| match o.value {
                    VaultValue::Coin(amount) => Ok(amount),
                    _ => Err(TransactionConsensusError::VaultValueMismatch),
                })
                .collect::<Result<Vec<_>, _>>()?;
            let source_remainder =
                validate_coin_values(inputs, &outputs, lock.intent().signer, state)?;
            if !source_remainder.is_zero() {
                return Err(TransactionConsensusError::VaultValueMismatch);
            }
            let payment = transaction
                .payment
                .ok_or(TransactionConsensusError::Intent(IntentError::InvalidVault))?;
            let payment =
                validate_account_intent_authorization(payment, chain, current_height, state)?;
            let (payment_inputs, payment_outputs) = coin_parts(payment.intent())?;
            if payment_inputs.iter().any(|id| inputs.contains(id)) {
                return Err(TransactionConsensusError::Intent(
                    IntentError::DuplicateInput,
                ));
            }
            let actual = validate_coin_inputs(
                payment_inputs,
                payment_outputs,
                payment.intent().signer,
                state,
            )?;
            validate_required_burn(
                actual,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(payment_outputs)?,
                    consumed_coin_utxos: count_inputs(inputs.len())?
                        .checked_add(count_inputs(payment_inputs.len())?)
                        .ok_or(TransactionConsensusError::Burn(BurnError::WeightOverflow))?,
                    created_account_key_weight: combined_revealed_key_weight(
                        lock.intent().signer,
                        lock.revealed_account_key(),
                        payment.intent().signer,
                        payment.revealed_account_key(),
                    )?,
                    created_state_weight: vault_weight,
                },
                canonical_weight,
            )?;
            Ok(ValidatedAuthorizedTransaction::VaultLock(
                ValidatedVaultLockTransaction {
                    lock,
                    payment: Some(payment),
                },
            ))
        }
        VaultSource::Asset { asset, inputs } => {
            validate_share_ownership(inputs, lock.intent().signer, state)?;
            let input_total = asset_input_total(*asset, inputs, state)?;
            let output_total = lock.intent().outputs.iter().try_fold(
                crate::native::asset::Unit::ZERO,
                |sum, output| match output.value {
                    VaultValue::Asset(share) if share.asset == *asset => sum
                        .checked_add(share.amount)
                        .ok_or(TransactionConsensusError::AssetAmountOverflow),
                    _ => Err(TransactionConsensusError::VaultValueMismatch),
                },
            )?;
            if input_total != output_total {
                return Err(TransactionConsensusError::VaultValueMismatch);
            }
            let payment = transaction
                .payment
                .ok_or(TransactionConsensusError::Intent(IntentError::InvalidVault))?;
            let payment =
                validate_account_intent_authorization(payment, chain, current_height, state)?;
            let (pi, po) = coin_parts(payment.intent())?;
            let actual = validate_coin_inputs(pi, po, payment.intent().signer, state)?;
            validate_required_burn(
                actual,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(po)?,
                    consumed_coin_utxos: count_inputs(pi.len())?,
                    created_account_key_weight: combined_revealed_key_weight(
                        lock.intent().signer,
                        lock.revealed_account_key(),
                        payment.intent().signer,
                        payment.revealed_account_key(),
                    )?,
                    created_state_weight: vault_weight,
                },
                canonical_weight,
            )?;
            Ok(ValidatedAuthorizedTransaction::VaultLock(
                ValidatedVaultLockTransaction {
                    lock,
                    payment: Some(payment),
                },
            ))
        }
    }
}

fn validate_vault_spend(
    transaction: AuthorizedVaultSpendTransaction,
    chain: ChainContext,
    current_height: u64,
    canonical_weight: u64,
    state: &impl TransactionStateView,
) -> Result<ValidatedAuthorizedTransaction, TransactionConsensusError> {
    let spend = validate_intent(transaction.spend, chain)?;
    if spend.intent().outputs.iter().any(|output| matches!(output, VaultSpendOutput::Vault(vault) if !vault.envelope.kem_ciphertext().kem().active_at_height(current_height))) {
        return Err(TransactionConsensusError::KemSchemeInactive);
    }
    if transaction.authorizations.len() != spend.intent().inputs.len() {
        return Err(TransactionConsensusError::InvalidVaultAuthorization);
    }
    let mut input_values = Vec::with_capacity(spend.intent().inputs.len());
    for (id, authorization) in spend
        .intent()
        .inputs
        .iter()
        .zip(&transaction.authorizations)
    {
        validate_vault_authorization(
            *id,
            authorization,
            spend.commitment(),
            current_height,
            state,
        )?;
        input_values.push(
            state
                .vault(*id)
                .ok_or(TransactionConsensusError::VaultNotFound)?
                .value,
        );
    }
    let vault_outputs: Vec<VaultOutput> = spend
        .intent()
        .outputs
        .iter()
        .filter_map(|o| match o {
            VaultSpendOutput::Vault(v) => Some(v.clone()),
            _ => None,
        })
        .collect();
    let created_state_weight = vault_outputs_weight(&vault_outputs)?
        .checked_add(vault_asset_outputs_weight(spend.intent())?)
        .ok_or(TransactionConsensusError::Burn(BurnError::WeightOverflow))?;
    match input_values
        .first()
        .copied()
        .ok_or(TransactionConsensusError::VaultNotFound)?
    {
        VaultValue::Coin(_) => {
            if transaction.payment.is_some() || input_values.iter().any(|v| !v.is_coin()) {
                return Err(TransactionConsensusError::VaultValueMismatch);
            }
            let input_total = input_values.iter().try_fold(Zeno::ZERO, |sum, v| {
                sum.checked_add(v.as_coin().unwrap())
                    .ok_or(TransactionConsensusError::ZenoOverflow)
            })?;
            let mut transparent_count = 0_u64;
            let output_total =
                spend
                    .intent()
                    .outputs
                    .iter()
                    .try_fold(Zeno::ZERO, |sum, output| {
                        let amount = match output {
                            VaultSpendOutput::Vault(v) => v
                                .value
                                .as_coin()
                                .ok_or(TransactionConsensusError::VaultValueMismatch)?,
                            VaultSpendOutput::Coin(v) => {
                                transparent_count = transparent_count.checked_add(1).ok_or(
                                    TransactionConsensusError::Burn(BurnError::WeightOverflow),
                                )?;
                                v.amount
                            }
                            VaultSpendOutput::Asset(_) => {
                                return Err(TransactionConsensusError::VaultValueMismatch);
                            }
                        };
                        sum.checked_add(amount)
                            .ok_or(TransactionConsensusError::ZenoOverflow)
                    })?;
            let actual = input_total
                .checked_sub(output_total)
                .ok_or(TransactionConsensusError::ValueMismatch)?;
            validate_required_burn(
                actual,
                StateTransitionWeight {
                    created_coin_utxos: transparent_count,
                    created_state_weight,
                    ..Default::default()
                },
                canonical_weight,
            )?;
            Ok(ValidatedAuthorizedTransaction::VaultSpend(
                ValidatedVaultSpendTransaction {
                    spend,
                    payment: None,
                },
            ))
        }
        VaultValue::Asset(first) => {
            if input_values
                .iter()
                .any(|v| !matches!(v, VaultValue::Asset(s) if s.asset == first.asset))
            {
                return Err(TransactionConsensusError::VaultValueMismatch);
            }
            let input_total =
                input_values
                    .iter()
                    .try_fold(crate::native::asset::Unit::ZERO, |sum, v| {
                        sum.checked_add(v.as_asset().unwrap().amount)
                            .ok_or(TransactionConsensusError::AssetAmountOverflow)
                    })?;
            let output_total = spend.intent().outputs.iter().try_fold(
                crate::native::asset::Unit::ZERO,
                |sum, output| {
                    let amount = match output {
                        VaultSpendOutput::Vault(v) => match v.value {
                            VaultValue::Asset(s) if s.asset == first.asset => s.amount,
                            _ => return Err(TransactionConsensusError::VaultValueMismatch),
                        },
                        VaultSpendOutput::Asset(v) => v.amount,
                        _ => return Err(TransactionConsensusError::VaultValueMismatch),
                    };
                    sum.checked_add(amount)
                        .ok_or(TransactionConsensusError::AssetAmountOverflow)
                },
            )?;
            if input_total != output_total {
                return Err(TransactionConsensusError::VaultValueMismatch);
            }
            let payment = transaction
                .payment
                .ok_or(TransactionConsensusError::Intent(IntentError::InvalidVault))?;
            let payment =
                validate_account_intent_authorization(payment, chain, current_height, state)?;
            let (pi, po) = coin_parts(payment.intent())?;
            let actual = validate_coin_inputs(pi, po, payment.intent().signer, state)?;
            validate_required_burn(
                actual,
                StateTransitionWeight {
                    created_coin_utxos: created_coin_output_count(po)?,
                    consumed_coin_utxos: count_inputs(pi.len())?,
                    created_account_key_weight: revealed_account_key_weight(
                        payment.revealed_account_key(),
                    )?,
                    created_state_weight,
                },
                canonical_weight,
            )?;
            Ok(ValidatedAuthorizedTransaction::VaultSpend(
                ValidatedVaultSpendTransaction {
                    spend,
                    payment: Some(payment),
                },
            ))
        }
    }
}

fn validate_vault_authorization(
    id: VaultId,
    auth: &VaultAuthorization,
    commitment: SpendCommitment,
    height: u64,
    state: &impl TransactionStateView,
) -> Result<(), TransactionConsensusError> {
    if auth.vault != id {
        return Err(TransactionConsensusError::InvalidVaultAuthorization);
    }
    let vault = state
        .vault(id)
        .ok_or(TransactionConsensusError::VaultNotFound)?;
    if !auth.public_key.account.active_at_height(height)
        || VaultLock::derive(&auth.public_key, &auth.opening) != vault.lock
        || !verify(&auth.public_key, commitment.as_bytes(), &auth.signature)
    {
        return Err(TransactionConsensusError::InvalidVaultAuthorization);
    }
    Ok(())
}

fn validate_coin_values(
    inputs: &[XPQ],
    outputs: &[Zeno],
    signer: Address,
    state: &impl TransactionStateView,
) -> Result<Zeno, TransactionConsensusError> {
    ensure_unique_coin_ids(inputs.iter().copied())?;
    let input_total = inputs.iter().try_fold(Zeno::ZERO, |sum, id| {
        let coin = state
            .coin(*id)
            .ok_or(TransactionConsensusError::UtxoNotFound)?;
        if state.coin_recipient(*id) != Some(signer) {
            return Err(TransactionConsensusError::RecipientMismatch);
        }
        sum.checked_add(coin.amount)
            .ok_or(TransactionConsensusError::ZenoOverflow)
    })?;
    let output_total = outputs.iter().try_fold(Zeno::ZERO, |sum, amount| {
        sum.checked_add(*amount)
            .ok_or(TransactionConsensusError::ZenoOverflow)
    })?;
    input_total
        .checked_sub(output_total)
        .ok_or(TransactionConsensusError::ValueMismatch)
}

fn asset_input_total(
    asset: crate::native::asset::Contract,
    inputs: &[Share],
    state: &impl TransactionStateView,
) -> Result<crate::native::asset::Unit, TransactionConsensusError> {
    inputs
        .iter()
        .try_fold(crate::native::asset::Unit::ZERO, |sum, id| {
            let share = state
                .asset_share(*id)
                .ok_or(TransactionConsensusError::UtxoNotFound)?;
            if share.asset != asset {
                return Err(TransactionConsensusError::VaultValueMismatch);
            }
            sum.checked_add(share.amount)
                .ok_or(TransactionConsensusError::AssetAmountOverflow)
        })
}

fn vault_outputs_weight(outputs: &[VaultOutput]) -> Result<u64, TransactionConsensusError> {
    outputs.iter().try_fold(0_u64, |sum, output| {
        let len = canonical_bytes(&(VaultId::ZERO, output))
            .map_err(|_| TransactionConsensusError::Encoding)?
            .len();
        sum.checked_add(
            u64::try_from(len)
                .map_err(|_| TransactionConsensusError::Burn(BurnError::WeightOverflow))?,
        )
        .ok_or(TransactionConsensusError::Burn(BurnError::WeightOverflow))
    })
}

fn vault_asset_outputs_weight(intent: &VaultSpendIntent) -> Result<u64, TransactionConsensusError> {
    intent.outputs.iter().try_fold(0_u64, |sum, output| {
        let VaultSpendOutput::Asset(output) = output else {
            return Ok(sum);
        };
        let value_len = canonical_bytes(&AssetShare {
            asset: crate::native::asset::Contract::from_bytes([0; HASH_SIZE]),
            amount: output.amount,
        })
        .map_err(|_| TransactionConsensusError::Encoding)?
        .len();
        let entry = HASH_SIZE
            .checked_add(value_len)
            .ok_or(TransactionConsensusError::Burn(BurnError::WeightOverflow))?;
        sum.checked_add(
            u64::try_from(entry)
                .map_err(|_| TransactionConsensusError::Burn(BurnError::WeightOverflow))?,
        )
        .ok_or(TransactionConsensusError::Burn(BurnError::WeightOverflow))
    })
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
    KemSchemeInactive,
    UtxoNotFound,
    OwnershipProofMissing,
    RecipientMismatch,
    ZenoOverflow,
    ValueMismatch,
    VaultNotFound,
    InvalidVaultAuthorization,
    VaultValueMismatch,
    AssetAmountOverflow,
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
            Self::KemSchemeInactive => {
                formatter.write_str("transaction KEM scheme is not active at this height")
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
            Self::VaultNotFound => formatter.write_str("transaction input vault was not found"),
            Self::InvalidVaultAuthorization => {
                formatter.write_str("vault ownership authorization is invalid")
            }
            Self::VaultValueMismatch => {
                formatter.write_str("vault input and output values are incompatible")
            }
            Self::AssetAmountOverflow => formatter.write_str("vault asset amount overflow"),
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
