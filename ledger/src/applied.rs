use std::{error::Error, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_coin::{Amount, Coin, CoinId, TransactionOutputKind};
use xparq_consensus::{AuthorizationValidated, RevealedAccountKey, ValidatedTransaction};
use xparq_crypto::Address;
use xparq_qcash::QCash;
use xparq_transaction::{
    MergeIntent, OnChainSpendIntent, OutputTarget, RedeemIntent, SpendCommitment, SplitIntent,
    WithdrawIntent,
};

use crate::{
    AccountKeyRegistry, CoinUtxo, CoinUtxoSet, ExtensionRollbackJournal, ExtensionStateSet,
    QCashUtxo, QCashUtxoSet, UtxoError, UtxoRollbackJournal,
};

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pub coins: CoinUtxoSet,
    pub qcash: QCashUtxoSet,
    pub account_keys: AccountKeyRegistry,
    pub assets: xparq_asset::AssetState,
    pub extensions: ExtensionStateSet,
    pub total_burned: Amount,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum StateRollbackJournal {
    Utxo(UtxoRollbackJournal),
    Extension(ExtensionRollbackJournal),
    AssetWithFee {
        asset: xparq_asset::AssetRollbackJournal,
        fee: UtxoRollbackJournal,
    },
    ExtensionWithFee {
        extension: ExtensionRollbackJournal,
        fee: UtxoRollbackJournal,
    },
}

impl LedgerState {
    pub fn apply_validated_transaction(
        &mut self,
        transaction: &ValidatedTransaction,
        _height: xparq_common::Height,
        block_miner: Address,
    ) -> Result<StateRollbackJournal, SpendStateError> {
        if let ValidatedTransaction::Asset(asset_transaction) = transaction {
            let mut fee = self.apply_validated_onchain_spend(&asset_transaction.fee, block_miner)?;
            if let Some(RevealedAccountKey::Profile(public_key)) =
                asset_transaction.fee.revealed_account_key().cloned()
            {
                match self.account_keys.register_profile(
                    asset_transaction.fee.intent().sender,
                    public_key,
                ) {
                    Ok(true) => fee
                        .registered_profile_public_keys
                        .push(asset_transaction.fee.intent().sender),
                    Ok(false) => {}
                    Err(error) => {
                        self.rollback(fee)?;
                        return Err(error.into());
                    }
                }
            }
            return match self
                .assets
                .apply(asset_transaction.chain_id, &asset_transaction.call)
            {
                Ok(asset) => Ok(StateRollbackJournal::AssetWithFee { asset, fee }),
                Err(error) => {
                    self.rollback(fee)?;
                    Err(SpendStateError::Asset(error))
                }
            };
        }
        if let ValidatedTransaction::Extension(extension_transaction) = transaction {
            let mut fee =
                self.apply_validated_onchain_spend(&extension_transaction.fee, block_miner)?;
            if let Some(RevealedAccountKey::Profile(public_key)) =
                extension_transaction.fee.revealed_account_key().cloned()
            {
                match self
                    .account_keys
                    .register_profile(extension_transaction.fee.intent().sender, public_key)
                {
                    Ok(true) => fee
                        .registered_profile_public_keys
                        .push(extension_transaction.fee.intent().sender),
                    Ok(false) => {}
                    Err(error) => {
                        self.rollback(fee)?;
                        return Err(error.into());
                    }
                }
            }
            let applied = self.extensions.apply(
                xparq_extension::production_registry(),
                xparq_common::ExtensionContext { height: _height },
                &extension_transaction.call,
            );
            return match applied {
                Ok(extension) => Ok(StateRollbackJournal::ExtensionWithFee { extension, fee }),
                Err(error) => {
                    self.rollback(fee)?;
                    Err(SpendStateError::Extension(error))
                }
            };
        }
        let mut journal = match transaction {
            ValidatedTransaction::OnChainSpend(validated) => {
                self.apply_validated_onchain_spend(validated, block_miner)
            }
            ValidatedTransaction::Withdraw(validated) => {
                self.apply_validated_withdraw(validated, block_miner)
            }
            ValidatedTransaction::Redeem(validated) => {
                self.apply_authorized_redeem(validated, block_miner)
            }
            ValidatedTransaction::Merge(validated) => {
                self.apply_authorized_merge(validated, block_miner)
            }
            ValidatedTransaction::Split(validated) => {
                self.apply_authorized_split(validated, block_miner)
            }
            ValidatedTransaction::Asset(_) => unreachable!("asset handled above"),
            ValidatedTransaction::Extension(_) => unreachable!("extension handled above"),
        }?;
        if let Some((address, public_key)) = revealed_account_key(transaction) {
            let result = match public_key {
                RevealedAccountKey::Profile(public_key) => self
                    .account_keys
                    .register_profile(address, public_key)
                    .map(|inserted| (inserted, 0_u8)),
            };
            match result {
                Ok((true, 0)) => journal.registered_profile_public_keys.push(address),
                Ok((true, _)) => unreachable!("known account key registry kind"),
                Ok((false, _)) => {}
                Err(error) => {
                    self.rollback(journal)?;
                    return Err(error.into());
                }
            }
        }
        Ok(StateRollbackJournal::Utxo(journal))
    }

    pub(crate) fn rollback_state(
        &mut self,
        journal: StateRollbackJournal,
    ) -> Result<(), SpendStateError> {
        match journal {
            StateRollbackJournal::Utxo(journal) => self.rollback(journal),
            StateRollbackJournal::Extension(journal) => self
                .extensions
                .rollback(journal)
                .map_err(SpendStateError::Extension),
            StateRollbackJournal::AssetWithFee { asset, fee } => {
                self.assets.rollback(asset);
                self.rollback(fee)
            }
            StateRollbackJournal::ExtensionWithFee { extension, fee } => {
                self.extensions
                    .rollback(extension)
                    .map_err(SpendStateError::Extension)?;
                self.rollback(fee)
            }
        }
    }

    fn apply_validated_onchain_spend(
        &mut self,
        validated: &AuthorizationValidated<OnChainSpendIntent>,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        self.apply_onchain_spend_with_commitment(
            validated.intent(),
            validated.commitment(),
            block_miner,
        )
    }

    fn apply_validated_withdraw(
        &mut self,
        validated: &AuthorizationValidated<WithdrawIntent>,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        self.apply_withdraw_with_commitment(validated.intent(), validated.commitment(), block_miner)
    }

    fn apply_onchain_spend_with_commitment(
        &mut self,
        intent: &OnChainSpendIntent,
        commitment: SpendCommitment,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            for id in &intent.inputs {
                journal.consumed_coins.push(self.coins.consume(id)?);
            }
            for (index, output) in intent.outputs.iter().enumerate() {
                let Some(owner) = resolve_target(output.target, block_miner) else {
                    continue;
                };
                let id = output_id(TransactionOutputKind::AccountSpendOutput, commitment, index)?;
                self.coins.insert(CoinUtxo {
                    coin: Coin::new(id, output.amount),
                    owner,
                })?;
                journal.created_coin_ids.push(id);
            }
            self.record_burn_outputs(&intent.outputs, &mut journal)?;
            Ok(())
        })();
        self.finish_transition(journal, result)
    }

    fn apply_withdraw_with_commitment(
        &mut self,
        intent: &WithdrawIntent,
        commitment: SpendCommitment,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            for id in &intent.inputs {
                journal.consumed_coins.push(self.coins.consume(id)?);
            }
            for (index, output) in intent.qcash_outputs.iter().enumerate() {
                let id = withdraw_qcash_output_id(commitment, index)?;
                self.qcash.insert(QCashUtxo {
                    coin: Coin::new(id, output.amount),
                    public_key: output.public_key,
                })?;
                journal.created_qcash_ids.push(id);
            }
            for (index, output) in intent.outputs.iter().enumerate() {
                let Some(owner) = resolve_target(output.target, block_miner) else {
                    continue;
                };
                let id = output_id(TransactionOutputKind::WithdrawChange, commitment, index)?;
                self.coins.insert(CoinUtxo {
                    coin: Coin::new(id, output.amount),
                    owner,
                })?;
                journal.created_coin_ids.push(id);
            }
            self.record_burn_outputs(&intent.outputs, &mut journal)?;
            Ok(())
        })();
        self.finish_transition(journal, result)
    }

    pub(crate) fn apply_authorized_redeem(
        &mut self,
        validated: &AuthorizationValidated<RedeemIntent>,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let intent = validated.intent();
        let commitment = validated.commitment();
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            self.consume_qcash_inputs(&intent.inputs, &mut journal)?;
            self.create_qcash_outputs(
                &intent.qcash_outputs,
                commitment,
                TransactionOutputKind::RedeemQCashChange,
                &mut journal,
            )?;
            self.create_coin_outputs(
                &intent.outputs,
                commitment,
                TransactionOutputKind::RedeemCoin,
                block_miner,
                &mut journal,
            )?;
            self.record_burn_outputs(&intent.outputs, &mut journal)
        })();
        self.finish_transition(journal, result)
    }

    pub(crate) fn apply_authorized_merge(
        &mut self,
        validated: &AuthorizationValidated<MergeIntent>,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let intent = validated.intent();
        let commitment = validated.commitment();
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            self.consume_qcash_inputs(&intent.inputs, &mut journal)?;
            self.create_qcash_outputs(
                std::slice::from_ref(&intent.output),
                commitment,
                TransactionOutputKind::MergeQCash,
                &mut journal,
            )?;
            if !intent.public_outputs.is_empty() {
                self.create_coin_outputs(
                    &intent.public_outputs,
                    commitment,
                    TransactionOutputKind::MergePublicOutput,
                    block_miner,
                    &mut journal,
                )?;
            }
            self.record_burn_outputs(&intent.public_outputs, &mut journal)?;
            Ok(())
        })();
        self.finish_transition(journal, result)
    }

    pub(crate) fn apply_authorized_split(
        &mut self,
        validated: &AuthorizationValidated<SplitIntent>,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let intent = validated.intent();
        let commitment = validated.commitment();
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            self.consume_qcash_inputs(std::slice::from_ref(&intent.input), &mut journal)?;
            self.create_qcash_outputs(
                &intent.outputs,
                commitment,
                TransactionOutputKind::SplitQCash,
                &mut journal,
            )?;
            if !intent.public_outputs.is_empty() {
                self.create_coin_outputs(
                    &intent.public_outputs,
                    commitment,
                    TransactionOutputKind::SplitPublicOutput,
                    block_miner,
                    &mut journal,
                )?;
            }
            self.record_burn_outputs(&intent.public_outputs, &mut journal)?;
            Ok(())
        })();
        self.finish_transition(journal, result)
    }

    pub(crate) fn rollback(&mut self, journal: UtxoRollbackJournal) -> Result<(), SpendStateError> {
        self.total_burned = self
            .total_burned
            .checked_sub(journal.burned)
            .ok_or(SpendStateError::BurnUnderflow)?;
        for id in journal.created_coin_ids {
            self.coins.consume(&id)?;
        }
        for id in journal.created_qcash_ids {
            self.qcash.consume(&id)?;
        }
        for utxo in journal.consumed_coins {
            self.coins.restore(utxo)?;
        }
        for utxo in journal.consumed_qcash {
            self.qcash.restore(utxo)?;
        }
        for address in journal.registered_profile_public_keys {
            self.account_keys.remove_profile(&address)?;
        }
        Ok(())
    }

    fn record_burn_outputs(
        &mut self,
        outputs: &[xparq_transaction::SpendOutput],
        journal: &mut UtxoRollbackJournal,
    ) -> Result<(), SpendStateError> {
        let burned = outputs
            .iter()
            .filter(|output| output.target == OutputTarget::Burn)
            .try_fold(Amount::from_zeno(0), |total, output| {
                total.checked_add(output.amount)
            })
            .ok_or(SpendStateError::BurnOverflow)?;
        self.record_protocol_burn(burned, journal)
    }

    pub(crate) fn record_protocol_burn(
        &mut self,
        burned: Amount,
        journal: &mut UtxoRollbackJournal,
    ) -> Result<(), SpendStateError> {
        self.total_burned = self
            .total_burned
            .checked_add(burned)
            .ok_or(SpendStateError::BurnOverflow)?;
        journal.burned = journal
            .burned
            .checked_add(burned)
            .ok_or(SpendStateError::BurnOverflow)?;
        Ok(())
    }

    fn finish_transition(
        &mut self,
        journal: UtxoRollbackJournal,
        result: Result<(), SpendStateError>,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        match result {
            Ok(()) => Ok(journal),
            Err(error) => {
                self.rollback(journal)?;
                Err(error)
            }
        }
    }

    fn consume_qcash_inputs(
        &mut self,
        inputs: &[QCash],
        journal: &mut UtxoRollbackJournal,
    ) -> Result<(), SpendStateError> {
        for qcash in inputs {
            journal
                .consumed_qcash
                .push(self.qcash.consume(&qcash.id())?);
        }
        Ok(())
    }

    fn create_qcash_outputs(
        &mut self,
        outputs: &[xparq_transaction::QCashOutput],
        commitment: SpendCommitment,
        kind: TransactionOutputKind,
        journal: &mut UtxoRollbackJournal,
    ) -> Result<(), SpendStateError> {
        for (index, output) in outputs.iter().enumerate() {
            let id = output_id(kind, commitment, index)?;
            self.qcash.insert(QCashUtxo {
                coin: Coin::new(id, output.amount),
                public_key: output.public_key,
            })?;
            journal.created_qcash_ids.push(id);
        }
        Ok(())
    }

    fn create_coin_outputs(
        &mut self,
        outputs: &[xparq_transaction::SpendOutput],
        commitment: SpendCommitment,
        kind: TransactionOutputKind,
        block_miner: Address,
        journal: &mut UtxoRollbackJournal,
    ) -> Result<(), SpendStateError> {
        for (index, output) in outputs.iter().enumerate() {
            let Some(owner) = resolve_target(output.target, block_miner) else {
                continue;
            };
            let id = output_id(kind, commitment, index)?;
            self.coins.insert(CoinUtxo {
                coin: Coin::new(id, output.amount),
                owner,
            })?;
            journal.created_coin_ids.push(id);
        }
        Ok(())
    }
}

fn revealed_account_key(
    transaction: &ValidatedTransaction,
) -> Option<(Address, RevealedAccountKey)> {
    match transaction {
        ValidatedTransaction::OnChainSpend(validated) => validated
            .revealed_account_key()
            .cloned()
            .map(|key| (validated.intent().sender, key)),
        ValidatedTransaction::Withdraw(validated) => validated
            .revealed_account_key()
            .cloned()
            .map(|key| (validated.intent().sender, key)),
        ValidatedTransaction::Extension(validated) => validated
            .fee
            .revealed_account_key()
            .cloned()
            .map(|key| (validated.fee.intent().sender, key)),
        _ => None,
    }
}

fn resolve_target(target: OutputTarget, block_miner: Address) -> Option<Address> {
    match target {
        OutputTarget::Address(address) => Some(address),
        OutputTarget::BlockMiner => Some(block_miner),
        OutputTarget::Burn => None,
    }
}

fn output_id(
    kind: TransactionOutputKind,
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinId, SpendStateError> {
    let index = u32::try_from(index).map_err(|_| SpendStateError::OutputIndexOverflow)?;
    Ok(CoinId::from_transaction_output(
        kind,
        commitment.as_bytes(),
        index,
    ))
}

/// Derives the canonical QCash coin identifier created by a withdrawal.
pub fn withdraw_qcash_output_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinId, SpendStateError> {
    output_id(TransactionOutputKind::WithdrawQCash, commitment, index)
}

/// Derives the canonical QCash coin identifier created by a merge.
pub fn merge_qcash_output_id(commitment: SpendCommitment) -> Result<CoinId, SpendStateError> {
    output_id(TransactionOutputKind::MergeQCash, commitment, 0)
}

/// Derives the canonical public miner-output identifier created by a merge.
pub fn merge_miner_output_id(commitment: SpendCommitment) -> Result<CoinId, SpendStateError> {
    output_id(TransactionOutputKind::MergePublicOutput, commitment, 0)
}

/// Derives a canonical QCash change identifier created by a redemption.
pub fn redeem_qcash_change_output_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinId, SpendStateError> {
    output_id(TransactionOutputKind::RedeemQCashChange, commitment, index)
}

/// Derives a canonical QCash coin identifier created by a split.
pub fn split_qcash_output_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinId, SpendStateError> {
    output_id(TransactionOutputKind::SplitQCash, commitment, index)
}

/// Derives the canonical public miner-output identifier created by a split.
pub fn split_miner_output_id(commitment: SpendCommitment) -> Result<CoinId, SpendStateError> {
    output_id(TransactionOutputKind::SplitPublicOutput, commitment, 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendStateError {
    Utxo(UtxoError),
    OutputIndexOverflow,
    BurnOverflow,
    BurnUnderflow,
    Asset(xparq_asset::AssetError),
    Extension(xparq_common::ExtensionFailure),
}

#[cfg(test)]
mod tests {
    use super::*;
    use xparq_consensus::{ValidatedTransaction, validate_transaction};
    use xparq_transaction::{
        AuthorizedQCashIntent, AuthorizedTransaction, ChainContext, QCashAuthorization,
        QCashOutput, SplitIntent,
    };

    #[test]
    fn protocol_burn_is_rolled_back_with_its_created_utxo() {
        let mut state = LedgerState::default();
        let mut journal = UtxoRollbackJournal::default();
        let burned = xparq_consensus::EMISSION_UTXO_STATE_BURN;

        state.record_protocol_burn(burned, &mut journal).unwrap();
        assert_eq!(state.total_burned, burned);
        state.rollback(journal).unwrap();
        assert_eq!(state.total_burned, Amount::from_zeno(0));
    }

    #[test]
    fn failed_in_place_transition_restores_consumed_inputs() {
        let id = CoinId::from_bytes([0x51; CoinId::SIZE]);
        let utxo = CoinUtxo {
            coin: Coin::new(id, xparq_coin::Amount::from_zeno(7)),
            owner: Address::ZERO,
        };
        let mut state = LedgerState::default();
        state.coins.insert(utxo).unwrap();
        let consumed = state.coins.consume(&id).unwrap();
        let journal = UtxoRollbackJournal {
            consumed_coins: vec![consumed],
            ..UtxoRollbackJournal::default()
        };

        assert_eq!(
            state.finish_transition(journal, Err(SpendStateError::OutputIndexOverflow)),
            Err(SpendStateError::OutputIndexOverflow)
        );
        assert_eq!(
            state.coins.get(&id).map(|coin| coin.coin.amount.as_zeno()),
            Some(7)
        );
    }

    #[test]
    fn signed_split_consumes_input_and_rolls_back_atomically() {
        let input_id = CoinId::from_bytes([0x52; CoinId::SIZE]);
        let seed = xparq_qcash::QCashSigningSeed::from_bytes([3; 32]);
        let mut state = LedgerState::default();
        state
            .qcash
            .insert(QCashUtxo {
                coin: Coin::new(input_id, xparq_coin::Amount::from_zeno(3_000)),
                public_key: seed.public_key(),
            })
            .unwrap();
        let intent = SplitIntent::new(
            QCash::new(input_id, xparq_coin::Amount::from_zeno(3_000)),
            vec![
                QCashOutput::new(
                    xparq_coin::Amount::from_zeno(500),
                    xparq_crypto::QCashPublicKey([4; xparq_crypto::QCASH_PUBLIC_KEY_SIZE]),
                ),
                QCashOutput::new(
                    xparq_coin::Amount::from_zeno(
                        2_500 - 2 * xparq_consensus::QCASH_UTXO_STATE_WEIGHT,
                    ),
                    xparq_crypto::QCashPublicKey([5; xparq_crypto::QCASH_PUBLIC_KEY_SIZE]),
                ),
            ],
            vec![xparq_transaction::SpendOutput::burn(
                xparq_coin::Amount::from_zeno(2 * xparq_consensus::QCASH_UTXO_STATE_WEIGHT),
            )],
        )
        .unwrap();
        let chain = ChainContext::new([6; 32]);
        let commitment = intent.commitment(chain).unwrap();
        let signed = AuthorizedQCashIntent::new(
            intent,
            vec![QCashAuthorization {
                signature: seed.sign(commitment.as_bytes()),
            }],
        )
        .unwrap();
        let validated = validate_transaction(
            AuthorizedTransaction::Split(Box::new(signed)),
            chain,
            10,
            &state,
        )
        .unwrap();
        assert!(matches!(validated, ValidatedTransaction::Split(_)));
        let journal = state
            .apply_validated_transaction(&validated, xparq_common::Height(10), Address::ZERO)
            .unwrap();
        assert!(state.qcash.get(&input_id).is_none());
        assert_eq!(state.qcash.len(), 2);
        assert_eq!(
            state.total_burned,
            Amount::from_zeno(2 * xparq_consensus::QCASH_UTXO_STATE_WEIGHT)
        );
        state.rollback_state(journal).unwrap();
        assert!(state.qcash.get(&input_id).is_some());
        assert_eq!(state.qcash.len(), 1);
        assert_eq!(state.total_burned, Amount::from_zeno(0));
    }
}

impl fmt::Display for SpendStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utxo(error) => write!(formatter, "UTXO transition failed: {error}"),
            Self::OutputIndexOverflow => formatter.write_str("transaction output index overflow"),
            Self::BurnOverflow => formatter.write_str("total burned amount overflow"),
            Self::BurnUnderflow => formatter.write_str("total burned amount underflow"),
            Self::Asset(error) => write!(formatter, "native asset transition failed: {error}"),
            Self::Extension(error) => write!(formatter, "extension transition failed: {error:?}"),
        }
    }
}

impl Error for SpendStateError {}

impl From<UtxoError> for SpendStateError {
    fn from(error: UtxoError) -> Self {
        Self::Utxo(error)
    }
}
