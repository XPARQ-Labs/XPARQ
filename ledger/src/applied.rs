use std::{error::Error, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_coin::{Coin, CoinId};
use xparq_common::Height;
use xparq_consensus::{AuthorizationValidated, ValidatedTransaction};
use xparq_crypto::{Address, PublicKey};
use xparq_qcash::QCash;
use xparq_transaction::{
    MergeIntent, OnChainSpendIntent, OutputTarget, RedeemIntent, SpendCommitment, SplitIntent,
    WithdrawIntent,
};

use crate::{
    AccountKeyRegistry, CoinUtxo, CoinUtxoSet, QCashUtxo, QCashUtxoSet, UtxoError,
    UtxoRollbackJournal,
};

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pub coins: CoinUtxoSet,
    pub qcash: QCashUtxoSet,
    pub account_keys: AccountKeyRegistry,
}

impl LedgerState {
    pub fn apply_validated_transaction(
        &mut self,
        transaction: &ValidatedTransaction,
        height: Height,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let mut journal = match transaction {
            ValidatedTransaction::OnChainSpend(validated) => {
                self.apply_validated_onchain_spend(validated, height, block_miner)
            }
            ValidatedTransaction::Withdraw(validated) => {
                self.apply_validated_withdraw(validated, height, block_miner)
            }
            ValidatedTransaction::Redeem(validated) => {
                self.apply_authorized_redeem(validated, height, block_miner)
            }
            ValidatedTransaction::Merge(validated) => {
                self.apply_authorized_merge(validated, height, block_miner)
            }
            ValidatedTransaction::Split(validated) => {
                self.apply_authorized_split(validated, height, block_miner)
            }
        }?;
        if let Some((address, public_key)) = revealed_account_key(transaction) {
            match self.account_keys.register(address, public_key) {
                Ok(true) => journal.registered_public_keys.push(address),
                Ok(false) => {}
                Err(error) => {
                    self.rollback(journal)?;
                    return Err(error.into());
                }
            }
        }
        Ok(journal)
    }

    fn apply_validated_onchain_spend(
        &mut self,
        validated: &AuthorizationValidated<OnChainSpendIntent>,
        height: Height,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        self.apply_onchain_spend_with_commitment(
            validated.intent(),
            validated.commitment(),
            height,
            block_miner,
        )
    }

    fn apply_validated_withdraw(
        &mut self,
        validated: &AuthorizationValidated<WithdrawIntent>,
        height: Height,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        self.apply_withdraw_with_commitment(
            validated.intent(),
            validated.commitment(),
            height,
            block_miner,
        )
    }

    fn apply_onchain_spend_with_commitment(
        &mut self,
        intent: &OnChainSpendIntent,
        commitment: SpendCommitment,
        height: Height,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            for id in &intent.inputs {
                journal.consumed_coins.push(self.coins.consume(id)?);
            }
            for (index, output) in intent.outputs.iter().enumerate() {
                let id = output_id(b"onchain", commitment, index)?;
                self.coins.insert(CoinUtxo {
                    coin: Coin::new(id, output.amount),
                    owner: resolve_target(output.target, block_miner),
                    spendable_height: height,
                })?;
                journal.created_coin_ids.push(id);
            }
            Ok(())
        })();
        self.finish_transition(journal, result)
    }

    fn apply_withdraw_with_commitment(
        &mut self,
        intent: &WithdrawIntent,
        commitment: SpendCommitment,
        height: Height,
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
                let id = output_id(b"change", commitment, index)?;
                self.coins.insert(CoinUtxo {
                    coin: Coin::new(id, output.amount),
                    owner: resolve_target(output.target, block_miner),
                    spendable_height: height,
                })?;
                journal.created_coin_ids.push(id);
            }
            Ok(())
        })();
        self.finish_transition(journal, result)
    }

    pub(crate) fn apply_authorized_redeem(
        &mut self,
        validated: &AuthorizationValidated<RedeemIntent>,
        height: Height,
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
                b"redeem-change",
                &mut journal,
            )?;
            self.create_coin_outputs(
                &intent.outputs,
                commitment,
                b"redeem",
                height,
                block_miner,
                &mut journal,
            )
        })();
        self.finish_transition(journal, result)
    }

    pub(crate) fn apply_authorized_merge(
        &mut self,
        validated: &AuthorizationValidated<MergeIntent>,
        height: Height,
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
                b"merge",
                &mut journal,
            )?;
            if let Some(output) = intent.miner_output {
                self.create_coin_outputs(
                    std::slice::from_ref(&output),
                    commitment,
                    b"merge-miner",
                    height,
                    block_miner,
                    &mut journal,
                )?;
            }
            Ok(())
        })();
        self.finish_transition(journal, result)
    }

    pub(crate) fn apply_authorized_split(
        &mut self,
        validated: &AuthorizationValidated<SplitIntent>,
        height: Height,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let intent = validated.intent();
        let commitment = validated.commitment();
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            self.consume_qcash_inputs(std::slice::from_ref(&intent.input), &mut journal)?;
            self.create_qcash_outputs(&intent.outputs, commitment, b"split", &mut journal)?;
            if let Some(output) = intent.miner_output {
                self.create_coin_outputs(
                    std::slice::from_ref(&output),
                    commitment,
                    b"split-miner",
                    height,
                    block_miner,
                    &mut journal,
                )?;
            }
            Ok(())
        })();
        self.finish_transition(journal, result)
    }

    pub(crate) fn rollback(&mut self, journal: UtxoRollbackJournal) -> Result<(), SpendStateError> {
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
        for address in journal.registered_public_keys {
            self.account_keys.remove(&address)?;
        }
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
        kind: &[u8],
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
        kind: &[u8],
        height: Height,
        block_miner: Address,
        journal: &mut UtxoRollbackJournal,
    ) -> Result<(), SpendStateError> {
        for (index, output) in outputs.iter().enumerate() {
            let id = output_id(kind, commitment, index)?;
            self.coins.insert(CoinUtxo {
                coin: Coin::new(id, output.amount),
                owner: resolve_target(output.target, block_miner),
                spendable_height: height,
            })?;
            journal.created_coin_ids.push(id);
        }
        Ok(())
    }
}

fn revealed_account_key(transaction: &ValidatedTransaction) -> Option<(Address, PublicKey)> {
    match transaction {
        ValidatedTransaction::OnChainSpend(validated) => validated
            .revealed_public_key()
            .copied()
            .map(|key| (validated.intent().sender, key)),
        ValidatedTransaction::Withdraw(validated) => validated
            .revealed_public_key()
            .copied()
            .map(|key| (validated.intent().sender, key)),
        _ => None,
    }
}

fn resolve_target(target: OutputTarget, block_miner: Address) -> Address {
    match target {
        OutputTarget::Address(address) => address,
        OutputTarget::BlockMiner => block_miner,
    }
}

fn output_id(
    kind: &[u8],
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinId, SpendStateError> {
    let index = u32::try_from(index).map_err(|_| SpendStateError::OutputIndexOverflow)?;
    Ok(CoinId::derive(&[
        b"XPARQ transaction output v1",
        kind,
        commitment.as_bytes(),
        &index.to_le_bytes(),
    ]))
}

/// Derives the canonical QCash coin identifier created by a withdrawal.
pub fn withdraw_qcash_output_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinId, SpendStateError> {
    output_id(b"qcash", commitment, index)
}

/// Derives the canonical QCash coin identifier created by a merge.
pub fn merge_qcash_output_id(commitment: SpendCommitment) -> Result<CoinId, SpendStateError> {
    output_id(b"merge", commitment, 0)
}

/// Derives the canonical public miner-output identifier created by a merge.
pub fn merge_miner_output_id(commitment: SpendCommitment) -> Result<CoinId, SpendStateError> {
    output_id(b"merge-miner", commitment, 0)
}

/// Derives a canonical QCash change identifier created by a redemption.
pub fn redeem_qcash_change_output_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinId, SpendStateError> {
    output_id(b"redeem-change", commitment, index)
}

/// Derives a canonical QCash coin identifier created by a split.
pub fn split_qcash_output_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinId, SpendStateError> {
    output_id(b"split", commitment, index)
}

/// Derives the canonical public miner-output identifier created by a split.
pub fn split_miner_output_id(commitment: SpendCommitment) -> Result<CoinId, SpendStateError> {
    output_id(b"split-miner", commitment, 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendStateError {
    Utxo(UtxoError),
    OutputIndexOverflow,
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
    fn failed_in_place_transition_restores_consumed_inputs() {
        let id = CoinId::derive(&[b"rollback regression coin"]);
        let utxo = CoinUtxo {
            coin: Coin::new(id, xparq_coin::Amount(7)),
            owner: Address::ZERO,
            spendable_height: Height(0),
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
        assert_eq!(state.coins.get(&id).map(|coin| coin.coin.amount.0), Some(7));
    }

    #[test]
    fn signed_split_consumes_input_and_rolls_back_atomically() {
        let input_id = CoinId::derive(&[b"signed split input"]);
        let seed = xparq_qcash::QCashSigningSeed::from_bytes([3; 32]);
        let mut state = LedgerState::default();
        state
            .qcash
            .insert(QCashUtxo {
                coin: Coin::new(input_id, xparq_coin::Amount(10)),
                public_key: seed.public_key(),
            })
            .unwrap();
        let intent = SplitIntent::new(
            QCash::new(input_id, xparq_coin::Amount(10)),
            vec![
                QCashOutput::new(
                    xparq_coin::Amount(4),
                    xparq_crypto::QCashPublicKey([4; xparq_crypto::QCASH_PUBLIC_KEY_SIZE]),
                ),
                QCashOutput::new(
                    xparq_coin::Amount(6),
                    xparq_crypto::QCashPublicKey([5; xparq_crypto::QCASH_PUBLIC_KEY_SIZE]),
                ),
            ],
            None,
            100,
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
            .apply_validated_transaction(&validated, Height(10), Address::ZERO)
            .unwrap();
        assert!(state.qcash.get(&input_id).is_none());
        assert_eq!(state.qcash.len(), 2);
        state.rollback(journal).unwrap();
        assert!(state.qcash.get(&input_id).is_some());
        assert_eq!(state.qcash.len(), 1);
    }
}

impl fmt::Display for SpendStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utxo(error) => write!(formatter, "UTXO transition failed: {error}"),
            Self::OutputIndexOverflow => formatter.write_str("transaction output index overflow"),
        }
    }
}

impl Error for SpendStateError {}

impl From<UtxoError> for SpendStateError {
    fn from(error: UtxoError) -> Self {
        Self::Utxo(error)
    }
}
