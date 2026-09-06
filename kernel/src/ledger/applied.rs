use std::{error::Error, fmt};

use crate::coin::{Coin, CoinHash, Zeno};
use crate::consensus::{AuthorizationValidated, RevealedAccountKey, ValidatedTransaction};
use crate::transaction::{Recipient, SpendCommitment, SpendIntent};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::Address;

use crate::ledger::{
    AccountKeyRegistry, CoinOwner, CoinUtxo, UtxoError, UtxoRollbackJournal,
};

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pub account_keys: AccountKeyRegistry,
    pub utxos: crate::ledger::UtxoSet,
    pub assets: crate::ledger::AssetState,
    pub total_burned: Zeno,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum StateRollbackJournal {
    Utxo(UtxoRollbackJournal),
    AssetWithPayment {
        asset: crate::ledger::AssetRollbackJournal,
        payment: UtxoRollbackJournal,
    },
    AssetSpendWithPayment {
        asset: crate::ledger::AssetRollbackJournal,
        payment: UtxoRollbackJournal,
    },
}

impl LedgerState {
    pub const fn utxos(&self) -> &crate::ledger::UtxoSet {
        &self.utxos
    }

    pub fn apply_validated_transaction(
        &mut self,
        transaction: &ValidatedTransaction,
        _height: crate::common::Height,
        block_miner: Address,
        chain: crate::transaction::ChainContext,
    ) -> Result<StateRollbackJournal, SpendStateError> {
        if let ValidatedTransaction::Spend(transaction) = transaction {
            if let Some(payment) = &transaction.payment {
                let mut payment_journal =
                    self.apply_validated_onchain_spend(payment, block_miner)?;
                let (asset_id, inputs, outputs) =
                    transaction
                        .spend
                        .intent()
                        .asset_parts()
                        .ok_or(SpendStateError::Asset(
                            crate::asset::AssetError::InvalidProgram,
                        ))?;
                let asset = match self.assets.apply_user_transfer(
                    &mut self.utxos,
                    transaction.spend.intent().signer,
                    asset_id,
                    inputs,
                    outputs,
                    transaction.spend.commitment().into_bytes(),
                ) {
                    Ok(journal) => journal,
                    Err(error) => {
                        self.rollback(payment_journal)?;
                        return Err(SpendStateError::Asset(error));
                    }
                };
                let registrations = [
                    (payment.intent().signer, payment.revealed_account_key()),
                    (
                        transaction.spend.intent().signer,
                        transaction.spend.revealed_account_key(),
                    ),
                ];
                for (address, revealed) in registrations {
                    let Some(RevealedAccountKey::Account(key)) = revealed.cloned() else {
                        continue;
                    };
                    match self.account_keys.register_account(address, key) {
                        Ok(true) => payment_journal.registered_account_public_keys.push(address),
                        Ok(false) => {}
                        Err(error) => {
                            self.assets.rollback(&mut self.utxos, asset);
                            self.rollback(payment_journal)?;
                            return Err(error.into());
                        }
                    }
                }
                return Ok(StateRollbackJournal::AssetSpendWithPayment {
                    asset,
                    payment: payment_journal,
                });
            }
        }
        if let ValidatedTransaction::Asset(asset_transaction) = transaction {
            let mut payment =
                self.apply_validated_onchain_spend(&asset_transaction.payment, block_miner)?;
            if let Some(RevealedAccountKey::Account(public_key)) =
                asset_transaction.payment.revealed_account_key().cloned()
            {
                match self
                    .account_keys
                    .register_account(asset_transaction.payment.intent().signer, public_key)
                {
                    Ok(true) => payment
                        .registered_account_public_keys
                        .push(asset_transaction.payment.intent().signer),
                    Ok(false) => {}
                    Err(error) => {
                        self.rollback(payment)?;
                        return Err(error.into());
                    }
                }
            }
            if let Some(RevealedAccountKey::Account(public_key)) =
                asset_transaction.call.revealed_account_key().cloned()
            {
                match self
                    .account_keys
                    .register_account(asset_transaction.call.intent().signer, public_key)
                {
                    Ok(true) => payment
                        .registered_account_public_keys
                        .push(asset_transaction.call.intent().signer),
                    Ok(false) => {}
                    Err(error) => {
                        self.rollback(payment)?;
                        return Err(error.into());
                    }
                }
            }
            return match self.assets.apply(
                &mut self.utxos,
                asset_transaction.call.intent(),
                chain.genesis_hash,
            ) {
                Ok(asset) => Ok(StateRollbackJournal::AssetWithPayment { asset, payment }),
                Err(error) => {
                    self.rollback(payment)?;
                    Err(SpendStateError::Asset(error))
                }
            };
        }
        let mut journal = match transaction {
            ValidatedTransaction::Spend(validated) => {
                self.apply_validated_onchain_spend(&validated.spend, block_miner)
            }
            ValidatedTransaction::Asset(_) => unreachable!("asset handled above"),
        }?;
        if let Some((address, public_key)) = revealed_account_key(transaction) {
            let result = match public_key {
                RevealedAccountKey::Account(public_key) => self
                    .account_keys
                    .register_account(address, public_key)
                    .map(|inserted| (inserted, 0_u8)),
            };
            match result {
                Ok((true, 0)) => journal.registered_account_public_keys.push(address),
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
            StateRollbackJournal::AssetWithPayment { asset, payment } => {
                self.assets.rollback(&mut self.utxos, asset);
                self.rollback(payment)
            }
            StateRollbackJournal::AssetSpendWithPayment { asset, payment } => {
                self.assets.rollback(&mut self.utxos, asset);
                self.rollback(payment)
            }
        }
    }

    fn apply_validated_onchain_spend(
        &mut self,
        validated: &AuthorizationValidated<SpendIntent>,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        self.apply_onchain_spend_with_commitment(
            validated.intent(),
            validated.commitment(),
            block_miner,
        )
    }

    fn apply_onchain_spend_with_commitment(
        &mut self,
        intent: &SpendIntent,
        commitment: SpendCommitment,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            let (inputs, outputs, burn) = intent.coin_parts().ok_or(SpendStateError::Asset(
                crate::asset::AssetError::InvalidProgram,
            ))?;
            for id in inputs {
                journal.consumed_coins.push(self.utxos.consume(id)?);
            }
            for (index, output) in outputs.iter().enumerate() {
                let owner = resolve_target(output.output, block_miner);
                let id = account_output_id(commitment, index)?;
                self.utxos.insert(CoinUtxo {
                    coin: Coin::new(id, output.amount),
                    owner,
                })?;
                journal.created_coin_ids.push(id);
            }
            self.record_protocol_burn(burn, &mut journal)?;
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
            self.utxos.consume(&id)?;
        }
        for utxo in journal.consumed_coins {
            self.utxos.restore(utxo)?;
        }
        for address in journal.registered_account_public_keys {
            self.account_keys.remove_account(&address)?;
        }
        Ok(())
    }

    pub(crate) fn record_protocol_burn(
        &mut self,
        burned: Zeno,
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
}

fn revealed_account_key(
    transaction: &ValidatedTransaction,
) -> Option<(Address, RevealedAccountKey)> {
    match transaction {
        ValidatedTransaction::Spend(validated) => validated
            .spend
            .revealed_account_key()
            .cloned()
            .map(|key| (validated.spend.intent().signer, key)),

        _ => None,
    }
}

fn resolve_target(target: Recipient, block_miner: Address) -> CoinOwner {
    match target {
        Recipient::Address(address) => address,
        Recipient::BlockMiner => block_miner,
    }
}

fn output_index(index: usize) -> Result<u32, SpendStateError> {
    u32::try_from(index).map_err(|_| SpendStateError::OutputIndexOverflow)
}

fn account_output_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinHash, SpendStateError> {
    Ok(CoinHash::from_output(
        commitment.as_bytes(),
        output_index(index)?,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendStateError {
    Utxo(UtxoError),
    OutputIndexOverflow,
    BurnOverflow,
    BurnUnderflow,
    Asset(crate::asset::AssetError),
    AmountOverflow,
}

impl fmt::Display for SpendStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utxo(error) => write!(formatter, "UTXO transition failed: {error}"),
            Self::OutputIndexOverflow => formatter.write_str("transaction output index overflow"),
            Self::BurnOverflow => formatter.write_str("total burned amount overflow"),
            Self::BurnUnderflow => formatter.write_str("total burned amount underflow"),
            Self::Asset(error) => write!(formatter, "native asset transition failed: {error}"),
            Self::AmountOverflow => formatter.write_str("coin amount overflow"),
        }
    }
}

impl Error for SpendStateError {}

impl From<UtxoError> for SpendStateError {
    fn from(error: UtxoError) -> Self {
        Self::Utxo(error)
    }
}
