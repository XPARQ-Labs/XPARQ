use std::{error::Error, fmt};

use crate::asset::Unit;
use crate::coin::{Coin, CoinHash, Zeno};
use crate::common::{Authority, ExtensionEffect, ExtensionHash};
use crate::consensus::{AuthorizationValidated, RevealedAccountKey, ValidatedTransaction};
use crate::transaction::{Recipient, SpendCommitment, SpendIntent};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::Address;

use crate::ledger::{
    AccountKeyRegistry, CoinOwner, CoinUtxo, ExtensionRollbackJournal, ExtensionStateSet,
    UtxoError, UtxoRollbackJournal,
};

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pub account_keys: AccountKeyRegistry,
    pub utxos: crate::ledger::UtxoSet,
    pub assets: crate::ledger::AssetState,
    pub extensions: ExtensionStateSet,
    pub total_burned: Zeno,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum StateRollbackJournal {
    Utxo(UtxoRollbackJournal),
    Extension(ExtensionRollbackJournal),
    AssetWithPayment {
        asset: crate::ledger::AssetRollbackJournal,
        payment: UtxoRollbackJournal,
    },
    AssetSpendWithPayment {
        asset: crate::ledger::AssetRollbackJournal,
        payment: UtxoRollbackJournal,
    },
    ExtensionWithFee {
        extension: ExtensionRollbackJournal,
        assets: Vec<crate::ledger::AssetRollbackJournal>,
        fee: UtxoRollbackJournal,
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
        if let ValidatedTransaction::Extension(extension_transaction) = transaction {
            let mut fee =
                self.apply_validated_onchain_spend(&extension_transaction.fee, block_miner)?;
            if let Some(RevealedAccountKey::Account(public_key)) =
                extension_transaction.fee.revealed_account_key().cloned()
            {
                match self
                    .account_keys
                    .register_account(extension_transaction.fee.intent().signer, public_key)
                {
                    Ok(true) => fee
                        .registered_account_public_keys
                        .push(extension_transaction.fee.intent().signer),
                    Ok(false) => {}
                    Err(error) => {
                        self.rollback(fee)?;
                        return Err(error.into());
                    }
                }
            }
            let applied = self.extensions.apply(
                extension::production_registry(),
                crate::common::ExtensionContext::system(_height ),
                &extension_transaction.call,
            );
            return match applied {
                Ok(applied) => {
                    match self.apply_extension_effects(
                        extension_transaction.call.extension_id(),
                        extension_transaction.fee.commitment(),
                        applied.effects,
                        chain.genesis_hash,
                    ) {
                        Ok((assets, effects)) => {
                            for coin in effects.consumed_coins {
                                fee.record_consumed(coin);
                            }
                            fee.created_coin_ids.extend(effects.created_coin_ids);
                            Ok(StateRollbackJournal::ExtensionWithFee {
                                extension: applied.journal,
                                assets,
                                fee,
                            })
                        }
                        Err(error) => {
                            self.extensions
                                .rollback(applied.journal)
                                .map_err(SpendStateError::Extension)?;
                            self.rollback(fee)?;
                            Err(error)
                        }
                    }
                }
                Err(error) => {
                    self.rollback(fee)?;
                    Err(SpendStateError::Extension(error))
                }
            };
        }
        let mut journal = match transaction {
            ValidatedTransaction::Spend(validated) => {
                self.apply_validated_onchain_spend(&validated.spend, block_miner)
            }
            ValidatedTransaction::Asset(_) => unreachable!("asset handled above"),
            ValidatedTransaction::Extension(_) => unreachable!("extension handled above"),
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
            StateRollbackJournal::Extension(journal) => self
                .extensions
                .rollback(journal)
                .map_err(SpendStateError::Extension),
            StateRollbackJournal::AssetWithPayment { asset, payment } => {
                self.assets.rollback(&mut self.utxos, asset);
                self.rollback(payment)
            }
            StateRollbackJournal::AssetSpendWithPayment { asset, payment } => {
                self.assets.rollback(&mut self.utxos, asset);
                self.rollback(payment)
            }
            StateRollbackJournal::ExtensionWithFee {
                extension,
                assets,
                fee,
            } => {
                for journal in assets.into_iter().rev() {
                    self.assets.rollback(&mut self.utxos, journal);
                }
                self.extensions
                    .rollback(extension)
                    .map_err(SpendStateError::Extension)?;
                self.rollback(fee)
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

    fn apply_extension_effects(
        &mut self,
        program: ExtensionHash,
        commitment: SpendCommitment,
        effects: Vec<ExtensionEffect>,
        genesis_hash: [u8; 32],
    ) -> Result<
        (
            Vec<crate::ledger::AssetRollbackJournal>,
            UtxoRollbackJournal,
        ),
        SpendStateError,
    > {
        // Bind every effect to the trusted program and the unique, chain-bound
        // fee spend. An effect index alone repeats in every invocation.
        let execution_origin = crate::common::domain_hash(
            b"XPARQ Extension Execution",
            &[&genesis_hash, program.as_bytes(), commitment.as_bytes()],
        );
        let mut journals = Vec::new();
        let mut coins = UtxoRollbackJournal::default();
        for (index, effect) in effects.into_iter().enumerate() {
            let execution_nonce =
                u64::try_from(index).map_err(|_| SpendStateError::OutputIndexOverflow)?;
            let result = match effect {
                ExtensionEffect::MintAsset {
                    asset_id,
                    recipient,
                    amount,
                } => self
                    .assets
                    .apply_program_mint(
                        &mut self.utxos,
                        program,
                        crate::asset::AssetHash::from_bytes(asset_id),
                        Authority::Address(Address(recipient)),
                        Unit::from_units(amount),
                        execution_origin,
                        execution_nonce,
                    )
                    .map(Some)
                    .map_err(SpendStateError::Asset),
                ExtensionEffect::TransferAsset {
                    asset_id,
                    recipient,
                    amount,
                } => self
                    .apply_program_asset_transfer(
                        program,
                        crate::asset::AssetHash::from_bytes(asset_id),
                        Address(recipient),
                        Unit::from_units(amount),
                        execution_origin,
                        execution_nonce,
                    )
                    .map(Some),
                ExtensionEffect::TransferCoin { recipient, amount } => self
                    .apply_program_coin_transfer(
                        program,
                        match recipient {
                            extension::CoinRecipient::Address(address) => {
                                Authority::Address(Address(address))
                            }
                            extension::CoinRecipient::Extension(extension) => {
                                Authority::Extension(ExtensionHash::from_bytes(extension))
                            }
                        },
                        Zeno::from_zeno(amount),
                        SpendCommitment::from_bytes(execution_origin),
                        index,
                        &mut coins,
                    )
                    .map(|()| None),
                ExtensionEffect::BurnCoin { amount } => self
                    .apply_program_coin_burn(
                        program,
                        Zeno::from_zeno(amount),
                        SpendCommitment::from_bytes(execution_origin),
                        index,
                        &mut coins,
                    )
                    .map(|()| None),
                ExtensionEffect::BurnAsset { asset_id, amount } => self
                    .assets
                    .apply_program_burn(
                        &mut self.utxos,
                        program,
                        crate::asset::AssetHash::from_bytes(asset_id),
                        Unit::from_units(amount),
                        execution_origin,
                        execution_nonce,
                    )
                    .map(Some)
                    .map_err(SpendStateError::Asset),
            };
            match result {
                Ok(Some(journal)) => journals.push(journal),
                Ok(None) => {}
                Err(error) => {
                    for journal in journals.into_iter().rev() {
                        self.assets.rollback(&mut self.utxos, journal);
                    }
                    self.rollback(coins)?;
                    return Err(error);
                }
            }
        }
        Ok((journals, coins))
    }

    fn apply_program_asset_transfer(
        &mut self,
        program: ExtensionHash,
        asset_id: crate::asset::AssetHash,
        recipient: Address,
        amount: Unit,
        execution_origin: [u8; 32],
        execution_nonce: u64,
    ) -> Result<crate::ledger::AssetRollbackJournal, SpendStateError> {
        let (inputs, outputs) = self
            .assets
            .program_transfer_plan(&self.utxos, program, asset_id, recipient, amount)
            .map_err(SpendStateError::Asset)?;
        self.assets
            .apply_program_transfer(
                &mut self.utxos,
                program,
                asset_id,
                &inputs,
                &outputs,
                execution_origin,
                execution_nonce,
            )
            .map_err(SpendStateError::Asset)
    }

    fn apply_program_coin_transfer(
        &mut self,
        program: ExtensionHash,
        recipient: CoinOwner,
        amount: Zeno,
        commitment: SpendCommitment,
        effect_index: usize,
        journal: &mut UtxoRollbackJournal,
    ) -> Result<(), SpendStateError> {
        if amount.as_zeno() == 0 {
            return Err(SpendStateError::InvalidExtensionAmount);
        }
        let owner = Authority::Extension(program);
        let mut selected = Vec::new();
        let mut total = Zeno::from_zeno(0);
        for utxo in self.utxos.owned_by(owner) {
            selected.push(utxo.coin.utxo);
            total = total
                .checked_add(utxo.coin.amount)
                .ok_or(SpendStateError::AmountOverflow)?;
            if total.as_zeno() >= amount.as_zeno() {
                break;
            }
        }
        if total.as_zeno() < amount.as_zeno() {
            return Err(SpendStateError::InsufficientExtensionCoin);
        }
        for id in selected {
            journal.record_consumed(self.utxos.consume(&id)?);
        }
        let output = extension_output_id(commitment, effect_index)?;
        self.utxos.insert(CoinUtxo {
            coin: Coin::new(output, amount),
            owner: recipient,
        })?;
        journal.created_coin_ids.push(output);
        let change = total
            .checked_sub(amount)
            .ok_or(SpendStateError::AmountOverflow)?;
        if change.as_zeno() != 0 {
            let change_id = extension_change_id(commitment, effect_index)?;
            self.utxos.insert(CoinUtxo {
                coin: Coin::new(change_id, change),
                owner,
            })?;
            journal.created_coin_ids.push(change_id);
        }
        Ok(())
    }

    fn apply_program_coin_burn(
        &mut self,
        program: ExtensionHash,
        amount: Zeno,
        commitment: SpendCommitment,
        effect_index: usize,
        journal: &mut UtxoRollbackJournal,
    ) -> Result<(), SpendStateError> {
        if amount.is_zero() {
            return Err(SpendStateError::InvalidExtensionAmount);
        }
        let owner = Authority::Extension(program);
        let mut selected = Vec::new();
        let mut total = Zeno::ZERO;
        for utxo in self.utxos.owned_by(owner) {
            selected.push(utxo.coin.utxo);
            total = total
                .checked_add(utxo.coin.amount)
                .ok_or(SpendStateError::AmountOverflow)?;
            if total.as_zeno() >= amount.as_zeno() {
                break;
            }
        }
        if total.as_zeno() < amount.as_zeno() {
            return Err(SpendStateError::InsufficientExtensionCoin);
        }
        for id in selected {
            journal.record_consumed(self.utxos.consume(&id)?);
        }
        let change = total
            .checked_sub(amount)
            .ok_or(SpendStateError::AmountOverflow)?;
        if !change.is_zero() {
            let change_id = extension_change_id(commitment, effect_index)?;
            self.utxos.insert(CoinUtxo {
                coin: Coin::new(change_id, change),
                owner,
            })?;
            journal.created_coin_ids.push(change_id);
        }
        self.record_protocol_burn(amount, journal)
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

        ValidatedTransaction::Extension(validated) => validated
            .fee
            .revealed_account_key()
            .cloned()
            .map(|key| (validated.fee.intent().signer, key)),
        _ => None,
    }
}

fn resolve_target(target: Recipient, block_miner: Address) -> CoinOwner {
    match target {
        Recipient::Address(address) => Authority::Address(address),
        Recipient::BlockMiner => Authority::Address(block_miner),
        Recipient::Extension(extension) => Authority::Extension(extension),
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

fn extension_output_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinHash, SpendStateError> {
    Ok(CoinHash::from_bytes(crate::common::domain_hash(
        b"XPARQ Extension Coin Output",
        &[commitment.as_bytes(), &output_index(index)?.to_le_bytes()],
    )))
}

fn extension_change_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinHash, SpendStateError> {
    Ok(CoinHash::from_bytes(crate::common::domain_hash(
        b"XPARQ Extension Coin Change",
        &[commitment.as_bytes(), &output_index(index)?.to_le_bytes()],
    )))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendStateError {
    Utxo(UtxoError),
    OutputIndexOverflow,
    BurnOverflow,
    BurnUnderflow,
    Asset(crate::asset::AssetError),
    Extension(crate::common::ExtensionFailure),
    InvalidExtensionAmount,
    InsufficientExtensionCoin,
    InsufficientExtensionAsset,
    AmountOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_burn_is_rolled_back_with_its_created_utxo() {
        let mut state = LedgerState::default();
        let mut journal = UtxoRollbackJournal::default();
        let burned = crate::consensus::MINER_PROTOCOL_BURN;

        state.record_protocol_burn(burned, &mut journal).unwrap();
        assert_eq!(state.total_burned, burned);
        state.rollback(journal).unwrap();
        assert_eq!(state.total_burned, Zeno::from_zeno(0));
    }

    #[test]
    fn failed_in_place_transition_restores_consumed_inputs() {
        let id = CoinHash::from_bytes([0x51; CoinHash::SIZE]);
        let utxo = CoinUtxo {
            coin: Coin::new(id, Zeno::from_zeno(7)),
            owner: Authority::Address(Address::ZERO),
        };
        let mut state = LedgerState::default();
        state.utxos.insert(utxo).unwrap();
        let consumed = state.utxos.consume(&id).unwrap();
        let journal = UtxoRollbackJournal {
            consumed_coins: vec![consumed],
            ..UtxoRollbackJournal::default()
        };

        assert_eq!(
            state.finish_transition(journal, Err(SpendStateError::OutputIndexOverflow)),
            Err(SpendStateError::OutputIndexOverflow)
        );
        assert_eq!(
            state.utxos.get(&id).map(|coin| coin.coin.amount.as_zeno()),
            Some(7)
        );
    }

    #[test]
    fn failed_program_mint_effect_rolls_back_prior_asset_effects() {
        let creator = Address([7; crypto::ADDRESS_SIZE]);
        let first_recipient = Address([8; crypto::ADDRESS_SIZE]);
        let second_recipient = Address([9; crypto::ADDRESS_SIZE]);
        let program = ExtensionHash::derive("test.asset.minter");
        let register = crate::transaction::AssetIntent::new(
            crate::transaction::AssetInstruction::Register {
                name: "Program Asset".into(),
                symbol: "PRG".into(),
                decimals: 0,
                max_supply: Unit::from_units(120),
                initial_mint: Unit::from_units(100),
                mint_authority: Some(Authority::Extension(program)),
            },
            creator,
            0,
        );
        let asset_id = register.asset_id();
        let mut state = LedgerState::default();
        state
            .assets
            .apply(&mut state.utxos, &register, [0; 32])
            .unwrap();

        let result = state.apply_extension_effects(
            program,
            SpendCommitment::from_bytes([0x44; 32]),
            vec![
                ExtensionEffect::MintAsset {
                    asset_id: *asset_id.as_bytes(),
                    recipient: first_recipient.0,
                    amount: 10,
                },
                ExtensionEffect::MintAsset {
                    asset_id: *asset_id.as_bytes(),
                    recipient: second_recipient.0,
                    amount: 20,
                },
            ],
            [0; 32],
        );

        assert_eq!(
            result,
            Err(SpendStateError::Asset(
                crate::asset::AssetError::SupplyOverflow
            ))
        );
        assert_eq!(state.assets.supply(asset_id), Unit::from_units(100));
        assert_eq!(
            state
                .assets
                .account_balance(&state.utxos, asset_id, first_recipient),
            Unit::ZERO
        );
        assert_eq!(
            state
                .assets
                .account_balance(&state.utxos, asset_id, second_recipient),
            Unit::ZERO
        );
    }

    #[test]
    fn extension_coin_transfer_supports_account_and_extension_recipients() {
        let program = ExtensionHash::derive("test.coin.vault");
        let recipient = Address([0x31; crypto::ADDRESS_SIZE]);
        let recipient_extension = ExtensionHash::derive("test.coin.receiver");
        let deposit_id = CoinHash::from_bytes([0x32; CoinHash::SIZE]);
        let mut state = LedgerState::default();
        state
            .utxos
            .insert(CoinUtxo {
                coin: Coin::new(deposit_id, Zeno::from_zeno(25)),
                owner: Authority::Extension(program),
            })
            .unwrap();

        let (assets, journal) = state
            .apply_extension_effects(
                program,
                SpendCommitment::from_bytes([0x33; 32]),
                vec![
                    ExtensionEffect::TransferCoin {
                        recipient: extension::CoinRecipient::Address(recipient.0),
                        amount: 10,
                    },
                    ExtensionEffect::TransferCoin {
                        recipient: extension::CoinRecipient::Extension(
                            *recipient_extension.as_bytes(),
                        ),
                        amount: 5,
                    },
                ],
                [0; 32],
            )
            .unwrap();

        assert!(assets.is_empty());
        assert_eq!(
            state
                .utxos
                .owned_by(Authority::Address(recipient))
                .map(|utxo| utxo.coin.amount.as_zeno())
                .sum::<u64>(),
            10
        );
        assert_eq!(
            state
                .utxos
                .owned_by(Authority::Extension(recipient_extension))
                .map(|utxo| utxo.coin.amount.as_zeno())
                .sum::<u64>(),
            5
        );
        assert_eq!(
            state
                .utxos
                .owned_by(Authority::Extension(program))
                .map(|utxo| utxo.coin.amount.as_zeno())
                .sum::<u64>(),
            10
        );
        state.rollback(journal).unwrap();
        assert_eq!(
            state.utxos.get(&deposit_id).unwrap().coin.amount.as_zeno(),
            25
        );
    }

    #[test]
    fn extension_coin_burn_is_atomic_and_restores_on_rollback() {
        let program = ExtensionHash::derive("test.coin.burner");
        let deposit_id = CoinHash::from_bytes([0x41; CoinHash::SIZE]);
        let mut state = LedgerState::default();
        state
            .utxos
            .insert(CoinUtxo {
                coin: Coin::new(deposit_id, Zeno::from_zeno(25)),
                owner: Authority::Extension(program),
            })
            .unwrap();

        let (_, journal) = state
            .apply_extension_effects(
                program,
                SpendCommitment::from_bytes([0x42; 32]),
                vec![ExtensionEffect::BurnCoin { amount: 5 }],
                [0; 32],
            )
            .unwrap();
        assert_eq!(state.total_burned, Zeno::from_zeno(5));
        assert_eq!(
            state
                .utxos
                .owned_by(Authority::Extension(program))
                .map(|utxo| utxo.coin.amount.as_zeno())
                .sum::<u64>(),
            20
        );

        state.rollback(journal).unwrap();
        assert_eq!(state.total_burned, Zeno::ZERO);
        assert_eq!(
            state.utxos.get(&deposit_id).unwrap().coin.amount,
            Zeno::from_zeno(25)
        );
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
            Self::InvalidExtensionAmount => {
                formatter.write_str("extension transfer amount is zero")
            }
            Self::InsufficientExtensionCoin => {
                formatter.write_str("extension coin balance is insufficient")
            }
            Self::InsufficientExtensionAsset => {
                formatter.write_str("extension asset balance is insufficient")
            }
            Self::AmountOverflow => formatter.write_str("extension coin amount overflow"),
        }
    }
}

impl Error for SpendStateError {}

impl From<UtxoError> for SpendStateError {
    fn from(error: UtxoError) -> Self {
        Self::Utxo(error)
    }
}

#[cfg(test)]
#[path = "effect_regression_tests.rs"]
mod effect_regression_tests;
