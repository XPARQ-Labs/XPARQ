use std::{error::Error, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_asset::Unit;
use xparq_coin::{Coin, CoinHash, Zeno};
use xparq_common::{Authority, ExtensionEffect, ExtensionHash};
use xparq_consensus::{AuthorizationValidated, RevealedAccountKey, ValidatedTransaction};
use xparq_crypto::Address;
use xparq_transaction::{CoinIntent, Recipient, SpendCommitment};

use crate::{
    AccountKeyRegistry, CoinUtxo, ExtensionRollbackJournal, ExtensionStateSet, UtxoError,
    UtxoRollbackJournal,
};

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerState {
    pub account_keys: AccountKeyRegistry,
    pub assets: crate::AssetState,
    pub extensions: ExtensionStateSet,
    pub total_burned: Zeno,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum StateRollbackJournal {
    Utxo(UtxoRollbackJournal),
    Extension(ExtensionRollbackJournal),
    AssetWithPayment {
        asset: crate::AssetRollbackJournal,
        payment: UtxoRollbackJournal,
    },
    ExtensionWithFee {
        extension: ExtensionRollbackJournal,
        assets: Vec<crate::AssetRollbackJournal>,
        fee: UtxoRollbackJournal,
    },
}

impl LedgerState {
    pub const fn utxos(&self) -> &crate::UtxoSet {
        &self.assets.utxos
    }

    pub fn apply_validated_transaction(
        &mut self,
        transaction: &ValidatedTransaction,
        _height: xparq_common::Height,
        block_miner: Address,
        chain: xparq_transaction::ChainContext,
    ) -> Result<StateRollbackJournal, SpendStateError> {
        if let ValidatedTransaction::Asset(asset_transaction) = transaction {
            let mut payment =
                self.apply_validated_onchain_spend(&asset_transaction.payment, block_miner)?;
            if let Some(RevealedAccountKey::Profile(public_key)) =
                asset_transaction.payment.revealed_account_key().cloned()
            {
                match self
                    .account_keys
                    .register_profile(asset_transaction.payment.intent().sender, public_key)
                {
                    Ok(true) => payment
                        .registered_profile_public_keys
                        .push(asset_transaction.payment.intent().sender),
                    Ok(false) => {}
                    Err(error) => {
                        self.rollback(payment)?;
                        return Err(error.into());
                    }
                }
            }
            if let Some(RevealedAccountKey::Profile(public_key)) =
                asset_transaction.call.revealed_account_key().cloned()
            {
                match self
                    .account_keys
                    .register_profile(asset_transaction.call.intent().signer, public_key)
                {
                    Ok(true) => payment
                        .registered_profile_public_keys
                        .push(asset_transaction.call.intent().signer),
                    Ok(false) => {}
                    Err(error) => {
                        self.rollback(payment)?;
                        return Err(error.into());
                    }
                }
            }
            return match self
                .assets
                .apply(asset_transaction.call.intent(), chain.genesis_hash)
            {
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
                Ok(applied) => {
                    match self.apply_extension_effects(
                        extension_transaction.call.extension_id(),
                        extension_transaction.fee.commitment(),
                        applied.effects,
                        chain.genesis_hash,
                    ) {
                        Ok((assets, effects)) => {
                            fee.consumed_coins.extend(effects.consumed_coins);
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
            ValidatedTransaction::Coin(validated) => {
                self.apply_validated_onchain_spend(validated, block_miner)
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
            StateRollbackJournal::AssetWithPayment { asset, payment } => {
                self.assets.rollback(asset);
                self.rollback(payment)
            }
            StateRollbackJournal::ExtensionWithFee {
                extension,
                assets,
                fee,
            } => {
                for journal in assets.into_iter().rev() {
                    self.assets.rollback(journal);
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
        validated: &AuthorizationValidated<CoinIntent>,
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
    ) -> Result<(Vec<crate::AssetRollbackJournal>, UtxoRollbackJournal), SpendStateError> {
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
                        program,
                        xparq_asset::AssetHash::from_bytes(asset_id),
                        Authority::Address(Address(recipient)),
                        Unit::from_units(amount),
                        genesis_hash,
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
                        xparq_asset::AssetHash::from_bytes(asset_id),
                        Address(recipient),
                        Unit::from_units(amount),
                        genesis_hash,
                        execution_nonce,
                    )
                    .map(Some),
                ExtensionEffect::TransferCoin { recipient, amount } => self
                    .apply_program_coin_transfer(
                        program,
                        Address(recipient),
                        Zeno::from_zeno(amount),
                        commitment,
                        index,
                        &mut coins,
                    )
                    .map(|()| None),
            };
            match result {
                Ok(Some(journal)) => journals.push(journal),
                Ok(None) => {}
                Err(error) => {
                    for journal in journals.into_iter().rev() {
                        self.assets.rollback(journal);
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
        asset_id: xparq_asset::AssetHash,
        recipient: Address,
        amount: Unit,
        genesis_hash: [u8; 32],
        execution_nonce: u64,
    ) -> Result<crate::AssetRollbackJournal, SpendStateError> {
        let (inputs, outputs) = self
            .assets
            .program_transfer_plan(program, asset_id, recipient, amount)
            .map_err(SpendStateError::Asset)?;
        self.assets
            .apply_program_transfer(
                program,
                asset_id,
                &inputs,
                &outputs,
                genesis_hash,
                execution_nonce,
            )
            .map_err(SpendStateError::Asset)
    }

    fn apply_program_coin_transfer(
        &mut self,
        program: ExtensionHash,
        recipient: Address,
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
        for utxo in self.assets.utxos.owned_by(owner) {
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
            journal.consumed_coins.push(self.assets.utxos.consume(&id)?);
        }
        let output = extension_output_id(commitment, effect_index)?;
        self.assets.utxos.insert(CoinUtxo {
            coin: Coin::new(output, amount),
            owner: Authority::Address(recipient),
        })?;
        journal.created_coin_ids.push(output);
        let change = total
            .checked_sub(amount)
            .ok_or(SpendStateError::AmountOverflow)?;
        if change.as_zeno() != 0 {
            let change_id = extension_change_id(commitment, effect_index)?;
            self.assets.utxos.insert(CoinUtxo {
                coin: Coin::new(change_id, change),
                owner,
            })?;
            journal.created_coin_ids.push(change_id);
        }
        Ok(())
    }

    fn apply_onchain_spend_with_commitment(
        &mut self,
        intent: &CoinIntent,
        commitment: SpendCommitment,
        block_miner: Address,
    ) -> Result<UtxoRollbackJournal, SpendStateError> {
        let mut journal = UtxoRollbackJournal::default();
        let result = (|| {
            for id in &intent.inputs {
                journal.consumed_coins.push(self.assets.utxos.consume(id)?);
            }
            for (index, output) in intent.outputs.iter().enumerate() {
                let Some(owner) = resolve_target(output.output, block_miner) else {
                    continue;
                };
                let id = account_output_id(commitment, index)?;
                self.assets.utxos.insert(CoinUtxo {
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

    pub(crate) fn rollback(&mut self, journal: UtxoRollbackJournal) -> Result<(), SpendStateError> {
        self.total_burned = self
            .total_burned
            .checked_sub(journal.burned)
            .ok_or(SpendStateError::BurnUnderflow)?;
        for id in journal.created_coin_ids {
            self.assets.utxos.consume(&id)?;
        }
        for utxo in journal.consumed_coins {
            self.assets.utxos.restore(utxo)?;
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
            .filter(|output| output.output == Recipient::Burn)
            .try_fold(Zeno::from_zeno(0), |total, output| {
                total.checked_add(output.amount)
            })
            .ok_or(SpendStateError::BurnOverflow)?;
        self.record_protocol_burn(burned, journal)
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
        ValidatedTransaction::Coin(validated) => validated
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

fn resolve_target(target: Recipient, block_miner: Address) -> Option<Authority<Address>> {
    match target {
        Recipient::Address(address) => Some(Authority::Address(address)),
        Recipient::BlockMiner => Some(Authority::Address(block_miner)),
        Recipient::Burn => None,
        Recipient::Extension(extension) => Some(Authority::Extension(extension)),
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
    Ok(CoinHash::from_output(
        commitment.as_bytes(),
        output_index(index)?,
    ))
}

fn extension_change_id(
    commitment: SpendCommitment,
    index: usize,
) -> Result<CoinHash, SpendStateError> {
    Ok(CoinHash::from_change(
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
    Asset(xparq_asset::AssetError),
    Extension(xparq_common::ExtensionFailure),
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
        let burned = xparq_consensus::MINER_PROTOCOL_BURN;

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
        state.assets.utxos.insert(utxo).unwrap();
        let consumed = state.assets.utxos.consume(&id).unwrap();
        let journal = UtxoRollbackJournal {
            consumed_coins: vec![consumed],
            ..UtxoRollbackJournal::default()
        };

        assert_eq!(
            state.finish_transition(journal, Err(SpendStateError::OutputIndexOverflow)),
            Err(SpendStateError::OutputIndexOverflow)
        );
        assert_eq!(
            state
                .assets
                .utxos
                .get(&id)
                .map(|coin| coin.coin.amount.as_zeno()),
            Some(7)
        );
    }

    #[test]
    fn failed_program_mint_effect_rolls_back_prior_asset_effects() {
        let creator = Address([7; xparq_crypto::ADDRESS_SIZE]);
        let first_recipient = Address([8; xparq_crypto::ADDRESS_SIZE]);
        let second_recipient = Address([9; xparq_crypto::ADDRESS_SIZE]);
        let program = ExtensionHash::derive("test.asset.minter");
        let register = xparq_transaction::AssetIntent::new(
            xparq_transaction::AssetInstruction::Register {
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
        state.assets.apply(&register, [0; 32]).unwrap();

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
                xparq_asset::AssetError::SupplyOverflow
            ))
        );
        assert_eq!(state.assets.supply(asset_id), Unit::from_units(100));
        assert_eq!(
            state.assets.account_balance(asset_id, first_recipient),
            Unit::ZERO
        );
        assert_eq!(
            state.assets.account_balance(asset_id, second_recipient),
            Unit::ZERO
        );
    }

    #[test]
    fn extension_coin_transfer_creates_account_output_and_extension_change() {
        let program = ExtensionHash::derive("test.coin.vault");
        let recipient = Address([0x31; xparq_crypto::ADDRESS_SIZE]);
        let deposit_id = CoinHash::from_bytes([0x32; CoinHash::SIZE]);
        let mut state = LedgerState::default();
        state
            .assets
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
                vec![ExtensionEffect::TransferCoin {
                    recipient: recipient.0,
                    amount: 10,
                }],
                [0; 32],
            )
            .unwrap();

        assert!(assets.is_empty());
        assert_eq!(
            state
                .assets
                .utxos
                .owned_by(Authority::Address(recipient))
                .map(|utxo| utxo.coin.amount.as_zeno())
                .sum::<u64>(),
            10
        );
        assert_eq!(
            state
                .assets
                .utxos
                .owned_by(Authority::Extension(program))
                .map(|utxo| utxo.coin.amount.as_zeno())
                .sum::<u64>(),
            15
        );
        state.rollback(journal).unwrap();
        assert_eq!(
            state
                .assets
                .utxos
                .get(&deposit_id)
                .unwrap()
                .coin
                .amount
                .as_zeno(),
            25
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
