use std::collections::BTreeMap;

use borsh::BorshSerialize;

use crypto::{Address, HASH_SIZE};

use crate::{
    common::Recipient,
    consensus::{AuthorizationValidated, ValidatedTransaction},
    ledger::{
        AssetRecord, AssetRollbackJournal, AssetState, CoinUtxo, LedgerState, SpendRollbackJournal,
        StateError, StateRollbackJournal, utxo,
    },
    native::{
        asset::{AssetError, AssetOutput, AssetShare, Contract, Metadata, Share, Unit},
        coin::{XPQ, Zeno},
    },
    transaction::{AssetInstruction, AssetIntent, SpendCommitment, SpendIntent},
};

//
// Apply validated transaction
//

impl LedgerState {
    pub fn apply_validated_transaction(
        &mut self,
        transaction: &ValidatedTransaction,
        block_miner: Address,
        chain: crate::common::ChainContext,
    ) -> Result<StateRollbackJournal, StateError> {
        match transaction {
            ValidatedTransaction::CoinSpend(transaction) => {
                let spend = self.apply_validated_onchain_spend(&transaction.spend, block_miner)?;
                Ok(StateRollbackJournal {
                    spend: Some(spend),
                    asset: None,
                })
            }
            ValidatedTransaction::AssetTransfer(transaction) => {
                let payment_journal =
                    self.apply_validated_onchain_spend(&transaction.payment, block_miner)?;

                let (asset, inputs, outputs) = transaction
                    .spend
                    .intent()
                    .asset_parts()
                    .ok_or(StateError::Asset(AssetError::InvalidProgram))?;

                let asset_journal = match self.assets.apply_account_transfer(
                    &mut self.utxos,
                    asset,
                    inputs,
                    outputs,
                    transaction.spend.commitment().into_bytes(),
                ) {
                    Ok(journal) => journal,

                    Err(error) => {
                        self.rollback_spend(payment_journal)?;
                        return Err(StateError::Asset(error));
                    }
                };

                Ok(StateRollbackJournal {
                    spend: Some(payment_journal),
                    asset: Some(asset_journal),
                })
            }
            ValidatedTransaction::AssetCall(transaction) => {
                let payment =
                    self.apply_validated_onchain_spend(&transaction.payment, block_miner)?;

                match self.assets.apply(
                    &mut self.utxos,
                    transaction.call.intent(),
                    chain.genesis_hash,
                ) {
                    Ok(asset) => Ok(StateRollbackJournal {
                        spend: Some(payment),
                        asset: Some(asset),
                    }),

                    Err(error) => {
                        self.rollback_spend(payment)?;
                        Err(StateError::Asset(error))
                    }
                }
            }
        }
    }
}

//
// Coin state transition
//

impl LedgerState {
    fn apply_validated_onchain_spend(
        &mut self,
        validated: &AuthorizationValidated<SpendIntent>,
        block_miner: Address,
    ) -> Result<SpendRollbackJournal, StateError> {
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
    ) -> Result<SpendRollbackJournal, StateError> {
        let mut journal = SpendRollbackJournal::default();

        let result = (|| {
            let (inputs, outputs) = intent.coin_parts().ok_or(StateError::InvalidTransaction)?;

            let input_total = inputs.iter().try_fold(Zeno::ZERO, |total, id| {
                total
                    .checked_add(
                        self.utxos
                            .coin(id)
                            .ok_or(StateError::InvalidTransaction)?
                            .amount,
                    )
                    .ok_or(StateError::AmountOverflow)
            })?;
            let output_total = outputs.iter().try_fold(Zeno::ZERO, |total, output| {
                total
                    .checked_add(output.amount)
                    .ok_or(StateError::AmountOverflow)
            })?;
            let burn = input_total
                .checked_sub(output_total)
                .ok_or(StateError::InvalidTransaction)?;

            //
            // Consume existing XPQ objects.
            //
            for id in inputs {
                let coin = self.utxos.consume_coin(id)?;
                journal.consumed_coins.push((*id, coin));
            }

            //
            // Create new XPQ objects.
            //
            for (index, output) in outputs.iter().enumerate() {
                let id = coin_output_id(commitment, index)?;

                //
                // Recipient is intentionally NOT stored
                // in the canonical UTXO state.
                //
                // Ownership is bound by the transaction
                // commitment and validated by consensus.
                //
                let recipient = match output.output {
                    Recipient::Address(address) => address,
                    Recipient::BlockMiner => block_miner,
                };
                self.utxos.insert_coin(
                    id,
                    CoinUtxo {
                        amount: output.amount,
                        owner: recipient,
                    },
                )?;

                journal.created_coin_ids.push(id);
            }

            self.record_protocol_burn(burn, &mut journal)?;

            Ok(())
        })();

        self.finish_spend_transition(journal, result)
    }
}

impl AssetState {
    pub fn apply(
        &mut self,
        utxos: &mut utxo::UtxoSet,
        call: &AssetIntent,
        genesis_hash: [u8; 32],
    ) -> Result<AssetRollbackJournal, AssetError> {
        call.validate_structure()?;

        self.validate_transition(utxos, call, genesis_hash)?;

        let commitment = call.commitment(genesis_hash)?;

        let created_share = match &call.instruction {
            AssetInstruction::Register { .. } => Some(Share::derive(call.asset()?, commitment, 0)),
            AssetInstruction::Mint { asset, .. } => Some(Share::derive(*asset, commitment, 0)),
            AssetInstruction::Burn {
                asset,
                output,
                ..
            } => {
                if output.is_zero() {
                    None
                } else {
                    Some(Share::derive(*asset, commitment, 0))
                }
            }
        };
        if created_share.is_some_and(|share| utxos.asset(&share).is_some()) {
            return Err(AssetError::ShareAlreadyExists);
        }

        let mut journal = AssetRollbackJournal::default();

        match &call.instruction {
            AssetInstruction::Register {
                name,
                decimals,
                max_supply,
                initial_mint,
                mint_authority,
                nonce,
            } => {
                let metadata = Metadata::new(
                    name.clone(),
                    *decimals,
                    *max_supply,
                    call.signer,
                    *mint_authority,
                )?;

                let asset = Contract::derive(&metadata, *nonce)?;

                let share = Share::derive(asset, commitment, 0);

                journal
                    .assets
                    .push((asset, self.assets.get(&asset).cloned()));

                journal.utxos.push((share, utxos.asset(&share).copied()));
                self.assets.insert(
                    asset,
                    AssetRecord {
                        metadata,
                        supply: *initial_mint,
                        total_minted: *initial_mint,
                        mint_nonce: 0,
                        total_burned: Unit::ZERO,
                    },
                );

                utxos
                    .insert_asset(
                        share,
                        AssetShare {
                            asset: asset,
                            amount: *initial_mint,
                            owner: call.signer,
                        },
                    )
                    .map_err(|_| AssetError::ShareAlreadyExists)?;
            }

            AssetInstruction::Mint {
                asset,
                nonce,
                recipient,
                amount,
            } => {
                let share = Share::derive(*asset, commitment, 0);
                let previous = self.assets.get(asset).cloned();
                let record = self.assets.get_mut(asset).ok_or(AssetError::UnknownAsset)?;
                record.supply = record
                    .supply
                    .checked_add(*amount)
                    .ok_or(AssetError::SupplyOverflow)?;
                record.total_minted = record
                    .total_minted
                    .checked_add(*amount)
                    .ok_or(AssetError::SupplyOverflow)?;
                record.mint_nonce = *nonce;
                journal.assets.push((*asset, previous));

                journal.utxos.push((share, utxos.asset(&share).copied()));

                utxos
                    .insert_asset(
                        share,
                        AssetShare {
                            asset: *asset,
                            amount: *amount,
                            owner: *recipient,
                        },
                    )
                    .map_err(|_| AssetError::ShareAlreadyExists)?;
            }

            AssetInstruction::Burn { asset, inputs, amount, output } => {
                let total = self.validate_inputs(utxos, *asset, inputs)?;
                let expected_total = amount
                    .checked_add(*output)
                    .ok_or(AssetError::BalanceOverflow)?;
                if total != expected_total {
                    return Err(AssetError::InvalidAmount);
                }
                let previous = self.assets.get(asset).cloned();
                let record = self.assets.get_mut(asset).ok_or(AssetError::UnknownAsset)?;
                record.supply = record
                    .supply
                    .checked_sub(*amount)
                    .ok_or(AssetError::SupplyOverflow)?;
                record.total_burned = record
                      .total_burned
                      .checked_add(*amount)
                      .ok_or(AssetError::SupplyOverflow)?;
                journal.assets.push((*asset, previous));

                for input in inputs {
                    journal.utxos.push((*input, utxos.asset(input).copied()));
                    utxos
                        .consume_asset(input)
                        .map_err(|_| AssetError::UnknownObject)?;
                }
                if !output.is_zero() {
                    let share = Share::derive(*asset, commitment, 0);
                    journal.utxos.push((share, utxos.asset(&share).copied()));
                    utxos
                        .insert_asset(
                            share,
                            AssetShare {
                                asset: *asset,
                                amount: *output,
                                owner: call.signer,
                            },
                        )
                        .map_err(|_| AssetError::ShareAlreadyExists)?;
                }
            }
        }

        Ok(journal)
    }

    pub fn apply_account_transfer(
        &mut self,
        utxos: &mut utxo::UtxoSet,
        asset: Contract,
        inputs: &[Share],
        outputs: &[AssetOutput],
        commitment: [u8; HASH_SIZE],
    ) -> Result<AssetRollbackJournal, AssetError> {
        self.metadata(asset).ok_or(AssetError::UnknownAsset)?;

        let input_total = self.validate_inputs(utxos, asset, inputs)?;

        let output_total = outputs_total(outputs)?;

        if input_total != output_total {
            return Err(AssetError::InvalidAmount);
        }

        for index in 0..outputs.len() {
            let index = u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?;

            let id = Share::derive(asset, commitment, index);

            if utxos.asset(&id).is_some() {
                return Err(AssetError::ShareAlreadyExists);
            }
        }

        let mut journal = AssetRollbackJournal::default();

        for input in inputs {
            journal.utxos.push((*input, utxos.asset(input).copied()));
            utxos
                .consume_asset(input)
                .map_err(|_| AssetError::UnknownObject)?;
        }

        for (index, output) in outputs.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?;

            let id = Share::derive(asset, commitment, index);

            journal.utxos.push((id, utxos.asset(&id).copied()));

            utxos
                .insert_asset(
                    id,
                    AssetShare {
                        asset: asset,
                        amount: output.amount,
                        owner: output.recipient,
                    },
                )
                .map_err(|_| AssetError::ShareAlreadyExists)?;
        }

        Ok(journal)
    }
}

impl AssetState {
    pub(crate) fn validate_transition(
        &self,
        utxos: &utxo::UtxoSet,
        call: &AssetIntent,
        _genesis_hash: [u8; 32],
    ) -> Result<(), AssetError> {
        match &call.instruction {
            AssetInstruction::Register {
                name,
                decimals,
                max_supply,
                mint_authority,
                nonce,
                ..
            } => {
                let metadata = Metadata::new(
                    name.clone(),
                    *decimals,
                    *max_supply,
                    call.signer,
                    *mint_authority,
                )?;

                let id = Contract::derive(&metadata, *nonce)?;

                if self.metadata(id).is_some() {
                    return Err(AssetError::AssetAlreadyExists);
                }
            }

            AssetInstruction::Mint {
                asset,
                nonce,
                amount,
                ..
            } => {
                let metadata = self.metadata(*asset).ok_or(AssetError::UnknownAsset)?;
                if metadata.mint_authority == Address::ZERO
                    || metadata.mint_authority != call.signer
                {
                    return Err(AssetError::Unauthorized);
                }
                let expected_nonce = self
                    .mint_nonce(*asset)
                    .ok_or(AssetError::UnknownAsset)?
                    .checked_add(1)
                    .ok_or(AssetError::InvalidMintNonce)?;
                if *nonce != expected_nonce {
                    return Err(AssetError::InvalidMintNonce);
                }

                self.record(*asset)
                    .ok_or(AssetError::UnknownAsset)?
                    .total_minted
                    .checked_add(*amount)
                    .filter(|total| *total <= metadata.max_supply)
                    .ok_or(AssetError::SupplyOverflow)?;
            }

            AssetInstruction::Burn {
                asset,
                inputs,
                ..
            } => {
                self.metadata(*asset).ok_or(AssetError::UnknownAsset)?;
                self.validate_inputs(utxos, *asset, inputs)?;
            }
        }

        Ok(())
    }

    fn validate_inputs(
        &self,
        utxos: &utxo::UtxoSet,
        asset: Contract,
        inputs: &[Share],
    ) -> Result<Unit, AssetError> {
        if inputs.is_empty() {
            return Err(AssetError::InvalidProgram);
        }

        ensure_unique_shares(inputs)?;

        let mut total = Unit::ZERO;

        for input in inputs {
            let share = utxos.asset(input).ok_or(AssetError::UnknownObject)?;

            if share.asset != asset {
                return Err(AssetError::AssetMismatch);
            }

            //
            // No owner comparison here.
            //
            // Authorization belongs to consensus.
            //

            total = total
                .checked_add(share.amount)
                .ok_or(AssetError::BalanceOverflow)?;
        }

        Ok(total)
    }

    pub fn account_transfer_created_state_weight(
        &self,
        utxos: &utxo::UtxoSet,
        asset: Contract,
        inputs: &[Share],
        outputs: &[AssetOutput],
    ) -> Result<u64, AssetError> {
        self.metadata(asset).ok_or(AssetError::UnknownAsset)?;

        let input_total = self.validate_inputs(utxos, asset, inputs)?;

        if input_total != outputs_total(outputs)? {
            return Err(AssetError::InvalidAmount);
        }

        outputs.iter().try_fold(0_u64, |weight, output| {
            checked_entry_weight(
                weight,
                HASH_SIZE,
                &AssetShare {
                    asset: asset,
                    amount: output.amount,
                    owner: output.recipient,
                },
            )
        })
    }
}

impl LedgerState {
    pub(crate) fn rollback_state(
        &mut self,
        journal: StateRollbackJournal,
    ) -> Result<(), StateError> {
        if let Some(asset) = journal.asset {
            self.assets.rollback(&mut self.utxos, asset)?;
        }
        if let Some(spend) = journal.spend {
            self.rollback_spend(spend)?;
        }
        Ok(())
    }

    pub(crate) fn rollback_spend(
        &mut self,
        journal: SpendRollbackJournal,
    ) -> Result<(), StateError> {
        self.coin.total_mined =self
            .coin
            .total_mined
            .checked_sub(journal.mined)
            .ok_or(StateError::AmountOverflow)?;

        self.coin.total_burned = self
            .coin
            .total_burned
            .checked_sub(journal.burned)
            .ok_or(StateError::BurnUnderflow)?;

        for id in journal.created_coin_ids {
            self.utxos.consume_coin(&id)?;
        }
        for (id, coin) in journal.consumed_coins {
            self.utxos.insert_coin(id, coin)?;
        }
        Ok(())
    }

    pub(crate) fn record_protocol_burn(
        &mut self,
        burned: Zeno,
        journal: &mut SpendRollbackJournal,
    ) -> Result<(), StateError> {
        self.coin.total_burned = self
            .coin
            .total_burned
            .checked_add(burned)
            .ok_or(StateError::BurnOverflow)?;

        journal.burned = journal
            .burned
            .checked_add(burned)
            .ok_or(StateError::BurnOverflow)?;

        Ok(())
    }

    fn finish_spend_transition(
        &mut self,
        journal: SpendRollbackJournal,
        result: Result<(), StateError>,
    ) -> Result<SpendRollbackJournal, StateError> {
        match result {
            Ok(()) => Ok(journal),

            Err(error) => {
                self.rollback_spend(journal)?;
                Err(error)
            }
        }
    }
}

impl AssetState {
    pub fn rollback(
        &mut self,
        utxos: &mut utxo::UtxoSet,
        journal: AssetRollbackJournal,
    ) -> Result<(), StateError> {
        restore_map(&mut self.assets, journal.assets);

        for (id, previous) in journal.utxos.into_iter().rev() {
            if utxos.asset(&id).is_some() {
                utxos.consume_asset(&id)?;
            }

            if let Some(previous) = previous {
                utxos.insert_asset(id, previous)?;
            }
        }
        Ok(())
    }
}

//
// Helpers
//

fn output_index(index: usize) -> Result<u32, StateError> {
    u32::try_from(index).map_err(|_| StateError::OutputIndexOverflow)
}

fn coin_output_id(commitment: SpendCommitment, index: usize) -> Result<XPQ, StateError> {
    Ok(XPQ::from_output(
        commitment.as_bytes(),
        output_index(index)?,
    ))
}

fn outputs_total(outputs: &[AssetOutput]) -> Result<Unit, AssetError> {
    if outputs.is_empty() {
        return Err(AssetError::InvalidProgram);
    }

    let mut total = Unit::ZERO;

    for output in outputs {
        if output.amount.is_zero() {
            return Err(AssetError::InvalidAmount);
        }

        total = total
            .checked_add(output.amount)
            .ok_or(AssetError::BalanceOverflow)?;
    }

    Ok(total)
}

fn ensure_unique_shares(inputs: &[Share]) -> Result<(), AssetError> {
    let mut sorted = inputs.to_vec();

    sorted.sort_unstable();

    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AssetError::InvalidProgram);
    }

    Ok(())
}

fn checked_entry_weight<T: BorshSerialize>(
    current: u64,
    key_len: usize,
    value: &T,
) -> Result<u64, AssetError> {
    let value_len = borsh::to_vec(value)
        .map_err(|_| AssetError::Encoding)?
        .len();

    let entry = key_len.checked_add(value_len).ok_or(AssetError::Encoding)?;

    let entry = u64::try_from(entry).map_err(|_| AssetError::Encoding)?;

    current.checked_add(entry).ok_or(AssetError::Encoding)
}

fn restore_map<K: Ord, V>(map: &mut BTreeMap<K, V>, entries: Vec<(K, Option<V>)>) {
    for (key, previous) in entries.into_iter().rev() {
        match previous {
            Some(value) => {
                map.insert(key, value);
            }

            None => {
                map.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(byte: u8) -> Address {
        Address([byte; crypto::ADDRESS_SIZE])
    }

    fn register(authority: Address) -> AssetIntent {
        AssetIntent::new(
            AssetInstruction::Register {
                name: "Nonce Asset".into(),
                decimals: 0,
                max_supply: Unit::from_units(100),
                initial_mint: Unit::from_units(10),
                mint_authority: authority,
            },
            address(1),
        )
    }

    #[test]
    fn mint_nonce_is_sequential_and_rollback_restores_it() {
        let authority = address(2);
        let register = register(authority);
        let asset = register.asset().unwrap();
        let mut state = AssetState::default();
        let mut utxos = utxo::UtxoSet::default();

        state.apply(&mut utxos, &register, [3; 32]).unwrap();
        assert_eq!(state.mint_nonce(asset), Some(0));

        let mint = AssetIntent::new(
            AssetInstruction::Mint {
                asset,
                nonce: 1,
                recipient: address(4),
                amount: Unit::from_units(5),
            },
            authority,
        );
        let journal = state.apply(&mut utxos, &mint, [3; 32]).unwrap();
        assert_eq!(state.mint_nonce(asset), Some(1));
        assert_eq!(state.supply(asset), Unit::from_units(15));
        assert_eq!(state.total_minted(asset), Some(Unit::from_units(15)));

        assert_eq!(
            state.apply(&mut utxos, &mint, [3; 32]),
            Err(AssetError::InvalidMintNonce)
        );

        state.rollback(&mut utxos, journal).unwrap();
        assert_eq!(state.mint_nonce(asset), Some(0));
        assert_eq!(state.supply(asset), Unit::from_units(10));
        assert_eq!(state.total_minted(asset), Some(Unit::from_units(10)));
    }

    #[test]
    fn mint_nonce_does_not_replace_authority_check() {
        let authority = address(2);
        let register = register(authority);
        let asset = register.asset().unwrap();
        let mut state = AssetState::default();
        let mut utxos = utxo::UtxoSet::default();
        state.apply(&mut utxos, &register, [3; 32]).unwrap();

        let mint = AssetIntent::new(
            AssetInstruction::Mint {
                asset,
                nonce: 1,
                recipient: address(4),
                amount: Unit::from_units(5),
            },
            address(9),
        );
        assert_eq!(
            state.apply(&mut utxos, &mint, [3; 32]),
            Err(AssetError::Unauthorized)
        );
    }

    #[test]
    fn burned_supply_cannot_be_minted_past_cumulative_cap() {
        let authority = address(2);
        let register = register(authority);
        let asset = register.asset().unwrap();
        let genesis_hash = [3; 32];
        let initial_share = Share::derive(asset, register.commitment(genesis_hash).unwrap(), 0);
        let mut state = AssetState::default();
        let mut utxos = utxo::UtxoSet::default();
        state.apply(&mut utxos, &register, genesis_hash).unwrap();

        let burn = AssetIntent::new(
            AssetInstruction::Burn {
                asset,
                inputs: vec![initial_share],
            },
            address(1),
        );
        state.apply(&mut utxos, &burn, genesis_hash).unwrap();
        assert_eq!(state.supply(asset), Unit::ZERO);
        assert_eq!(state.total_minted(asset), Some(Unit::from_units(10)));

        let mint = AssetIntent::new(
            AssetInstruction::Mint {
                asset,
                nonce: 1,
                recipient: address(4),
                amount: Unit::from_units(95),
            },
            authority,
        );
        assert_eq!(
            state.apply(&mut utxos, &mint, genesis_hash),
            Err(AssetError::SupplyOverflow)
        );
    }
}
