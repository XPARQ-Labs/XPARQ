use std::collections::BTreeMap;

use borsh::BorshSerialize;

use crypto::{Address, HASH_SIZE};

use crate::{
    common::{Height, Recipient},
    consensus::{
        AuthorizationValidated, RevealedAccountKey, ValidatedAuthorizedTransaction,
        ValidatedTransaction,
    },
    ledger::{
        AssetRollbackJournal, AssetState, LedgerState, SpendRollbackJournal, StateError,
        StateRollbackJournal, utxo,
    },
    native::{
        asset::{
            AssetError, AssetOutput, AssetShare, Contract, Metadata, MintCapability,
            MintCapabilityId, Share, Unit,
        },
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
        height: Height,
        block_miner: Address,
        chain: crate::transaction::ChainContext,
    ) -> Result<StateRollbackJournal, StateError> {
        self.apply_validated_authorized_transaction(transaction, chain, block_miner, height)
    }

    fn apply_validated_authorized_transaction(
        &mut self,
        transaction: &ValidatedAuthorizedTransaction,
        chain: crate::transaction::ChainContext,
        block_miner: Address,
        _height: Height,
    ) -> Result<StateRollbackJournal, StateError> {
        if let ValidatedAuthorizedTransaction::Spend(transaction) = transaction {
            if let Some(payment) = &transaction.payment {
                let mut payment_journal =
                    self.apply_validated_onchain_spend(payment, block_miner)?;

                let (asset, inputs, outputs) = transaction
                    .spend
                    .intent()
                    .asset_parts()
                    .ok_or(StateError::Asset(AssetError::InvalidProgram))?;

                let asset_journal = match self.assets.apply_account_transfer(
                    &mut self.utxos,
                    transaction.spend.intent().signer,
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

                let registrations = [
                    (payment.intent().signer, payment.revealed_account_key()),
                    (
                        transaction.spend.intent().signer,
                        transaction.spend.revealed_account_key(),
                    ),
                ];

                for (address, revealed) in registrations {
                    self.register_revealed_account(
                        address,
                        revealed.cloned(),
                        &mut payment_journal,
                    )?;
                }

                return Ok(StateRollbackJournal::AssetSpendWithPayment {
                    asset: asset_journal,
                    payment: payment_journal,
                });
            }
        }

        //
        // Asset program transaction:
        // register / mint / burn.
        //
        if let ValidatedAuthorizedTransaction::Asset(asset_transaction) = transaction {
            let mut payment =
                self.apply_validated_onchain_spend(&asset_transaction.payment, block_miner)?;

            self.register_revealed_account(
                asset_transaction.payment.intent().signer,
                asset_transaction.payment.revealed_account_key().cloned(),
                &mut payment,
            )?;

            self.register_revealed_account(
                asset_transaction.call.intent().signer,
                asset_transaction.call.revealed_account_key().cloned(),
                &mut payment,
            )?;

            return match self.assets.apply(
                &mut self.utxos,
                asset_transaction.call.intent(),
                chain.genesis_hash,
            ) {
                Ok(asset) => Ok(StateRollbackJournal::AssetWithPayment { asset, payment }),

                Err(error) => {
                    self.rollback_spend(payment)?;
                    Err(StateError::Asset(error))
                }
            };
        }

        //
        // Normal native XPQ spend.
        //
        let mut journal = match transaction {
            ValidatedAuthorizedTransaction::Spend(validated) => {
                self.apply_validated_onchain_spend(&validated.spend, block_miner)
            }

            ValidatedAuthorizedTransaction::Asset(_) => {
                unreachable!("asset transaction handled above")
            }
        }?;

        if let Some((address, public_key)) = revealed_account_key(transaction) {
            self.register_revealed_account(address, Some(public_key), &mut journal)?;
        }

        Ok(StateRollbackJournal::Spend(journal))
    }

    fn register_revealed_account(
        &mut self,
        address: Address,
        revealed: Option<RevealedAccountKey>,
        journal: &mut SpendRollbackJournal,
    ) -> Result<(), StateError> {
        let Some(RevealedAccountKey::Account(public_key)) = revealed else {
            return Ok(());
        };

        match self.account_keys.register_account(address, public_key) {
            Ok(true) => {
                journal.registered_accounts.push(address);
                Ok(())
            }

            Ok(false) => Ok(()),

            Err(error) => Err(StateError::Account(error)),
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
                    .checked_add(self.utxos.coin(id).ok_or(StateError::InvalidTransaction)?)
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
                let amount = self.utxos.consume_coin(id)?;

                let recipient = self
                    .coin_recipients
                    .remove(id)
                    .ok_or(StateError::InvalidTransaction)?;

                journal.consumed_coins.push((*id, amount));
                journal.consumed_coin_recipients.push((*id, recipient));
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
                self.utxos.insert_coin(id, output.amount)?;

                let recipient = match output.output {
                    Recipient::Address(address) => address,
                    Recipient::BlockMiner => block_miner,
                };
                if self.coin_recipients.insert(id, recipient).is_some() {
                    return Err(StateError::InvalidTransaction);
                }

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

        let mut journal = AssetRollbackJournal::default();

        match &call.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority,
            } => {
                let metadata = Metadata::new(
                    name.clone(),
                    symbol.clone(),
                    *decimals,
                    *max_supply,
                    call.signer,
                    *mint_authority,
                )?;

                let asset = Contract::derive(&metadata)?;

                let share = Share::derive(asset, commitment, 0);

                journal
                    .metadata
                    .push((asset, self.metadata.get(&asset).cloned()));

                journal
                    .supplies
                    .push((asset, self.supplies.get(&asset).copied()));

                journal.utxos.push((share, utxos.asset(&share).copied()));
                journal
                    .recipients
                    .push((share, self.share_recipients.get(&share).copied()));

                self.metadata.insert(asset, metadata);

                self.supplies.insert(asset, *initial_mint);

                utxos
                    .insert_asset(
                        share,
                        AssetShare {
                            asset: asset,
                            amount: *initial_mint,
                        },
                    )
                    .map_err(|_| AssetError::ShareAlreadyExists)?;
                self.share_recipients.insert(share, call.signer);

                if *mint_authority != Address::ZERO {
                    let capability_id = MintCapabilityId::derive(asset, commitment);
                    journal.capabilities.push((
                        capability_id,
                        utxos.mint_capability(&capability_id).copied(),
                    ));
                    utxos
                        .insert_mint_capability(
                            capability_id,
                            MintCapability {
                                asset,
                                authority: *mint_authority,
                            },
                        )
                        .map_err(|_| AssetError::ShareAlreadyExists)?;
                }
            }

            AssetInstruction::Mint {
                asset,
                capability,
                recipient,
                amount,
            } => {
                let share = Share::derive(*asset, commitment, 0);
                let next_capability = MintCapabilityId::derive(*asset, commitment);

                let supply = self
                    .supply(*asset)
                    .checked_add(*amount)
                    .ok_or(AssetError::SupplyOverflow)?;

                journal
                    .supplies
                    .push((*asset, self.supplies.get(asset).copied()));

                journal.utxos.push((share, utxos.asset(&share).copied()));
                journal
                    .recipients
                    .push((share, self.share_recipients.get(&share).copied()));
                journal
                    .capabilities
                    .push((*capability, utxos.mint_capability(capability).copied()));
                journal.capabilities.push((
                    next_capability,
                    utxos.mint_capability(&next_capability).copied(),
                ));

                self.supplies.insert(*asset, supply);

                let consumed = utxos
                    .consume_mint_capability(capability)
                    .map_err(|_| AssetError::UnknownObject)?;
                utxos
                    .insert_mint_capability(next_capability, consumed)
                    .map_err(|_| AssetError::ShareAlreadyExists)?;

                utxos
                    .insert_asset(
                        share,
                        AssetShare {
                            asset: *asset,
                            amount: *amount,
                        },
                    )
                    .map_err(|_| AssetError::ShareAlreadyExists)?;
                self.share_recipients.insert(share, *recipient);
            }

            AssetInstruction::Burn { asset, inputs } => {
                let total = self.validate_inputs(utxos, *asset, inputs)?;

                let supply = self
                    .supply(*asset)
                    .checked_sub(total)
                    .ok_or(AssetError::SupplyOverflow)?;

                journal
                    .supplies
                    .push((*asset, self.supplies.get(asset).copied()));

                for input in inputs {
                    journal.utxos.push((*input, utxos.asset(input).copied()));
                    journal
                        .recipients
                        .push((*input, self.share_recipients.remove(input)));

                    utxos
                        .consume_asset(input)
                        .map_err(|_| AssetError::UnknownObject)?;
                }

                self.supplies.insert(*asset, supply);
            }
        }

        Ok(journal)
    }

    pub fn apply_account_transfer(
        &mut self,
        utxos: &mut utxo::UtxoSet,
        _signer: Address,
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
            journal
                .recipients
                .push((*input, self.share_recipients.remove(input)));

            utxos
                .consume_asset(input)
                .map_err(|_| AssetError::UnknownObject)?;
        }

        for (index, output) in outputs.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?;

            let id = Share::derive(asset, commitment, index);

            journal.utxos.push((id, utxos.asset(&id).copied()));
            journal
                .recipients
                .push((id, self.share_recipients.get(&id).copied()));

            utxos
                .insert_asset(
                    id,
                    AssetShare {
                        asset: asset,
                        amount: output.amount,
                    },
                )
                .map_err(|_| AssetError::ShareAlreadyExists)?;
            self.share_recipients.insert(id, output.recipient);
        }

        Ok(journal)
    }
}

impl AssetState {
    pub(crate) fn validate_transition(
        &self,
        utxos: &utxo::UtxoSet,
        call: &AssetIntent,
        genesis_hash: [u8; 32],
    ) -> Result<(), AssetError> {
        match &call.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                mint_authority,
                ..
            } => {
                let metadata = Metadata::new(
                    name.clone(),
                    symbol.clone(),
                    *decimals,
                    *max_supply,
                    call.signer,
                    *mint_authority,
                )?;

                let id = Contract::derive(&metadata)?;

                if self.metadata(id).is_some() {
                    return Err(AssetError::AssetAlreadyExists);
                }

                if *mint_authority != Address::ZERO {
                    let commitment = call.commitment(genesis_hash)?;
                    let capability_id = MintCapabilityId::derive(id, commitment);
                    if utxos.mint_capability(&capability_id).is_some() {
                        return Err(AssetError::ShareAlreadyExists);
                    }
                }
            }

            AssetInstruction::Mint {
                asset,
                capability,
                amount,
                ..
            } => {
                let metadata = self.metadata(*asset).ok_or(AssetError::UnknownAsset)?;
                let capability_utxo = utxos
                    .mint_capability(capability)
                    .ok_or(AssetError::UnknownObject)?;

                if capability_utxo.asset != *asset
                    || capability_utxo.authority != call.signer
                    || metadata.mint_authority != capability_utxo.authority
                {
                    return Err(AssetError::Unauthorized);
                }

                let commitment = call.commitment(genesis_hash)?;
                let next_capability = MintCapabilityId::derive(*asset, commitment);
                if next_capability == *capability
                    || utxos.mint_capability(&next_capability).is_some()
                {
                    return Err(AssetError::ShareAlreadyExists);
                }

                self.supply(*asset)
                    .checked_add(*amount)
                    .filter(|supply| *supply <= metadata.max_supply)
                    .ok_or(AssetError::SupplyOverflow)?;
            }

            AssetInstruction::Burn { asset, inputs } => {
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
            let share = self.utxo(utxos, *input).ok_or(AssetError::UnknownObject)?;

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
        _signer: Address,
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
        match journal {
            StateRollbackJournal::Spend(journal) => self.rollback_spend(journal),

            StateRollbackJournal::AssetWithPayment { asset, payment }
            | StateRollbackJournal::AssetSpendWithPayment { asset, payment } => {
                self.assets.rollback(&mut self.utxos, asset)?;

                self.rollback_spend(payment)
            }
        }
    }

    pub(crate) fn rollback_spend(
        &mut self,
        journal: SpendRollbackJournal,
    ) -> Result<(), StateError> {
        self.total_burned = self
            .total_burned
            .checked_sub(journal.burned)
            .ok_or(StateError::BurnUnderflow)?;

        for id in journal.created_coin_ids {
            self.utxos.consume_coin(&id)?;
            self.coin_recipients.remove(&id);
        }
        for (id, amount) in journal.consumed_coins {
            self.utxos.insert_coin(id, amount)?;
        }
        for (id, recipient) in journal.consumed_coin_recipients {
            self.coin_recipients.insert(id, recipient);
        }
        for address in journal.registered_accounts {
            self.account_keys.remove_account(&address)?;
        }

        Ok(())
    }

    pub(crate) fn record_protocol_burn(
        &mut self,
        burned: Zeno,
        journal: &mut SpendRollbackJournal,
    ) -> Result<(), StateError> {
        self.total_burned = self
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
        restore_map(&mut self.metadata, journal.metadata);

        restore_map(&mut self.supplies, journal.supplies);

        for (id, previous) in journal.utxos.into_iter().rev() {
            if utxos.asset(&id).is_some() {
                utxos.consume_asset(&id)?;
            }

            if let Some(previous) = previous {
                utxos.insert_asset(id, previous)?;
            }
        }

        for (id, previous) in journal.capabilities.into_iter().rev() {
            if utxos.mint_capability(&id).is_some() {
                utxos.consume_mint_capability(&id)?;
            }
            if let Some(previous) = previous {
                utxos.insert_mint_capability(id, previous)?;
            }
        }
        restore_map(&mut self.share_recipients, journal.recipients);

        Ok(())
    }
}

//
// Helpers
//

fn revealed_account_key(
    transaction: &ValidatedAuthorizedTransaction,
) -> Option<(Address, RevealedAccountKey)> {
    match transaction {
        ValidatedAuthorizedTransaction::Spend(validated) => validated
            .spend
            .revealed_account_key()
            .cloned()
            .map(|key| (validated.spend.intent().signer, key)),

        _ => None,
    }
}

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
