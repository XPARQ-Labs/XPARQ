use std::collections::BTreeMap;

use borsh::BorshSerialize;

use crypto::{Address, HASH_SIZE};

use crate::native::asset::{
    Asset, AssetError, AssetMetadata, AssetShare, MintCapability, MintCapabilityId,
    Output as AssetOutput, Share, Unit,
};

use crate::native::coin::{Recipient, XPQ, Zeno};
use crate::native::pool::{Pair, PoolAmount, PoolError, PoolHash, PoolShareHash, canonical_pair};

use crate::consensus::{
    AuthorizationValidated, RevealedAccountKey, ValidatedAuthorizedTransaction,
    ValidatedPoolTransaction, ValidatedTransaction,
};

use crate::ledger::{
    AssetRollbackJournal, AssetState, LedgerState, PoolRollbackJournal, SpendRollbackJournal,
    StateError, StateRollbackJournal, utxo,
};

use crate::transaction::{
    AssetInstruction, AssetIntent, PoolFunding, PoolInstruction, SpendCommitment, SpendIntent,
};

//
// Apply validated transaction
//

impl LedgerState {
    pub fn apply_validated_transaction(
        &mut self,
        transaction: &ValidatedTransaction,
        height: crypto::Height,
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
        height: crypto::Height,
    ) -> Result<StateRollbackJournal, StateError> {
        if let ValidatedAuthorizedTransaction::Pool(pool_transaction) = transaction {
            let mut staged = self.clone();
            let mut payment =
                staged.apply_validated_onchain_spend(&pool_transaction.payment, block_miner)?;
            staged.register_revealed_account(
                pool_transaction.payment.intent().signer,
                pool_transaction.payment.revealed_account_key().cloned(),
                &mut payment,
            )?;
            staged.register_revealed_account(
                pool_transaction.call.intent().signer,
                pool_transaction.call.revealed_account_key().cloned(),
                &mut payment,
            )?;
            let pool = staged.apply_pool_transaction(pool_transaction, height)?;
            *self = staged;
            return Ok(StateRollbackJournal::PoolWithPayment { pool, payment });
        }
        //
        // Asset transfer that also carries native XPQ payment.
        //
        if let ValidatedAuthorizedTransaction::Spend(transaction) = transaction {
            if let Some(payment) = &transaction.payment {
                let mut payment_journal =
                    self.apply_validated_onchain_spend(payment, block_miner)?;

                let (asset, inputs, outputs) = transaction
                    .spend
                    .intent()
                    .asset_parts()
                    .ok_or(StateError::Asset(AssetError::InvalidProgram))?;

                let asset_journal = match self.assets.apply_user_transfer(
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

            ValidatedAuthorizedTransaction::Asset(_) | ValidatedAuthorizedTransaction::Pool(_) => {
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
// Pool state transition
//

impl LedgerState {
    fn apply_pool_transaction(
        &mut self,
        validated: &ValidatedPoolTransaction,
        height: crypto::Height,
    ) -> Result<PoolRollbackJournal, StateError> {
        let intent = validated.call.intent();
        let commitment = validated.call.commitment().into_bytes();
        let mut journal = PoolRollbackJournal::default();

        match &intent.instruction {
            PoolInstruction::Create {
                asset_x,
                asset_y,
                amount_x,
                amount_y,
                funding_x,
                funding_y,
                fee_units,
            } => {
                let (canonical_x, canonical_y) = canonical_pair(*asset_x, *asset_y)?;
                let id = PoolHash::derive(canonical_x, canonical_y)?;
                journal.pools.push((id, self.pools.pool(id).copied()));
                let share = PoolShareHash::derive(id, commitment, 0);
                journal
                    .pool_shares
                    .push((share, self.pools.pool_share(share).copied()));
                self.consume_pool_funding(funding_x, &mut journal)?;
                self.consume_pool_funding(funding_y, &mut journal)?;
                self.pools.create_pool(
                    *asset_x,
                    *asset_y,
                    *amount_x,
                    *amount_y,
                    *fee_units,
                    intent.signer,
                    commitment,
                    height,
                )?;
            }
            PoolInstruction::AddLiquidity {
                pool,
                amount_x,
                amount_y,
                funding_x,
                funding_y,
                minimum_liquidity,
            } => {
                let current = self
                    .pools
                    .pool(*pool)
                    .copied()
                    .ok_or(PoolError::UnknownPool)?;
                if funding_x.pair() != current.asset_x || funding_y.pair() != current.asset_y {
                    return Err(StateError::Pool(PoolError::InvalidAmount));
                }
                journal.pools.push((*pool, Some(current)));
                let share = PoolShareHash::derive(*pool, commitment, 0);
                journal
                    .pool_shares
                    .push((share, self.pools.pool_share(share).copied()));
                self.consume_pool_funding(funding_x, &mut journal)?;
                self.consume_pool_funding(funding_y, &mut journal)?;
                self.pools.add_liquidity(
                    *pool,
                    *amount_x,
                    *amount_y,
                    *minimum_liquidity,
                    intent.signer,
                    commitment,
                    0,
                    height,
                )?;
            }
            PoolInstruction::RemoveLiquidity {
                share,
                minimum_x,
                minimum_y,
            } => {
                let owned = self
                    .pools
                    .pool_share(*share)
                    .copied()
                    .ok_or(PoolError::UnknownShare)?;
                let current = self
                    .pools
                    .pool(owned.pool)
                    .copied()
                    .ok_or(PoolError::UnknownPool)?;
                journal.pools.push((owned.pool, Some(current)));
                journal.pool_shares.push((*share, Some(owned)));
                let (x, y) = self.pools.remove_liquidity(
                    *share,
                    intent.signer,
                    *minimum_x,
                    *minimum_y,
                    height,
                )?;
                self.create_pool_output(
                    current.asset_x,
                    x,
                    intent.signer,
                    commitment,
                    0,
                    &mut journal,
                )?;
                self.create_pool_output(
                    current.asset_y,
                    y,
                    intent.signer,
                    commitment,
                    1,
                    &mut journal,
                )?;
            }
            PoolInstruction::Swap {
                pool,
                input_asset,
                amount_in,
                funding,
                minimum_out,
            } => {
                let current = self
                    .pools
                    .pool(*pool)
                    .copied()
                    .ok_or(PoolError::UnknownPool)?;
                if funding.pair() != *input_asset {
                    return Err(StateError::Pool(PoolError::InvalidAmount));
                }
                journal.pools.push((*pool, Some(current)));
                self.consume_pool_funding(funding, &mut journal)?;
                let output =
                    self.pools
                        .swap(*pool, *input_asset, *amount_in, *minimum_out, height)?;
                let output_asset = if *input_asset == current.asset_x {
                    current.asset_y
                } else {
                    current.asset_x
                };
                self.create_pool_output(
                    output_asset,
                    output,
                    intent.signer,
                    commitment,
                    0,
                    &mut journal,
                )?;
            }
        }
        Ok(journal)
    }

    fn consume_pool_funding(
        &mut self,
        funding: &PoolFunding,
        journal: &mut PoolRollbackJournal,
    ) -> Result<(), StateError> {
        match funding {
            PoolFunding::Coin { inputs } => {
                for id in inputs {
                    let amount = self.utxos.consume_coin(id)?;
                    let owner = self
                        .coin_recipients
                        .remove(id)
                        .ok_or(StateError::InvalidTransaction)?;
                    journal.consumed_coins.push((*id, amount, owner));
                }
            }
            PoolFunding::Asset { inputs, .. } => {
                for id in inputs {
                    let share = self.utxos.consume_asset(id)?;
                    let owner = self
                        .assets
                        .share_recipients
                        .remove(id)
                        .ok_or(StateError::InvalidTransaction)?;
                    journal.consumed_assets.push((*id, share, owner));
                }
            }
        }
        Ok(())
    }

    fn create_pool_output(
        &mut self,
        pair: Pair,
        amount: PoolAmount,
        owner: Address,
        commitment: [u8; HASH_SIZE],
        index: u32,
        journal: &mut PoolRollbackJournal,
    ) -> Result<(), StateError> {
        match pair {
            Pair::Coin => {
                let id = XPQ::from_output(&commitment, index);
                self.utxos.insert_coin(id, amount.into_zeno()?)?;
                self.coin_recipients.insert(id, owner);
                journal.created_coins.push(id);
            }
            Pair::Asset(asset) => {
                let id = Share::derive(asset, commitment, index);
                self.utxos.insert_asset(
                    id,
                    AssetShare {
                        parent: asset,
                        amount: amount.into_unit(),
                    },
                )?;
                self.assets.share_recipients.insert(id, owner);
                journal.created_assets.push(id);
            }
        }
        Ok(())
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

//
// Asset transitions
//

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
            //
            // Register asset contract.
            //
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority,
            } => {
                let metadata = AssetMetadata::new(
                    name.clone(),
                    symbol.clone(),
                    *decimals,
                    *max_supply,
                    call.signer,
                    *mint_authority,
                )?;

                let asset = Asset::derive(&metadata)?;

                let share_id = Share::derive(asset, commitment, 0);

                journal
                    .metadata
                    .push((asset, self.metadata.get(&asset).cloned()));

                journal
                    .supplies
                    .push((asset, self.supplies.get(&asset).copied()));

                journal
                    .utxos
                    .push((share_id, utxos.asset(&share_id).copied()));
                journal
                    .recipients
                    .push((share_id, self.share_recipients.get(&share_id).copied()));

                self.metadata.insert(asset, metadata);

                self.supplies.insert(asset, *initial_mint);

                utxos
                    .insert_asset(
                        share_id,
                        AssetShare {
                            parent: asset,
                            amount: *initial_mint,
                        },
                    )
                    .map_err(|_| AssetError::ShareAlreadyExists)?;
                self.share_recipients.insert(share_id, call.signer);

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

            //
            // Mint new share.
            //
            AssetInstruction::Mint {
                asset,
                capability,
                recipient,
                amount,
            } => {
                let share_id = Share::derive(*asset, commitment, 0);
                let next_capability = MintCapabilityId::derive(*asset, commitment);

                let supply = self
                    .supply(*asset)
                    .checked_add(*amount)
                    .ok_or(AssetError::SupplyOverflow)?;

                journal
                    .supplies
                    .push((*asset, self.supplies.get(asset).copied()));

                journal
                    .utxos
                    .push((share_id, utxos.asset(&share_id).copied()));
                journal
                    .recipients
                    .push((share_id, self.share_recipients.get(&share_id).copied()));
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

                //
                // Recipient remains inside the transaction
                // commitment, not canonical UTXO state.
                //
                utxos
                    .insert_asset(
                        share_id,
                        AssetShare {
                            parent: *asset,
                            amount: *amount,
                        },
                    )
                    .map_err(|_| AssetError::ShareAlreadyExists)?;
                self.share_recipients.insert(share_id, *recipient);
            }

            //
            // Burn existing shares.
            //
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

    pub fn apply_user_transfer(
        &mut self,
        utxos: &mut utxo::UtxoSet,
        _signer: Address,
        asset: Asset,
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

        //
        // Ensure none of the new Share IDs already exist.
        //
        for index in 0..outputs.len() {
            let index = u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?;

            let id = Share::derive(asset, commitment, index);

            if utxos.asset(&id).is_some() {
                return Err(AssetError::ShareAlreadyExists);
            }
        }

        let mut journal = AssetRollbackJournal::default();

        //
        // Consume old shares.
        //
        for input in inputs {
            journal.utxos.push((*input, utxos.asset(input).copied()));
            journal
                .recipients
                .push((*input, self.share_recipients.remove(input)));

            utxos
                .consume_asset(input)
                .map_err(|_| AssetError::UnknownObject)?;
        }

        //
        // Create new shares.
        //
        for (index, output) in outputs.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?;

            let id = Share::derive(asset, commitment, index);

            journal.utxos.push((id, utxos.asset(&id).copied()));
            journal
                .recipients
                .push((id, self.share_recipients.get(&id).copied()));

            //
            // output.recipient is NOT stored.
            //
            utxos
                .insert_asset(
                    id,
                    AssetShare {
                        parent: asset,
                        amount: output.amount,
                    },
                )
                .map_err(|_| AssetError::ShareAlreadyExists)?;
            self.share_recipients.insert(id, output.recipient);
        }

        Ok(journal)
    }
}

//
// Asset validation required by state transition.
//
// Signature / ownership authorization should already have
// been validated by consensus before reaching this code.
//

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
                let metadata = AssetMetadata::new(
                    name.clone(),
                    symbol.clone(),
                    *decimals,
                    *max_supply,
                    call.signer,
                    *mint_authority,
                )?;

                let id = Asset::derive(&metadata)?;

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
        asset: Asset,
        inputs: &[Share],
    ) -> Result<Unit, AssetError> {
        if inputs.is_empty() {
            return Err(AssetError::InvalidProgram);
        }

        ensure_unique_shares(inputs)?;

        let mut total = Unit::ZERO;

        for input in inputs {
            let share = self.utxo(utxos, *input).ok_or(AssetError::UnknownObject)?;

            if share.parent != asset {
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

    pub fn user_transfer_created_state_weight(
        &self,
        utxos: &utxo::UtxoSet,
        _signer: Address,
        asset: Asset,
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
                    parent: asset,
                    amount: output.amount,
                },
            )
        })
    }
}

//
// Rollback
//

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
            StateRollbackJournal::PoolWithPayment { pool, payment } => {
                self.rollback_pool(pool)?;
                self.rollback_spend(payment)
            }
        }
    }

    fn rollback_pool(&mut self, journal: PoolRollbackJournal) -> Result<(), StateError> {
        for id in journal.created_coins.into_iter().rev() {
            self.utxos.consume_coin(&id)?;
            self.coin_recipients.remove(&id);
        }
        for id in journal.created_assets.into_iter().rev() {
            self.utxos.consume_asset(&id)?;
            self.assets.share_recipients.remove(&id);
        }
        for (id, share, owner) in journal.consumed_assets.into_iter().rev() {
            self.utxos.insert_asset(id, share)?;
            self.assets.share_recipients.insert(id, owner);
        }
        for (id, amount, owner) in journal.consumed_coins.into_iter().rev() {
            self.utxos.insert_coin(id, amount)?;
            self.coin_recipients.insert(id, owner);
        }
        restore_map(&mut self.pools.pool_shares, journal.pool_shares);
        restore_map(&mut self.pools.pools, journal.pools);
        Ok(())
    }

    pub(crate) fn rollback_spend(
        &mut self,
        journal: SpendRollbackJournal,
    ) -> Result<(), StateError> {
        self.total_burned = self
            .total_burned
            .checked_sub(journal.burned)
            .ok_or(StateError::BurnUnderflow)?;

        //
        // Delete newly-created coins.
        //
        for id in journal.created_coin_ids {
            self.utxos.consume_coin(&id)?;
            self.coin_recipients.remove(&id);
        }

        //
        // Restore consumed coins.
        //
        for (id, amount) in journal.consumed_coins {
            self.utxos.insert_coin(id, amount)?;
        }

        for (id, recipient) in journal.consumed_coin_recipients {
            self.coin_recipients.insert(id, recipient);
        }

        //
        // Roll back account key registrations.
        //
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
            //
            // Remove whatever currently occupies
            // this Share ID.
            //
            if utxos.asset(&id).is_some() {
                utxos.consume_asset(&id)?;
            }

            //
            // Restore previous value if one existed.
            //
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
