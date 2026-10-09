//! Checked asset register, mint, transfer, and burn with atomic journal recovery.

use super::{AssetJournal, AssetState, ExecutionContext, SupplyAuditCache};
use crate::{
    monetary::asset::{AssetContract, AssetError, AssetRecord, Metadata, Unit},
    program::system::asset_program::type_::AssetCall,
};
use std::sync::{Arc, Mutex};

impl AssetState {
    /// Apply a checked monetary instruction; application dispatch belongs to extension.
    pub(crate) fn apply(
        &mut self,

        call: &AssetCall,

        context: ExecutionContext,
    ) -> Result<AssetJournal, AssetError> {
        use crate::program::system::asset_program::opcode::AssetOpcode;

        let (opcode, payload) = match call {
            AssetCall::Register(value) => (AssetOpcode::Register, borsh::to_vec(value)),

            AssetCall::Mint(value) => (AssetOpcode::Mint, borsh::to_vec(value)),

            AssetCall::Transfer(value) => (AssetOpcode::Transfer, borsh::to_vec(value)),

            AssetCall::Burn(value) => (AssetOpcode::Burn, borsh::to_vec(value)),
        };

        let payload = payload.map_err(|_| AssetError::Encoding)?;

        crate::program::system::asset_program::decode(opcode as u8, &payload)
            .map_err(|_| AssetError::InvalidProgram)?;

        let previous_supply = self.supply_snapshot();
        let mut journal = self.snapshot_operation(call, context)?;
        if let Err(error) = self.apply_monetary_operation(call, context) {
            self.rollback(journal);
            self.supply_cache =
                SupplyAuditCache(Arc::new(Mutex::new(previous_supply.map(|mut key| {
                    key.records = self.records.clone();
                    key.shares = self.shares.clone();
                    key
                }))));
            return Err(error);
        }
        // Preserve the historical journal encoding: sorted keys, changed values only.
        journal
            .records
            .retain(|(key, previous)| self.records.get(key) != previous.as_ref());
        journal
            .shares
            .retain(|(key, previous)| self.shares.get(key) != previous.as_ref());
        self.advance_supply_summary(previous_supply, &journal);
        Ok(journal)
    }

    pub(super) fn apply_monetary_operation(
        &mut self,

        call: &AssetCall,

        context: ExecutionContext,
    ) -> Result<(), AssetError> {
        match call {
            AssetCall::Register(call) => {
                let metadata = Metadata::new(
                    call.name.clone(),
                    call.max_supply,
                    context.actor,
                    call.mint_authority,
                )?;

                if call.initial_mint.is_zero() || call.initial_mint > call.max_supply {
                    return Err(AssetError::InvalidAmount);
                }

                let asset = AssetContract::derive(&metadata, call.nonce)?;

                if self.records.contains_key(&asset) {
                    return Err(AssetError::AssetAlreadyExists);
                }

                self.insert_share(
                    asset,
                    context.commitment,
                    0,
                    call.initial_mint,
                    context.actor,
                )?;

                self.records.insert(
                    asset,
                    AssetRecord {
                        metadata,

                        supply: call.initial_mint,

                        total_minted: call.initial_mint,

                        mint_nonce: 0,

                        total_burned: Unit::ZERO,
                    },
                );
            }

            AssetCall::Mint(call) => {
                if call.amount.is_zero() {
                    return Err(AssetError::InvalidAmount);
                }

                let record = self
                    .records
                    .get(&call.asset)
                    .ok_or(AssetError::UnknownAsset)?;

                if record.metadata.mint_authority != context.actor {
                    return Err(AssetError::Unauthorized);
                }

                if call.nonce
                    != record
                        .mint_nonce
                        .checked_add(1)
                        .ok_or(AssetError::InvalidMintNonce)?
                {
                    return Err(AssetError::InvalidMintNonce);
                }

                let supply = record
                    .supply
                    .checked_add(call.amount)
                    .ok_or(AssetError::SupplyOverflow)?;

                if supply > record.metadata.max_supply {
                    return Err(AssetError::SupplyOverflow);
                }

                let total_minted = record
                    .total_minted
                    .checked_add(call.amount)
                    .ok_or(AssetError::SupplyOverflow)?;

                if total_minted > record.metadata.max_supply {
                    return Err(AssetError::SupplyOverflow);
                }

                self.insert_share(
                    call.asset,
                    context.commitment,
                    0,
                    call.amount,
                    call.recipient,
                )?;

                let record = self
                    .records
                    .get_mut(&call.asset)
                    .ok_or(AssetError::UnknownAsset)?;

                record.supply = supply;

                record.total_minted = total_minted;

                record.mint_nonce = call.nonce;
            }

            AssetCall::Transfer(call) => {
                if !self.records.contains_key(&call.asset) {
                    return Err(AssetError::UnknownAsset);
                }

                if call.inputs.is_empty() || call.outputs.is_empty() {
                    return Err(AssetError::InvalidProgram);
                }

                crate::monetary::asset::ensure_unique_asset_inputs(&call.inputs)?;

                let input_total = self.input_total(call.asset, &call.inputs, context.actor)?;

                let mut output_total = Unit::ZERO;

                for output in &call.outputs {
                    if output.amount.is_zero() {
                        return Err(AssetError::InvalidAmount);
                    }

                    output_total = output_total
                        .checked_add(output.amount)
                        .ok_or(AssetError::BalanceOverflow)?;
                }

                if input_total != output_total {
                    return Err(AssetError::InvalidAmount);
                }

                for input in &call.inputs {
                    self.remove_share(input);
                }

                for (index, output) in call.outputs.iter().enumerate() {
                    self.insert_share(
                        call.asset,
                        context.commitment,
                        index,
                        output.amount,
                        output.recipient,
                    )?;
                }
            }

            AssetCall::Burn(call) => {
                if call.inputs.is_empty() || call.amount.is_zero() {
                    return Err(AssetError::InvalidAmount);
                }

                crate::monetary::asset::ensure_unique_asset_inputs(&call.inputs)?;

                let input_total = self.input_total(call.asset, &call.inputs, context.actor)?;

                let expected = call
                    .amount
                    .checked_add(call.output)
                    .ok_or(AssetError::BalanceOverflow)?;

                if input_total != expected {
                    return Err(AssetError::InvalidAmount);
                }

                let record = self
                    .records
                    .get(&call.asset)
                    .ok_or(AssetError::UnknownAsset)?;

                let supply = record
                    .supply
                    .checked_sub(call.amount)
                    .ok_or(AssetError::SupplyOverflow)?;

                let total_burned = record
                    .total_burned
                    .checked_add(call.amount)
                    .ok_or(AssetError::SupplyOverflow)?;

                for input in &call.inputs {
                    self.remove_share(input);
                }

                if !call.output.is_zero() {
                    self.insert_share(
                        call.asset,
                        context.commitment,
                        0,
                        call.output,
                        context.actor,
                    )?;
                }

                let record = self
                    .records
                    .get_mut(&call.asset)
                    .ok_or(AssetError::UnknownAsset)?;

                record.supply = supply;

                record.total_burned = total_burned;
            }
        }

        Ok(())
    }
}
