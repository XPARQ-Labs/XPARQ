//! Coin and asset supply audits and block burn accounting.

use super::LedgerError;
use crate::{ledger::LedgerState, monetary::coin::Zeno, program::CoinTransition};
use std::collections::BTreeMap;

pub(super) fn coin_utxo_total(state: &LedgerState) -> Result<Zeno, LedgerError> {
    Ok(state.utxos.total_value())
}

pub(super) fn expected_coin_burn(
    state: &LedgerState,
    intent: &CoinTransition,
) -> Result<Zeno, LedgerError> {
    let (inputs, outputs) = intent
        .coin_parts()
        .ok_or(LedgerError::BlockAccountingMismatch)?;

    let input_total = inputs.iter().try_fold(Zeno::ZERO, |total, id| {
        let coin = state
            .utxos
            .coin(id)
            .ok_or(LedgerError::BlockAccountingMismatch)?;

        total
            .checked_add(coin.amount)
            .ok_or(LedgerError::SupplyOverflow)
    })?;

    let output_total = outputs
        .iter()
        .try_fold(intent.charges.miner_fee, |total, output| {
            total
                .checked_add(output.amount)
                .ok_or(LedgerError::SupplyOverflow)
        })?;

    input_total
        .checked_sub(output_total)
        .ok_or(LedgerError::BlockAccountingMismatch)
}

pub(super) fn validate_block_accounting(
    before: Zeno,

    after: &LedgerState,

    subsidy: Zeno,

    burns: Zeno,
) -> Result<(), LedgerError> {
    let expected = before
        .checked_add(subsidy)
        .and_then(|total| total.checked_sub(burns))
        .ok_or(LedgerError::BlockAccountingMismatch)?;

    if coin_utxo_total(after)? != expected {
        return Err(LedgerError::BlockAccountingMismatch);
    }

    Ok(())
}

impl LedgerState {
    /// Cross-check accounting records against independently stored live UTXOs.
    pub fn validate_supply_invariants(&self) -> Result<(), LedgerError> {
        self.validate_supply_with_asset_cache(true)
    }

    /// Deep audit for restore/recovery, including an uncached asset scan.
    pub fn audit_supply_invariants(&self) -> Result<(), LedgerError> {
        self.validate_supply_with_asset_cache(false)?;
        self.audit_coin_supply()
    }

    fn validate_supply_with_asset_cache(&self, allow_cached: bool) -> Result<(), LedgerError> {
        let coin_total = self.utxos.total_value();
        if self.coin.supply() != Some(coin_total) || self.utxos.is_empty() != coin_total.is_zero() {
            return Err(LedgerError::CoinSupplyMismatch);
        }
        if allow_cached && let Some(result) = self.extensions.assets.validate_incremental_supply() {
            return result;
        }
        self.audit_asset_supply()
    }

    /// Scan all asset records and shares independently of previous successful audits.
    pub fn audit_asset_supply(&self) -> Result<(), LedgerError> {
        let assets = &self.extensions.assets;

        let mut totals = BTreeMap::new();

        for share in assets.shares().values() {
            if share.amount.is_zero() {
                return Err(LedgerError::InvalidAssetState);
            }
            if !assets.records().contains_key(&share.asset) {
                return Err(LedgerError::UnknownAssetShare);
            }

            let total = totals
                .entry(share.asset)
                .or_insert(crate::program::system::asset_program::asset::Unit::ZERO);

            *total = total
                .checked_add(share.amount)
                .ok_or(LedgerError::SupplyOverflow)?;
        }

        for (asset, record) in assets.records().iter() {
            record
                .metadata
                .validate()
                .map_err(|_| LedgerError::InvalidAssetState)?;
            if record.total_minted > record.metadata.max_supply
                || record.total_minted.checked_sub(record.total_burned) != Some(record.supply)
                || totals
                    .get(asset)
                    .copied()
                    .unwrap_or(crate::program::system::asset_program::asset::Unit::ZERO)
                    != record.supply
            {
                return Err(LedgerError::AssetSupplyMismatch);
            }
        }

        assets.remember_valid_supply(totals);
        Ok(())
    }

    /// Deep audit of the cached XPQ UTXO total against the live UTXO set.
    ///
    /// This is intentionally O(number of UTXOs) and should be used for
    /// snapshot/recovery validation or tests, not for every operation/block.
    pub fn audit_coin_supply(&self) -> Result<(), LedgerError> {
        let actual = self
            .utxos
            .coins()
            .try_fold(Zeno::ZERO, |total, (_, coin)| {
                if coin.amount.is_zero() {
                    return Err(LedgerError::InvalidCoinState);
                }
                total
                    .checked_add(coin.amount)
                    .ok_or(LedgerError::SupplyOverflow)
            })?;

        if actual != self.utxos.total_value() || self.coin.supply() != Some(actual) {
            return Err(LedgerError::CoinSupplyMismatch);
        }

        Ok(())
    }
}
