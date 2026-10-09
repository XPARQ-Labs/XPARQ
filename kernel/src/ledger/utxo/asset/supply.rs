//! Root-guarded incremental asset supply audit and summary maintenance.

use super::{AssetJournal, AssetState, SupplyAuditCache, ValidatedAssetRoots};
use crate::{
    monetary::asset::{AssetContract, Unit},
    state_map::StateMap,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

impl PartialEq for SupplyAuditCache {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for SupplyAuditCache {}
impl std::fmt::Debug for SupplyAuditCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SupplyAuditCache")
    }
}

impl AssetState {
    pub(super) fn supply_snapshot(&self) -> Option<ValidatedAssetRoots> {
        let Self {
            records,
            shares,
            by_owner: _,
            supply_cache,
        } = self;
        supply_cache
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .filter(|key| records.shares_root(&key.records) && shares.shares_root(&key.shares))
            .cloned()
    }

    #[cfg(test)]
    pub(crate) fn cached_supply_valid(&self) -> bool {
        self.supply_snapshot()
            .is_some_and(|key| key.dirty.is_empty())
    }

    pub(crate) fn remember_valid_supply(&self, totals: BTreeMap<AssetContract, Unit>) {
        let key = ValidatedAssetRoots {
            records: self.records.clone(),
            shares: self.shares.clone(),
            totals: totals.into(),
            dirty: StateMap::default(),
        };
        *self
            .supply_cache
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(key);
    }

    /// Return None when a full audit is required. Only a successful full audit
    /// establishes a baseline; touched journals then carry it across mutations.
    pub(crate) fn validate_incremental_supply(
        &self,
    ) -> Option<Result<(), crate::ledger::LedgerError>> {
        use crate::ledger::LedgerError;
        let mut key = self.supply_snapshot()?;
        // Unknown shares take precedence over record accounting errors, as in the full audit.
        for asset in key.dirty.keys() {
            if !key
                .totals
                .get(asset)
                .copied()
                .unwrap_or(Unit::ZERO)
                .is_zero()
                && !self.records.contains_key(asset)
            {
                return Some(Err(LedgerError::UnknownAssetShare));
            }
        }
        for asset in key.dirty.keys() {
            if let Some(record) = self.records.get(asset) {
                if record.metadata.validate().is_err() {
                    return Some(Err(LedgerError::InvalidAssetState));
                }
                if record.total_minted > record.metadata.max_supply
                    || record.total_minted.checked_sub(record.total_burned) != Some(record.supply)
                    || key.totals.get(asset).copied().unwrap_or(Unit::ZERO) != record.supply
                {
                    return Some(Err(LedgerError::AssetSupplyMismatch));
                }
            }
        }
        key.dirty.clear();
        // Another fork can replace this shared slot; its root guards remain authoritative.
        *self
            .supply_cache
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(key);
        Some(Ok(()))
    }

    pub(super) fn advance_supply_summary(
        &mut self,
        previous: Option<ValidatedAssetRoots>,
        journal: &AssetJournal,
    ) {
        let updated = previous.and_then(|mut key| {
            for (asset, _) in &journal.records {
                key.dirty.insert(*asset, ());
            }
            // Subtract all old shares first: valid transfers cannot overflow temporarily.
            for (_, old) in &journal.shares {
                if let Some(share) = old {
                    if share.amount.is_zero() {
                        return None;
                    }
                    key.dirty.insert(share.asset, ());
                    let total = key
                        .totals
                        .get(&share.asset)
                        .copied()
                        .unwrap_or(Unit::ZERO)
                        .checked_sub(share.amount)?;
                    if total.is_zero() {
                        key.totals.remove(&share.asset);
                    } else {
                        key.totals.insert(share.asset, total);
                    }
                }
            }
            for (id, _) in &journal.shares {
                if let Some(share) = self.shares.get(id) {
                    if share.amount.is_zero() {
                        return None;
                    }
                    key.dirty.insert(share.asset, ());
                    let total = key
                        .totals
                        .get(&share.asset)
                        .copied()
                        .unwrap_or(Unit::ZERO)
                        .checked_add(share.amount)?;
                    key.totals.insert(share.asset, total);
                }
            }
            key.records = self.records.clone();
            key.shares = self.shares.clone();
            Some(key)
        });
        // Detach the slot when this fork changes; other forks keep their own baseline.
        self.supply_cache = SupplyAuditCache(Arc::new(Mutex::new(updated)));
    }
}
