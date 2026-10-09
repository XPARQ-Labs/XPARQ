//! Live asset-share lookup, owner indexes, and bounded share insertion checks.

use super::AssetState;
use crate::{
    common::Owner,
    monetary::asset::{AssetContract, AssetError, AssetRecord, AssetShare, Share, Unit},
    state_map::StateMap,
};
use crypto::HASH_SIZE;

impl AssetState {
    pub(super) fn rebuild_owner_index(&mut self) {
        let by_owner = &mut self.by_owner;
        by_owner.clear();
        for (&id, share) in self.shares.iter() {
            by_owner
                .entry(share.owner)
                .or_default()
                .entry(share.asset)
                .or_default()
                .insert(id, ());
        }
    }
    /// Read-only asset accounting records. Mutation is restricted to the kernel.
    ///
    /// ```compile_fail
    /// use kernel::ledger::utxo::AssetState;
    /// let mut state = AssetState::default();
    /// state.records().clear();
    /// ```
    pub fn records(&self) -> &StateMap<AssetContract, AssetRecord> {
        &self.records
    }

    /// Read-only live shares; applications must use the bound asset host.
    ///
    /// ```compile_fail
    /// use kernel::ledger::utxo::AssetState;
    /// let mut state = AssetState::default();
    /// state.shares.clear();
    /// ```
    pub fn shares(&self) -> &StateMap<Share, AssetShare> {
        &self.shares
    }

    /// Ordered by asset then share ID; entries always resolve through the primary map.
    pub fn shares_by_owner(&self, owner: Owner) -> impl Iterator<Item = (Share, &AssetShare)> + '_ {
        self.by_owner
            .get(&owner)
            .into_iter()
            .flat_map(|assets| assets.values())
            .flat_map(|ids| ids.keys())
            .filter_map(move |id| {
                self.shares
                    .get(id)
                    .filter(|share| share.owner == owner)
                    .map(|share| (*id, share))
            })
    }

    /// Preserve historical per-asset share-ID ordering for bounded input selection.
    pub fn shares_by_owner_asset(
        &self,
        owner: Owner,
        asset: AssetContract,
    ) -> impl Iterator<Item = (Share, &AssetShare)> + '_ {
        self.by_owner
            .get(&owner)
            .and_then(|assets| assets.get(&asset))
            .into_iter()
            .flat_map(|ids| ids.keys())
            .filter_map(move |id| {
                self.shares
                    .get(id)
                    .filter(|share| share.owner == owner && share.asset == asset)
                    .map(|share| (*id, share))
            })
    }

    pub(super) fn remove_share(&mut self, id: &Share) -> Option<AssetShare> {
        let share = *self.shares.get(id)?;
        self.shares.remove(id);
        let by_owner = &mut self.by_owner;
        if let Some(assets) = by_owner.get_mut(&share.owner) {
            if let Some(ids) = assets.get_mut(&share.asset) {
                ids.remove(id);
                if ids.is_empty() {
                    assets.remove(&share.asset);
                }
            }
            if assets.is_empty() {
                by_owner.remove(&share.owner);
            }
        }
        Some(share)
    }

    pub(super) fn put_share(&mut self, id: Share, share: AssetShare) {
        if self.shares.get(&id) == Some(&share) {
            return;
        }
        self.remove_share(&id);
        self.by_owner
            .entry(share.owner)
            .or_default()
            .entry(share.asset)
            .or_default()
            .insert(id, ());
        self.shares.insert(id, share);
    }

    pub(super) fn input_total(
        &self,
        asset: AssetContract,
        inputs: &[Share],
        actor: Owner,
    ) -> Result<Unit, AssetError> {
        let mut total = Unit::ZERO;

        for input in inputs {
            let share = self.shares.get(input).ok_or(AssetError::UnknownObject)?;

            if share.asset != asset {
                return Err(AssetError::AssetMismatch);
            }

            if share.owner != actor {
                return Err(AssetError::Unauthorized);
            }

            total = total
                .checked_add(share.amount)
                .ok_or(AssetError::BalanceOverflow)?;
        }

        Ok(total)
    }

    pub(super) fn insert_share(
        &mut self,

        asset: AssetContract,

        commitment: [u8; HASH_SIZE],

        index: usize,

        amount: Unit,

        owner: Owner,
    ) -> Result<(), AssetError> {
        let index = u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?;

        let id = Share::derive(asset, commitment, index);

        if self.shares.contains_key(&id) {
            return Err(AssetError::ShareAlreadyExists);
        }

        self.put_share(id, AssetShare::new(asset, amount, owner));

        Ok(())
    }
}
