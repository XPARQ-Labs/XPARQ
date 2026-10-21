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
        self.by_owner.clear();
        self.owner_asset_balances.clear();
        self.asset_roles.clear();
        for (&id, share) in self.shares.iter() {
            self.by_owner
                .entry(share.owner)
                .or_default()
                .entry(share.asset)
                .or_default()
                .insert(id, ());
            let key = (share.owner, share.asset);
            let balance = self
                .owner_asset_balances
                .get(&key)
                .copied()
                .unwrap_or(Unit::ZERO)
                .saturating_add(share.amount);
            self.owner_asset_balances.insert(key, balance);
        }
        let asset_roles = &mut self.asset_roles;
        for (&asset, record) in self.records.iter() {
            asset_roles
                .entry(record.metadata.creator)
                .or_default()
                .insert(asset, ());
            asset_roles
                .entry(record.metadata.mint_authority)
                .or_default()
                .insert(asset, ());
        }
    }

    pub(super) fn index_asset_role(&mut self, asset: AssetContract, owner: Owner) {
        self.asset_roles.entry(owner).or_default().insert(asset, ());
    }

    pub(super) fn unindex_asset_role(&mut self, asset: AssetContract, owner: Owner) {
        if let Some(assets) = self.asset_roles.get_mut(&owner) {
            assets.remove(&asset);
            if assets.is_empty() {
                self.asset_roles.remove(&owner);
            }
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

    /// Return a bounded page ordered by asset ID and then share ID.
    pub fn asset_share_page_by_owner(
        &self,
        owner: Owner,
        after: Option<(AssetContract, Share)>,
        limit: usize,
    ) -> (
        Vec<(AssetContract, Share, AssetShare)>,
        Option<(AssetContract, Share)>,
    ) {
        let Some(assets) = self.by_owner.get(&owner) else {
            return (Vec::new(), None);
        };
        let first_asset =
            after.map_or(AssetContract::from_bytes([0; HASH_SIZE]), |cursor| cursor.0);
        let mut page = Vec::with_capacity(limit.saturating_add(1));
        for (asset, ids) in assets.iter_from(&first_asset) {
            for (id, _) in ids.iter_from(
                &after
                    .filter(|cursor| cursor.0 == *asset)
                    .map_or(Share::from_bytes([0; HASH_SIZE]), |cursor| cursor.1),
            ) {
                if after.is_some_and(|cursor| *asset == cursor.0 && *id <= cursor.1) {
                    continue;
                }
                if let Some(share) = self.shares.get(id).copied() {
                    page.push((*asset, *id, share));
                    if page.len() > limit {
                        break;
                    }
                }
            }
            if page.len() > limit {
                break;
            }
        }
        let has_more = page.len() > limit;
        page.truncate(limit);
        let next = has_more
            .then(|| page.last().map(|(asset, share, _)| (*asset, *share)))
            .flatten();
        (page, next)
    }

    /// Return a bounded page for one asset, seeking directly to the share cursor.
    pub fn asset_share_page_by_owner_asset(
        &self,
        owner: Owner,
        asset: AssetContract,
        after: Option<Share>,
        limit: usize,
    ) -> (Vec<(Share, AssetShare)>, Option<Share>) {
        let Some(ids) = self
            .by_owner
            .get(&owner)
            .and_then(|assets| assets.get(&asset))
        else {
            return (Vec::new(), None);
        };
        let first_share = after.unwrap_or_else(|| Share::from_bytes([0; HASH_SIZE]));
        let mut page = Vec::with_capacity(limit.saturating_add(1));
        for (id, _) in ids.iter_from(&first_share) {
            if after.is_some_and(|cursor| *id <= cursor) {
                continue;
            }
            if let Some(share) = self.shares.get(id).copied() {
                page.push((*id, share));
                if page.len() > limit {
                    break;
                }
            }
        }
        let has_more = page.len() > limit;
        page.truncate(limit);
        let next = has_more
            .then(|| page.last().map(|(share, _)| *share))
            .flatten();
        (page, next)
    }

    /// Aggregate balance from a derived owner-and-asset index.
    pub fn balance_by_owner_asset(&self, owner: Owner, asset: AssetContract) -> Unit {
        self.owner_asset_balances
            .get(&(owner, asset))
            .copied()
            .unwrap_or(Unit::ZERO)
    }

    /// Live share count without scanning share values.
    pub fn share_count_by_owner_asset(&self, owner: Owner, asset: AssetContract) -> usize {
        self.by_owner
            .get(&owner)
            .and_then(|assets| assets.get(&asset))
            .map_or(0, StateMap::len)
    }

    /// Assets created by or assigned to this owner's mint authority.
    pub fn assets_by_owner_role(&self, owner: Owner) -> impl Iterator<Item = AssetContract> + '_ {
        self.asset_roles
            .get(&owner)
            .into_iter()
            .flat_map(|assets| assets.keys().copied())
    }

    /// Assets for which this owner has at least one live share.
    pub fn assets_by_owner_shares(&self, owner: Owner) -> impl Iterator<Item = AssetContract> + '_ {
        self.by_owner
            .get(&owner)
            .into_iter()
            .flat_map(|assets| assets.keys().copied())
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
        let key = (share.owner, share.asset);
        let balance = self
            .owner_asset_balances
            .get(&key)
            .copied()
            .and_then(|balance| balance.checked_sub(share.amount))
            .unwrap_or(Unit::ZERO);
        if balance.is_zero() {
            self.owner_asset_balances.remove(&key);
        } else {
            self.owner_asset_balances.insert(key, balance);
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
        let balance_key = (share.owner, share.asset);
        let balance = self
            .owner_asset_balances
            .get(&balance_key)
            .copied()
            .unwrap_or(Unit::ZERO)
            .saturating_add(share.amount);
        self.owner_asset_balances.insert(balance_key, balance);
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
