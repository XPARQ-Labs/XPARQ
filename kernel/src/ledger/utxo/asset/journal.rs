//! Sparse operation footprints, quote views, merged journals, and rollback.

use super::{AssetJournal, AssetState, ExecutionContext};
use crate::{
    monetary::asset::{AssetContract, AssetError, AssetShare, Metadata, Share},
    program::system::asset_program::type_::AssetCall,
};
use borsh::BorshSerialize;
use std::collections::{BTreeMap, BTreeSet};

impl AssetJournal {
    /// Exact canonical map-size delta using original snapshots and final touched entries.
    /// Map length prefixes have fixed width; unchanged entries need no serialization.
    pub(crate) fn canonical_delta(&self, state: &AssetState) -> Result<i128, AssetError> {
        fn size<K: BorshSerialize, V: BorshSerialize>(
            key: &K,
            value: Option<&V>,
        ) -> Result<i128, AssetError> {
            value
                .map(|value| {
                    crypto::canonical_bytes(&(key, value))
                        .map(|v| v.len() as i128)
                        .map_err(|_| AssetError::Encoding)
                })
                .unwrap_or(Ok(0))
        }
        let mut delta = 0i128;
        for (key, previous) in &self.records {
            delta = delta
                .checked_add(size(key, state.records.get(key))? - size(key, previous.as_ref())?)
                .ok_or(AssetError::BalanceOverflow)?;
        }
        for (key, previous) in &self.shares {
            delta = delta
                .checked_add(size(key, state.shares.get(key))? - size(key, previous.as_ref())?)
                .ok_or(AssetError::BalanceOverflow)?;
        }
        Ok(delta)
    }

    pub(crate) fn share_changes(&self) -> impl Iterator<Item = (Share, Option<AssetShare>)> + '_ {
        self.shares.iter().copied()
    }

    /// Compose sequential operations while preserving each key's pre-call value.
    /// A later snapshot must not replace the original rollback value.
    pub(crate) fn merge(self, next: Self) -> Self {
        let mut records: BTreeMap<_, _> = self.records.into_iter().collect();
        for (key, previous) in next.records {
            records.entry(key).or_insert(previous);
        }
        let mut shares: BTreeMap<_, _> = self.shares.into_iter().collect();
        for (key, previous) in next.shares {
            shares.entry(key).or_insert(previous);
        }
        Self {
            records: records.into_iter().collect(),
            shares: shares.into_iter().collect(),
        }
    }
}

impl AssetState {
    /// Include every input, possible output collision and accounting record before
    /// mutation. No monetary operation may read or write outside this footprint.
    pub(super) fn snapshot_operation(
        &self,
        call: &AssetCall,
        context: ExecutionContext,
    ) -> Result<AssetJournal, AssetError> {
        let (asset, inputs, outputs) = match call {
            AssetCall::Register(call) => {
                let metadata = Metadata::new(
                    call.name.clone(),
                    call.max_supply,
                    context.actor,
                    call.mint_authority,
                )?;
                (AssetContract::derive(&metadata, call.nonce)?, &[][..], 1)
            }
            AssetCall::Mint(call) => (call.asset, &[][..], 1),
            AssetCall::Transfer(call) => (call.asset, call.inputs.as_slice(), call.outputs.len()),
            AssetCall::Burn(call) => (
                call.asset,
                call.inputs.as_slice(),
                usize::from(!call.output.is_zero()),
            ),
        };
        let mut shares: BTreeSet<_> = inputs.iter().copied().collect();
        for index in 0..outputs {
            shares.insert(Share::derive(
                asset,
                context.commitment,
                u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?,
            ));
        }
        Ok(AssetJournal {
            records: vec![(asset, self.records.get(&asset).cloned())],
            shares: shares
                .into_iter()
                .map(|key| (key, self.shares.get(&key).copied()))
                .collect(),
        })
    }

    /// Build a private quote state containing only entries read or written by this
    /// instruction. Existing output IDs are included so collisions fail identically.
    pub(crate) fn operation_view(
        &self,
        call: &AssetCall,
        context: ExecutionContext,
    ) -> Result<Self, AssetError> {
        let journal = self.snapshot_operation(call, context)?;
        let mut view = Self {
            records: journal
                .records
                .into_iter()
                .filter_map(|(key, value)| value.map(|value| (key, value)))
                .collect::<BTreeMap<_, _>>()
                .into(),
            shares: journal
                .shares
                .into_iter()
                .filter_map(|(key, value)| value.map(|value| (key, value)))
                .collect::<BTreeMap<_, _>>()
                .into(),
            ..Self::default()
        };
        view.rebuild_owner_index();
        Ok(view)
    }

    pub(crate) fn rollback(&mut self, journal: AssetJournal) {
        let previous_supply = self.supply_snapshot();
        let before = AssetJournal {
            records: journal
                .records
                .iter()
                .map(|(key, _)| (*key, self.records.get(key).cloned()))
                .collect(),
            shares: journal
                .shares
                .iter()
                .map(|(key, _)| (*key, self.shares.get(key).copied()))
                .collect(),
        };
        for (key, previous) in journal.records {
            if self.records.get(&key) == previous.as_ref() {
                continue;
            }
            match previous {
                Some(record) => {
                    self.records.insert(key, record);
                }

                None => {
                    if self.records.contains_key(&key) {
                        self.records.remove(&key);
                    }
                }
            }
        }

        for (key, previous) in journal.shares {
            match previous {
                Some(share) => {
                    self.put_share(key, share);
                }

                None => {
                    self.remove_share(&key);
                }
            }
        }
        self.advance_supply_summary(previous_supply, &before);
    }
}
