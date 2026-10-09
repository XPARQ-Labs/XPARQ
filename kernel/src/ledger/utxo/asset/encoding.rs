//! Canonical asset-state encoding and rebuild of derived indexes on decode.

use super::{AssetState, SupplyAuditCache};
use crate::{
    common::Owner,
    monetary::asset::{AssetContract, AssetShare, Share, Unit},
    state_map::StateMap,
};
use borsh::BorshDeserialize;
use crypto::HASH_SIZE;
use std::collections::BTreeMap;

impl BorshDeserialize for AssetState {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let records = BTreeMap::deserialize_reader(reader)?;
        let shares = BTreeMap::deserialize_reader(reader)?;
        let mut state = Self {
            records: records.into(),
            shares: shares.into(),
            by_owner: StateMap::default(),
            supply_cache: SupplyAuditCache::default(),
        };
        state.rebuild_owner_index();
        Ok(state)
    }
}

impl AssetState {
    pub(crate) fn canonical_encoded_len(&self) -> Result<u64, crypto::CodecError> {
        let Self {
            records,
            shares,
            by_owner: _,
            supply_cache: _,
        } = self;
        let width = crypto::canonical_length(&(
            Share::from_bytes([0; crypto::HASH_SIZE]),
            AssetShare::new(
                AssetContract::from_bytes([0; HASH_SIZE]),
                Unit::ZERO,
                Owner::Program(crypto::ProgramId::ZERO),
            ),
        ))?;
        crypto::canonical_length(records)?
            .checked_add(crypto::canonical_fixed_map_length(shares.len(), width)?)
            .ok_or(crypto::CodecError::EncodeFailed)
    }

    pub(crate) fn same_canonical_view(&self, other: &Self) -> bool {
        let Self {
            records,
            shares,
            by_owner: _,
            supply_cache: _,
        } = self;
        records.shares_root(&other.records) && shares.shares_root(&other.shares)
    }
}
