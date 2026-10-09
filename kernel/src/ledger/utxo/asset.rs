//! Ledger-owned asset shares, accounting records, and rollback journal types.

use crate::{
    common::Owner,
    monetary::asset::{AssetContract, AssetShare, Share, Unit},
    state_map::StateMap,
};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::HASH_SIZE;
use std::sync::{Arc, Mutex};

pub use crate::monetary::asset::AssetRecord;

mod encoding;
mod index;
mod journal;
mod operations;
mod supply;

/// Kernel-owned asset state with immutable public inspection.
///
/// Raw authorization contexts and rollback are not application capabilities.
///
/// ```compile_fail
/// use kernel::ledger::utxo::ExecutionContext;
/// ```
///
/// ```compile_fail
/// use kernel::ledger::utxo::AssetState;
/// let _rollback = AssetState::rollback;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize)]

pub struct AssetState {
    // Writes detach only affected paths; tree shape is not canonical state.
    records: StateMap<AssetContract, AssetRecord>,

    shares: StateMap<Share, AssetShare>,
    #[borsh(skip)]
    by_owner: StateMap<Owner, StateMap<AssetContract, StateMap<Share, ()>>>,
    #[borsh(skip)]
    supply_cache: SupplyAuditCache,
}

#[derive(Clone, Default)]
struct SupplyAuditCache(Arc<Mutex<Option<ValidatedAssetRoots>>>);
#[derive(Clone)]
struct ValidatedAssetRoots {
    records: StateMap<AssetContract, AssetRecord>,
    shares: StateMap<Share, AssetShare>,
    totals: StateMap<AssetContract, Unit>,
    dirty: StateMap<AssetContract, ()>,
}
/// The kernel must authenticate the caller and bind `commitment` to this call.
///
/// `actor` is the ledger principal whose authority is exercised by the call.
/// For a signature-policy action it is `Owner::Program(signer)`; for a VM action
/// it is `Owner::Program(program_id)`. The kernel, not call payload data, must
/// bind the actor to the authenticated execution path.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExecutionContext {
    pub actor: Owner,
    pub commitment: [u8; HASH_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]

pub struct AssetJournal {
    records: Vec<(AssetContract, Option<AssetRecord>)>,

    shares: Vec<(Share, Option<AssetShare>)>,
}

#[cfg(test)]
mod tests;
