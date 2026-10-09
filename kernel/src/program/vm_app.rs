//! XPVM v4: bounded application bytecode executed with kernel-created call frames.
//! No instruction can supply its own caller identity or mutate another program's storage.

use crate::ledger::utxo::AssetJournal;
use crate::{ledger::CoinRollbackJournal, program::ProgramJournal};

mod engine;
mod execution;
mod storage;
mod validation;

pub(crate) use execution::apply;
pub use execution::{call_input, preview};
pub(crate) use storage::read_storage;
pub(super) use storage::valid_storage;
pub use validation::validate_code;

pub const MAX_DATA_BYTES: usize = 4096;
pub const MAX_CODE_BYTES: usize = 65_536;
pub const MAX_INSTRUCTIONS: usize = 4096;
pub const MAX_KEY_BYTES: usize = 128;
pub const MAX_STORAGE_ENTRIES: usize = 4096;
pub const MAX_STORAGE_BYTES: usize = 1_048_576;
pub const MAX_CALL_DEPTH: usize = 8;
pub const MAX_CALLS: usize = 64;
pub const MAX_ACTIONS: usize = 256;
pub const CALL_COST: u64 = 20;

pub struct AppliedVm {
    pub value: u128,
    pub fuel_used: u64,
    pub quote: super::vm_transfer::TransferQuote,
    pub(crate) coin: CoinRollbackJournal,
    pub(crate) asset: Option<AssetJournal>,
    pub(crate) program: Option<ProgramJournal>,
}

#[cfg(test)]
mod tests;
