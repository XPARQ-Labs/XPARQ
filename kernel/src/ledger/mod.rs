//! Canonical UTXO ledger state.

pub mod applied;
#[path = "ledger.rs"]
pub mod canonical;
// Preserve the existing public module path for downstream Rust callers.
pub use canonical as ledger;
mod state;
pub mod utxo;

pub use crate::error::StateError;
pub use canonical::*;
pub use state::*;
pub use utxo::*;

pub use crate::blockchain::Chain;
pub use crate::consensus::{ForkChoice, ForkChoiceError};
