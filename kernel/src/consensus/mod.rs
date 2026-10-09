//! XPARQ consensus rules.
//!
//! Consensus is intentionally split by responsibility:
//! - block: canonical block admission/application
//! - program_call: authorization and value validation for program calls
//! - policy: WBDA, emission, and protocol burn
//! - pow: Argon2id proof of work
//! - fork: fork choice and reorganization planning
//! - header: header-only synchronization validation

mod block;
mod deploy;
mod fork;
mod header;
mod policy;
mod pow;
pub(crate) mod program_call;
mod target;

pub use crate::error::ConsensusError;
pub use block::*;
pub use deploy::*;
pub use fork::*;
pub use header::*;
pub use policy::*;
pub use pow::*;
pub use program_call::*;

pub use crate::monetary::coin::{DECIMALS, Zeno};

pub use target::{PoWTarget, hash_meets_target};
