//! XPARQ consensus rules.
//!
//! Consensus is intentionally split by responsibility:
//! - block: canonical block admission/application
//! - transaction: direct authorization/value validation
//! - policy: WBDA, emission, and protocol burn
//! - pow: Argon2id proof of work
//! - fork: fork choice and reorganization planning
//! - header: header-only synchronization validation

mod block;
mod error;
mod fork;
mod header;
mod policy;
mod pow;
mod transaction;

pub use block::*;
pub use error::*;
pub use fork::*;
pub use header::*;
pub use policy::*;
pub use pow::*;
pub use transaction::*;

pub use crate::native::coin::{DECIMALS, XPQ, Zeno};
