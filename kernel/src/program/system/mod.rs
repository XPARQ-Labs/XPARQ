//! System-program wire contracts and checked monetary primitives.
//!
//! Application execution is supplied by extension through ApplicationExecutor.
//! The kernel owns canonical state, authorization, monetary checks, and rollback.

pub mod asset_program;
pub mod coin_program;
pub mod monetary;
pub mod script;
pub mod signature_policy;
