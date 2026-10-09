//! Atomic application of validated operations and rollback of kernel state.
//!
//! Public entry points validate and stage changes before committing. Block
//! execution uses the crate-private staged entry points and discards staging
//! state on failure. Coin mutations are restricted to an authenticated host.

mod coin;
mod deploy;
mod program_call;
mod rollback;

#[cfg(test)]
#[path = "applied/tests/vm_state_call.rs"]
mod vm_state_call_tests;

#[cfg(test)]
#[path = "applied/tests/coin_atomicity.rs"]
mod coin_atomicity_tests;
