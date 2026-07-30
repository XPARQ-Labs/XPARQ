#![allow(clippy::module_inception)]

mod block;
pub mod coinbase;
pub mod encoding;
pub mod header;
pub mod merkle;
pub mod witness;

pub use block::*;
