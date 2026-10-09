//! Application layer implemented on restricted kernel capabilities.

pub mod applications;
pub mod asset_program;
pub mod coin_program;
pub mod monetary;
pub mod script;

pub use applications::SystemApplications;
