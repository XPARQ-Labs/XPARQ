//! Canonical cryptographic primitives for the experimental XPARQ sidechain.
//!
//! The sidechain uses SHA3-256 like L1 and SQIsign Level 5 signatures. Address
//! shape remains compatible with L1, but address derivation is domain-separated.

mod address;
mod hash;
mod signature;

pub use address::{
    ADDRESS_HRP, ADDRESS_SIZE, Address, AddressError, address_from_string, address_to_string,
    dual_address_from_public_keys,
};
pub use hash::{HASH_SIZE, Hash256, HashDomain, domain_hash, hash_bytes};
pub use signature::{
    PUBLIC_KEY_SIZE, PublicKey, SIGNATURE_SIZE, SQISIGN_LEVEL, Signature, SignatureError, verify,
    verify_dual,
};

/// Active sidechain wire and protocol format identifier.
pub const PROTOCOL_VERSION: u8 = 1;

/// Cryptographic hash selected for every sidechain consensus hash.
pub const HASH_ALGORITHM: &str = "SHA3-256 (FIPS 202)";

/// Signature scheme selected for sidechain consensus authorization.
pub const SIGNATURE_ALGORITHM: &str = "SQIsign Level 5 (experimental)";
