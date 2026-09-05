//! Shared kernel primitives and re-exports of lower-level contracts.
pub use xparq_crypto::primitives::{codec, types};
pub use xparq_extension::protocol as extension;
mod authority;

pub mod input;
pub mod output;

pub use authority::Authority;
pub use codec::{
    CANONICAL_ENCODING_PROFILE, canonical_bytes, canonical_decode, canonical_deserialize,
};
pub use extension::{
    EXTENSION_HASH_PREFIX, EXTENSION_HASH_SIZE, EXTENSION_PAYLOAD_MAX_SIZE,
    EXTENSION_STATE_MAX_ENTRIES, EXTENSION_STATE_ROOT_SIZE, EXTENSION_STATE_VALUE_MAX_SIZE,
    Extension, ExtensionCall, ExtensionCommitment, ExtensionContext, ExtensionEffect,
    ExtensionFailure, ExtensionHash, ExtensionHashParseError, ExtensionJournalEntry,
    ExtensionStateRead, ExtensionStateRoot, ExtensionStateWrite, extension_set_root,
};
pub use input::Input;
pub use output::Output;
pub use types::{BlockHeight, BlockNonce, Height, Nonce};
pub use xparq_crypto::primitives::CodecError;
pub use xparq_crypto::primitives::{HASH_SIZE, domain_hash};
