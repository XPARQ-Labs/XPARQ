pub mod codec;
mod error;
pub mod extension;
pub mod types;

pub use codec::{
    CANONICAL_ENCODING_PROFILE, canonical_bytes, canonical_decode, canonical_deserialize,
};
pub use error::CodecError;
pub use extension::{
    EXTENSION_ID_SIZE, EXTENSION_PAYLOAD_MAX_SIZE, EXTENSION_STATE_KEY_MAX_SIZE,
    EXTENSION_STATE_MAX_ENTRIES, EXTENSION_STATE_ROOT_SIZE, EXTENSION_STATE_VALUE_MAX_SIZE,
    Extension, ExtensionCall, ExtensionCommitment, ExtensionContext, ExtensionFailure, ExtensionId,
    ExtensionJournalEntry, ExtensionStateRead, ExtensionStateRoot, ExtensionStateWrite,
    extension_set_root,
};
pub use types::{BlockHeight, BlockNonce, Height, Nonce};
