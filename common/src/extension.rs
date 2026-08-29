//! Consensus-neutral primitives for deterministic extensions.
//!
//! Core code owns the envelope, resource bound, root commitment, and state
//! capabilities. Business primitives remain in their extension crates.

use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeSet;
use std::io::{Error as IoError, ErrorKind, Read};

use crate::Height;

pub const EXTENSION_ID_SIZE: usize = 32;
pub const EXTENSION_STATE_ROOT_SIZE: usize = 32;
pub const EXTENSION_PAYLOAD_MAX_SIZE: usize = 3 * 1024 * 1024;
pub const EXTENSION_STATE_KEY_MAX_SIZE: usize = 256;
pub const EXTENSION_STATE_VALUE_MAX_SIZE: usize = 3 * 1024 * 1024;
pub const EXTENSION_STATE_MAX_ENTRIES: usize = 65_536;

const EXTENSION_ID_CONTEXT: &str = "XPARQ Extension Id";
const EXTENSION_SET_ROOT_CONTEXT: &str = "XPARQ Extension Set Root";

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct ExtensionId([u8; EXTENSION_ID_SIZE]);

impl ExtensionId {
    pub fn derive(name: &str) -> Self {
        Self(blake3::derive_key(EXTENSION_ID_CONTEXT, name.as_bytes()))
    }

    pub const fn from_bytes(bytes: [u8; EXTENSION_ID_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; EXTENSION_ID_SIZE] {
        &self.0
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct ExtensionStateRoot([u8; EXTENSION_STATE_ROOT_SIZE]);

impl ExtensionStateRoot {
    pub const ZERO: Self = Self([0; EXTENSION_STATE_ROOT_SIZE]);

    pub const fn from_bytes(bytes: [u8; EXTENSION_STATE_ROOT_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; EXTENSION_STATE_ROOT_SIZE] {
        &self.0
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct ExtensionCall {
    extension_id: ExtensionId,
    payload: Vec<u8>,
}

impl ExtensionCall {
    pub fn new(extension_id: ExtensionId, payload: Vec<u8>) -> Result<Self, ExtensionFailure> {
        if payload.len() > EXTENSION_PAYLOAD_MAX_SIZE {
            return Err(ExtensionFailure::PayloadTooLarge);
        }
        Ok(Self {
            extension_id,
            payload,
        })
    }

    pub const fn extension_id(&self) -> ExtensionId {
        self.extension_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl BorshDeserialize for ExtensionCall {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let extension_id = ExtensionId::deserialize_reader(reader)?;
        let payload_len = u32::deserialize_reader(reader)? as usize;
        if payload_len > EXTENSION_PAYLOAD_MAX_SIZE {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "extension payload exceeds the consensus bound",
            ));
        }
        let mut payload = vec![0_u8; payload_len];
        reader.read_exact(&mut payload)?;
        Ok(Self {
            extension_id,
            payload,
        })
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionCommitment {
    pub extension_id: ExtensionId,
    pub state_root: ExtensionStateRoot,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExtensionJournalEntry {
    pub key: Vec<u8>,
    pub previous_value: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionContext {
    pub height: Height,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionFailure {
    PayloadTooLarge,
    UnknownExtension,
    DuplicateExtension,
    InactiveExtension,
    InvalidPayload,
    InvalidState,
    StateAccess,
    StateKeyTooLarge,
    StateValueTooLarge,
    StateEntryLimit,
    StateRootMismatch,
}

pub trait ExtensionStateRead {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure>;
    fn entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ExtensionFailure>;
    fn get_extension(
        &self,
        extension_id: ExtensionId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ExtensionFailure>;
}

pub trait ExtensionStateWrite: ExtensionStateRead {
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ExtensionFailure>;
    fn delete(&mut self, key: &[u8]) -> Result<(), ExtensionFailure>;
}

pub trait Extension: Send + Sync {
    fn id(&self) -> ExtensionId;
    fn activation_height(&self) -> Height;

    fn validate(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &dyn ExtensionStateRead,
    ) -> Result<(), ExtensionFailure>;

    fn apply(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &mut dyn ExtensionStateWrite,
    ) -> Result<(), ExtensionFailure>;
}

pub fn extension_set_root(
    commitments: &[ExtensionCommitment],
) -> Result<ExtensionStateRoot, ExtensionFailure> {
    let mut ordered = commitments.to_vec();
    ordered.sort_by_key(|commitment| commitment.extension_id);

    let mut ids = BTreeSet::new();
    let mut hasher = blake3::Hasher::new_derive_key(EXTENSION_SET_ROOT_CONTEXT);
    hasher.update(&(ordered.len() as u64).to_le_bytes());
    for commitment in ordered {
        if !ids.insert(commitment.extension_id) {
            return Err(ExtensionFailure::DuplicateExtension);
        }
        hasher.update(commitment.extension_id.as_bytes());
        hasher.update(commitment.state_root.as_bytes());
    }
    Ok(ExtensionStateRoot::from_bytes(
        *hasher.finalize().as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_set_root_is_order_independent_and_rejects_duplicates() {
        let asset = ExtensionCommitment {
            extension_id: ExtensionId::derive("asset"),
            state_root: ExtensionStateRoot::from_bytes([1; 32]),
        };
        let bridge = ExtensionCommitment {
            extension_id: ExtensionId::derive("bridge"),
            state_root: ExtensionStateRoot::from_bytes([2; 32]),
        };
        assert_eq!(
            extension_set_root(&[asset, bridge]),
            extension_set_root(&[bridge, asset])
        );
        assert_eq!(
            extension_set_root(&[asset, asset]),
            Err(ExtensionFailure::DuplicateExtension)
        );
    }

    #[test]
    fn extension_call_decode_rejects_an_oversized_payload_before_allocation() {
        let mut encoded = Vec::from(ExtensionId::derive("asset").as_bytes().as_slice());
        encoded.extend_from_slice(&((EXTENSION_PAYLOAD_MAX_SIZE + 1) as u32).to_le_bytes());
        assert!(ExtensionCall::try_from_slice(&encoded).is_err());
    }
}
