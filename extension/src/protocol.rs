//! Consensus-neutral primitives for deterministic extensions.
//!
//! Core code owns the envelope, resource bound, root commitment, and state
//! capabilities. Business primitives remain in their extension crates.

use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeSet;
use std::fmt;
use std::io::{Error as IoError, ErrorKind, Read};
use std::str::FromStr;

use crypto::primitives::{Height, domain_hash};

pub const EXTENSION_HASH_SIZE: usize = 32;
pub const EXTENSION_HASH_PREFIX: &str = "extension:";
pub const EXTENSION_STATE_ROOT_SIZE: usize = 32;
pub const EXTENSION_PAYLOAD_MAX_SIZE: usize = 3 * 1024 * 1024;
pub const EXTENSION_STATE_KEY_MAX_SIZE: usize = 256;
pub const EXTENSION_STATE_VALUE_MAX_SIZE: usize = 3 * 1024 * 1024;
pub const EXTENSION_STATE_MAX_ENTRIES: usize = 65_536;

const EXTENSION_HASH_CONTEXT: &[u8] = b"XPARQ Extension Id";
const EXTENSION_SET_ROOT_CONTEXT: &[u8] = b"XPARQ Extension Set Root";

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct ExtensionHash([u8; EXTENSION_HASH_SIZE]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionHashParseError;

impl fmt::Display for ExtensionHashParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid extension hash")
    }
}

impl std::error::Error for ExtensionHashParseError {}

impl ExtensionHash {
    pub fn derive(name: &str) -> Self {
        Self(domain_hash(EXTENSION_HASH_CONTEXT, &[name.as_bytes()]))
    }

    pub const fn from_bytes(bytes: [u8; EXTENSION_HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; EXTENSION_HASH_SIZE] {
        &self.0
    }
}

impl fmt::Display for ExtensionHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(EXTENSION_HASH_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ExtensionHash {
    type Err = ExtensionHashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let encoded = value
            .strip_prefix(EXTENSION_HASH_PREFIX)
            .ok_or(ExtensionHashParseError)?;
        if encoded.len() != EXTENSION_HASH_SIZE * 2
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ExtensionHashParseError);
        }

        let mut bytes = [0_u8; EXTENSION_HASH_SIZE];
        for (index, output) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *output = (extension_hex_nibble(encoded.as_bytes()[offset])
                .ok_or(ExtensionHashParseError)?
                << 4)
                | extension_hex_nibble(encoded.as_bytes()[offset + 1])
                    .ok_or(ExtensionHashParseError)?;
        }
        Ok(Self(bytes))
    }
}

const fn extension_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
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
    extension_id: ExtensionHash,
    payload: Vec<u8>,
}

impl ExtensionCall {
    pub fn new(extension_id: ExtensionHash, payload: Vec<u8>) -> Result<Self, ExtensionFailure> {
        if payload.len() > EXTENSION_PAYLOAD_MAX_SIZE {
            return Err(ExtensionFailure::PayloadTooLarge);
        }
        Ok(Self {
            extension_id,
            payload,
        })
    }

    pub const fn extension_id(&self) -> ExtensionHash {
        self.extension_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl BorshDeserialize for ExtensionCall {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let extension_id = ExtensionHash::deserialize_reader(reader)?;
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
    pub extension_id: ExtensionHash,
    pub state_root: ExtensionStateRoot,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExtensionJournalEntry {
    pub key: Vec<u8>,
    pub previous_value: Option<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinRecipient {
    Address([u8; 20]),
    Extension([u8; 32]),
}

/// A native L1 state transition requested by an authenticated extension.
/// The executing extension ID is supplied separately by the ledger and is
/// never accepted from guest-controlled data.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum ExtensionEffect {
    MintAsset {
        asset_id: [u8; 32],
        recipient: [u8; 20],
        amount: u128,
    },
    TransferAsset {
        asset_id: [u8; 32],
        recipient: [u8; 20],
        amount: u128,
    },
    TransferCoin {
        recipient: CoinRecipient,
        amount: u64,
    },
    BurnCoin {
        amount: u64,
    },
    BurnAsset {
        asset_id: [u8; 32],
        amount: u128,
    },
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
    fn state_size(&self) -> Result<usize, ExtensionFailure> {
        self.entries()?
            .iter()
            .try_fold(0_usize, |total, (key, value)| {
                total
                    .checked_add(key.len())
                    .and_then(|size| size.checked_add(value.len()))
                    .ok_or(ExtensionFailure::StateEntryLimit)
            })
    }
    fn get_extension(
        &self,
        extension_id: ExtensionHash,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ExtensionFailure>;
}

pub trait ExtensionStateWrite: ExtensionStateRead {
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ExtensionFailure>;
    fn delete(&mut self, key: &[u8]) -> Result<(), ExtensionFailure>;
    fn emit(&mut self, _effect: ExtensionEffect) -> Result<(), ExtensionFailure> {
        Err(ExtensionFailure::InvalidState)
    }
}

pub trait Extension: Send + Sync {
    fn id(&self) -> ExtensionHash;
    fn activation_height(&self) -> Height;

    /// Maximum deterministic execution weight reserved by one call. Native
    /// extensions default to zero; metered VMs override this value.
    fn execution_weight(&self, _call: &ExtensionCall) -> Result<u64, ExtensionFailure> {
        Ok(0)
    }

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
    let mut encoded = Vec::with_capacity(8 + ordered.len() * 64);
    encoded.extend_from_slice(&(ordered.len() as u64).to_le_bytes());
    for commitment in ordered {
        if !ids.insert(commitment.extension_id) {
            return Err(ExtensionFailure::DuplicateExtension);
        }
        encoded.extend_from_slice(commitment.extension_id.as_bytes());
        encoded.extend_from_slice(commitment.state_root.as_bytes());
    }
    Ok(ExtensionStateRoot::from_bytes(domain_hash(
        EXTENSION_SET_ROOT_CONTEXT,
        &[&encoded],
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_set_root_is_order_independent_and_rejects_duplicates() {
        let asset = ExtensionCommitment {
            extension_id: ExtensionHash::derive("asset"),
            state_root: ExtensionStateRoot::from_bytes([1; 32]),
        };
        let bridge = ExtensionCommitment {
            extension_id: ExtensionHash::derive("bridge"),
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
        let mut encoded = Vec::from(ExtensionHash::derive("asset").as_bytes().as_slice());
        encoded.extend_from_slice(&((EXTENSION_PAYLOAD_MAX_SIZE + 1) as u32).to_le_bytes());
        assert!(ExtensionCall::try_from_slice(&encoded).is_err());
    }

    #[test]
    fn extension_hash_text_format_is_explicit_and_canonical() {
        let hash = ExtensionHash::from_bytes([0xab; EXTENSION_HASH_SIZE]);
        let encoded = format!(
            "{EXTENSION_HASH_PREFIX}{}",
            "ab".repeat(EXTENSION_HASH_SIZE)
        );

        assert_eq!(hash.to_string(), encoded);
        assert_eq!(encoded.parse(), Ok(hash));
        assert!(
            "ab".repeat(EXTENSION_HASH_SIZE)
                .parse::<ExtensionHash>()
                .is_err()
        );
        assert!(
            format!(
                "{EXTENSION_HASH_PREFIX}{}",
                "AB".repeat(EXTENSION_HASH_SIZE)
            )
            .parse::<ExtensionHash>()
            .is_err()
        );
    }
}
