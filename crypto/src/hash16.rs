use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use static_assertions::{const_assert, const_assert_eq};
use std::{error::Error, fmt};

pub const HASH_SIZE: usize = 32;
pub const POW_HASH_SIZE: usize = HASH_SIZE;

// Compact consensus identifiers. Change only these constants to test
// different serialized ID sizes. The underlying SHA3-256 digest remains 32 bytes.
pub const COIN_SIZE: usize = 16;
pub const ASSET_SIZE: usize = 16;
pub const SHARE_SIZE: usize = 8;

const_assert_eq!(HASH_SIZE, 32);
const_assert!(COIN_SIZE > 0 && COIN_SIZE <= HASH_SIZE);
const_assert!(ASSET_SIZE > 0 && ASSET_SIZE <= HASH_SIZE);
const_assert!(SHARE_SIZE > 0 && SHARE_SIZE <= HASH_SIZE);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashParseError;

impl fmt::Display for HashParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid hexadecimal hash or identifier")
    }
}

impl Error for HashParseError {}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct Hash(pub [u8; HASH_SIZE]);

impl Hash {
    pub const ZERO: Self = Self([0; HASH_SIZE]);

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HashVisitor;

        impl<'de> Visitor<'de> for HashVisitor {
            type Value = Hash;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{HASH_SIZE} hash bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let bytes: [u8; HASH_SIZE] = value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))?;

                Ok(Hash(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0_u8; HASH_SIZE];

                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| DeError::invalid_length(index, &self))?;
                }

                Ok(Hash(bytes))
            }
        }

        deserializer.deserialize_bytes(HashVisitor)
    }
}

pub fn format_bytes<const N: usize>(
    prefix: &str,
    bytes: &[u8; N],
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    formatter.write_str(prefix)?;

    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }

    Ok(())
}

pub fn parse_bytes<const N: usize>(
    prefix: &str,
    value: &str,
) -> Result<[u8; N], HashParseError> {
    let encoded = value.strip_prefix(prefix).ok_or(HashParseError)?;

    if encoded.len() != N * 2 {
        return Err(HashParseError);
    }

    let encoded = encoded.as_bytes();
    let mut bytes = [0_u8; N];

    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        let high = hex_nibble(encoded[offset]).ok_or(HashParseError)?;
        let low = hex_nibble(encoded[offset + 1]).ok_or(HashParseError)?;
        *byte = (high << 4) | low;
    }

    Ok(bytes)
}

pub fn truncate_hash<const N: usize>(hash: Hash) -> [u8; N] {
    assert!(N > 0 && N <= HASH_SIZE, "identifier size must be 1..=HASH_SIZE");

    let source = hash.into_bytes();
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(&source[..N]);
    bytes
}

pub fn format(prefix: &str, hash: &Hash, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    format_bytes(prefix, hash.as_bytes(), formatter)
}

pub fn parse(prefix: &str, value: &str) -> Result<Hash, HashParseError> {
    parse_bytes::<HASH_SIZE>(prefix, value).map(Hash::from_bytes)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

macro_rules! hash_newtype {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Serialize,
            Deserialize,
            BorshSerialize,
            BorshDeserialize,
        )]
        pub struct $name(pub [u8; HASH_SIZE]);

        impl $name {
            pub const ZERO: Self = Self([0; HASH_SIZE]);

            pub const fn as_hash(self) -> Hash {
                Hash::from_bytes(self.0)
            }

            pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
                self.0
            }
        }

        impl From<Hash> for $name {
            fn from(hash: Hash) -> Self {
                Self(hash.into_bytes())
            }
        }

        impl From<$name> for Hash {
            fn from(hash: $name) -> Self {
                Hash::from_bytes(hash.0)
            }
        }

        impl PartialEq<Hash> for $name {
            fn eq(&self, other: &Hash) -> bool {
                self.0 == other.0
            }
        }

        impl PartialEq<$name> for Hash {
            fn eq(&self, other: &$name) -> bool {
                self.0 == other.0
            }
        }
    };
}

hash_newtype!(BlockHash);
hash_newtype!(TransactionHash);
hash_newtype!(MerkleHash);
hash_newtype!(StateRoot);
hash_newtype!(PreviousHash);
hash_newtype!(PoWHash);

impl From<BlockHash> for PreviousHash {
    fn from(hash: BlockHash) -> Self {
        Self(hash.0)
    }
}

impl PartialEq<BlockHash> for PreviousHash {
    fn eq(&self, other: &BlockHash) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<PreviousHash> for BlockHash {
    fn eq(&self, other: &PreviousHash) -> bool {
        self.0 == other.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashDomain {
    Transaction,
    TransactionCommit,
    SpendIntent,
    AssetIntent,
    Block,
    Header,
    ChainParams,
    ChainSpec,
    MerkleNode,
    AccountState,
    AuthorizationProof,
    StateNode,
    BlockStateCommitment,
    XPQState,
    XPARQArtifact,
    ProtocolState,
    PoWSeed,
    PoWSalt,
    Address,
    AddressChecksum,
    Asset,
    Share,
    Pool,
    PoolShare,
    PoolIntent,
    MintCapability,
    Output,
    Emission,
    Raw,
}

impl HashDomain {
    fn tag(self) -> &'static [u8] {
        match self {
            HashDomain::Transaction => b"XPARQ_HASH_TX",
            HashDomain::TransactionCommit => b"XPARQ_HASH_TX_COMMIT",
            HashDomain::SpendIntent => b"XPARQ_SPEND_INTENT",
            HashDomain::AssetIntent => b"XPARQ_ASSET_INTENT",
            HashDomain::Block => b"XPARQ_HASH_BLOCK",
            HashDomain::Header => b"XPARQ_HASH_BLOCK_HEADER",
            HashDomain::ChainParams => b"XPARQ_HASH_CHAIN_PARAMS",
            HashDomain::ChainSpec => b"XPARQ_HASH_CHAIN_SPEC",
            HashDomain::MerkleNode => b"XPARQ_HASH_MERKLE_NODE",
            HashDomain::AccountState => b"XPARQ_HASH_ACCOUNT_STATE",
            HashDomain::AuthorizationProof => b"XPARQ_HASH_AUTHORIZATION_PROOF",
            HashDomain::StateNode => b"XPARQ_HASH_STATE_NODE",
            HashDomain::BlockStateCommitment => b"XPARQ_HASH_BLOCK_STATE_COMMITMENT",
            HashDomain::XPQState => b"XPARQ_HASH_XPQ_STATE",
            HashDomain::XPARQArtifact => b"XPARQ_HASH_ARTIFACT",
            HashDomain::ProtocolState => b"XPARQ_HASH_PROTOCOL_STATE",
            HashDomain::PoWSeed => b"XPARQ_POW_SEED",
            HashDomain::PoWSalt => b"XPARQ_POW_SALT",
            HashDomain::Address => b"XPARQ_HASH_ADDRESS",
            HashDomain::AddressChecksum => b"XPARQ_HASH_ADDRESS_CHECKSUM",
            HashDomain::Asset => b"XPARQ_ASSET",
            HashDomain::Share => b"XPARQ_ASSET_SHARE",
            HashDomain::Pool => b"XPARQ_POOL",
            HashDomain::PoolShare => b"XPARQ_POOL_SHARE",
            HashDomain::PoolIntent => b"XPARQ_POOL_INTENT",
            HashDomain::MintCapability => b"XPARQ_MINT_CAPABILITY",
            HashDomain::Output => b"XPARQ_COIN_OUTPUT",
            HashDomain::Emission => b"XPARQ_COIN_EMISSION",
            HashDomain::Raw => b"XPARQ_HASH_RAW",
        }
    }
}

pub fn hash_bytes(bytes: &[u8]) -> Hash {
    domain(HashDomain::Raw, bytes)
}

pub fn domain(domain: HashDomain, bytes: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();

    hasher.update(domain.tag());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);

    let digest = hasher.finalize();

    let mut hash = [0_u8; HASH_SIZE];
    hash.copy_from_slice(&digest);

    Hash(hash)
}

pub fn domain_hash(domain: HashDomain, bytes: &[u8]) -> Hash {
    self::domain(domain, bytes)
}

pub fn hash_meets_difficulty(hash: &PoWHash, difficulty: u32) -> bool {
    let bytes = hash.as_bytes();

    let full_zero_bytes = (difficulty / 8) as usize;
    let remaining_zero_bits = (difficulty % 8) as u8;

    if full_zero_bytes > bytes.len() {
        return false;
    }

    if !bytes.iter().take(full_zero_bytes).all(|byte| *byte == 0) {
        return false;
    }

    if remaining_zero_bits == 0 {
        return true;
    }

    let Some(next_byte) = bytes.get(full_zero_bytes) else {
        return false;
    };

    let mask = 0xff << (8 - remaining_zero_bits);

    next_byte & mask == 0
}
