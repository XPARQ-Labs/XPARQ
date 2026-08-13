use crate::error::CryptoError;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use static_assertions::const_assert_eq;
use std::fmt;

pub const HASH_SIZE: usize = 32;
pub const POW_HASH_SIZE: usize = 32;
const_assert_eq!(HASH_SIZE, 32);
const_assert_eq!(POW_HASH_SIZE, 32);

pub type HashBytes = [u8; HASH_SIZE];
pub type PoWHashBytes = [u8; POW_HASH_SIZE];

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct Hash(pub HashBytes);

impl Hash {
    pub const ZERO: Self = Self([0; HASH_SIZE]);
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
                let bytes: HashBytes = value
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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct PoWHash(pub PoWHashBytes);

impl Serialize for PoWHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for PoWHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PoWHashVisitor;

        impl<'de> Visitor<'de> for PoWHashVisitor {
            type Value = PoWHash;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{POW_HASH_SIZE} proof-of-work hash bytes")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let bytes: PoWHashBytes = value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))?;
                Ok(PoWHash(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0_u8; POW_HASH_SIZE];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| DeError::invalid_length(index, &self))?;
                }
                Ok(PoWHash(bytes))
            }
        }

        deserializer.deserialize_bytes(PoWHashVisitor)
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
        pub struct $name(pub HashBytes);

        impl $name {
            pub const ZERO: Self = Self([0; HASH_SIZE]);

            pub fn as_hash(self) -> Hash {
                Hash(self.0)
            }
        }

        impl From<Hash> for $name {
            fn from(hash: Hash) -> Self {
                Self(hash.0)
            }
        }

        impl From<$name> for Hash {
            fn from(hash: $name) -> Self {
                Hash(hash.0)
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
    Block,
    Header,
    ChainParams,
    ChainSpec,
    Emission,
    MerkleNode,
    AccountState,
    AuthorizationProof,
    StateNode,
    BlockStateCommitment,
    XpqCoin,
    XpqState,
    QCashCoin,
    QCashRedeemKeyCommitment,
    QCashRedeemAuthorization,
    QCashRedeemTransaction,
    QCashFile,
    QCashState,
    XPARQArtifact,
    ProtocolEvent,
    ProtocolState,
    PoWSeed,
    PoWSalt,
    Raw,
}

impl HashDomain {
    fn tag(self) -> &'static [u8] {
        match self {
            HashDomain::Transaction => b"XPARQ_HASH_TX",
            HashDomain::Block => b"XPARQ_HASH_BLOCK_V1",
            HashDomain::Header => b"XPARQ_HASH_BLOCK_HEADER",
            HashDomain::ChainParams => b"XPARQ_HASH_CHAIN_PARAMS_V1",
            HashDomain::ChainSpec => b"XPARQ_HASH_CHAIN_SPEC_V1",
            HashDomain::Emission => b"XPARQ_HASH_Emission",
            HashDomain::MerkleNode => b"XPARQ_HASH_MERKLE_NODE",
            HashDomain::AccountState => b"XPARQ_HASH_ACCOUNT_STATE",
            HashDomain::AuthorizationProof => b"XPARQ_HASH_AUTHORIZATION_PROOF_V1",
            HashDomain::StateNode => b"XPARQ_HASH_STATE_NODE",
            HashDomain::BlockStateCommitment => b"XPARQ_HASH_BLOCK_STATE_COMMITMENT_V1",
            HashDomain::XpqCoin => b"XPARQ_HASH_COIN_V1",
            HashDomain::XpqState => b"XPARQ_HASH_XPQ_STATE_V1",
            HashDomain::QCashCoin => b"XPARQ_HASH_QCASH_COIN_V1",
            HashDomain::QCashRedeemKeyCommitment => b"XPARQ_HASH_QCASH_REDEEM_KEY_COMMITMENT_V1",
            HashDomain::QCashRedeemAuthorization => b"XPARQ_HASH_QCASH_REDEEM_AUTH_V1",
            HashDomain::QCashRedeemTransaction => b"XPARQ_HASH_QCASH_REDEEM_TX_V1",
            HashDomain::QCashFile => b"XPARQ_HASH_QCASH_FILE_V1",
            HashDomain::QCashState => b"XPARQ_HASH_QCASH_STATE_V1",
            HashDomain::XPARQArtifact => b"XPARQ_HASH_ARTIFACT_V1",
            HashDomain::ProtocolEvent => b"XPARQ_HASH_PROTOCOL_EVENT_V1",
            HashDomain::ProtocolState => b"XPARQ_HASH_PROTOCOL_STATE_V1",
            HashDomain::PoWSeed => b"XPARQ_POW_SEED_V1",
            HashDomain::PoWSalt => b"XPARQ_POW_SALT_V1",
            HashDomain::Raw => b"XPARQ_HASH_RAW",
        }
    }
}

pub fn hash_bytes(bytes: &[u8]) -> Hash {
    domain_hash(HashDomain::Raw, bytes)
}

pub fn domain_hash(domain: HashDomain, bytes: &[u8]) -> Hash {
    let mut hasher = Sha3_256::new();
    hasher.update(domain.tag());
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hash = [0_u8; HASH_SIZE];
    hash.copy_from_slice(&digest);
    Hash(hash)
}

/// Argon2id proof-of-work memory in KiB. This is a consensus parameter.
pub const POW_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id proof-of-work iteration count. This is a consensus parameter.
pub const POW_ARGON2_ITERATIONS: u32 = 1;
/// Argon2id proof-of-work parallelism. This is a consensus parameter.
pub const POW_ARGON2_LANES: u32 = 2;

/// Evaluates the fixed XPARQ Argon2id work function over an already
/// domain-separated seed and salt.
pub(crate) fn argon2id_pow_hash(
    seed: &[u8; HASH_SIZE],
    salt: &[u8; HASH_SIZE],
) -> Result<PoWHash, CryptoError> {
    let params = argon2::Params::new(
        POW_ARGON2_MEMORY_KIB,
        POW_ARGON2_ITERATIONS,
        POW_ARGON2_LANES,
        Some(POW_HASH_SIZE),
    )
    .map_err(|_| CryptoError::InvalidPoWParameters)?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = [0_u8; POW_HASH_SIZE];
    argon2
        .hash_password_into(seed, salt, &mut output)
        .map_err(|_| CryptoError::PoWHashFailed)?;
    Ok(PoWHash(output))
}

pub fn hash_meets_difficulty(hash: &PoWHash, difficulty: u32) -> bool {
    let full_zero_bytes = (difficulty / 8) as usize;
    let remaining_zero_bits = (difficulty % 8) as u8;

    if full_zero_bytes > hash.0.len() {
        return false;
    }

    if !hash.0.iter().take(full_zero_bytes).all(|byte| *byte == 0) {
        return false;
    }

    if remaining_zero_bits == 0 {
        return true;
    }

    let Some(next_byte) = hash.0.get(full_zero_bytes) else {
        return false;
    };
    let mask = 0xff << (8 - remaining_zero_bits);
    next_byte & mask == 0
}
