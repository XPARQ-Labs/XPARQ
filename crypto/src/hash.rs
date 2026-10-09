use borsh::{BorshDeserialize, BorshSerialize};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use static_assertions::const_assert_eq;
use std::{error::Error, fmt, str::FromStr};

pub const HASH_SIZE: usize = 32;
pub const POW_HASH_SIZE: usize = HASH_SIZE;
const_assert_eq!(HASH_SIZE, 32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashParseError;

impl fmt::Display for HashParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("hash has invalid hexadecimal length or encoding")
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

impl fmt::Display for Hash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        format("", self, formatter)
    }
}

impl FromStr for Hash {
    type Err = HashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        parse("", value)
    }
}

pub fn format(prefix: &str, hash: &Hash, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(prefix)?;

    for byte in hash.as_bytes() {
        write!(formatter, "{byte:02x}")?;
    }

    Ok(())
}

pub fn parse(prefix: &str, value: &str) -> Result<Hash, HashParseError> {
    let encoded = value.strip_prefix(prefix).ok_or(HashParseError)?;

    if encoded.len() != HASH_SIZE * 2 {
        return Err(HashParseError);
    }

    let encoded = encoded.as_bytes();
    let mut bytes = [0_u8; HASH_SIZE];

    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        let high = hex_nibble(encoded[offset]).ok_or(HashParseError)?;
        let low = hex_nibble(encoded[offset + 1]).ok_or(HashParseError)?;
        *byte = (high << 4) | low;
    }

    Ok(Hash::from_bytes(bytes))
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
    Operation,
    CoinTransition,
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
    ProgramAccount,
    Asset,
    Share,
    Output,
    Emission,
    Raw,
}

impl HashDomain {
    fn tag(self) -> &'static [u8] {
        match self {
            HashDomain::Transaction => b"XPARQ_HASH_TX",
            HashDomain::TransactionCommit => b"XPARQ_HASH_TX_COMMIT",
            HashDomain::Operation => b"XPARQ_HASH_OPERATION",
            HashDomain::CoinTransition => b"XPARQ_COIN_TRANSITION",
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
            HashDomain::ProgramAccount => b"XPARQ_HASH_PROGRAM_ACCOUNT",
            HashDomain::Asset => b"XPARQ_ASSET",
            HashDomain::Share => b"XPARQ_ASSET_SHARE",
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

/// Hash canonical serialization with the historical domain/length framing.
/// The declared length is checked against the actual stream before returning a hash.
pub fn domain_serialized<T: BorshSerialize>(
    domain: HashDomain,
    encoded_len: u64,
    value: &T,
) -> Result<Hash, crate::CodecError> {
    use std::io::{BufWriter, Write};
    struct HashWriter {
        hasher: Sha3_256,
        remaining: u64,
    }
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let len = u64::try_from(bytes.len()).map_err(std::io::Error::other)?;
            self.remaining = self
                .remaining
                .checked_sub(len)
                .ok_or_else(|| std::io::Error::other("canonical length exceeded"))?;
            self.hasher.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter {
        hasher: Sha3_256::new(),
        remaining: encoded_len,
    };
    writer.hasher.update(domain.tag());
    writer.hasher.update(encoded_len.to_le_bytes());
    {
        let mut buffer = BufWriter::with_capacity(64 * 1024, &mut writer);
        value
            .serialize(&mut buffer)
            .map_err(|_| crate::CodecError::EncodeFailed)?;
        buffer
            .flush()
            .map_err(|_| crate::CodecError::EncodeFailed)?;
    }
    if writer.remaining != 0 {
        return Err(crate::CodecError::EncodeFailed);
    }
    let mut hash = [0; HASH_SIZE];
    hash.copy_from_slice(&writer.hasher.finalize());
    Ok(Hash(hash))
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::{CodecError, canonical_bytes, canonical_length};
    #[test]
    fn streaming_matches_original_and_rejects_wrong_lengths() {
        for len in [0, 1, 31, 65535, 65536, 65537, 1_048_576] {
            let value = (17u64, vec![9u8; len], vec![vec![4u8; 23]; 7]);
            let bytes = canonical_bytes(&value).unwrap();
            let count = canonical_length(&value).unwrap();
            assert_eq!(count, bytes.len() as u64);
            for tag in [
                HashDomain::ProtocolState,
                HashDomain::Raw,
                HashDomain::Asset,
            ] {
                assert_eq!(
                    domain_serialized(tag, count, &value).unwrap(),
                    domain(tag, &bytes)
                );
                assert_eq!(
                    domain_serialized(tag, count + 1, &value),
                    Err(CodecError::EncodeFailed)
                );
                assert_eq!(
                    domain_serialized(tag, count - 1, &value),
                    Err(CodecError::EncodeFailed)
                );
            }
        }
    }
    #[test]
    fn serialization_failure_is_not_a_hash() {
        struct Failing;
        impl BorshSerialize for Failing {
            fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                writer.write_all(&[1, 2, 3])?;
                Err(std::io::Error::other("failure"))
            }
        }
        assert_eq!(canonical_length(&Failing), Err(CodecError::EncodeFailed));
        assert_eq!(
            domain_serialized(HashDomain::Raw, 3, &Failing),
            Err(CodecError::EncodeFailed)
        );
        assert_eq!(
            crate::canonical_fixed_map_length(1, u64::MAX),
            Err(CodecError::EncodeFailed)
        );
    }
}
