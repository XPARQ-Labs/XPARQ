use borsh::{BorshDeserialize, BorshSerialize};
use sha3::{Digest, Sha3_256};

pub const HASH_SIZE: usize = 32;
const HASH_PREFIX: &[u8] = b"XPARQ_SIDECHAIN_HASH_V1";

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Hash256(pub [u8; HASH_SIZE]);

impl Hash256 {
    pub const ZERO: Self = Self([0; HASH_SIZE]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashDomain {
    Address,
    BlockHeader,
    State,
    Transaction,
    NativeTokenProgram,
    NativeTokenProgramState,
    NativeTokenTransaction,
    UserToken,
    UserTokenState,
    ValidatorSet,
    Vote,
    WxpqDeposit,
    WxpqState,
    WxpqWithdrawal,
}

impl HashDomain {
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::Address => b"XPARQ_SIDECHAIN_ADDRESS_V1",
            Self::BlockHeader => b"XPARQ_SIDECHAIN_BLOCK_HEADER_V1",
            Self::State => b"XPARQ_SIDECHAIN_STATE_V1",
            Self::Transaction => b"XPARQ_SIDECHAIN_TRANSACTION_V1",
            Self::NativeTokenProgram => b"XPARQ_SIDECHAIN_NATIVE_TOKEN_PROGRAM_V1",
            Self::NativeTokenProgramState => b"XPARQ_SIDECHAIN_NATIVE_TOKEN_PROGRAM_STATE_V1",
            Self::NativeTokenTransaction => b"XPARQ_SIDECHAIN_NATIVE_TOKEN_TRANSACTION_V1",
            Self::UserToken => b"XPARQ_SIDECHAIN_USER_TOKEN_V1",
            Self::UserTokenState => b"XPARQ_SIDECHAIN_USER_TOKEN_STATE_V1",
            Self::ValidatorSet => b"XPARQ_SIDECHAIN_VALIDATOR_SET_V1",
            Self::Vote => b"XPARQ_SIDECHAIN_VOTE_V1",
            Self::WxpqDeposit => b"XPARQ_SIDECHAIN_WXPQ_DEPOSIT_V1",
            Self::WxpqState => b"XPARQ_SIDECHAIN_WXPQ_STATE_V1",
            Self::WxpqWithdrawal => b"XPARQ_SIDECHAIN_WXPQ_WITHDRAWAL_V1",
        }
    }
}

/// Hash arbitrary bytes with the same SHA3-256 algorithm used by XPARQ L1.
pub fn hash_bytes(bytes: &[u8]) -> Hash256 {
    let digest = Sha3_256::digest(bytes);
    Hash256(digest.into())
}

/// Hash a consensus payload under an explicit sidechain domain.
///
/// Length prefixes prevent ambiguity between the protocol prefix, domain tag,
/// and payload. All integer prefixes are canonical little-endian values.
pub fn domain_hash(domain: HashDomain, payload: &[u8]) -> Hash256 {
    let tag = domain.tag();
    let mut hasher = Sha3_256::new();
    hasher.update(HASH_PREFIX);
    hasher.update((tag.len() as u16).to_le_bytes());
    hasher.update(tag);
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    Hash256(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separation_changes_the_hash() {
        let payload = b"same payload";
        assert_ne!(
            domain_hash(HashDomain::Transaction, payload),
            domain_hash(HashDomain::Vote, payload)
        );
    }

    #[test]
    fn hashing_is_deterministic_and_fixed_width() {
        let first = hash_bytes(b"xparq-sidechain");
        let second = hash_bytes(b"xparq-sidechain");
        assert_eq!(first, second);
        assert_eq!(first.0.len(), HASH_SIZE);
    }

    #[test]
    fn raw_hash_matches_nist_sha3_256_empty_vector() {
        assert_eq!(
            hash_bytes(b"").0,
            [
                0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
                0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
                0x80, 0xf8, 0x43, 0x4a,
            ]
        );
    }
}
