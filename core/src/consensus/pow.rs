//! XPARQ proof-of-work construction.
//!
//! Block identity remains a cheap domain-separated SHA3 header hash. This
//! module alone owns the memory-hard work construction used by miners and
//! validators.

use crate::block::Header;
use crate::codec::block_header_bytes;
use crate::crypto::hash::argon2id_pow_hash;
use crate::crypto::{
    HASH_SIZE, Hash, HashDomain, PoWHash, PreviousHash, domain_hash, hash_meets_difficulty,
};
use crate::error::{ConsensusError, CryptoError};
use crate::genesis::CURRENT_CHAIN_PARAMS;

pub const POW_ALGORITHM: &str = "xparq-argon2id-v1";

/// Derives the fixed-size Argon2id input from the complete canonical header.
/// The header includes the nonce, so miners vary only `header.nonce`.
pub fn pow_seed(header: &Header) -> Result<Hash, ConsensusError> {
    let bytes = block_header_bytes(header).map_err(|_| ConsensusError::PoWHashFailed)?;
    Ok(domain_hash(HashDomain::PoWSeed, &bytes))
}

/// Derives a deterministic salt that binds work to one network and parent.
pub fn pow_salt(chain_id: u32, previous_hash: &PreviousHash) -> Hash {
    let mut context = [0_u8; size_of::<u32>() + HASH_SIZE];
    context[..size_of::<u32>()].copy_from_slice(&chain_id.to_le_bytes());
    context[size_of::<u32>()..].copy_from_slice(&previous_hash.0);
    domain_hash(HashDomain::PoWSalt, &context)
}

/// Calculates the active network's 256-bit Argon2id proof-of-work hash.
pub fn calculate_work(header: &Header) -> Result<PoWHash, ConsensusError> {
    calculate_work_for_chain(header, CURRENT_CHAIN_PARAMS.chain_id)
}

fn calculate_work_for_chain(header: &Header, chain_id: u32) -> Result<PoWHash, ConsensusError> {
    let seed = pow_seed(header)?;
    let salt = pow_salt(chain_id, &header.previous_hash);
    argon2id_pow_hash(&seed.0, &salt.0).map_err(map_crypto_error)
}

/// Verifies claimed difficulty and memory-hard work using the one canonical
/// construction shared by block admission, header sync, and mining.
pub fn verify_pow(header: &Header, expected_difficulty: u32) -> Result<(), ConsensusError> {
    if !(super::MIN_DIFFICULTY..=super::MAX_DIFFICULTY).contains(&expected_difficulty) {
        return Err(ConsensusError::InvalidDifficulty);
    }
    if header.difficulty != expected_difficulty {
        return Err(ConsensusError::UnexpectedDifficulty);
    }
    let hash = calculate_work(header)?;
    if hash_meets_difficulty(&hash, expected_difficulty) {
        Ok(())
    } else {
        Err(ConsensusError::InsufficientPoW)
    }
}

fn map_crypto_error(error: CryptoError) -> ConsensusError {
    match error {
        CryptoError::InvalidPoWParameters => ConsensusError::InvalidPoWParameters,
        _ => ConsensusError::PoWHashFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BLOCK_VERSION, Nonce};
    use crate::crypto::{MerkleHash, StateRoot};
    use crate::genesis::{XPARQ_CHAIN, XPARQ_DEVNET_CHAIN, XPARQ_TESTNET_CHAIN};

    fn vector_header() -> Header {
        Header {
            version: BLOCK_VERSION,
            previous_hash: PreviousHash([0x11; HASH_SIZE]),
            merkle_root: MerkleHash([0x22; HASH_SIZE]),
            state_root: StateRoot([0x33; HASH_SIZE]),
            difficulty: 7,
            block_weight: 1_234_567,
            nonce: Nonce(0x0102_0304_0506_0708),
        }
    }

    #[test]
    fn pow_vectors_are_network_separated() {
        let header = vector_header();
        let mainnet = calculate_work_for_chain(&header, XPARQ_CHAIN.chain_id).unwrap();
        let testnet = calculate_work_for_chain(&header, XPARQ_TESTNET_CHAIN.chain_id).unwrap();
        let devnet = calculate_work_for_chain(&header, XPARQ_DEVNET_CHAIN.chain_id).unwrap();
        assert_eq!(
            mainnet.0,
            [
                184, 3, 93, 115, 225, 9, 251, 250, 15, 244, 130, 216, 96, 200, 142, 104, 173, 77,
                235, 242, 219, 6, 207, 211, 231, 130, 104, 7, 158, 35, 76, 197,
            ]
        );
        assert_eq!(
            testnet.0,
            [
                118, 19, 193, 252, 92, 86, 134, 17, 238, 128, 39, 126, 100, 199, 241, 192, 223,
                176, 52, 185, 168, 125, 18, 213, 87, 46, 113, 177, 158, 227, 128, 76,
            ]
        );
        assert_eq!(
            devnet.0,
            [
                131, 252, 144, 211, 101, 64, 87, 221, 238, 199, 41, 74, 0, 196, 125, 158, 204, 116,
                21, 33, 152, 178, 146, 58, 112, 42, 84, 213, 194, 118, 255, 233,
            ]
        );
    }

    #[test]
    fn nonce_and_parent_are_bound_to_work() {
        let header = vector_header();
        let original = calculate_work_for_chain(&header, XPARQ_CHAIN.chain_id).unwrap();
        let mut changed_nonce = header.clone();
        changed_nonce.nonce.0 = changed_nonce.nonce.0.wrapping_add(1);
        let mut changed_parent = header.clone();
        changed_parent.previous_hash.0[0] ^= 1;
        assert_ne!(
            original,
            calculate_work_for_chain(&changed_nonce, XPARQ_CHAIN.chain_id).unwrap()
        );
        assert_ne!(
            original,
            calculate_work_for_chain(&changed_parent, XPARQ_CHAIN.chain_id).unwrap()
        );
    }

    #[test]
    fn difficulty_cannot_exceed_the_pow_output_width() {
        let mut header = vector_header();
        header.difficulty = super::super::MAX_DIFFICULTY + 1;
        assert_eq!(
            verify_pow(&header, header.difficulty),
            Err(ConsensusError::InvalidDifficulty)
        );
    }
}
