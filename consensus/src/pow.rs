//! XPARQ proof-of-work construction.
//!
//! Block identity remains a cheap domain-separated SHA3 header hash. This
//! module alone owns the memory-hard work construction used by miners and
//! validators.

use crate::block::Header;
use crate::codec::block_header_bytes;
use crate::crypto::argon2::{argon2id_pow_hash, argon2id_pow_hash_with_memory};
use crate::crypto::{
    Hash, HashDomain, PoWHash, PoWMemory, PreviousHash, domain_hash, hash_meets_difficulty,
};
use crate::error::{ConsensusError, CryptoError};

pub const POW_ALGORITHM: &str = "xparq-argon2id-algorithm";
pub const POW_ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const POW_ARGON2_ITERATIONS: u32 = 1;
pub const POW_ARGON2_LANES: u32 = 1;

pub fn new_pow_memory() -> PoWMemory {
    PoWMemory::new(POW_ARGON2_MEMORY_KIB)
}

/// Derives the fixed-size Argon2id input from the complete canonical header.
/// The header includes the nonce, so miners vary only `header.nonce`.
pub fn pow_seed(header: &Header) -> Result<Hash, ConsensusError> {
    let bytes = block_header_bytes(header).map_err(|_| ConsensusError::PoWHashFailed)?;
    Ok(domain_hash(HashDomain::PoWSeed, &bytes))
}

/// Derives a deterministic salt from the parent being extended.
pub fn pow_salt(previous_hash: &PreviousHash) -> Hash {
    domain_hash(HashDomain::PoWSalt, &previous_hash.0)
}

/// Calculates the active network's 256-bit Argon2id proof-of-work hash.
pub fn calculate_work(header: &Header) -> Result<PoWHash, ConsensusError> {
    let seed = pow_seed(header)?;
    let salt = pow_salt(&header.previous_hash);
    argon2id_pow_hash(
        &seed.0,
        &salt.0,
        POW_ARGON2_MEMORY_KIB,
        POW_ARGON2_ITERATIONS,
        POW_ARGON2_LANES,
    )
    .map_err(map_crypto_error)
}

/// Calculates proof of work using caller-owned Argon2id memory.
///
/// Miners should retain the memory across nonce attempts.
pub fn calculate_work_with_memory(
    header: &Header,
    memory: &mut PoWMemory,
) -> Result<PoWHash, ConsensusError> {
    let seed = pow_seed(header)?;
    let salt = pow_salt(&header.previous_hash);
    argon2id_pow_hash_with_memory(
        &seed.0,
        &salt.0,
        POW_ARGON2_MEMORY_KIB,
        POW_ARGON2_ITERATIONS,
        POW_ARGON2_LANES,
        memory,
    )
    .map_err(map_crypto_error)
}

/// Verifies claimed difficulty and memory-hard work using the one canonical
/// construction shared by block admission, header sync, and mining.
pub fn verify_pow(header: &Header, expected_difficulty: u32) -> Result<(), ConsensusError> {
    validate_pow_claim(header, expected_difficulty)?;
    verify_pow_hash(calculate_work(header)?, expected_difficulty)
}

/// Verifies proof of work using caller-owned Argon2id memory.
///
/// Batch validators should retain one allocation for the complete batch.
pub fn verify_pow_with_memory(
    header: &Header,
    expected_difficulty: u32,
    memory: &mut PoWMemory,
) -> Result<(), ConsensusError> {
    validate_pow_claim(header, expected_difficulty)?;
    verify_pow_hash(
        calculate_work_with_memory(header, memory)?,
        expected_difficulty,
    )
}

fn validate_pow_claim(header: &Header, expected_difficulty: u32) -> Result<(), ConsensusError> {
    if !(super::MIN_DIFFICULTY..=super::MAX_DIFFICULTY).contains(&expected_difficulty) {
        return Err(ConsensusError::InvalidDifficulty);
    }
    if header.difficulty != expected_difficulty {
        return Err(ConsensusError::UnexpectedDifficulty);
    }
    Ok(())
}

fn verify_pow_hash(hash: PoWHash, expected_difficulty: u32) -> Result<(), ConsensusError> {
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
    use crate::block::Nonce;
    use crate::crypto::{HASH_SIZE, MerkleHash, StateRoot};

    fn vector_header() -> Header {
        Header {
            previous_hash: PreviousHash([0x11; HASH_SIZE]),
            merkle_root: MerkleHash([0x22; HASH_SIZE]),
            state_root: StateRoot([0x33; HASH_SIZE]),
            difficulty: 7,
            block_weight: 1_234_567,
            nonce: Nonce(0x0102_0304_0506_0708),
        }
    }

    #[test]
    fn nonce_and_parent_are_bound_to_work() {
        let header = vector_header();
        let original = calculate_work(&header).unwrap();
        let mut changed_nonce = header.clone();
        changed_nonce.nonce.0 = changed_nonce.nonce.0.wrapping_add(1);
        let mut changed_parent = header.clone();
        changed_parent.previous_hash.0[0] ^= 1;
        assert_ne!(original, calculate_work(&changed_nonce).unwrap());
        assert_ne!(original, calculate_work(&changed_parent).unwrap());
    }

    #[test]
    fn reusable_memory_produces_the_canonical_work_hash() {
        let header = vector_header();
        let expected = calculate_work(&header).unwrap();
        let mut memory = new_pow_memory();
        assert_eq!(
            calculate_work_with_memory(&header, &mut memory).unwrap(),
            expected
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
