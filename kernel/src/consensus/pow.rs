//! XPARQ proof-of-work construction.

use crate::blockchain::Header;
use crate::blockchain::codec::block_header_bytes;
use crate::consensus::{ConsensusError, MAX_DIFFICULTY, MIN_DIFFICULTY};

use crypto::argon2::{argon2id_pow_hash, argon2id_pow_hash_with_memory};
use crypto::{
    CryptoError, Hash, HashDomain, PoWHash, PoWMemory, PreviousHash, domain, hash_meets_difficulty,
};

pub const POW_ALGORITHM: &str = "xparq-argon2id-algorithm";

// Consensus parameters. Do not change on an existing chain without a hard fork.
pub const POW_ARGON2_MEMORY_KIB: u32 = 128 * 1024;
pub const POW_ARGON2_ITERATIONS: u32 = 1;
pub const POW_ARGON2_LANES: u32 = 1;

pub fn new_pow_memory() -> PoWMemory {
    PoWMemory::new(POW_ARGON2_MEMORY_KIB)
}

pub fn pow_seed(header: &Header) -> Result<Hash, ConsensusError> {
    let bytes = block_header_bytes(header).map_err(|_| ConsensusError::PoWHashFailed)?;
    Ok(domain(HashDomain::PoWSeed, &bytes))
}

pub fn pow_salt(previous_hash: &PreviousHash) -> Hash {
    domain(HashDomain::PoWSalt, previous_hash.as_bytes())
}

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

pub fn calculate_work_with_memory(
    header: &Header,
    memory: &mut PoWMemory,
) -> Result<PoWHash, ConsensusError> {
    let seed = pow_seed(header)?;
    let salt = pow_salt(&header.previous_hash);

    argon2id_pow_hash_with_memory(
        &seed.0,
        &salt.0,
        POW_ARGON2_ITERATIONS,
        POW_ARGON2_LANES,
        memory,
    )
    .map_err(map_crypto_error)
}

pub fn verify_pow(header: &Header, expected_difficulty: u32) -> Result<(), ConsensusError> {
    validate_pow_claim(header, expected_difficulty)?;
    verify_pow_hash(calculate_work(header)?, expected_difficulty)
}

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
    if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&expected_difficulty) {
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
