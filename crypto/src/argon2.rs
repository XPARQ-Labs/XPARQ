use crate::{CryptoError, HASH_SIZE, POW_HASH_SIZE, PoWHash};

/// Reusable Argon2 working memory supplied by higher-level protocols.
pub struct PoWMemory {
    blocks: Vec<::argon2::Block>,
}

impl PoWMemory {
    pub fn new(memory_kib: u32) -> Self {
        Self {
            blocks: vec![::argon2::Block::default(); memory_kib as usize],
        }
    }
}

pub fn argon2id_pow_hash(
    seed: &[u8; HASH_SIZE],
    salt: &[u8; HASH_SIZE],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Result<PoWHash, CryptoError> {
    let params = ::argon2::Params::new(memory_kib, iterations, lanes, Some(POW_HASH_SIZE))
        .map_err(|_| CryptoError::InvalidPoWParameters)?;
    let argon2 = ::argon2::Argon2::new(
        ::argon2::Algorithm::Argon2id,
        ::argon2::Version::V0x13,
        params,
    );
    let mut output = [0_u8; POW_HASH_SIZE];
    argon2
        .hash_password_into(seed, salt, &mut output)
        .map_err(|_| CryptoError::PoWHashFailed)?;
    Ok(PoWHash(output))
}

pub fn argon2id_pow_hash_with_memory(
    seed: &[u8; HASH_SIZE],
    salt: &[u8; HASH_SIZE],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    memory: &mut PoWMemory,
) -> Result<PoWHash, CryptoError> {
    let params = ::argon2::Params::new(memory_kib, iterations, lanes, Some(POW_HASH_SIZE))
        .map_err(|_| CryptoError::InvalidPoWParameters)?;
    let argon2 = ::argon2::Argon2::new(
        ::argon2::Algorithm::Argon2id,
        ::argon2::Version::V0x13,
        params,
    );
    let mut output = [0_u8; POW_HASH_SIZE];
    argon2
        .hash_password_into_with_memory(seed, salt, &mut output, &mut memory.blocks)
        .map_err(|_| CryptoError::PoWHashFailed)?;
    Ok(PoWHash(output))
}
