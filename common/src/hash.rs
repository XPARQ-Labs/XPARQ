use sha3::{Digest, Sha3_256};

pub const HASH_SIZE: usize = 32;

/// Canonical domain-separated SHA3-256 hashing.
pub fn domain_hash(context: &[u8], fields: &[&[u8]]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha3_256::new();

    hasher.update((context.len() as u64).to_le_bytes());
    hasher.update(context);

    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }

    hasher.finalize().into()
}
