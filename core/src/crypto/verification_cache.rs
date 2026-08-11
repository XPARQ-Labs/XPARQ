use super::{PublicKey, Signature, hash_bytes, verify_dual_parallel};
use crate::block::BlockHeight;
use crate::crypto::Hash;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Mutex, OnceLock};

const STATELESS_VERIFICATION_CACHE_CAPACITY: usize = 4_096;
const CACHE_DOMAIN: &[u8] = b"XPARQ_STATELESS_AUTH_CACHE_V1";

#[derive(Default)]
struct VerificationCache {
    entries: BTreeSet<Hash>,
    insertion_order: VecDeque<Hash>,
}

pub fn verify_dual_parallel_at_height(
    height: BlockHeight,
    owner_public_key: &PublicKey,
    auth_public_key: &PublicKey,
    message: &[u8],
    owner_signature: &Signature,
    auth_signature: &Signature,
) -> (bool, bool) {
    let key = cache_key(
        height,
        owner_public_key,
        auth_public_key,
        message,
        owner_signature,
        auth_signature,
    );
    if verification_cache()
        .lock()
        .is_ok_and(|cache| cache.entries.contains(&key))
    {
        return (true, true);
    }

    let result = verify_dual_parallel(
        owner_public_key,
        auth_public_key,
        message,
        owner_signature,
        auth_signature,
    );
    if result == (true, true)
        && let Ok(mut cache) = verification_cache().lock()
    {
        if cache.entries.insert(key) {
            cache.insertion_order.push_back(key);
        }
        while cache.entries.len() > STATELESS_VERIFICATION_CACHE_CAPACITY {
            if let Some(expired) = cache.insertion_order.pop_front() {
                cache.entries.remove(&expired);
            }
        }
    }
    result
}

fn verification_cache() -> &'static Mutex<VerificationCache> {
    static CACHE: OnceLock<Mutex<VerificationCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VerificationCache::default()))
}

fn cache_key(
    height: BlockHeight,
    owner_public_key: &PublicKey,
    auth_public_key: &PublicKey,
    message: &[u8],
    owner_signature: &Signature,
    auth_signature: &Signature,
) -> Hash {
    let mut material = Vec::with_capacity(
        CACHE_DOMAIN.len()
            + std::mem::size_of::<u64>()
            + owner_public_key.0.len()
            + auth_public_key.0.len()
            + message.len()
            + owner_signature.0.len()
            + auth_signature.0.len(),
    );
    material.extend_from_slice(CACHE_DOMAIN);
    material.extend_from_slice(&height.0.to_le_bytes());
    material.extend_from_slice(&owner_public_key.0);
    material.extend_from_slice(&auth_public_key.0);
    material.extend_from_slice(message);
    material.extend_from_slice(&owner_signature.0);
    material.extend_from_slice(&auth_signature.0);
    hash_bytes(&material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, sign};

    #[test]
    fn cache_is_scoped_to_height_and_complete_authorization() {
        let owner = generate_keypair();
        let auth = generate_keypair();
        let message = b"cache-test";
        let owner_signature = sign(&owner.secret_key, message);
        let auth_signature = sign(&auth.secret_key, message);
        assert_eq!(
            verify_dual_parallel_at_height(
                crate::block::Height(7),
                &owner.public_key,
                &auth.public_key,
                message,
                &owner_signature,
                &auth_signature,
            ),
            (true, true)
        );
        let mut invalid = auth_signature;
        invalid.0[0] ^= 1;
        assert_ne!(
            verify_dual_parallel_at_height(
                crate::block::Height(7),
                &owner.public_key,
                &auth.public_key,
                message,
                &owner_signature,
                &invalid,
            ),
            (true, true)
        );
    }
}
