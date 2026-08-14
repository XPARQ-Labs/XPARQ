pub mod address;
pub mod agility;
pub mod hash;
#[cfg(not(feature = "sqisign-blockchain-test"))]
pub mod keygen;
#[cfg(feature = "sqisign-blockchain-test")]
#[path = "keygen_sqisign.rs"]
pub mod keygen;
#[cfg(feature = "sqisign-candidate")]
pub mod sqisign_candidate;

pub use crate::error::CryptoError;
pub use address::{
    ADDRESS_HRP, ADDRESS_SIZE, Address, AddressBytes, address_from_public_key, address_from_string,
    address_to_string, try_address_from_public_key, wallet_address_from_public_key,
};
pub use agility::{
    CryptoPrimitive, CryptoPrimitiveFamily, CryptoUpgradeError, CryptoUpgradePhase,
    CryptoUpgradePlan, HashScheme, INITIAL_SIGNATURE_SCHEME, PoWScheme, SignatureContext,
    SignatureScheme, SignatureSchemeStatus, signature_scheme_active_at_height,
    signature_scheme_active_for_consensus, signature_scheme_status,
};
pub use hash::{
    BlockHash, HASH_SIZE, Hash, HashBytes, HashDomain, MerkleHash, POW_ARGON2_ITERATIONS,
    POW_ARGON2_LANES, POW_ARGON2_MEMORY_KIB, POW_HASH_SIZE, PoWHash, PoWHashBytes, PoWMemory,
    PreviousHash, StateRoot, TransactionHash, domain_hash, hash_bytes, hash_meets_difficulty,
};
pub use keygen::{
    CachedVerifyingKey, KeyPair, PUBLIC_KEY_SIZE, PublicKey, PublicKeyBytes, SECRET_KEY_SIZE,
    SIGNATURE_SIZE, SecretKey, SecretKeyBytes, Signature, SignatureBytes,
    VerificationQueueSnapshot, cached_verifying_key, derive_public_key, generate_keypair,
    keypair_from_seed, public_key_from_seed, sign, sign_from_seed, verification_queue_snapshot,
    verify, verify_result,
};
#[cfg(feature = "sqisign-blockchain-test")]
pub use keygen::{
    SqisignVerificationWork, clear_verifying_key_cache, verify_batch_parallel,
    verify_batch_parallel_accounted,
};
