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
    ADDRESS_SIZE, Address, AddressBytes, ML_DSA_ADDRESS_HRP, SQISIGN_ADDRESS_HRP,
    address_from_public_key, address_from_string, address_to_string, dual_address_from_public_keys,
    try_address_from_public_key, try_dual_address_from_public_keys, wallet_address_from_public_key,
};
#[cfg(feature = "sqisign-candidate")]
pub use address::{
    sqisign_address_from_string, sqisign_address_to_string, sqisign_dual_address_from_public_keys,
};
pub use agility::{
    CryptoPrimitive, CryptoPrimitiveFamily, CryptoUpgradeError, CryptoUpgradePhase,
    CryptoUpgradePlan, HashScheme, INITIAL_SIGNATURE_SCHEME, ProofOfWorkScheme, SignatureContext,
    SignatureScheme, SignatureSchemeStatus, signature_scheme_active_at_height,
    signature_scheme_active_for_consensus, signature_scheme_status,
};
pub use hash::{
    BlockHash, HASH_SIZE, Hash, HashBytes, HashDomain, MerkleHash, POW_ARGON2_ITERATIONS,
    POW_ARGON2_LANES, POW_ARGON2_MEMORY_KIB, PROOF_OF_WORK_HASH_SIZE, PreviousHash,
    ProofOfWorkHash, ProofOfWorkHashBytes, StateRoot, TransactionHash, argon2id_proof_of_work_hash,
    domain_hash, hash_bytes, hash_meets_difficulty,
};
pub use keygen::{
    AuthorizationSeed, CachedVerifyingKey, KeyPair, PUBLIC_KEY_SIZE, PublicKey, PublicKeyBytes,
    SECRET_KEY_SIZE, SIGNATURE_SIZE, SecretKey, SecretKeyBytes, Signature, SignatureBytes,
    authorization_keypair_from_password, authorization_seed_from_password, cached_verifying_key,
    derive_public_key, generate_keypair, keypair_from_seed, public_key_from_seed, sign,
    sign_from_seed, verify, verify_dual_parallel, verify_result,
};
#[cfg(feature = "sqisign-blockchain-test")]
pub use keygen::{clear_verifying_key_cache, verify_batch_parallel};
