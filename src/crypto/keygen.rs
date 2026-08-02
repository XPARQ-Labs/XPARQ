use crate::error::CryptoError;
use crate::genesis::CURRENT_CHAIN_PARAMS;
use borsh::{BorshDeserialize, BorshSerialize};
use ml_dsa::{
    ExpandedSigningKey, Generate, Keypair, MlDsa44, Signature as MlDsaSignature, SignatureEncoding,
    Signer, SigningKey, Verifier, VerifyingKey,
};
use static_assertions::const_assert_eq;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

type PaqusSigningKey = SigningKey<MlDsa44>;
type PaqusExpandedSigningKey = ExpandedSigningKey<MlDsa44>;
type PaqusVerifyingKey = VerifyingKey<MlDsa44>;
type PaqusSignature = MlDsaSignature<MlDsa44>;

pub const PUBLIC_KEY_SIZE: usize = 1_312;
pub const SECRET_KEY_SIZE: usize = 2_560;
pub const SIGNATURE_SIZE: usize = 2_420;
const_assert_eq!(PUBLIC_KEY_SIZE, 1_312);
const_assert_eq!(SECRET_KEY_SIZE, 2_560);
const_assert_eq!(SIGNATURE_SIZE, 2_420);

pub type PublicKeyBytes = [u8; PUBLIC_KEY_SIZE];
pub type SecretKeyBytes = [u8; SECRET_KEY_SIZE];
pub type SignatureBytes = [u8; SIGNATURE_SIZE];
pub type AuthorizationSeed = Zeroizing<[u8; 32]>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct PublicKey(pub PublicKeyBytes);

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Zeroize,
    ZeroizeOnDrop,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SecretKey(pub SecretKeyBytes);

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct Signature(pub SignatureBytes);

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bytes::<PUBLIC_KEY_SIZE, D>(deserializer).map(PublicKey)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bytes::<SIGNATURE_SIZE, D>(deserializer).map(Signature)
    }
}

fn deserialize_bytes<'de, const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct BytesVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{N} bytes")
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: DeError,
        {
            value
                .try_into()
                .map_err(|_| E::invalid_length(value.len(), &self))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut bytes = [0_u8; N];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = seq
                    .next_element()?
                    .ok_or_else(|| DeError::invalid_length(index, &self))?;
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_bytes(BytesVisitor::<N>)
}

#[derive(Clone)]
pub struct CachedVerifyingKey {
    inner: PaqusVerifyingKey,
}

impl fmt::Debug for CachedVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CachedVerifyingKey(..)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub fn generate_keypair() -> KeyPair {
    let signing_key = PaqusSigningKey::generate();
    keypair_from_signing_key(signing_key)
}

pub fn keypair_from_seed(seed: &[u8; 32]) -> KeyPair {
    let signing_key = PaqusSigningKey::from_seed(&(*seed).into());
    keypair_from_signing_key(signing_key)
}

fn keypair_from_signing_key(signing_key: PaqusSigningKey) -> KeyPair {
    let public_key = PublicKey(signing_key.verifying_key().encode().into());

    #[allow(deprecated)]
    let secret_key = SecretKey(signing_key.expanded_key().to_expanded().into());

    KeyPair {
        public_key,
        secret_key,
    }
}

pub fn authorization_keypair_from_password(
    password: &[u8],
    primary_public_key: &PublicKey,
) -> Result<KeyPair, CryptoError> {
    let seed = authorization_seed_from_password(password, primary_public_key)?;
    let mut encoded_seed = (*seed).into();
    let signing_key = PaqusSigningKey::from_seed(&encoded_seed);
    encoded_seed.zeroize();
    let public_key = PublicKey(signing_key.verifying_key().encode().into());

    #[allow(deprecated)]
    let secret_key = SecretKey(signing_key.expanded_key().to_expanded().into());

    Ok(KeyPair {
        public_key,
        secret_key,
    })
}

pub fn authorization_seed_from_password(
    password: &[u8],
    primary_public_key: &PublicKey,
) -> Result<AuthorizationSeed, CryptoError> {
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|_| CryptoError::InvalidKeyDerivationParameters)?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut wallet_salt_material =
        Vec::with_capacity(b"PAQUS_AUTHORIZATION_V1".len() + size_of::<u32>() + PUBLIC_KEY_SIZE);
    wallet_salt_material.extend_from_slice(b"PAQUS_AUTHORIZATION_V1");
    wallet_salt_material.extend_from_slice(&CURRENT_CHAIN_PARAMS.chain_id.to_le_bytes());
    wallet_salt_material.extend_from_slice(&primary_public_key.0);
    let wallet_salt = crate::crypto::hash::hash_bytes(&wallet_salt_material);
    let mut seed = [0_u8; 32];
    argon2
        .hash_password_into(password, &wallet_salt.0, &mut seed)
        .map_err(|_| CryptoError::InvalidKeyDerivationParameters)?;
    Ok(AuthorizationSeed::new(seed))
}

/// Deterministically derives an ML-DSA-44 public key from a compact 32-byte seed.
/// This is used by bearer QCash files so the large expanded secret key never
/// needs to be stored in the file.
pub fn public_key_from_seed(seed: &[u8; 32]) -> PublicKey {
    let signing_key = PaqusSigningKey::from_seed(&(*seed).into());
    PublicKey(signing_key.verifying_key().encode().into())
}

/// Signs with the ML-DSA-44 key deterministically derived from a 32-byte seed.
pub fn sign_from_seed(seed: &[u8; 32], message: &[u8]) -> Signature {
    let signing_key = PaqusSigningKey::from_seed(&(*seed).into());
    let signature: PaqusSignature = signing_key.sign(message);
    Signature(signature.to_bytes().into())
}

pub fn derive_public_key(secret_key: &SecretKey) -> PublicKey {
    let expanded_key = expanded_signing_key(secret_key);
    PublicKey(expanded_key.verifying_key().encode().into())
}

pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Signature {
    let expanded_key = expanded_signing_key(secret_key);
    let signature: PaqusSignature = expanded_key.sign(message);
    Signature(signature.to_bytes().into())
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    verify_result(public_key, message, signature).is_ok()
}

struct VerificationJob {
    public_key: PublicKey,
    message: Vec<u8>,
    signature: Signature,
    result: mpsc::SyncSender<bool>,
}

fn verification_workers() -> Option<&'static mpsc::Sender<VerificationJob>> {
    static WORKERS: OnceLock<Option<mpsc::Sender<VerificationJob>>> = OnceLock::new();
    WORKERS
        .get_or_init(|| {
            let worker_count = std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
                .saturating_sub(1);
            if worker_count == 0 {
                return None;
            }
            let (sender, receiver) = mpsc::channel::<VerificationJob>();
            let receiver = Arc::new(Mutex::new(receiver));
            for index in 0..worker_count {
                let receiver = Arc::clone(&receiver);
                if std::thread::Builder::new()
                    .name(format!("paqus-ml-dsa-{index}"))
                    .spawn(move || {
                        loop {
                            let job = {
                                let Ok(receiver) = receiver.lock() else {
                                    return;
                                };
                                let Ok(job) = receiver.recv() else {
                                    return;
                                };
                                job
                            };
                            let valid = verify(&job.public_key, &job.message, &job.signature);
                            let _ = job.result.send(valid);
                        }
                    })
                    .is_err()
                {
                    return None;
                }
            }
            Some(sender)
        })
        .as_ref()
}

/// Verifies the owner and authorization signatures concurrently when at least
/// two logical CPUs are available. The persistent worker pool avoids creating
/// operating-system threads for individual transactions.
pub fn verify_dual_parallel(
    owner_public_key: &PublicKey,
    auth_public_key: &PublicKey,
    message: &[u8],
    owner_signature: &Signature,
    auth_signature: &Signature,
) -> (bool, bool) {
    let Some(workers) = verification_workers() else {
        return (
            verify(owner_public_key, message, owner_signature),
            verify(auth_public_key, message, auth_signature),
        );
    };
    let (result_sender, result_receiver) = mpsc::sync_channel(1);
    let job = VerificationJob {
        public_key: *auth_public_key,
        message: message.to_vec(),
        signature: *auth_signature,
        result: result_sender,
    };
    if workers.send(job).is_err() {
        return (
            verify(owner_public_key, message, owner_signature),
            verify(auth_public_key, message, auth_signature),
        );
    }
    let owner_valid = verify(owner_public_key, message, owner_signature);
    let auth_valid = result_receiver
        .recv()
        .unwrap_or_else(|_| verify(auth_public_key, message, auth_signature));
    (owner_valid, auth_valid)
}

pub fn cached_verifying_key(public_key: &PublicKey) -> CachedVerifyingKey {
    CachedVerifyingKey {
        inner: verifying_key(public_key),
    }
}

pub fn verify_result(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    cached_verifying_key(public_key).verify(message, signature)
}

impl CachedVerifyingKey {
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let Some(signature) = PaqusSignature::decode(&signature.0.into()) else {
            return Err(CryptoError::InvalidSignatureEncoding);
        };

        self.inner
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

fn expanded_signing_key(secret_key: &SecretKey) -> PaqusExpandedSigningKey {
    #[allow(deprecated)]
    PaqusExpandedSigningKey::from_expanded(&secret_key.0.into())
}

fn verifying_key(public_key: &PublicKey) -> PaqusVerifyingKey {
    PaqusVerifyingKey::decode(&public_key.0.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_key_is_deterministic_and_bound_to_primary_public_key() {
        let password = b"same authorization password";
        let primary_a = keypair_from_seed(&[1; 32]).public_key;
        let primary_b = keypair_from_seed(&[2; 32]).public_key;

        let key_a = authorization_keypair_from_password(password, &primary_a).unwrap();
        let key_a_again = authorization_keypair_from_password(password, &primary_a).unwrap();
        let key_b = authorization_keypair_from_password(password, &primary_b).unwrap();

        assert_eq!(key_a.public_key, key_a_again.public_key);
        assert_ne!(key_a.public_key, key_b.public_key);
    }

    #[test]
    fn parallel_dual_verification_matches_individual_verification() {
        let owner = keypair_from_seed(&[3; 32]);
        let auth = keypair_from_seed(&[4; 32]);
        let message = b"parallel dual ML-DSA verification";
        let owner_signature = sign(&owner.secret_key, message);
        let auth_signature = sign(&auth.secret_key, message);

        assert_eq!(
            verify_dual_parallel(
                &owner.public_key,
                &auth.public_key,
                message,
                &owner_signature,
                &auth_signature,
            ),
            (true, true)
        );
        assert_eq!(
            verify_dual_parallel(
                &owner.public_key,
                &auth.public_key,
                b"modified",
                &owner_signature,
                &auth_signature,
            ),
            (false, false)
        );
    }
}
