//! SQIsign Level 5 replacement for the core signature API.
//!
//! This module is selected only by `sqisign-blockchain-test`. Its wire format
//! is deliberately incompatible with the default ML-DSA-44 chain.

use crate::error::CryptoError;
use crate::genesis::CURRENT_CHAIN_PARAMS;
use borsh::{BorshDeserialize, BorshSerialize};
use chacha20::ChaCha12Rng;
use rand_10::SeedableRng;
use rand_10::rand_core::UnwrapErr;
use rand_10::rngs::SysRng;
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sqisign_rs::{
    Level5, PublicKey as SqisignPublicKey, Signature as SqisignSignature,
    SigningKey as SqisignSigningKey, Verifier, generate,
};
use static_assertions::const_assert_eq;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type XparqSigningKey = SqisignSigningKey<Level5>;
type XparqVerifyingKey = SqisignPublicKey<Level5>;
type XparqSignature = SqisignSignature<Level5>;

pub const PUBLIC_KEY_SIZE: usize = 129;
pub const SECRET_KEY_SIZE: usize = 705;
pub const SIGNATURE_SIZE: usize = 292;
const_assert_eq!(PUBLIC_KEY_SIZE, 129);
const_assert_eq!(SECRET_KEY_SIZE, 705);
const_assert_eq!(SIGNATURE_SIZE, 292);
const VERIFYING_KEY_CACHE_CAPACITY: usize = 4_096;
const VERIFICATION_QUEUE_CAPACITY: usize = 256;
static VERIFICATION_QUEUE_DEPTH: AtomicU64 = AtomicU64::new(0);
static VERIFICATION_QUEUE_QUEUED: AtomicU64 = AtomicU64::new(0);
static VERIFICATION_QUEUE_FALLBACK: AtomicU64 = AtomicU64::new(0);
static VERIFICATION_QUEUE_WAIT_MICROS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerificationQueueSnapshot {
    pub depth: u64,
    pub capacity: usize,
    pub queued_total: u64,
    pub fallback_total: u64,
    pub wait_micros_total: u64,
}

pub fn verification_queue_snapshot() -> VerificationQueueSnapshot {
    VerificationQueueSnapshot {
        depth: VERIFICATION_QUEUE_DEPTH.load(Ordering::Relaxed),
        capacity: VERIFICATION_QUEUE_CAPACITY,
        queued_total: VERIFICATION_QUEUE_QUEUED.load(Ordering::Relaxed),
        fallback_total: VERIFICATION_QUEUE_FALLBACK.load(Ordering::Relaxed),
        wait_micros_total: VERIFICATION_QUEUE_WAIT_MICROS.load(Ordering::Relaxed),
    }
}

/// Deterministic, non-consensus accounting for SQIsign verification jobs.
/// Public-key decodes are charged at their worst-case count because cache
/// state is process-local and must never influence admission decisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SqisignVerificationWork {
    pub signature_checks: u64,
    pub public_key_decodes: u64,
    pub message_bytes: u64,
}

impl SqisignVerificationWork {
    pub fn for_jobs(jobs: &[(PublicKey, Vec<u8>, Signature)]) -> Self {
        Self {
            signature_checks: jobs.len() as u64,
            public_key_decodes: jobs.len() as u64,
            message_bytes: jobs.iter().fold(0_u64, |total, (_, message, _)| {
                total.saturating_add(message.len() as u64)
            }),
        }
    }
}

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
    inner: Option<Arc<XparqVerifyingKey>>,
}

impl fmt::Debug for CachedVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CachedVerifyingKey(SQIsign-Level5)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub fn generate_keypair() -> KeyPair {
    let (public_key, signing_key) = generate::<Level5>(&mut UnwrapErr(SysRng));
    keypair_from_parts(public_key, signing_key)
}

pub fn keypair_from_seed(seed: &[u8; 32]) -> KeyPair {
    // ChaCha12Rng matches rand 0.10 StdRng's stream while additionally
    // zeroizing its key, state, and buffered output when dropped.
    let mut rng = ChaCha12Rng::from_seed(*seed);
    let (public_key, signing_key) = generate::<Level5>(&mut rng);
    keypair_from_parts(public_key, signing_key)
}

fn keypair_from_parts(public_key: XparqVerifyingKey, signing_key: XparqSigningKey) -> KeyPair {
    let public_key = PublicKey(
        public_key
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("SQIsign Level 5 public-key length"),
    );
    let encoded_secret = signing_key
        .to_bytes()
        .expect("SQIsign Level 5 signing-key encoding");
    let secret_key = SecretKey(
        encoded_secret
            .as_slice()
            .try_into()
            .expect("SQIsign Level 5 signing-key length"),
    );
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
    Ok(keypair_from_seed(&seed))
}

pub fn authorization_seed_from_password(
    password: &[u8],
    primary_public_key: &PublicKey,
) -> Result<AuthorizationSeed, CryptoError> {
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|_| CryptoError::InvalidKeyDerivationParameters)?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut salt_material =
        Vec::with_capacity(b"XPARQ_SQISIGN_LEVEL5_AUTHORIZATION_V1".len() + 4 + PUBLIC_KEY_SIZE);
    salt_material.extend_from_slice(b"XPARQ_SQISIGN_LEVEL5_AUTHORIZATION_V1");
    salt_material.extend_from_slice(&CURRENT_CHAIN_PARAMS.chain_id.to_le_bytes());
    salt_material.extend_from_slice(&primary_public_key.0);
    let salt = crate::crypto::hash::hash_bytes(&salt_material);
    let mut seed = [0_u8; 32];
    argon2
        .hash_password_into(password, &salt.0, &mut seed)
        .map_err(|_| CryptoError::InvalidKeyDerivationParameters)?;
    Ok(AuthorizationSeed::new(seed))
}

pub fn public_key_from_seed(seed: &[u8; 32]) -> PublicKey {
    keypair_from_seed(seed).public_key
}

pub fn sign_from_seed(seed: &[u8; 32], message: &[u8]) -> Signature {
    let keypair = keypair_from_seed(seed);
    sign(&keypair.secret_key, message)
}

pub fn derive_public_key(secret_key: &SecretKey) -> PublicKey {
    let signing_key = XparqSigningKey::from_bytes(&secret_key.0)
        .expect("valid SQIsign Level 5 secret key required");
    PublicKey(
        signing_key
            .public_key()
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("SQIsign Level 5 public-key length"),
    )
}

pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Signature {
    let signing_key = XparqSigningKey::from_bytes(&secret_key.0)
        .expect("valid SQIsign Level 5 secret key required");
    let signature = signing_key
        .sign(message, &mut UnwrapErr(SysRng))
        .expect("SQIsign Level 5 signing failed");
    Signature(
        signature
            .to_bytes()
            .as_slice()
            .try_into()
            .expect("SQIsign Level 5 signature length"),
    )
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    verify_result(public_key, message, signature).is_ok()
}

pub fn verify_dual_parallel(
    owner_public_key: &PublicKey,
    auth_public_key: &PublicKey,
    message: &[u8],
    owner_signature: &Signature,
    auth_signature: &Signature,
) -> (bool, bool) {
    let owner_key = cached_verifying_key(owner_public_key);
    let auth_key = cached_verifying_key(auth_public_key);
    let Some(workers) = verification_workers() else {
        return (
            owner_key.verify(message, owner_signature).is_ok(),
            auth_key.verify(message, auth_signature).is_ok(),
        );
    };
    let (result_sender, result_receiver) = mpsc::sync_channel(1);
    let job = VerificationJob {
        verifying_key: auth_key.clone(),
        message: message.to_vec(),
        signature: *auth_signature,
        result: result_sender,
        queued_at: Instant::now(),
    };
    VERIFICATION_QUEUE_DEPTH.fetch_add(1, Ordering::Relaxed);
    match workers.try_send(job) {
        Ok(()) => {
            VERIFICATION_QUEUE_QUEUED.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {
            VERIFICATION_QUEUE_DEPTH.fetch_sub(1, Ordering::Relaxed);
            VERIFICATION_QUEUE_FALLBACK.fetch_add(1, Ordering::Relaxed);
            return (
                owner_key.verify(message, owner_signature).is_ok(),
                auth_key.verify(message, auth_signature).is_ok(),
            );
        }
    }
    let owner_valid = owner_key.verify(message, owner_signature).is_ok();
    let auth_valid = result_receiver
        .recv()
        .unwrap_or_else(|_| auth_key.verify(message, auth_signature).is_ok());
    (owner_valid, auth_valid)
}

/// Verifies independent SQIsign jobs concurrently using the persistent pool.
///
/// The returned booleans preserve input order. This is the primitive used for
/// block-level preverification experiments; state-dependent transaction rules
/// must still execute in consensus order.
pub fn verify_batch_parallel(jobs: &[(PublicKey, Vec<u8>, Signature)]) -> Vec<bool> {
    verify_batch_parallel_accounted(jobs).0
}

/// Verifies independent jobs and returns their deterministic worst-case work.
pub fn verify_batch_parallel_accounted(
    jobs: &[(PublicKey, Vec<u8>, Signature)],
) -> (Vec<bool>, SqisignVerificationWork) {
    let work = SqisignVerificationWork::for_jobs(jobs);
    let Some(workers) = verification_workers() else {
        return (
            jobs.iter()
                .map(|(key, message, signature)| verify(key, message, signature))
                .collect(),
            work,
        );
    };

    let mut pending = Vec::with_capacity(jobs.len());
    for (key, message, signature) in jobs {
        let cached = cached_verifying_key(key);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let job = VerificationJob {
            verifying_key: cached.clone(),
            message: message.clone(),
            signature: *signature,
            result: result_sender,
            queued_at: Instant::now(),
        };
        VERIFICATION_QUEUE_DEPTH.fetch_add(1, Ordering::Relaxed);
        match workers.try_send(job) {
            Ok(()) => {
                VERIFICATION_QUEUE_QUEUED.fetch_add(1, Ordering::Relaxed);
                pending.push((
                    Some(result_receiver),
                    cached,
                    message.as_slice(),
                    *signature,
                ));
            }
            Err(_) => {
                VERIFICATION_QUEUE_DEPTH.fetch_sub(1, Ordering::Relaxed);
                VERIFICATION_QUEUE_FALLBACK.fetch_add(1, Ordering::Relaxed);
                pending.push((None, cached, message.as_slice(), *signature));
            }
        }
    }

    (
        pending
            .into_iter()
            .map(|(receiver, cached, message, signature)| {
                receiver
                    .and_then(|receiver| receiver.recv().ok())
                    .unwrap_or_else(|| cached.verify(message, &signature).is_ok())
            })
            .collect(),
        work,
    )
}

pub fn cached_verifying_key(public_key: &PublicKey) -> CachedVerifyingKey {
    if let Some(inner) = verifying_key_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(public_key)
    {
        return CachedVerifyingKey { inner: Some(inner) };
    }

    let Ok(decoded) = XparqVerifyingKey::from_bytes(&public_key.0) else {
        return CachedVerifyingKey { inner: None };
    };
    let decoded = Arc::new(decoded);
    let inner = verifying_key_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(*public_key, decoded);
    CachedVerifyingKey { inner: Some(inner) }
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
        let public_key = self.inner.as_ref().ok_or(CryptoError::InvalidPublicKey)?;
        let signature = XparqSignature::from_bytes(&signature.0)
            .map_err(|_| CryptoError::InvalidSignatureEncoding)?;
        public_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

struct VerifyingKeyCache {
    entries: HashMap<PublicKey, Arc<XparqVerifyingKey>>,
    insertion_order: VecDeque<PublicKey>,
}

impl VerifyingKeyCache {
    fn new() -> Self {
        Self {
            entries: HashMap::with_capacity(VERIFYING_KEY_CACHE_CAPACITY),
            insertion_order: VecDeque::with_capacity(VERIFYING_KEY_CACHE_CAPACITY),
        }
    }

    fn get(&self, key: &PublicKey) -> Option<Arc<XparqVerifyingKey>> {
        self.entries.get(key).cloned()
    }

    fn insert(
        &mut self,
        key: PublicKey,
        decoded: Arc<XparqVerifyingKey>,
    ) -> Arc<XparqVerifyingKey> {
        if let Some(existing) = self.entries.get(&key) {
            return Arc::clone(existing);
        }
        while self.entries.len() >= VERIFYING_KEY_CACHE_CAPACITY {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        self.insertion_order.push_back(key);
        self.entries.insert(key, Arc::clone(&decoded));
        decoded
    }

    #[cfg(any(test, feature = "sqisign-blockchain-test"))]
    fn clear(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
    }
}

fn verifying_key_cache() -> &'static Mutex<VerifyingKeyCache> {
    static CACHE: OnceLock<Mutex<VerifyingKeyCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VerifyingKeyCache::new()))
}

/// Clears the experimental SQIsign verifier cache.
///
/// This is intended for controlled benchmarks; normal node operation should
/// keep the bounded cache warm.
#[doc(hidden)]
pub fn clear_verifying_key_cache() {
    verifying_key_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

struct VerificationJob {
    verifying_key: CachedVerifyingKey,
    message: Vec<u8>,
    signature: Signature,
    result: mpsc::SyncSender<bool>,
    queued_at: Instant,
}

fn verification_workers() -> Option<&'static mpsc::SyncSender<VerificationJob>> {
    static WORKERS: OnceLock<Option<mpsc::SyncSender<VerificationJob>>> = OnceLock::new();
    WORKERS
        .get_or_init(|| {
            let worker_count = std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
                .saturating_sub(1);
            if worker_count == 0 {
                return None;
            }
            let (sender, receiver) =
                mpsc::sync_channel::<VerificationJob>(VERIFICATION_QUEUE_CAPACITY);
            let receiver = Arc::new(Mutex::new(receiver));
            for index in 0..worker_count {
                let receiver = Arc::clone(&receiver);
                if std::thread::Builder::new()
                    .name(format!("Xparq-sqisign-l5-{index}"))
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
                            VERIFICATION_QUEUE_DEPTH.fetch_sub(1, Ordering::Relaxed);
                            VERIFICATION_QUEUE_WAIT_MICROS.fetch_add(
                                job.queued_at
                                    .elapsed()
                                    .as_micros()
                                    .min(u128::from(u64::MAX))
                                    as u64,
                                Ordering::Relaxed,
                            );
                            let valid = job
                                .verifying_key
                                .verify(&job.message, &job.signature)
                                .is_ok();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_seed_and_sign_verify_work() {
        let key_a = keypair_from_seed(&[7; 32]);
        let key_b = keypair_from_seed(&[7; 32]);
        assert_eq!(key_a, key_b);
        let signature = sign(&key_a.secret_key, b"SQIsign blockchain test");
        assert!(verify(
            &key_a.public_key,
            b"SQIsign blockchain test",
            &signature
        ));
        assert!(!verify(&key_a.public_key, b"modified", &signature));
    }

    #[test]
    fn dual_sqisign_level5_verification_works() {
        let owner = keypair_from_seed(&[3; 32]);
        let auth = keypair_from_seed(&[4; 32]);
        let message = b"dual SQIsign Level 5 authorization";
        let owner_signature = sign(&owner.secret_key, message);
        let auth_signature = sign(&auth.secret_key, message);
        assert_eq!(
            verify_dual_parallel(
                &owner.public_key,
                &auth.public_key,
                message,
                &owner_signature,
                &auth_signature
            ),
            (true, true)
        );

        let jobs = vec![
            (owner.public_key, message.to_vec(), owner_signature),
            (auth.public_key, message.to_vec(), auth_signature),
            (owner.public_key, b"modified".to_vec(), owner_signature),
        ];
        assert_eq!(verify_batch_parallel(&jobs), vec![true, true, false]);
    }

    #[test]
    fn batch_work_is_deterministic_and_cache_independent() {
        let keypair = keypair_from_seed(&[29; 32]);
        let messages = [b"one".as_slice(), b"longer-message".as_slice()];
        let jobs = messages
            .iter()
            .map(|message| {
                (
                    keypair.public_key,
                    message.to_vec(),
                    sign(&keypair.secret_key, message),
                )
            })
            .collect::<Vec<_>>();

        clear_verifying_key_cache();
        let (cold_results, cold_work) = verify_batch_parallel_accounted(&jobs);
        let (warm_results, warm_work) = verify_batch_parallel_accounted(&jobs);
        assert_eq!(cold_results, vec![true, true]);
        assert_eq!(warm_results, cold_results);
        assert_eq!(warm_work, cold_work);
        assert_eq!(cold_work.signature_checks, 2);
        assert_eq!(cold_work.public_key_decodes, 2);
        assert_eq!(cold_work.message_bytes, 3 + 14);
    }

    #[test]
    fn invalid_signature_is_not_accepted_through_cache() {
        clear_verifying_key_cache();
        let invalid = PublicKey([0; PUBLIC_KEY_SIZE]);
        let signature = Signature([0; SIGNATURE_SIZE]);
        assert!(
            cached_verifying_key(&invalid)
                .verify(b"message", &signature)
                .is_err()
        );
    }

    #[test]
    fn deterministic_rng_matches_previous_stream_and_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<ChaCha12Rng>();

        let seed = [0x5a; 32];
        let mut previous = rand_10::rngs::StdRng::from_seed(seed);
        let mut hardened = ChaCha12Rng::from_seed(seed);
        let mut previous_bytes = [0_u8; 256];
        let mut hardened_bytes = [0_u8; 256];
        use rand_10::Rng;
        previous.fill_bytes(&mut previous_bytes);
        hardened.fill_bytes(&mut hardened_bytes);
        assert_eq!(previous_bytes, hardened_bytes);
        previous_bytes.zeroize();
        hardened_bytes.zeroize();
    }
}
