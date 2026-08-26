use crate::error::CryptoError;
use borsh::{BorshDeserialize, BorshSerialize};
use ml_dsa::{
    ExpandedSigningKey, Generate, Keypair, MlDsa44, Signature as MlDsaSignature, SignatureEncoding,
    Signer, SigningKey, Verifier, VerifyingKey,
};
use static_assertions::const_assert_eq;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

type XPARQSigningKey = SigningKey<MlDsa44>;
type XPARQExpandedSigningKey = ExpandedSigningKey<MlDsa44>;
type XPARQVerifyingKey = VerifyingKey<MlDsa44>;
type XPARQSignature = MlDsaSignature<MlDsa44>;

pub const PUBLIC_KEY_SIZE: usize = 1_312;
pub const SECRET_KEY_SIZE: usize = 2_560;
pub const SIGNATURE_SIZE: usize = 2_420;
const_assert_eq!(PUBLIC_KEY_SIZE, 1_312);
const_assert_eq!(SECRET_KEY_SIZE, 2_560);
const_assert_eq!(SIGNATURE_SIZE, 2_420);

pub type PublicKeyBytes = [u8; PUBLIC_KEY_SIZE];
pub type SecretKeyBytes = [u8; SECRET_KEY_SIZE];
pub type SignatureBytes = [u8; SIGNATURE_SIZE];

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
    inner: XPARQVerifyingKey,
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
    let signing_key = XPARQSigningKey::generate();
    keypair_from_signing_key(signing_key)
}

pub fn keypair_from_seed(seed: &[u8; 32]) -> KeyPair {
    let signing_key = XPARQSigningKey::from_seed(&(*seed).into());
    keypair_from_signing_key(signing_key)
}

fn keypair_from_signing_key(signing_key: XPARQSigningKey) -> KeyPair {
    let public_key = PublicKey(signing_key.verifying_key().encode().into());

    #[allow(deprecated)]
    let secret_key = SecretKey(signing_key.expanded_key().to_expanded().into());

    KeyPair {
        public_key,
        secret_key,
    }
}

/// Deterministically derives an ML-DSA-44 public key from a compact 32-byte seed.
/// This is used by bearer QCash files so the large expanded secret key never
/// needs to be stored in the file.
pub fn public_key_from_seed(seed: &[u8; 32]) -> PublicKey {
    let signing_key = XPARQSigningKey::from_seed(&(*seed).into());
    PublicKey(signing_key.verifying_key().encode().into())
}

/// Signs with the ML-DSA-44 key deterministically derived from a 32-byte seed.
pub fn sign_from_seed(seed: &[u8; 32], message: &[u8]) -> Signature {
    let signing_key = XPARQSigningKey::from_seed(&(*seed).into());
    let signature: XPARQSignature = signing_key.sign(message);
    Signature(signature.to_bytes().into())
}

pub fn derive_public_key(secret_key: &SecretKey) -> PublicKey {
    let expanded_key = expanded_signing_key(secret_key);
    PublicKey(expanded_key.verifying_key().encode().into())
}

pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Signature {
    let expanded_key = expanded_signing_key(secret_key);
    let signature: XPARQSignature = expanded_key.sign(message);
    Signature(signature.to_bytes().into())
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    verify_result(public_key, message, signature).is_ok()
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
        let Some(signature) = XPARQSignature::decode(&signature.0.into()) else {
            return Err(CryptoError::InvalidSignatureEncoding);
        };

        self.inner
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

fn expanded_signing_key(secret_key: &SecretKey) -> XPARQExpandedSigningKey {
    #[allow(deprecated)]
    XPARQExpandedSigningKey::from_expanded(&secret_key.0.into())
}

fn verifying_key(public_key: &PublicKey) -> XPARQVerifyingKey {
    XPARQVerifyingKey::decode(&public_key.0.into())
}
