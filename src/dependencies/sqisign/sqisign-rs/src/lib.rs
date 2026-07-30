//!
//! Pure Rust implementation of the SQIsign signature scheme (NIST PQC
//! Additional Signatures, Round 2/3 candidate).
//!
//! # Experimental internal dependency
//!
//! This crate is published only to support Paqus devnet and testnet dependency
//! resolution. SQIsign is not standardized, this implementation is not
//! production-audited by Paqus, and neither its API nor its wire format is
//! stable. It must not be used by Paqus mainnet or for production custody.
//!
//! This crate provides key generation, signing, and re-exports everything
//! from `sqisign-verify` for verification. For verify-only usage (`no_std`),
//! depend on `sqisign-verify` directly.
//!
//! Two signature schemes are available, chosen at keygen time: the dimension-2
//! formats ([`generate`]) and the **compact** 108-byte format
//! ([`generate_compact`]). Verification autodetects the format from byte length
//! via [`AnySignature`]. At Level 1, dim-2 verification is about 1.4 ms (Apple
//! M4 Pro, at parity with the C reference) and compact verification ~33 ms
//! (~20.5 ms with the `parallel` feature).
//!
//! ## Quick Start
//!
//! ```
//! use sqisign_rs::{generate, generate_compact, PublicKey, SigningKey, Verifier};
//!
//! # fn main() -> Result<(), sqisign_rs::Error> {
//! let mut rng = rand::rng();
//!
//! // Standard (dimension-2, 148 bytes at Level 1):
//! let (pk, sk): (PublicKey, SigningKey) = generate(&mut rng);
//! let sig = sk.sign(b"hello world", &mut rng)?;
//! pk.verify(b"hello world", &sig)?;
//!
//! // Compact (smallest signature, 108 bytes at Level 1):
//! let (cpk, csk) = generate_compact(&mut rng);
//! let csig = csk.sign(b"hello world", &mut rng)?;
//! cpk.verify(b"hello world", &csig)?;
//! # Ok(())
//! # }
//! ```
//!
//! The library is `no_std` (it uses `alloc` for heap, but does not require an
//! operating system). Unit tests link `std`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;
extern crate self as sqisign_verify;

pub mod compact;
pub mod ec;
pub mod formats;
pub mod fp;
pub mod hash;
pub mod hd;
pub mod id2iso;
pub mod keygen;
pub mod params;
pub mod precomp;
pub mod precomp_signing;
pub mod quaternion;
pub mod secure_alloc;
pub mod sign;
#[cfg(feature = "sqisign-rk")]
pub mod sqisign_rk;
pub mod theta;
mod transcript;
pub mod types;
pub mod verify;

pub use compact::{CompactPublicKey, CompactSignature};
pub use formats::{AnySignature, CompressedSignature, ExpandedSignature, SignatureFormat};
pub use fp::{Fp, Fp2, FpBackend};
pub use hash::hash_to_challenge;
pub use params::{Level1, Level3, Level5, SecurityLevel};
pub use precomp::LevelPrecomp;
pub use signature::{self, SignatureEncoding, Verifier};
pub use types::{PublicKey, Scalar, Signature};

/// Error type for verification and encoding failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The signature is cryptographically invalid.
    InvalidSignature,
    /// The input bytes could not be deserialized.
    MalformedInput,
    /// The input length does not match the expected encoding size.
    InvalidLength,
    /// An internal computation failed.
    InternalError,
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSignature => formatter.write_str("invalid signature"),
            Self::MalformedInput => formatter.write_str("malformed input"),
            Self::InvalidLength => formatter.write_str("invalid length"),
            Self::InternalError => formatter.write_str("internal error"),
        }
    }
}

impl From<signature::Error> for Error {
    fn from(_: signature::Error) -> Self {
        Self::InvalidSignature
    }
}

// Public API.
pub use keygen::SecretKey;
// Crate-root re-export so the `enable_secure_allocator!` macro can name it.
pub use secure_alloc::ZeroizingAllocator;

// The compact (108-byte-signature) scheme's signing-side entry points. The
// matching verification types are re-exported from this crate's internal
// verifier implementation above.
pub use sign::{generate_compact, CompactSigningKey};

use alloc::vec::Vec;
use hybrid_array::typenum::Unsigned;
use id2iso::sign_precomp::HasSigningPrecomp;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A signing key that bundles everything needed to produce signatures.
///
/// Created by [`generate`]. Holds the secret key and public key.
pub struct SigningKey<L: sqisign_verify::fp::FpBackend + LevelPrecomp = Level1> {
    sk: SecretKey<L>,
    pk: PublicKey<L>,
}

impl<L: HasSigningPrecomp + LevelPrecomp> SigningKey<L> {
    /// Sign a message.
    #[inline]
    pub fn sign(
        &self,
        msg: &[u8],
        rng: &mut (impl rand_core::Rng + rand_core::CryptoRng),
    ) -> Result<Signature<L>, Error> {
        crate::sign::sign(&self.sk, &self.pk, msg, rng)
    }

    /// The public key corresponding to this signing key.
    #[inline]
    pub fn public_key(&self) -> &PublicKey<L> {
        &self.pk
    }

    /// Encode the signing key as `secret_key_bytes || public_key_bytes`.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut sk_bytes = self.sk.to_bytes()?;
        let pk_bytes = self.pk.to_bytes();
        let mut out = Zeroizing::new(Vec::with_capacity(L::SkLen::USIZE + L::PkLen::USIZE));
        out.extend_from_slice(&sk_bytes);
        out.extend_from_slice(&pk_bytes);
        sk_bytes.as_mut_slice().zeroize();
        Ok(out)
    }

    /// Decode a signing key from `secret_key_bytes || public_key_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let expected = L::SkLen::USIZE + L::PkLen::USIZE;
        if bytes.len() != expected {
            return Err(Error::InvalidLength);
        }
        let (sk_bytes, pk_bytes) = bytes.split_at(L::SkLen::USIZE);
        let mut sk = SecretKey::<L>::from_bytes(sk_bytes)?;
        let pk = PublicKey::<L>::from_bytes(pk_bytes)?;
        sk.populate_from_pk(&pk);
        Ok(SigningKey { sk, pk })
    }
}

impl<L: sqisign_verify::fp::FpBackend + LevelPrecomp> core::fmt::Debug for SigningKey<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey([REDACTED])")
    }
}

impl<L: sqisign_verify::fp::FpBackend + LevelPrecomp> core::fmt::Display for SigningKey<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningKey([REDACTED])")
    }
}

impl<L: id2iso::sign_precomp::HasSigningPrecomp + LevelPrecomp> SigningKey<L> {
    /// Return a wrapper that prints the raw signing key bytes as hex.
    ///
    /// # Security Warning
    ///
    /// The returned type implements [`Display`](core::fmt::Display) and
    /// will output **secret key material in plaintext**. Use only for
    /// debugging in secure, ephemeral environments. Never log this
    /// output in production, persist it to files, or transmit it over
    /// untrusted channels.
    #[cfg(feature = "dangerous-secret-display")]
    #[inline]
    pub fn display_secret(&self) -> SigningKeyDisplay<'_, L> {
        SigningKeyDisplay(self)
    }
}

/// Wrapper returned by [`SigningKey::display_secret`] that prints raw
/// signing key bytes as lowercase hex.
///
/// # Security Warning
///
/// This will output secret key material in plaintext when formatted.
#[cfg(feature = "dangerous-secret-display")]
pub struct SigningKeyDisplay<'a, L: sqisign_verify::fp::FpBackend + LevelPrecomp>(
    &'a SigningKey<L>,
);

#[cfg(feature = "dangerous-secret-display")]
impl<L: id2iso::sign_precomp::HasSigningPrecomp + LevelPrecomp> core::fmt::Display
    for SigningKeyDisplay<'_, L>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0.to_bytes() {
            Ok(bytes) => {
                for &b in bytes.as_slice() {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
            Err(_) => f.write_str("<encoding error>"),
        }
    }
}

impl<L: sqisign_verify::fp::FpBackend + LevelPrecomp> Zeroize for SigningKey<L> {
    fn zeroize(&mut self) {
        self.sk.zeroize();
    }
}

impl<L: sqisign_verify::fp::FpBackend + LevelPrecomp> Drop for SigningKey<L> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<L: sqisign_verify::fp::FpBackend + LevelPrecomp> ZeroizeOnDrop for SigningKey<L> {}

/// Generate a fresh SQIsign keypair.
///
/// Returns the public key (for the verifier) and a signing key (for
/// the signer). Level 1 (128-bit security) is the default; specify
/// `generate::<Level3>` or `generate::<Level5>` for higher levels.
pub fn generate<L: HasSigningPrecomp + LevelPrecomp>(
    rng: &mut (impl rand_core::Rng + rand_core::CryptoRng),
) -> (PublicKey<L>, SigningKey<L>) {
    let precomp = L::signing_precomp();
    let (pk, sk) = keygen::keygen::protocols_keygen(rng, &precomp);
    let signing_key = SigningKey { sk, pk: pk.clone() };
    (pk, signing_key)
}
