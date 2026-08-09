//! A deterministic SHAKE256-seeded RNG, so the public `RandSK` / `VerKey`
//! operations need no caller-supplied RNG while the internal ideal-to-isogeny
//! and prime-norm-reduction steps (which sample) still get randomness.
//!
//! Seeding from `(domain ‖ A(E_pk) ‖ rr)` makes `RandSK` deterministic in
//! `(sk, pk, rr)`; the same inputs always yield the same derived key; and
//! keeps the module `no_std`-friendly (no OS RNG, no `std_rng`).

use crate::transcript::{ExtendableOutput, Shake256, Update, XofReader};
use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};

/// An `RngCore` backed by an unbounded SHAKE256 XOF stream.
pub(crate) struct ShakeRng<R: XofReader> {
    reader: R,
}

/// Seed a `ShakeRng` from a domain separator and context bytes.
pub(crate) fn seed_rng(domain: &[u8], context: &[&[u8]]) -> ShakeRng<impl XofReader> {
    let mut hasher = Shake256::default();
    hasher.update(domain);
    for part in context {
        hasher.update(part);
    }
    ShakeRng {
        reader: hasher.finalize_xof(),
    }
}

impl<R: XofReader> TryRng for ShakeRng<R> {
    type Error = Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.reader.read(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.reader.read(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.reader.read(dest);
        Ok(())
    }
}

impl<R: XofReader> TryCryptoRng for ShakeRng<R> {}
