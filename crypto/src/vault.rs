use std::{error::Error, fmt};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{HashDomain, KemSharedSecret, domain};

pub const VAULT_OPENING_SIZE: usize = 32;
pub const VAULT_ENVELOPE_TAG_SIZE: usize = 32;
pub const VAULT_ENVELOPE_PAYLOAD_SIZE: usize = VAULT_OPENING_SIZE + VAULT_ENVELOPE_TAG_SIZE;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct VaultOpening([u8; VAULT_OPENING_SIZE]);

impl VaultOpening {
    pub const fn from_bytes(bytes: [u8; VAULT_OPENING_SIZE]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; VAULT_OPENING_SIZE] {
        &self.0
    }
}

impl fmt::Debug for VaultOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultOpening([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultEnvelopeError {
    InvalidLength,
    AuthenticationFailed,
}

impl fmt::Display for VaultEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => formatter.write_str("vault envelope payload length is invalid"),
            Self::AuthenticationFailed => {
                formatter.write_str("vault envelope authentication failed")
            }
        }
    }
}

impl Error for VaultEnvelopeError {}

pub fn seal_vault_opening(
    shared: &KemSharedSecret,
    context: &[u8],
    opening: &VaultOpening,
) -> Vec<u8> {
    let key = derive_key(shared, context);
    let stream = stream_block(&key, context);
    let mut ciphertext = [0_u8; VAULT_OPENING_SIZE];
    for index in 0..VAULT_OPENING_SIZE {
        ciphertext[index] = opening.0[index] ^ stream[index];
    }
    let tag = envelope_tag(&key, context, &ciphertext);
    let mut payload = Vec::with_capacity(VAULT_ENVELOPE_PAYLOAD_SIZE);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&tag);
    payload
}

pub fn open_vault_opening(
    shared: &KemSharedSecret,
    context: &[u8],
    payload: &[u8],
) -> Result<VaultOpening, VaultEnvelopeError> {
    if payload.len() != VAULT_ENVELOPE_PAYLOAD_SIZE {
        return Err(VaultEnvelopeError::InvalidLength);
    }
    let (ciphertext, supplied_tag) = payload.split_at(VAULT_OPENING_SIZE);
    let key = derive_key(shared, context);
    let expected_tag = envelope_tag(&key, context, ciphertext);
    let mismatch = supplied_tag
        .iter()
        .zip(expected_tag.iter())
        .fold(0_u8, |acc, (left, right)| acc | (left ^ right));
    if mismatch != 0 {
        return Err(VaultEnvelopeError::AuthenticationFailed);
    }
    let stream = stream_block(&key, context);
    let mut opening = [0_u8; VAULT_OPENING_SIZE];
    for index in 0..VAULT_OPENING_SIZE {
        opening[index] = ciphertext[index] ^ stream[index];
    }
    Ok(VaultOpening(opening))
}

fn derive_key(shared: &KemSharedSecret, context: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut material = Zeroizing::new(Vec::with_capacity(32 + context.len()));
    material.extend_from_slice(shared.as_bytes());
    material.extend_from_slice(context);
    Zeroizing::new(domain(HashDomain::VaultEnvelopeKey, &material).into_bytes())
}

fn stream_block(key: &[u8; 32], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut material = Zeroizing::new(Vec::with_capacity(32 + context.len()));
    material.extend_from_slice(key);
    material.extend_from_slice(context);
    Zeroizing::new(domain(HashDomain::VaultEnvelopeStream, &material).into_bytes())
}

fn envelope_tag(key: &[u8; 32], context: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut material = Zeroizing::new(Vec::with_capacity(32 + context.len() + ciphertext.len()));
    material.extend_from_slice(key);
    material.extend_from_slice(context);
    material.extend_from_slice(ciphertext);
    domain(HashDomain::VaultEnvelopeTag, &material).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_and_authentication() {
        let shared = KemSharedSecret::from_bytes([7; 32]);
        let opening = VaultOpening::from_bytes([9; 32]);
        let mut payload = seal_vault_opening(&shared, b"context", &opening);
        assert_eq!(
            open_vault_opening(&shared, b"context", &payload)
                .unwrap()
                .as_bytes(),
            opening.as_bytes()
        );
        payload[0] ^= 1;
        assert_eq!(
            open_vault_opening(&shared, b"context", &payload),
            Err(VaultEnvelopeError::AuthenticationFailed)
        );
    }
}
