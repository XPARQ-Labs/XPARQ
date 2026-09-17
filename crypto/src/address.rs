use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{HASH_SIZE, HashDomain, PublicKey, error::CryptoError, hash};

pub const ADDRESS_SIZE: usize = 28;
pub const ADDRESS_CHECKSUM_SIZE: usize = 4;

const ADDRESS_PAYLOAD_SIZE: usize = ADDRESS_SIZE + ADDRESS_CHECKSUM_SIZE;

pub const ADDRESS_ENCODED_SIZE: usize = 43;

pub const ADDRESS_STRING_LEN: usize = ADDRESS_ENCODED_SIZE;

const CHARACTER: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const TOTAL_CHARACTER: u16 = 62;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Address(pub [u8; ADDRESS_SIZE]);

impl Address {
    pub const ZERO: Self = Self([0; ADDRESS_SIZE]);

    pub const fn from_bytes(bytes: [u8; ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ADDRESS_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; ADDRESS_SIZE] {
        self.0
    }
}

pub fn address_from_public_key(public_key: &PublicKey) -> Address {
    let mut material = Vec::with_capacity(1 + public_key.bytes.len());

    material.push(public_key.account as u8);
    material.extend_from_slice(&public_key.bytes);

    address_from_key_material(&material)
}

fn address_from_key_material(key_material: &[u8]) -> Address {
    let digest = hash::domain(HashDomain::Address, key_material);

    let mut address = [0_u8; ADDRESS_SIZE];

    address.copy_from_slice(&digest.as_bytes()[HASH_SIZE - ADDRESS_SIZE..]);

    Address(address)
}

pub fn address_to_string(address: &Address) -> String {
    let checksum = address_checksum(address);

    let mut payload = [0_u8; ADDRESS_PAYLOAD_SIZE];

    payload[..ADDRESS_SIZE].copy_from_slice(address.as_bytes());
    payload[ADDRESS_SIZE..].copy_from_slice(&checksum);

    let encoded = xparq_encode(&payload);

    let mut output = String::with_capacity(ADDRESS_STRING_LEN);

    output.push_str(&encoded);

    output
}

pub fn address_from_string(value: &str) -> Result<Address, CryptoError> {
    if value.len() != ADDRESS_STRING_LEN {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let payload = xparq_decode(value)?;

    let mut address_bytes = [0_u8; ADDRESS_SIZE];
    address_bytes.copy_from_slice(&payload[..ADDRESS_SIZE]);

    let address = Address::from_bytes(address_bytes);

    let mut checksum = [0_u8; ADDRESS_CHECKSUM_SIZE];
    checksum.copy_from_slice(&payload[ADDRESS_SIZE..]);

    if checksum != address_checksum(&address) {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    if value != address_to_string(&address) {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    Ok(address)
}

fn address_checksum(address: &Address) -> [u8; ADDRESS_CHECKSUM_SIZE] {
    let digest = hash::domain(HashDomain::AddressChecksum, address.as_bytes());

    let mut checksum = [0_u8; ADDRESS_CHECKSUM_SIZE];

    checksum.copy_from_slice(&digest.as_bytes()[..ADDRESS_CHECKSUM_SIZE]);

    checksum
}

fn xparq_encode(payload: &[u8; ADDRESS_PAYLOAD_SIZE]) -> String {
    let mut number = *payload;

    let mut encoded = [b'0'; ADDRESS_ENCODED_SIZE];

    for position in (0..ADDRESS_ENCODED_SIZE).rev() {
        let mut remainder = 0_u16;

        for byte in &mut number {
            let value = (remainder << 8) | (*byte as u16);

            *byte = (value / TOTAL_CHARACTER) as u8;
            remainder = value % TOTAL_CHARACTER;
        }

        encoded[position] = CHARACTER[remainder as usize];
    }

    debug_assert!(number.iter().all(|byte| *byte == 0));
    String::from_utf8(encoded.to_vec()).expect("XPARQ alphabet must be valid ASCII")
}

fn xparq_decode(encoded: &str) -> Result<[u8; ADDRESS_PAYLOAD_SIZE], CryptoError> {
    if encoded.len() != ADDRESS_ENCODED_SIZE {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let mut payload = [0_u8; ADDRESS_PAYLOAD_SIZE];

    for character in encoded.bytes() {
        let digit = xparq_digit(character).ok_or(CryptoError::InvalidAddressEncoding)?;

        let mut carry = digit as u16;

        // payload = payload * 62 + digit
        for byte in payload.iter_mut().rev() {
            let value = (*byte as u16) * TOTAL_CHARACTER + carry;

            *byte = value as u8;
            carry = value >> 8;
        }

        if carry != 0 {
            return Err(CryptoError::InvalidAddressEncoding);
        }
    }

    Ok(payload)
}

#[inline]
fn xparq_digit(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),

        b'A'..=b'Z' => Some(10 + character - b'A'),

        b'a'..=b'z' => Some(36 + character - b'a'),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip() {
        let address = Address([7; ADDRESS_SIZE]);

        let encoded = address_to_string(&address);

        assert_eq!(encoded.len(), ADDRESS_STRING_LEN,);

        assert_eq!(address_from_string(&encoded), Ok(address),);
    }

    #[test]
    fn zero_address_roundtrip() {
        let address = Address::ZERO;

        let encoded = address_to_string(&address);

        assert_eq!(encoded.len(), ADDRESS_STRING_LEN,);

        assert_eq!(address_from_string(&encoded), Ok(address),);
    }

    #[test]
    fn base62_preserves_leading_zeroes() {
        let mut payload = [0_u8; ADDRESS_PAYLOAD_SIZE];

        payload[ADDRESS_PAYLOAD_SIZE - 1] = 1;

        let encoded = xparq_encode(&payload);

        assert_eq!(encoded.len(), ADDRESS_ENCODED_SIZE,);

        assert_eq!(xparq_decode(&encoded).unwrap(), payload,);
    }

    #[test]
    fn maximum_payload_roundtrip() {
        let payload = [0xff_u8; ADDRESS_PAYLOAD_SIZE];

        let encoded = xparq_encode(&payload);

        assert_eq!(encoded.len(), ADDRESS_ENCODED_SIZE,);

        assert_eq!(xparq_decode(&encoded).unwrap(), payload,);
    }

    #[test]
    fn incorrect_checksum_is_rejected() {
        let address = Address([7; ADDRESS_SIZE]);

        let encoded = address_to_string(&address);

        let mut payload = xparq_decode(&encoded).unwrap();

        payload[ADDRESS_SIZE] ^= 0x01;

        let corrupted = xparq_encode(&payload);

        assert_eq!(
            address_from_string(&corrupted),
            Err(CryptoError::InvalidAddressEncoding),
        );
    }
}
