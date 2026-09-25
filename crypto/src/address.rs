use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{HASH_SIZE, HashDomain, PublicKey, error::CryptoError, hash};

pub const ADDRESS_SIZE: usize = 21;
pub const ADDRESS_CHECKSUM_SIZE: usize = 4;

const ADDRESS_PAYLOAD_SIZE: usize = ADDRESS_SIZE + ADDRESS_CHECKSUM_SIZE;

pub const ADDRESS_ENCODED_SIZE: usize = 35;

pub const ADDRESS_STRING_LEN: usize = ADDRESS_ENCODED_SIZE;

// Human-friendly Base56 alphabet.
// Excludes visually ambiguous characters: O, o, I, i, L, l.
const CHARACTER: &[u8; 56] = b"0123456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";

const TOTAL_CHARACTER: u16 = CHARACTER.len() as u16;

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

    xparq_encode(&payload)
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

    let mut encoded = [CHARACTER[0]; ADDRESS_ENCODED_SIZE];

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

        // payload = payload * 56 + digit
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
    CHARACTER
        .iter()
        .position(|&candidate| candidate == character)
        .map(|index| index as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip() {
        let address = Address([7; ADDRESS_SIZE]);

        let encoded = address_to_string(&address);

        assert_eq!(encoded.len(), ADDRESS_STRING_LEN);

        assert_eq!(address_from_string(&encoded), Ok(address));
    }

    #[test]
    fn zero_address_roundtrip() {
        let address = Address::ZERO;

        let encoded = address_to_string(&address);

        assert_eq!(encoded.len(), ADDRESS_STRING_LEN);

        assert_eq!(address_from_string(&encoded), Ok(address));
    }

    #[test]
    fn base56_preserves_leading_zeroes() {
        let mut payload = [0_u8; ADDRESS_PAYLOAD_SIZE];

        payload[ADDRESS_PAYLOAD_SIZE - 1] = 1;

        let encoded = xparq_encode(&payload);

        assert_eq!(encoded.len(), ADDRESS_ENCODED_SIZE);

        assert_eq!(xparq_decode(&encoded).unwrap(), payload);
    }

    #[test]
    fn maximum_payload_roundtrip() {
        let payload = [0xff_u8; ADDRESS_PAYLOAD_SIZE];

        let encoded = xparq_encode(&payload);

        assert_eq!(encoded.len(), ADDRESS_ENCODED_SIZE);

        assert_eq!(xparq_decode(&encoded).unwrap(), payload);
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

    #[test]
    fn ambiguous_characters_are_rejected() {
        for character in [b'O', b'o', b'I', b'i', b'L', b'l'] {
            assert_eq!(xparq_digit(character), None);
        }
    }

    #[test]
    fn alphabet_has_expected_size() {
        assert_eq!(CHARACTER.len(), 56);
    }
}
