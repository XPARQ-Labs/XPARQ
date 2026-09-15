use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{HASH_SIZE, HashDomain, PublicKey, error::CryptoError, hash};

pub const ADDRESS_SIZE: usize = 16;
pub const ADDRESS_PREFIX: &str = "Qx";
pub const ADDRESS_CHECKSUM_SIZE: usize = 4;

pub const ADDRESS_STRING_LEN: usize =
    ADDRESS_PREFIX.len() + (ADDRESS_SIZE + ADDRESS_CHECKSUM_SIZE) * 2;

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

    let lowercase = format!(
        "{}{}",
        hex::encode(address.as_bytes()),
        hex::encode(checksum),
    );

    let checksummed = apply_checksum_case(&lowercase);

    format!("{ADDRESS_PREFIX}{checksummed}")
}

pub fn address_from_string(value: &str) -> Result<Address, CryptoError> {
    if value.len() != ADDRESS_STRING_LEN {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let encoded = value
        .strip_prefix(ADDRESS_PREFIX)
        .ok_or(CryptoError::InvalidAddressEncoding)?;

    let bytes =
        hex::decode(encoded).map_err(|_| CryptoError::InvalidAddressEncoding)?;

    if bytes.len() != ADDRESS_SIZE + ADDRESS_CHECKSUM_SIZE {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let (address_bytes, checksum_bytes) = bytes.split_at(ADDRESS_SIZE);

    let address = Address::from_bytes(
        address_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidAddressEncoding)?,
    );

    let checksum: [u8; ADDRESS_CHECKSUM_SIZE] = checksum_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidAddressEncoding)?;

    if checksum != address_checksum(&address) {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    // Mixed-case representation is part of the canonical address.
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

/// Applies an EIP-55-like mixed-case checksum.
///
/// Input must be lowercase hexadecimal without the `Qx` prefix.
///
/// Each hexadecimal letter `a-f` is uppercased when the corresponding
/// hash nibble is >= 8. Numeric characters remain unchanged.
fn apply_checksum_case(lowercase_hex: &str) -> String {
    debug_assert!(lowercase_hex.len() <= HASH_SIZE * 2);
    debug_assert!(
        lowercase_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let digest = hash::domain(
        HashDomain::AddressChecksum,
        lowercase_hex.as_bytes(),
    );

    let hash_bytes = digest.as_bytes();

    let mut output = String::with_capacity(lowercase_hex.len());

    for (index, byte) in lowercase_hex.bytes().enumerate() {
        if (b'a'..=b'f').contains(&byte) {
            let hash_byte = hash_bytes[index / 2];

            let nibble = if index % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            if nibble >= 8 {
                output.push((byte as char).to_ascii_uppercase());
                continue;
            }
        }

        output.push(byte as char);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_address_uses_mixed_case_checksum() {
        let address = Address([7; ADDRESS_SIZE]);

        let encoded = address_to_string(&address);

        assert!(encoded.starts_with(ADDRESS_PREFIX));
        assert_eq!(encoded.len(), ADDRESS_STRING_LEN);

        assert_eq!(
            address_from_string(&encoded),
            Ok(address),
        );
    }

    #[test]
    fn incorrect_case_is_rejected() {
        let address = Address([7; ADDRESS_SIZE]);

        let encoded = address_to_string(&address);

        let mut corrupted = encoded.into_bytes();

        let position = corrupted
            .iter()
            .enumerate()
            .skip(ADDRESS_PREFIX.len())
            .find_map(|(index, byte)| {
                if byte.is_ascii_alphabetic() {
                    Some(index)
                } else {
                    None
                }
            })
            .expect("address must contain hexadecimal letters");

        corrupted[position] = if corrupted[position].is_ascii_uppercase() {
            corrupted[position].to_ascii_lowercase()
        } else {
            corrupted[position].to_ascii_uppercase()
        };

        let corrupted = std::str::from_utf8(&corrupted).unwrap();

        assert_eq!(
            address_from_string(corrupted),
            Err(CryptoError::InvalidAddressEncoding),
        );
    }

    #[test]
    fn incorrect_checksum_is_rejected() {
        let address = Address([7; ADDRESS_SIZE]);

        let encoded = address_to_string(&address);

        let mut bytes = hex::decode(&encoded[ADDRESS_PREFIX.len()..]).unwrap();

        let last = bytes.last_mut().unwrap();
        *last ^= 0x01;

        let lowercase = hex::encode(bytes);
        let corrupted = format!(
            "{ADDRESS_PREFIX}{}",
            apply_checksum_case(&lowercase),
        );

        assert_eq!(
            address_from_string(&corrupted),
            Err(CryptoError::InvalidAddressEncoding),
        );
    }

    #[test]
    fn address_without_checksum_is_rejected() {
        let address = Address([7; ADDRESS_SIZE]);

        let raw = format!(
            "{ADDRESS_PREFIX}{}",
            hex::encode(address.as_bytes()),
        );

        assert_eq!(
            address_from_string(&raw),
            Err(CryptoError::InvalidAddressEncoding),
        );
    }
}