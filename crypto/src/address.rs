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

    format!(
        "{ADDRESS_PREFIX}{}{}",
        hex::encode(address.as_bytes()),
        hex::encode(checksum),
    )
}

pub fn address_from_string(value: &str) -> Result<Address, CryptoError> {
    if value.len() != ADDRESS_STRING_LEN {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let encoded = value
        .strip_prefix(ADDRESS_PREFIX)
        .ok_or(CryptoError::InvalidAddressEncoding)?;

    if encoded != encoded.to_ascii_lowercase() {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let bytes = hex::decode(encoded).map_err(|_| CryptoError::InvalidAddressEncoding)?;

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

    Ok(address)
}

fn address_checksum(address: &Address) -> [u8; ADDRESS_CHECKSUM_SIZE] {
    let digest = hash::domain(HashDomain::AddressChecksum, address.as_bytes());

    let mut checksum = [0_u8; ADDRESS_CHECKSUM_SIZE];

    checksum.copy_from_slice(&digest.as_bytes()[..ADDRESS_CHECKSUM_SIZE]);

    checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_address_uses_lowercase_hex_with_checksum() {
        let address = Address([7; ADDRESS_SIZE]);
        let encoded = address_to_string(&address);

        assert!(encoded.starts_with(ADDRESS_PREFIX));
        assert_eq!(encoded.len(), ADDRESS_STRING_LEN);

        assert_eq!(address_from_string(&encoded), Ok(address),);

        assert_eq!(
            address_from_string(&encoded.to_ascii_uppercase()),
            Err(CryptoError::InvalidAddressEncoding),
        );

        let raw_hex_without_checksum =
            format!("{ADDRESS_PREFIX}{}", hex::encode(address.as_bytes()),);

        assert_eq!(
            address_from_string(&raw_hex_without_checksum),
            Err(CryptoError::InvalidAddressEncoding),
        );

        let mut corrupted = encoded.into_bytes();
        let last = corrupted.last_mut().unwrap();

        *last = if *last == b'0' { b'1' } else { b'0' };

        assert_eq!(
            address_from_string(std::str::from_utf8(&corrupted).unwrap(),),
            Err(CryptoError::InvalidAddressEncoding),
        );
    }
}
