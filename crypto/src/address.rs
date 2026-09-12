use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    HASH_SIZE, HashDomain, PublicKey,
    error::CryptoError,
    hash,
    kem::{KemError, KemPublicKey},
};

pub const ADDRESS_SIZE: usize = 16;
pub const ADDRESS_PREFIX: &str = "Qx";
pub const ADDRESS_CHECKSUM_SIZE: usize = 4;
pub const PAYMENT_ADDRESS_PREFIX: &str = "Qp";
pub const PAYMENT_ADDRESS_MAX_BYTES: usize = 4096;

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

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct PaymentAddress {
    pub spend_public_key: PublicKey,
    pub kem_public_key: KemPublicKey,
}

impl PaymentAddress {
    pub fn new(
        spend_public_key: PublicKey,
        kem_public_key: KemPublicKey,
    ) -> Result<Self, KemError> {
        let kem_public_key =
            KemPublicKey::from_bytes(kem_public_key.kem(), kem_public_key.into_bytes())?;
        Ok(Self {
            spend_public_key,
            kem_public_key,
        })
    }

    pub fn account_address(&self) -> Address {
        address_from_public_key(&self.spend_public_key)
    }
}

pub fn payment_address_from_public_keys(
    spend_public_key: PublicKey,
    kem_public_key: KemPublicKey,
) -> Result<PaymentAddress, KemError> {
    PaymentAddress::new(spend_public_key, kem_public_key)
}

pub fn payment_address_to_string(payment_address: &PaymentAddress) -> String {
    let bytes = crate::canonical_bytes(payment_address).expect("payment address encoding");
    let checksum = payment_address_checksum(&bytes);
    format!(
        "{PAYMENT_ADDRESS_PREFIX}{}{}",
        hex::encode(bytes),
        hex::encode(checksum),
    )
}

pub fn payment_address_from_string(value: &str) -> Result<PaymentAddress, CryptoError> {
    let encoded = value
        .strip_prefix(PAYMENT_ADDRESS_PREFIX)
        .ok_or(CryptoError::InvalidPaymentAddressEncoding)?;
    if encoded != encoded.to_ascii_lowercase() {
        return Err(CryptoError::InvalidPaymentAddressEncoding);
    }

    let bytes = hex::decode(encoded).map_err(|_| CryptoError::InvalidPaymentAddressEncoding)?;
    if bytes.len() <= ADDRESS_CHECKSUM_SIZE
        || bytes.len() > PAYMENT_ADDRESS_MAX_BYTES + ADDRESS_CHECKSUM_SIZE
    {
        return Err(CryptoError::InvalidPaymentAddressEncoding);
    }

    let payload_len = bytes.len() - ADDRESS_CHECKSUM_SIZE;
    let (payload, checksum) = bytes.split_at(payload_len);
    if checksum != payment_address_checksum(payload) {
        return Err(CryptoError::InvalidPaymentAddressEncoding);
    }

    crate::canonical_deserialize(payload).map_err(|_| CryptoError::InvalidPaymentAddressEncoding)
}

fn payment_address_checksum(bytes: &[u8]) -> [u8; ADDRESS_CHECKSUM_SIZE] {
    let digest = hash::domain(HashDomain::PaymentAddressChecksum, bytes);
    let mut checksum = [0; ADDRESS_CHECKSUM_SIZE];
    checksum.copy_from_slice(&digest.as_bytes()[..ADDRESS_CHECKSUM_SIZE]);
    checksum
}

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
    use crate::{KemSeed, KeyExchange, Signature, SigningSeed};

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

    #[test]
    fn payment_address_binds_spend_and_kem_public_keys() {
        let spend_public_key = SigningSeed::new(Signature::MlDsa44, [3; 32]).public_key();
        let kem_public_key = KemSeed::new(KeyExchange::MlKem768, [5; 64]).public_key();
        let expected = address_from_public_key(&spend_public_key);

        let payment_address =
            payment_address_from_public_keys(spend_public_key, kem_public_key).unwrap();

        assert_eq!(payment_address.account_address(), expected);
        assert_eq!(payment_address.kem_public_key.kem(), KeyExchange::MlKem768);

        let encoded = payment_address_to_string(&payment_address);
        assert!(encoded.starts_with(PAYMENT_ADDRESS_PREFIX));
        assert_eq!(payment_address_from_string(&encoded), Ok(payment_address));
    }
}
