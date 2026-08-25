use crate::crypto::PublicKey;
use crate::error::CryptoError;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use static_assertions::const_assert_eq;

pub const ADDRESS_SIZE: usize = 20;
pub type AddressBytes = [u8; ADDRESS_SIZE];
const_assert_eq!(ADDRESS_SIZE, 20);

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
pub struct Address(pub AddressBytes);

impl Address {
    pub const ZERO: Self = Self([0; ADDRESS_SIZE]);
}

pub const ADDRESS_HRP: &str = "XPQ";
const BECH32_CHECKSUM_LEN: usize = 6;
const BECH32_ADDRESS_LEN: usize =
    ADDRESS_HRP.len() + 1 + (ADDRESS_SIZE * 8).div_ceil(5) + BECH32_CHECKSUM_LEN;
const_assert_eq!(BECH32_CHECKSUM_LEN, 6);
const_assert_eq!(BECH32_ADDRESS_LEN, 42);

pub fn wallet_address_from_public_key(public_key: &PublicKey) -> String {
    address_to_string(&address_from_public_key(public_key))
}

pub fn address_from_public_key(public_key: &PublicKey) -> Address {
    address_from_key_material(&public_key.0)
}

pub fn try_address_from_public_key(public_key: &PublicKey) -> Result<Address, CryptoError> {
    if public_key.0.iter().all(|byte| *byte == 0) {
        return Err(CryptoError::InvalidPublicKey);
    }

    Ok(address_from_key_material(&public_key.0))
}

fn address_from_key_material(public_key: &[u8]) -> Address {
    let digest = Sha3_256::digest(public_key);
    let mut address = [0_u8; ADDRESS_SIZE];
    address.copy_from_slice(&digest[12..]);
    Address(address)
}

pub fn address_to_string(address: &Address) -> String {
    address_to_string_with_hrp(address, ADDRESS_HRP)
}

pub fn address_from_string(address: &str) -> Result<Address, CryptoError> {
    address_from_string_with_hrp(address, ADDRESS_HRP, BECH32_ADDRESS_LEN)
}

fn address_to_string_with_hrp(address: &Address, hrp: &str) -> String {
    bech32::encode::<Bech32>(Hrp::parse_unchecked(hrp), &address.0)
        .expect("fixed-size XPARQ address encoding must be valid")
}

fn address_from_string_with_hrp(
    address: &str,
    expected_hrp: &str,
    expected_len: usize,
) -> Result<Address, CryptoError> {
    if address.len() != expected_len || address != address.to_ascii_lowercase() {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let decoded = CheckedHrpstring::new::<Bech32>(address)
        .map_err(|_| CryptoError::InvalidAddressEncoding)?;
    if decoded.hrp() != Hrp::parse_unchecked(expected_hrp) {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let bytes: Vec<u8> = decoded.byte_iter().collect();
    let bytes: [u8; ADDRESS_SIZE] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidAddressEncoding)?;

    Ok(Address(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen::keypair_from_seed;

    #[test]
    fn single_key_address_uses_the_last_20_sha3_256_bytes() {
        let public_key = keypair_from_seed(&[4; 32]).public_key;
        let digest = Sha3_256::digest(public_key.0);
        let expected: [u8; ADDRESS_SIZE] = digest[12..].try_into().unwrap();

        assert_eq!(address_from_public_key(&public_key), Address(expected));
    }

    #[test]
    fn every_network_address_uses_lowercase_z_hrp() {
        let address = Address([7; ADDRESS_SIZE]);
        let encoded = address_to_string(&address);
        assert!(encoded.starts_with("xpq1"));
        assert_eq!(encoded.len(), BECH32_ADDRESS_LEN);
        assert_eq!(address_from_string(&encoded), Ok(address));

        assert_eq!(
            address_from_string(&encoded.to_ascii_uppercase()),
            Err(CryptoError::InvalidAddressEncoding)
        );

        let old_hrp = address_to_string_with_hrp(&address, "p");
        assert_eq!(
            address_from_string(&old_hrp),
            Err(CryptoError::InvalidAddressEncoding)
        );
    }
}
