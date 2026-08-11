use crate::{HashDomain, PUBLIC_KEY_SIZE, PublicKey, domain_hash};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use borsh::{BorshDeserialize, BorshSerialize};
use thiserror::Error;

pub const ADDRESS_SIZE: usize = 20;
pub const ADDRESS_HRP: &str = "x";
const BECH32_CHECKSUM_LEN: usize = 6;
const BECH32_ADDRESS_LEN: usize =
    ADDRESS_HRP.len() + 1 + (ADDRESS_SIZE * 8 / 5) + BECH32_CHECKSUM_LEN;
const SQISIGN_LEVEL5_SCHEME_ID: u8 = 1;

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Address(pub [u8; ADDRESS_SIZE]);

impl Address {
    pub const ZERO: Self = Self([0; ADDRESS_SIZE]);
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    #[error("address public key is invalid")]
    InvalidPublicKey,
    #[error("address text encoding is invalid")]
    InvalidEncoding,
}

/// Derive a sidechain dual-authorization address with the same structural
/// layout as XPARQ L1: ordered owner/auth keys, 20 bytes, Bech32 HRP `x`.
///
/// SHA3-256, a sidechain domain, and `chain_id` deliberately prevent this
/// value from being treated as an L1 address.
pub fn dual_address_from_public_keys(
    chain_id: u32,
    owner_public_key: &PublicKey,
    authorization_public_key: &PublicKey,
) -> Result<Address, AddressError> {
    if owner_public_key.0.iter().all(|byte| *byte == 0)
        || authorization_public_key.0.iter().all(|byte| *byte == 0)
    {
        return Err(AddressError::InvalidPublicKey);
    }

    let mut material = Vec::with_capacity(4 + 1 + (2 * PUBLIC_KEY_SIZE));
    material.extend_from_slice(&chain_id.to_le_bytes());
    material.push(SQISIGN_LEVEL5_SCHEME_ID);
    material.extend_from_slice(&owner_public_key.0);
    material.extend_from_slice(&authorization_public_key.0);
    let digest = domain_hash(HashDomain::Address, &material);
    let mut address = [0_u8; ADDRESS_SIZE];
    address.copy_from_slice(&digest.0[12..]);
    Ok(Address(address))
}

pub fn address_to_string(address: &Address) -> String {
    bech32::encode::<Bech32>(Hrp::parse_unchecked(ADDRESS_HRP), &address.0)
        .expect("fixed-size XPARQ sidechain address must encode")
}

pub fn address_from_string(encoded: &str) -> Result<Address, AddressError> {
    if encoded.len() != BECH32_ADDRESS_LEN || encoded != encoded.to_ascii_lowercase() {
        return Err(AddressError::InvalidEncoding);
    }
    let decoded =
        CheckedHrpstring::new::<Bech32>(encoded).map_err(|_| AddressError::InvalidEncoding)?;
    if decoded.hrp() != Hrp::parse_unchecked(ADDRESS_HRP) {
        return Err(AddressError::InvalidEncoding);
    }
    let bytes: Vec<u8> = decoded.byte_iter().collect();
    let address = bytes
        .try_into()
        .map_err(|_| AddressError::InvalidEncoding)?;
    Ok(Address(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; PUBLIC_KEY_SIZE])
    }

    #[test]
    fn address_shape_matches_l1() {
        let address = dual_address_from_public_keys(9001, &key(1), &key(2)).unwrap();
        let encoded = address_to_string(&address);
        assert_eq!(address.0.len(), ADDRESS_SIZE);
        assert_eq!(encoded.len(), BECH32_ADDRESS_LEN);
        assert!(encoded.starts_with("x1"));
        assert_eq!(address_from_string(&encoded), Ok(address));
    }

    #[test]
    fn address_commits_to_chain_id_and_key_roles() {
        let owner = key(1);
        let authorization = key(2);
        let first = dual_address_from_public_keys(9001, &owner, &authorization).unwrap();
        let other_chain = dual_address_from_public_keys(9002, &owner, &authorization).unwrap();
        let swapped = dual_address_from_public_keys(9001, &authorization, &owner).unwrap();
        assert_ne!(first, other_chain);
        assert_ne!(first, swapped);
    }

    #[test]
    fn uppercase_and_zero_keys_are_rejected() {
        let encoded = address_to_string(&Address([7; ADDRESS_SIZE]));
        assert_eq!(
            address_from_string(&encoded.to_ascii_uppercase()),
            Err(AddressError::InvalidEncoding)
        );
        assert_eq!(
            dual_address_from_public_keys(9001, &PublicKey([0; PUBLIC_KEY_SIZE]), &key(2)),
            Err(AddressError::InvalidPublicKey)
        );
    }
}
