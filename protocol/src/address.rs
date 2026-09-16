use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{HASH_SIZE, HashDomain, PublicKey, error::CryptoError, hash};

// ─────────────────────────────────────────────────────────────────────────────
// Public L1 address
// ─────────────────────────────────────────────────────────────────────────────

pub const ADDRESS_SIZE: usize = 20;
pub const ADDRESS_PREFIX: &str = "Qx";
pub const ADDRESS_CHECKSUM_SIZE: usize = 4;

pub const ADDRESS_STRING_LEN: usize =
    ADDRESS_PREFIX.len() + (ADDRESS_SIZE + ADDRESS_CHECKSUM_SIZE) * 2;

// ─────────────────────────────────────────────────────────────────────────────
// Shielded L2 address
// ─────────────────────────────────────────────────────────────────────────────

pub const SHIELDED_ADDRESS_SIZE: usize = 20;
pub const SHIELDED_ADDRESS_PREFIX: &str = "Sx";
pub const SHIELDED_ADDRESS_CHECKSUM_SIZE: usize = 4;

pub const SHIELDED_ADDRESS_STRING_LEN: usize =
    SHIELDED_ADDRESS_PREFIX.len()
        + (SHIELDED_ADDRESS_SIZE + SHIELDED_ADDRESS_CHECKSUM_SIZE) * 2;

// ─────────────────────────────────────────────────────────────────────────────
// Public address
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Shielded address
// ─────────────────────────────────────────────────────────────────────────────

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
pub struct ShieldedAddress(pub [u8; SHIELDED_ADDRESS_SIZE]);

impl ShieldedAddress {
    pub const ZERO: Self = Self([0; SHIELDED_ADDRESS_SIZE]);

    pub const fn from_bytes(bytes: [u8; SHIELDED_ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SHIELDED_ADDRESS_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; SHIELDED_ADDRESS_SIZE] {
        self.0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public address derivation
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Public address encoding
// ─────────────────────────────────────────────────────────────────────────────

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

    if value != address_to_string(&address) {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    Ok(address)
}

// ─────────────────────────────────────────────────────────────────────────────
// Shielded address encoding
// ─────────────────────────────────────────────────────────────────────────────

pub fn shielded_address_to_string(address: &ShieldedAddress) -> String {
    let checksum = shielded_address_checksum(address);

    let lowercase = format!(
        "{}{}",
        hex::encode(address.as_bytes()),
        hex::encode(checksum),
    );

    let checksummed = apply_shielded_checksum_case(&lowercase);

    format!("{SHIELDED_ADDRESS_PREFIX}{checksummed}")
}

pub fn shielded_address_from_string(
    value: &str,
) -> Result<ShieldedAddress, CryptoError> {
    if value.len() != SHIELDED_ADDRESS_STRING_LEN {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let encoded = value
        .strip_prefix(SHIELDED_ADDRESS_PREFIX)
        .ok_or(CryptoError::InvalidAddressEncoding)?;

    let bytes = hex::decode(encoded).map_err(|_| CryptoError::InvalidAddressEncoding)?;

    if bytes.len() != SHIELDED_ADDRESS_SIZE + SHIELDED_ADDRESS_CHECKSUM_SIZE {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    let (address_bytes, checksum_bytes) =
        bytes.split_at(SHIELDED_ADDRESS_SIZE);

    let address = ShieldedAddress::from_bytes(
        address_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidAddressEncoding)?,
    );

    let checksum: [u8; SHIELDED_ADDRESS_CHECKSUM_SIZE] = checksum_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidAddressEncoding)?;

    if checksum != shielded_address_checksum(&address) {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    if value != shielded_address_to_string(&address) {
        return Err(CryptoError::InvalidAddressEncoding);
    }

    Ok(address)
}

// ─────────────────────────────────────────────────────────────────────────────
// Checksums
// ─────────────────────────────────────────────────────────────────────────────

fn address_checksum(address: &Address) -> [u8; ADDRESS_CHECKSUM_SIZE] {
    let digest = hash::domain(
        HashDomain::AddressChecksum,
        address.as_bytes(),
    );

    let mut checksum = [0_u8; ADDRESS_CHECKSUM_SIZE];

    checksum.copy_from_slice(&digest.as_bytes()[..ADDRESS_CHECKSUM_SIZE]);

    checksum
}

fn shielded_address_checksum(
    address: &ShieldedAddress,
) -> [u8; SHIELDED_ADDRESS_CHECKSUM_SIZE] {
    // Explicitly include the Qs domain so a shielded address cannot share
    // the same checksum namespace as a public Qx address.
    let mut material =
        Vec::with_capacity(SHIELDED_ADDRESS_PREFIX.len() + SHIELDED_ADDRESS_SIZE);

    material.extend_from_slice(SHIELDED_ADDRESS_PREFIX.as_bytes());
    material.extend_from_slice(address.as_bytes());

    let digest = hash::domain(
        HashDomain::AddressChecksum,
        &material,
    );

    let mut checksum = [0_u8; SHIELDED_ADDRESS_CHECKSUM_SIZE];

    checksum.copy_from_slice(
        &digest.as_bytes()[..SHIELDED_ADDRESS_CHECKSUM_SIZE],
    );

    checksum
}

// ─────────────────────────────────────────────────────────────────────────────
// Mixed-case canonical encoding
// ─────────────────────────────────────────────────────────────────────────────

/// Applies the canonical mixed-case checksum for public Qx addresses.
///
/// The first checksum-mask block is exactly compatible with the original
/// address encoding.
fn apply_checksum_case(lowercase_hex: &str) -> String {
    apply_checksum_case_with_seed(
        lowercase_hex,
        lowercase_hex.as_bytes(),
    )
}

/// Applies the canonical mixed-case checksum for shielded Qs addresses.
///
/// The Qs prefix is included in the checksum domain.
fn apply_shielded_checksum_case(lowercase_hex: &str) -> String {
    let mut seed =
        Vec::with_capacity(SHIELDED_ADDRESS_PREFIX.len() + lowercase_hex.len());

    seed.extend_from_slice(SHIELDED_ADDRESS_PREFIX.as_bytes());
    seed.extend_from_slice(lowercase_hex.as_bytes());

    apply_checksum_case_with_seed(lowercase_hex, &seed)
}

/// Generates enough checksum-mask material for addresses of arbitrary size.
///
/// A 16-byte Qx address plus checksum needs less than one SHA3-256 digest.
/// A 32-byte Qs receiver plus checksum needs 36 mask bytes, so it requires
/// a second digest block.
fn apply_checksum_case_with_seed(
    lowercase_hex: &str,
    seed: &[u8],
) -> String {
    debug_assert!(
        lowercase_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let required_mask_bytes = lowercase_hex.len().div_ceil(2);

    let mut mask = Vec::with_capacity(required_mask_bytes);

    // Preserve the original Qx checksum-case algorithm for the first block.
    let first = hash::domain(HashDomain::AddressChecksum, seed);

    let first_len = required_mask_bytes.min(HASH_SIZE);

    mask.extend_from_slice(&first.as_bytes()[..first_len]);

    let mut counter = 1_u32;

    while mask.len() < required_mask_bytes {
        let mut material = Vec::with_capacity(seed.len() + size_of::<u32>());

        material.extend_from_slice(seed);
        material.extend_from_slice(&counter.to_be_bytes());

        let digest = hash::domain(
            HashDomain::AddressChecksum,
            &material,
        );

        let remaining = required_mask_bytes - mask.len();
        let take = remaining.min(HASH_SIZE);

        mask.extend_from_slice(&digest.as_bytes()[..take]);

        counter = counter
            .checked_add(1)
            .expect("checksum mask counter overflow");
    }

    let mut output = String::with_capacity(lowercase_hex.len());

    for (index, byte) in lowercase_hex.bytes().enumerate() {
        if (b'a'..=b'f').contains(&byte) {
            let mask_byte = mask[index / 2];

            let nibble = if index % 2 == 0 {
                mask_byte >> 4
            } else {
                mask_byte & 0x0f
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

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

        let mut bytes =
            hex::decode(&encoded[ADDRESS_PREFIX.len()..]).unwrap();

        let last = bytes.last_mut().unwrap();
        *last ^= 0x01;

        let lowercase = hex::encode(bytes);
        let corrupted =
            format!("{ADDRESS_PREFIX}{}", apply_checksum_case(&lowercase));

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

    #[test]
    fn canonical_shielded_address_uses_qs_prefix() {
        let address = ShieldedAddress([7; SHIELDED_ADDRESS_SIZE]);

        let encoded = shielded_address_to_string(&address);

        assert!(encoded.starts_with(SHIELDED_ADDRESS_PREFIX));
        assert_eq!(
            encoded.len(),
            SHIELDED_ADDRESS_STRING_LEN,
        );

        assert_eq!(
            shielded_address_from_string(&encoded),
            Ok(address),
        );
    }

    #[test]
    fn shielded_address_incorrect_case_is_rejected() {
        let address = ShieldedAddress([7; SHIELDED_ADDRESS_SIZE]);

        let encoded = shielded_address_to_string(&address);

        let mut corrupted = encoded.into_bytes();

        let position = corrupted
            .iter()
            .enumerate()
            .skip(SHIELDED_ADDRESS_PREFIX.len())
            .find_map(|(index, byte)| {
                if byte.is_ascii_alphabetic() {
                    Some(index)
                } else {
                    None
                }
            })
            .expect("shielded address must contain hexadecimal letters");

        corrupted[position] = if corrupted[position].is_ascii_uppercase() {
            corrupted[position].to_ascii_lowercase()
        } else {
            corrupted[position].to_ascii_uppercase()
        };

        let corrupted = std::str::from_utf8(&corrupted).unwrap();

        assert_eq!(
            shielded_address_from_string(corrupted),
            Err(CryptoError::InvalidAddressEncoding),
        );
    }

    #[test]
    fn shielded_address_incorrect_checksum_is_rejected() {
        let address = ShieldedAddress([7; SHIELDED_ADDRESS_SIZE]);

        let encoded = shielded_address_to_string(&address);

        let mut bytes =
            hex::decode(&encoded[SHIELDED_ADDRESS_PREFIX.len()..]).unwrap();

        let last = bytes.last_mut().unwrap();
        *last ^= 0x01;

        let lowercase = hex::encode(bytes);

        let corrupted = format!(
            "{SHIELDED_ADDRESS_PREFIX}{}",
            apply_shielded_checksum_case(&lowercase),
        );

        assert_eq!(
            shielded_address_from_string(&corrupted),
            Err(CryptoError::InvalidAddressEncoding),
        );
    }

    #[test]
    fn shielded_address_without_checksum_is_rejected() {
        let address = ShieldedAddress([7; SHIELDED_ADDRESS_SIZE]);

        let raw = format!(
            "{SHIELDED_ADDRESS_PREFIX}{}",
            hex::encode(address.as_bytes()),
        );

        assert_eq!(
            shielded_address_from_string(&raw),
            Err(CryptoError::InvalidAddressEncoding),
        );
    }
}