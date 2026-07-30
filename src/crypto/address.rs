use crate::crypto::PublicKey;
use crate::error::CryptoError;
use crate::genesis::CURRENT_CHAIN_PARAMS;
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

pub const ML_DSA_ADDRESS_HRP: &str = "P";
pub const SQISIGN_ADDRESS_HRP: &str = "PX";
#[cfg(not(feature = "sqisign-blockchain-test"))]
const DUAL_AUTHORIZATION_DOMAIN: &[u8] = b"PAQUS_DUAL_AUTHORIZATION_V1";
#[cfg(feature = "sqisign-blockchain-test")]
const DUAL_AUTHORIZATION_DOMAIN: &[u8] = b"PAQUS_SQISIGN_LEVEL5_DUAL_AUTHORIZATION_V1";
#[cfg(feature = "sqisign-candidate")]
const SQISIGN_DUAL_AUTHORIZATION_DOMAIN: &[u8] = b"PAQUS_SQISIGN_LEVEL5_DUAL_AUTHORIZATION_V1";
const BECH32_CHECKSUM_LEN: usize = 6;
const ML_DSA_BECH32_ADDRESS_LEN: usize =
    ML_DSA_ADDRESS_HRP.len() + 1 + (ADDRESS_SIZE * 8 / 5) + BECH32_CHECKSUM_LEN;
const SQISIGN_BECH32_ADDRESS_LEN: usize =
    SQISIGN_ADDRESS_HRP.len() + 1 + (ADDRESS_SIZE * 8 / 5) + BECH32_CHECKSUM_LEN;
const_assert_eq!(BECH32_CHECKSUM_LEN, 6);
const_assert_eq!(ML_DSA_BECH32_ADDRESS_LEN, 40);
const_assert_eq!(SQISIGN_BECH32_ADDRESS_LEN, 41);

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

pub fn dual_address_from_public_keys(
    primary_public_key: &PublicKey,
    auth_public_key: &PublicKey,
) -> Address {
    dual_address_from_key_material(primary_public_key, auth_public_key)
}

pub fn try_dual_address_from_public_keys(
    primary_public_key: &PublicKey,
    auth_public_key: &PublicKey,
) -> Result<Address, CryptoError> {
    if primary_public_key.0.iter().all(|byte| *byte == 0)
        || auth_public_key.0.iter().all(|byte| *byte == 0)
    {
        return Err(CryptoError::InvalidPublicKey);
    }
    Ok(dual_address_from_key_material(
        primary_public_key,
        auth_public_key,
    ))
}

fn address_from_key_material(public_key: &[u8]) -> Address {
    let digest = Sha3_256::digest(public_key);
    let mut address = [0_u8; ADDRESS_SIZE];
    address.copy_from_slice(&digest[12..32]);
    Address(address)
}

fn dual_address_from_key_material(
    primary_public_key: &PublicKey,
    auth_public_key: &PublicKey,
) -> Address {
    let mut material = Vec::with_capacity(
        DUAL_AUTHORIZATION_DOMAIN.len() + size_of::<u32>() + (2 * crate::crypto::PUBLIC_KEY_SIZE),
    );
    material.extend_from_slice(DUAL_AUTHORIZATION_DOMAIN);
    material.extend_from_slice(&CURRENT_CHAIN_PARAMS.chain_id.to_le_bytes());
    material.extend_from_slice(&primary_public_key.0);
    material.extend_from_slice(&auth_public_key.0);
    let digest = Sha3_256::digest(material);
    let mut address = [0_u8; ADDRESS_SIZE];
    address.copy_from_slice(&digest[12..32]);
    Address(address)
}

pub fn address_to_string(address: &Address) -> String {
    #[cfg(feature = "sqisign-blockchain-test")]
    return address_to_string_with_hrp(address, SQISIGN_ADDRESS_HRP);
    #[cfg(not(feature = "sqisign-blockchain-test"))]
    address_to_string_with_hrp(address, ML_DSA_ADDRESS_HRP)
}

pub fn address_from_string(address: &str) -> Result<Address, CryptoError> {
    #[cfg(feature = "sqisign-blockchain-test")]
    return address_from_string_with_hrp(address, SQISIGN_ADDRESS_HRP, SQISIGN_BECH32_ADDRESS_LEN);
    #[cfg(not(feature = "sqisign-blockchain-test"))]
    address_from_string_with_hrp(address, ML_DSA_ADDRESS_HRP, ML_DSA_BECH32_ADDRESS_LEN)
}

/// Decodes the retired `PX` encoding for an ML-DSA wallet file.
///
/// This is only for validating stored credentials during the HRP transition.
/// Network-facing parsers must use [`address_from_string`], where `PX` is
/// reserved for SQIsign Level 5.
#[doc(hidden)]
pub fn legacy_ml_dsa_address_from_string(address: &str) -> Result<Address, CryptoError> {
    address_from_string_with_hrp(address, SQISIGN_ADDRESS_HRP, SQISIGN_BECH32_ADDRESS_LEN)
}

#[cfg(feature = "sqisign-candidate")]
pub fn sqisign_dual_address_from_public_keys(
    owner_public_key: &crate::crypto::sqisign_candidate::PublicKey,
    authorization_public_key: &crate::crypto::sqisign_candidate::PublicKey,
) -> Result<Address, CryptoError> {
    if owner_public_key.as_bytes().iter().all(|byte| *byte == 0)
        || authorization_public_key
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(CryptoError::InvalidPublicKey);
    }
    let mut material = Vec::with_capacity(
        SQISIGN_DUAL_AUTHORIZATION_DOMAIN.len()
            + size_of::<u32>()
            + 1
            + owner_public_key.as_bytes().len()
            + authorization_public_key.as_bytes().len(),
    );
    material.extend_from_slice(SQISIGN_DUAL_AUTHORIZATION_DOMAIN);
    material.extend_from_slice(&CURRENT_CHAIN_PARAMS.chain_id.to_le_bytes());
    material.push(crate::crypto::SignatureScheme::SqisignLevel5 as u8);
    material.extend_from_slice(owner_public_key.as_bytes());
    material.extend_from_slice(authorization_public_key.as_bytes());
    Ok(address_from_key_material(&material))
}

#[cfg(feature = "sqisign-candidate")]
pub fn sqisign_address_to_string(address: &Address) -> String {
    address_to_string_with_hrp(address, SQISIGN_ADDRESS_HRP)
}

#[cfg(feature = "sqisign-candidate")]
pub fn sqisign_address_from_string(address: &str) -> Result<Address, CryptoError> {
    address_from_string_with_hrp(address, SQISIGN_ADDRESS_HRP, SQISIGN_BECH32_ADDRESS_LEN)
}

fn address_to_string_with_hrp(address: &Address, hrp: &str) -> String {
    bech32::encode_upper::<Bech32>(Hrp::parse_unchecked(hrp), &address.0).unwrap_or_default()
}

fn address_from_string_with_hrp(
    address: &str,
    expected_hrp: &str,
    expected_len: usize,
) -> Result<Address, CryptoError> {
    if address.len() != expected_len || address != address.to_ascii_uppercase() {
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
    fn dual_address_binds_both_public_keys_and_is_deterministic() {
        let primary = keypair_from_seed(&[1; 32]);
        let auth_a = keypair_from_seed(&[2; 32]);
        let auth_b = keypair_from_seed(&[3; 32]);

        let address_a = dual_address_from_public_keys(&primary.public_key, &auth_a.public_key);
        let address_a_again =
            dual_address_from_public_keys(&primary.public_key, &auth_a.public_key);
        let address_b = dual_address_from_public_keys(&primary.public_key, &auth_b.public_key);

        assert_eq!(address_a, address_a_again);
        assert_ne!(address_a, address_b);
        assert_ne!(
            address_a,
            dual_address_from_public_keys(&auth_a.public_key, &primary.public_key)
        );
    }

    #[cfg(not(feature = "sqisign-blockchain-test"))]
    #[test]
    fn ml_dsa_address_uses_p_hrp_and_rejects_reserved_px_hrp() {
        let address = Address([7; ADDRESS_SIZE]);
        let encoded = address_to_string(&address);
        assert!(encoded.starts_with("P1"));
        assert!(!encoded.starts_with("PX1"));
        assert_eq!(encoded.len(), ML_DSA_BECH32_ADDRESS_LEN);
        assert_eq!(address_from_string(&encoded), Ok(address));

        let reserved = address_to_string_with_hrp(&address, SQISIGN_ADDRESS_HRP);
        assert!(reserved.starts_with("PX1"));
        assert_eq!(legacy_ml_dsa_address_from_string(&reserved), Ok(address));
        assert_eq!(
            address_from_string(&reserved),
            Err(CryptoError::InvalidAddressEncoding)
        );
    }

    #[cfg(feature = "sqisign-blockchain-test")]
    #[test]
    fn blockchain_test_address_uses_px_hrp_and_rejects_p_hrp() {
        let address = Address([7; ADDRESS_SIZE]);
        let encoded = address_to_string(&address);
        assert!(encoded.starts_with("PX1"));
        assert_eq!(encoded.len(), SQISIGN_BECH32_ADDRESS_LEN);
        assert_eq!(address_from_string(&encoded), Ok(address));

        let ml_dsa = address_to_string_with_hrp(&address, ML_DSA_ADDRESS_HRP);
        assert_eq!(
            address_from_string(&ml_dsa),
            Err(CryptoError::InvalidAddressEncoding)
        );
    }

    #[cfg(feature = "sqisign-candidate")]
    #[test]
    fn sqisign_address_uses_reserved_px_hrp() {
        use crate::crypto::sqisign_candidate::PublicKey as SqisignPublicKey;

        let owner = SqisignPublicKey::from_bytes_unchecked(
            [1; crate::crypto::sqisign_candidate::PUBLIC_KEY_SIZE],
        );
        let authorization = SqisignPublicKey::from_bytes_unchecked(
            [2; crate::crypto::sqisign_candidate::PUBLIC_KEY_SIZE],
        );
        let address =
            sqisign_dual_address_from_public_keys(&owner, &authorization).expect("valid keys");
        let encoded = sqisign_address_to_string(&address);

        assert!(encoded.starts_with("PX1"));
        assert_eq!(encoded.len(), SQISIGN_BECH32_ADDRESS_LEN);
        assert_eq!(sqisign_address_from_string(&encoded), Ok(address));
        #[cfg(not(feature = "sqisign-blockchain-test"))]
        assert_eq!(
            address_from_string(&encoded),
            Err(CryptoError::InvalidAddressEncoding)
        );
        #[cfg(feature = "sqisign-blockchain-test")]
        assert_eq!(address_from_string(&encoded), Ok(address));
    }
}
