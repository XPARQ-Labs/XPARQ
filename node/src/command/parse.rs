use borsh::BorshDeserialize;
use xparq::crypto::{Address, HASH_SIZE, Hash, SECRET_KEY_SIZE, SecretKey, address_from_string};
use xparq::transaction::{SignedProtocolTransaction, SignedQCashTransaction, SignedTransfer};
use zeroize::Zeroizing;

pub fn secret_key(value: Option<&String>) -> Result<SecretKey, String> {
    let value = value.ok_or_else(|| "missing secret key".to_string())?;
    let bytes =
        Zeroizing::new(hex::decode(value).map_err(|_| "invalid secret key hex".to_string())?);
    let bytes: [u8; SECRET_KEY_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "secret key has invalid length".to_string())?;
    Ok(SecretKey(bytes))
}

pub fn signed_transaction(value: &str) -> Result<SignedTransfer, String> {
    let bytes = hex::decode(value).map_err(|_| "invalid transaction hex".to_string())?;
    SignedTransfer::try_from_slice(&bytes)
        .map_err(|error| format!("invalid signed transaction bytes: {error}"))
}

pub fn signed_qcash_transaction(value: &str) -> Result<SignedQCashTransaction, String> {
    let bytes = hex::decode(value).map_err(|_| "invalid QCash transaction hex".to_string())?;
    SignedQCashTransaction::try_from_slice(&bytes)
        .map_err(|error| format!("invalid signed QCash transaction bytes: {error}"))
}

pub fn signed_protocol_transaction(value: &str) -> Result<SignedProtocolTransaction, String> {
    let bytes = hex::decode(value).map_err(|_| "invalid protocol transaction hex".to_string())?;
    SignedProtocolTransaction::try_from_slice(&bytes)
        .map_err(|error| format!("invalid signed protocol transaction bytes: {error}"))
}

pub fn address(value: Option<&String>) -> Result<Address, String> {
    value
        .ok_or_else(|| "missing address".to_string())
        .and_then(|value| address_string(value))
}

pub fn address_string(value: &str) -> Result<Address, String> {
    address_from_string(value).map_err(|_| "invalid xparq address".to_string())
}

pub fn hash_hex(value: &str) -> Result<Hash, String> {
    let bytes = hex::decode(value).map_err(|_| "invalid hash hex".to_string())?;
    let bytes: [u8; HASH_SIZE] = bytes
        .try_into()
        .map_err(|_| "hash has invalid length".to_string())?;
    Ok(Hash(bytes))
}
