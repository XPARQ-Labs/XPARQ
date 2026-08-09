use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use xparq::{
    crypto::{
        Address, PUBLIC_KEY_SIZE, PublicKey, SECRET_KEY_SIZE, SecretKey, address_from_string,
        address_to_string, authorization_keypair_from_password, derive_public_key,
        dual_address_from_public_keys, hash_bytes, keypair_from_seed, sign,
    },
    transaction::{QCashTransaction, SignedQCashTransaction, SignedTransfer, Transfer},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const WALLET_VERSION: u8 = 1;
pub const XPARQ_MNEMONIC_DEFAULT_WORDS: usize = 12;
pub const XPARQ_MNEMONIC_12_ENTROPY_BYTES: usize = 16;
pub const XPARQ_MNEMONIC_24_ENTROPY_BYTES: usize = 32;
const XPARQ_MNEMONIC_SPEND_TAG: &[u8] = b"XPARQ_WALLET_SPEND_ML_DSA44_V1";

#[derive(Clone, Debug)]
pub struct Wallet {
    pub mnemonic: Option<String>,
    pub address: Address,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
    pub auth_public_key: Option<PublicKey>,
    pub auth_secret_key: Option<SecretKey>,
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizationKeys {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub enum AuthorizationInput {
    Keys(Box<AuthorizationKeys>),
    Password(Zeroizing<String>),
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct WalletFile {
    version: u8,
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic: Option<String>,
    public_key: String,
    secret_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_secret_key: Option<String>,
}

pub fn wallet_address_string(wallet: &Wallet) -> String {
    address_to_string(&wallet.address)
}

pub fn wallet_file_bytes(wallet: &Wallet) -> Result<Zeroizing<Vec<u8>>, String> {
    let wallet_file = WalletFile {
        version: WALLET_VERSION,
        address: address_to_string(&wallet.address),
        mnemonic: wallet.mnemonic.clone(),
        public_key: hex::encode(wallet.public_key.0),
        secret_key: hex::encode(wallet.secret_key.0),
        auth_public_key: wallet.auth_public_key.map(|key| hex::encode(key.0)),
        auth_secret_key: None,
    };
    serde_json::to_vec_pretty(&wallet_file)
        .map(Zeroizing::new)
        .map_err(|error| format!("failed to encode wallet file: {error}"))
}

pub fn wallet_from_file_bytes(bytes: &[u8]) -> Result<Wallet, String> {
    let mut wallet_file: WalletFile = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;
    if wallet_file.version != WALLET_VERSION {
        return Err("unsupported wallet format".to_string());
    }
    let address = address_from_string(&wallet_file.address)
        .map_err(|error| format!("invalid wallet address: {error}"))?;
    let public_key =
        decode_key::<PUBLIC_KEY_SIZE>(&wallet_file.public_key, "public key").map(PublicKey)?;
    let secret_key =
        decode_key::<SECRET_KEY_SIZE>(&wallet_file.secret_key, "secret key").map(SecretKey)?;
    let auth_public_key = wallet_file
        .auth_public_key
        .as_deref()
        .ok_or_else(|| "wallet is missing authorization public key".to_string())
        .and_then(|value| decode_key::<PUBLIC_KEY_SIZE>(value, "authorization public key"))
        .map(PublicKey)?;
    let auth_secret_key = wallet_file
        .auth_secret_key
        .as_deref()
        .map(|value| decode_key::<SECRET_KEY_SIZE>(value, "authorization secret key"))
        .transpose()?
        .map(SecretKey);
    if derive_public_key(&secret_key) != public_key {
        return Err("wallet public key does not match secret key".to_string());
    }
    let mut wallet = Wallet::from_keys_with_authorization(
        public_key,
        secret_key,
        auth_public_key,
        auth_secret_key,
    );
    wallet.mnemonic = wallet_file.mnemonic.take();
    if wallet.address != address {
        return Err("wallet address does not match its key material".to_string());
    }
    Ok(wallet)
}

pub fn authorization_keys_from_password(
    wallet: &Wallet,
    password: &str,
) -> Result<AuthorizationKeys, String> {
    let keypair = authorization_keypair_from_password(password.as_bytes(), &wallet.public_key)
        .map_err(|error| format!("authorization key derivation failed: {error}"))?;
    if wallet.auth_public_key != Some(keypair.public_key) {
        return Err("authorization password does not match this wallet".to_string());
    }
    Ok(AuthorizationKeys {
        public_key: keypair.public_key,
        secret_key: keypair.secret_key,
    })
}

fn decode_key<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = Zeroizing::new(hex::decode(value).map_err(|_| format!("invalid {label} hex"))?);
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("invalid {label} length"))
}

pub fn generate_xparq_mnemonic(words: usize) -> Result<Zeroizing<String>, String> {
    let entropy_len = match words {
        12 => XPARQ_MNEMONIC_12_ENTROPY_BYTES,
        24 => XPARQ_MNEMONIC_24_ENTROPY_BYTES,
        _ => return Err("mnemonic words must be 12 or 24".to_string()),
    };
    let mut entropy = Zeroizing::new(vec![0_u8; entropy_len]);
    getrandom::fill(&mut entropy)
        .map_err(|error| format!("secure random generation failed: {error}"))?;
    encode_xparq_mnemonic(&entropy).map(Zeroizing::new)
}

pub fn wallet_from_xparq_mnemonic(phrase: &str, auth_password: &str) -> Result<Wallet, String> {
    let entropy = decode_xparq_mnemonic(phrase)?;
    let seed = Zeroizing::new(tagged_wallet_hash(XPARQ_MNEMONIC_SPEND_TAG, &entropy));
    let spend = keypair_from_seed(&seed);
    let authorization =
        authorization_keypair_from_password(auth_password.as_bytes(), &spend.public_key)
            .map_err(|error| format!("authorization key derivation failed: {error}"))?;
    Ok(Wallet::from_keys_with_authorization(
        spend.public_key,
        spend.secret_key,
        authorization.public_key,
        None,
    ))
}

pub fn encode_xparq_mnemonic(entropy: &[u8]) -> Result<String, String> {
    Mnemonic::from_entropy_in(Language::English, entropy)
        .map(|mnemonic| mnemonic.to_string())
        .map_err(|error| format!("failed to encode mnemonic: {error}"))
}

pub fn decode_xparq_mnemonic(phrase: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let normalized = Zeroizing::new(
        phrase
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join(" "),
    );
    let word_count = normalized.split_whitespace().count();
    if !matches!(word_count, 12 | 24) {
        return Err("invalid XPARQ mnemonic: expected 12 or 24 words".to_string());
    }
    Mnemonic::parse_in_normalized(Language::English, &normalized)
        .map(|mnemonic| Zeroizing::new(mnemonic.to_entropy()))
        .map_err(|error| format!("invalid XPARQ mnemonic: {error}"))
}

fn tagged_wallet_hash(tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut payload = Zeroizing::new(Vec::with_capacity(tag.len() + bytes.len()));
    payload.extend_from_slice(tag);
    payload.extend_from_slice(bytes);
    hash_bytes(&payload).0
}

impl Wallet {
    pub fn from_keys_with_authorization(
        public_key: PublicKey,
        secret_key: SecretKey,
        auth_public_key: PublicKey,
        auth_secret_key: Option<SecretKey>,
    ) -> Self {
        Self {
            mnemonic: None,
            address: dual_address_from_public_keys(&public_key, &auth_public_key),
            public_key,
            secret_key,
            auth_public_key: Some(auth_public_key),
            auth_secret_key,
        }
    }

    pub fn stored_authorization_keys(&self) -> Option<AuthorizationKeys> {
        Some(AuthorizationKeys {
            public_key: self.auth_public_key?,
            secret_key: self.auth_secret_key.clone()?,
        })
    }

    pub fn sign_transaction(
        &self,
        transaction: Transfer,
        authorization: Option<AuthorizationKeys>,
        authorization_registered: bool,
    ) -> Result<SignedTransfer, String> {
        let signing_bytes = transaction
            .signing_bytes()
            .map_err(|error| format!("failed to serialize transaction: {error}"))?;
        let signature = sign(&self.secret_key, &signing_bytes);
        let authorization = authorization
            .or_else(|| self.stored_authorization_keys())
            .ok_or_else(|| "authorization password is required".to_string())?;
        let auth_signature = sign(&authorization.secret_key, &signing_bytes);
        let signed = if authorization_registered {
            SignedTransfer::new_stored_authorized(transaction, signature, auth_signature)
        } else {
            SignedTransfer::new_authorized(
                transaction,
                self.public_key,
                signature,
                authorization.public_key,
                auth_signature,
            )
        };
        if authorization_registered {
            signed.validate_stored_keys_for_height(
                xparq::block::Height(0),
                &self.public_key,
                &authorization.public_key,
            )
        } else {
            signed.validate_signed()
        }
        .map_err(|error| format!("signed transaction failed validation: {error}"))?;
        Ok(signed)
    }

    pub fn sign_qcash_transaction(
        &self,
        transaction: QCashTransaction,
        authorization: &AuthorizationKeys,
        authorization_registered: bool,
    ) -> Result<SignedQCashTransaction, String> {
        let signing_bytes = transaction
            .signing_bytes()
            .map_err(|error| format!("failed to serialize QCash transaction: {error}"))?;
        let signature = sign(&self.secret_key, &signing_bytes);
        let auth_signature = sign(&authorization.secret_key, &signing_bytes);
        let signed = if authorization_registered {
            SignedQCashTransaction::new_stored_authorized(transaction, signature, auth_signature)
        } else {
            SignedQCashTransaction::new_authorized(
                transaction,
                self.public_key,
                signature,
                authorization.public_key,
                auth_signature,
            )
        };
        if authorization_registered {
            signed.validate_stored_keys_for_height(
                xparq::block::Height(0),
                &self.public_key,
                &authorization.public_key,
            )
        } else {
            signed.validate_signed()
        }
        .map_err(|error| format!("signed QCash transaction failed validation: {error}"))?;
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_file_roundtrip_preserves_signing_identity() {
        let spend = keypair_from_seed(&[7; 32]);
        let authorization =
            authorization_keypair_from_password(b"correct horse", &spend.public_key).unwrap();
        let wallet = Wallet::from_keys_with_authorization(
            spend.public_key,
            spend.secret_key,
            authorization.public_key,
            None,
        );
        let encoded = wallet_file_bytes(&wallet).unwrap();
        let decoded = wallet_from_file_bytes(&encoded).unwrap();

        assert_eq!(decoded.address, wallet.address);
        assert_eq!(decoded.public_key, wallet.public_key);
        assert!(authorization_keys_from_password(&decoded, "correct horse").is_ok());
        assert!(authorization_keys_from_password(&decoded, "wrong password").is_err());
    }
}
