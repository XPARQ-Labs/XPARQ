use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use xparq::{
    crypto::{
        Address, PublicKey, SecretKey, address_from_public_key, address_from_string,
        address_to_string, hash_bytes, keypair_from_seed, sign,
    },
    transaction::{
        AccountAuthorization, AccountIntent, AuthorizedAccountIntent, OnChainSpendIntent,
        WithdrawIntent,
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
    }
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    address: String,
    mnemonic: String,
}

#[derive(Deserialize)]
struct WalletHeader {
    address: String,
}

pub fn wallet_address_string(wallet: &Wallet) -> String {
    address_to_string(&wallet.address)
}

pub fn wallet_file_bytes(wallet: &Wallet) -> Result<Zeroizing<Vec<u8>>, String> {
    let mnemonic = wallet
        .mnemonic
        .as_deref()
        .ok_or_else(|| "wallet has no mnemonic recovery material".to_string())?;
    decode_xparq_mnemonic(mnemonic)?;
    let wallet_file = WalletFile {
        address: address_to_string(&wallet.address),
        mnemonic: mnemonic.to_string(),
    };
    serde_json::to_vec_pretty(&wallet_file)
        .map(Zeroizing::new)
        .map_err(|error| format!("failed to encode wallet file: {error}"))
}

pub fn wallet_address_from_file_bytes(bytes: &[u8]) -> Result<Address, String> {
    let header: WalletHeader = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;
    address_from_string(&header.address).map_err(|error| format!("invalid wallet address: {error}"))
}

pub fn wallet_from_file_bytes(bytes: &[u8]) -> Result<Wallet, String> {
    let wallet_file: WalletFile = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;
    let mut wallet = wallet_from_xparq_mnemonic(&wallet_file.mnemonic)?;
    let stored_address = address_from_string(&wallet_file.address)
        .map_err(|error| format!("invalid wallet address: {error}"))?;
    if wallet.address != stored_address {
        return Err("wallet address does not match its mnemonic".to_string());
    }
    wallet.mnemonic = Some(wallet_file.mnemonic.clone());
    Ok(wallet)
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

pub fn wallet_from_xparq_mnemonic(phrase: &str) -> Result<Wallet, String> {
    let entropy = decode_xparq_mnemonic(phrase)?;
    let spend_seed = Zeroizing::new(tagged_wallet_hash(XPARQ_MNEMONIC_SPEND_TAG, &entropy));
    let spend = keypair_from_seed(&spend_seed);
    Ok(Wallet::from_keys(spend.public_key, spend.secret_key))
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
    pub fn from_keys(public_key: PublicKey, secret_key: SecretKey) -> Self {
        Self {
            mnemonic: None,
            address: address_from_public_key(&public_key),
            public_key,
            secret_key,
        }
    }

    pub fn sign_onchain_spend(
        &self,
        intent: OnChainSpendIntent,
    ) -> Result<AuthorizedAccountIntent<OnChainSpendIntent>, String> {
        self.sign_account_intent(intent, false)
    }

    pub fn sign_known_onchain_spend(
        &self,
        intent: OnChainSpendIntent,
    ) -> Result<AuthorizedAccountIntent<OnChainSpendIntent>, String> {
        self.sign_account_intent(intent, true)
    }

    pub fn sign_withdraw(
        &self,
        intent: WithdrawIntent,
    ) -> Result<AuthorizedAccountIntent<WithdrawIntent>, String> {
        self.sign_account_intent(intent, false)
    }

    pub fn sign_known_withdraw(
        &self,
        intent: WithdrawIntent,
    ) -> Result<AuthorizedAccountIntent<WithdrawIntent>, String> {
        self.sign_account_intent(intent, true)
    }

    fn sign_account_intent<T: AccountIntent>(
        &self,
        intent: T,
        public_key_known: bool,
    ) -> Result<AuthorizedAccountIntent<T>, String> {
        let chain = xparq::genesis::chain_context()
            .map_err(|error| format!("failed to load chain identity: {error}"))?;
        let commitment = intent
            .commitment(chain)
            .map_err(|error| format!("invalid transaction intent: {error}"))?;
        let signature = sign(&self.secret_key, commitment.as_bytes());
        let authorization = if public_key_known {
            AccountAuthorization::Known { signature }
        } else {
            AccountAuthorization::Reveal {
                public_key: self.public_key,
                signature,
            }
        };
        let signed = AuthorizedAccountIntent {
            intent,
            authorization,
        };
        if !public_key_known
            && !signed
                .verify_revealed_signature(chain)
                .map_err(|error| format!("signed transaction validation failed: {error}"))?
        {
            return Err("signed transaction authorization is invalid".to_string());
        }
        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_file_roundtrip_preserves_signing_identity() {
        let mnemonic = encode_xparq_mnemonic(&[7; XPARQ_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let mut wallet = wallet_from_xparq_mnemonic(&mnemonic).unwrap();
        wallet.mnemonic = Some(mnemonic.clone());
        let encoded = wallet_file_bytes(&wallet).unwrap();
        let decoded = wallet_from_file_bytes(&encoded).unwrap();

        assert_eq!(decoded.address, wallet.address);
        assert_eq!(decoded.public_key, wallet.public_key);

        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 2);
        assert_eq!(json.get("mnemonic").unwrap(), &mnemonic);
        assert_eq!(
            json.get("address").unwrap().as_str(),
            Some(wallet_address_string(&wallet).as_str())
        );
        assert!(json.get("secret_key").is_none());
        assert!(encoded.len() < 512);
    }

    #[test]
    fn wallet_address_reader_accepts_legacy_version_field() {
        let mnemonic = encode_xparq_mnemonic(&[8; XPARQ_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let wallet = wallet_from_xparq_mnemonic(&mnemonic).unwrap();
        let encoded = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "address": wallet_address_string(&wallet),
            "mnemonic": mnemonic,
        }))
        .unwrap();

        assert_eq!(wallet_address_from_file_bytes(&encoded), Ok(wallet.address));
    }

    #[test]
    fn mnemonic_restore_preserves_signing_identity() {
        let mnemonic = encode_xparq_mnemonic(&[9; XPARQ_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let mut first = wallet_from_xparq_mnemonic(&mnemonic).unwrap();
        first.mnemonic = Some(mnemonic.clone());
        let first_file = wallet_file_bytes(&first).unwrap();

        let mut restored = wallet_from_xparq_mnemonic(&mnemonic).unwrap();
        restored.mnemonic = Some(mnemonic);
        let restored_file = wallet_file_bytes(&restored).unwrap();

        assert_eq!(first.address, restored.address);
        assert_eq!(first.public_key, restored.public_key);
        assert_eq!(
            wallet_from_file_bytes(&first_file).unwrap().address,
            wallet_from_file_bytes(&restored_file).unwrap().address
        );
    }
}
