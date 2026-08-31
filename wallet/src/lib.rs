use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use xparq::{
    crypto::{
        Address, ProfilePublicKey, ProfileSigningSeed, SignatureProfile,
        address_from_profile_public_key, address_from_string, address_to_string, hash_bytes,
    },
    transaction::{AccountAuthorization, AccountIntent, AuthorizedAccountIntent},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const XPARQ_MNEMONIC_DEFAULT_WORDS: usize = 12;
pub const XPARQ_MNEMONIC_12_ENTROPY_BYTES: usize = 16;
pub const XPARQ_MNEMONIC_24_ENTROPY_BYTES: usize = 32;

#[derive(Debug)]
pub struct ProfileWallet {
    pub mnemonic: Option<String>,
    pub address: Address,
    pub public_key: ProfilePublicKey,
    signing_seed: ProfileSigningSeed,
}

impl Drop for ProfileWallet {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
    }
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    address: String,
    mnemonic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
}

#[derive(Deserialize)]
struct WalletHeader {
    address: String,
}

pub fn wallet_address_from_file_bytes(bytes: &[u8]) -> Result<Address, String> {
    let header: WalletHeader = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;
    address_from_string(&header.address).map_err(|error| format!("invalid wallet address: {error}"))
}

pub fn profile_wallet_file_bytes(wallet: &ProfileWallet) -> Result<Zeroizing<Vec<u8>>, String> {
    let mnemonic = wallet
        .mnemonic
        .as_deref()
        .ok_or_else(|| "wallet has no mnemonic recovery material".to_string())?;
    decode_xparq_mnemonic(mnemonic)?;
    let wallet_file = WalletFile {
        address: address_to_string(&wallet.address),
        mnemonic: mnemonic.to_string(),
        signature_profile: Some(wallet.profile().as_str().to_string()),
        public_key: Some(hex::encode(&wallet.public_key.bytes)),
        private_key: Some(hex::encode(wallet.signing_seed.to_bytes())),
    };
    serde_json::to_vec_pretty(&wallet_file)
        .map(Zeroizing::new)
        .map_err(|error| format!("failed to encode wallet file: {error}"))
}

pub fn profile_wallet_from_file_bytes(bytes: &[u8]) -> Result<ProfileWallet, String> {
    let wallet_file: WalletFile = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;
    let profile = wallet_file
        .signature_profile
        .as_deref()
        .ok_or("wallet file does not contain a signature profile")?
        .parse::<SignatureProfile>()
        .map_err(str::to_string)?;
    let mut wallet = profile_wallet_from_xparq_mnemonic(&wallet_file.mnemonic, profile)?;
    let stored_address = address_from_string(&wallet_file.address)
        .map_err(|error| format!("invalid wallet address: {error}"))?;
    if wallet.address != stored_address {
        return Err("wallet address does not match its mnemonic and signature profile".to_string());
    }
    if let Some(public_key) = wallet_file.public_key.as_deref()
        && public_key != hex::encode(&wallet.public_key.bytes)
    {
        return Err("wallet public key does not match its mnemonic and signature profile".into());
    }
    if let Some(private_key) = wallet_file.private_key.as_deref()
        && private_key != hex::encode(wallet.signing_seed.to_bytes())
    {
        return Err("wallet private key does not match its mnemonic and signature profile".into());
    }
    wallet.mnemonic = Some(wallet_file.mnemonic.clone());
    Ok(wallet)
}

pub fn wallet_file_signature_profile(bytes: &[u8]) -> Result<Option<SignatureProfile>, String> {
    let wallet_file: WalletFile = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;
    wallet_file
        .signature_profile
        .as_deref()
        .map(|profile| profile.parse::<SignatureProfile>().map_err(str::to_string))
        .transpose()
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

pub fn profile_wallet_from_xparq_mnemonic(
    phrase: &str,
    profile: SignatureProfile,
) -> Result<ProfileWallet, String> {
    let entropy = decode_xparq_mnemonic(phrase)?;
    let mut tag = Vec::from(b"XPARQ_WALLET_SIGNATURE_PROFILE_V1".as_slice());
    tag.push(profile as u8);
    let seed = tagged_wallet_hash(&tag, &entropy);
    let signing_seed = ProfileSigningSeed::new(profile, seed);
    let public_key = signing_seed.public_key();
    Ok(ProfileWallet {
        mnemonic: None,
        address: address_from_profile_public_key(&public_key),
        public_key,
        signing_seed,
    })
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

/* Legacy wallet signing was removed after the profile-only chain reset.
impl Wallet {
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

impl FalconWallet {
    pub fn sign_onchain_spend(
        &self,
        intent: OnChainSpendIntent,
        public_key_known: bool,
    ) -> Result<AuthorizedAccountIntent<OnChainSpendIntent>, String> {
        self.sign_account_intent(intent, public_key_known)
    }

    pub fn sign_withdraw(
        &self,
        intent: WithdrawIntent,
        public_key_known: bool,
    ) -> Result<AuthorizedAccountIntent<WithdrawIntent>, String> {
        self.sign_account_intent(intent, public_key_known)
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
        let signature = falcon_sign(&self.secret_key, commitment.as_bytes())
            .map_err(|error| format!("Falcon-512 signing failed: {error:?}"))?;
        let authorization = if public_key_known {
            AccountAuthorization::Falcon512Known { signature }
        } else {
            AccountAuthorization::Falcon512Reveal {
                public_key: self.public_key.clone(),
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
            return Err("signed Falcon-512 transaction authorization is invalid".to_string());
        }
        Ok(signed)
    }
}
*/

impl ProfileWallet {
    pub const fn profile(&self) -> SignatureProfile {
        self.signing_seed.profile()
    }

    pub fn sign_account_intent<T: AccountIntent>(
        &self,
        intent: T,
        public_key_known: bool,
    ) -> Result<AuthorizedAccountIntent<T>, String> {
        let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
        let commitment = intent
            .commitment(chain)
            .map_err(|error| error.to_string())?;
        let signature = self.signing_seed.sign(commitment.as_bytes());
        let authorization = if public_key_known {
            AccountAuthorization::ProfileKnown {
                profile: self.profile(),
                signature,
            }
        } else {
            AccountAuthorization::ProfileReveal {
                public_key: self.public_key.clone(),
                signature,
            }
        };
        Ok(AuthorizedAccountIntent {
            intent,
            authorization,
        })
    }

    pub fn sign_asset_call(
        &self,
        action: xparq::extension::asset::AssetAction,
        nonce: u64,
    ) -> Result<xparq::common::ExtensionCall, String> {
        let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
        xparq::extension::asset::AssetCall::sign(
            chain.genesis_hash,
            action,
            nonce,
            &self.signing_seed,
        )
        .and_then(xparq::extension::asset::AssetCall::into_extension_call)
        .map_err(|error| format!("asset call signing failed: {error:?}"))
    }

    pub fn sign_wasm_deploy_call(
        &self,
        name: String,
        module: Vec<u8>,
        nonce: u64,
    ) -> Result<xparq::common::ExtensionCall, String> {
        let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
        xparq::extension::WasmDeployCall::sign(
            chain.genesis_hash,
            name,
            module,
            nonce,
            &self.signing_seed,
        )
        .and_then(xparq::extension::WasmDeployCall::into_extension_call)
        .map_err(|error| format!("WASM deploy call signing failed: {error:?}"))
    }

    pub fn sign_wasm_app_call(
        &self,
        extension_id: xparq::common::ExtensionId,
        payload: Vec<u8>,
        nonce: u64,
    ) -> Result<xparq::common::ExtensionCall, String> {
        let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
        xparq::extension::WasmAppCall::sign(
            chain.genesis_hash,
            extension_id,
            payload,
            nonce,
            &self.signing_seed,
        )
        .and_then(|call| call.into_extension_call(extension_id))
        .map_err(|error| format!("WASM application call signing failed: {error:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* Legacy wallet tests removed with the profile-only chain reset.
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

    #[test]
    fn mnemonic_restore_preserves_falcon_signing_identity() {
        let mnemonic = encode_xparq_mnemonic(&[10; XPARQ_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let first = falcon_wallet_from_xparq_mnemonic(&mnemonic).unwrap();
        let restored = falcon_wallet_from_xparq_mnemonic(&mnemonic).unwrap();
        assert_eq!(first.address, restored.address);
        assert_eq!(first.public_key, restored.public_key);
        assert_eq!(first.secret_key, restored.secret_key);
    }

    */
    #[test]
    fn mnemonic_derives_distinct_recoverable_profile_addresses() {
        let mnemonic = encode_xparq_mnemonic(&[12; XPARQ_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let profiles = [
            SignatureProfile::MlDsa44,
            SignatureProfile::MlDsa65,
            SignatureProfile::MlDsa87,
            SignatureProfile::Falcon512,
            SignatureProfile::Falcon1024,
        ];
        let first =
            profiles.map(|profile| profile_wallet_from_xparq_mnemonic(&mnemonic, profile).unwrap());
        let second =
            profiles.map(|profile| profile_wallet_from_xparq_mnemonic(&mnemonic, profile).unwrap());
        for (left, right) in first.iter().zip(&second) {
            assert_eq!(left.address, right.address);
        }
        let unique = first
            .iter()
            .map(|wallet| wallet.address)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), profiles.len());
    }

    #[test]
    fn profile_wallet_file_roundtrip_preserves_profile_and_identity() {
        let mnemonic = encode_xparq_mnemonic(&[13; XPARQ_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        for profile in [
            SignatureProfile::MlDsa44,
            SignatureProfile::MlDsa65,
            SignatureProfile::MlDsa87,
            SignatureProfile::Falcon512,
            SignatureProfile::Falcon1024,
        ] {
            let mut wallet = profile_wallet_from_xparq_mnemonic(&mnemonic, profile).unwrap();
            wallet.mnemonic = Some(mnemonic.clone());
            let bytes = profile_wallet_file_bytes(&wallet).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["public_key"], hex::encode(&wallet.public_key.bytes));
            assert_eq!(
                json["private_key"],
                hex::encode(wallet.signing_seed.to_bytes())
            );
            assert_eq!(
                wallet_file_signature_profile(&bytes).unwrap(),
                Some(profile)
            );
            let restored = profile_wallet_from_file_bytes(&bytes).unwrap();
            assert_eq!(restored.profile(), profile);
            assert_eq!(restored.address, wallet.address);
            assert_eq!(restored.public_key, wallet.public_key);
        }
    }

    #[test]
    fn profile_wallet_file_rejects_keys_that_do_not_match_recovery_material() {
        let mnemonic = encode_xparq_mnemonic(&[14; XPARQ_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let mut wallet =
            profile_wallet_from_xparq_mnemonic(&mnemonic, SignatureProfile::MlDsa44).unwrap();
        wallet.mnemonic = Some(mnemonic);
        let bytes = profile_wallet_file_bytes(&wallet).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        json["public_key"] = serde_json::Value::String("00".repeat(wallet.public_key.bytes.len()));
        let tampered_public = serde_json::to_vec(&json).unwrap();
        assert!(
            profile_wallet_from_file_bytes(&tampered_public)
                .unwrap_err()
                .contains("public key does not match")
        );

        json["public_key"] = serde_json::Value::String(hex::encode(&wallet.public_key.bytes));
        json["private_key"] = serde_json::Value::String("00".repeat(32));
        let tampered_private = serde_json::to_vec(&json).unwrap();
        assert!(
            profile_wallet_from_file_bytes(&tampered_private)
                .unwrap_err()
                .contains("private key does not match")
        );
    }
}
