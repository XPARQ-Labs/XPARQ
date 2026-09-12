use bip39::{Language, Mnemonic};
use kernel::{
    crypto::{
        Address, KemPublicKey, KemSeed, KeyExchange, PaymentAddress, PublicKey, Signature,
        SigningSeed, VaultOpening, address_from_public_key, address_from_string, address_to_string,
        decapsulate, encapsulate, hash_bytes, open_vault_opening, payment_address_from_public_keys,
        payment_address_to_string, seal_vault_opening,
    },
    transaction::{
        AccountAuthorization, AccountIntent, AuthorizedAccountIntent,
        AuthorizedVaultSpendTransaction, VaultAuthorization, VaultEnvelope, VaultId, VaultLock,
        VaultOutput, VaultSpendIntent, VaultValue,
    },
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const BIP39_MNEMONIC_DEFAULT_WORDS: usize = 12;
pub const BIP39_MNEMONIC_12_ENTROPY_BYTES: usize = 16;
pub const BIP39_MNEMONIC_24_ENTROPY_BYTES: usize = 32;

#[derive(Debug)]
pub struct AccountWallet {
    pub mnemonic: Option<String>,
    pub address: Address,
    pub public_key: PublicKey,
    signing_seed: SigningSeed,
    pub kem_public_key: KemPublicKey,
    kem_seed: KemSeed,
}

#[derive(Debug)]
pub struct OwnedVault {
    pub id: VaultId,
    pub value: VaultValue,
    opening: VaultOpening,
}

impl OwnedVault {
    pub const fn opening(&self) -> &VaultOpening {
        &self.opening
    }
}

impl Drop for AccountWallet {
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
    signature_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payment_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kem_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kem_private_key: Option<String>,
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

pub fn account_wallet_file_bytes(wallet: &AccountWallet) -> Result<Zeroizing<Vec<u8>>, String> {
    let mnemonic = wallet
        .mnemonic
        .as_deref()
        .ok_or_else(|| "wallet has no mnemonic recovery material".to_string())?;
    decode_bip39_mnemonic(mnemonic)?;
    let wallet_file = WalletFile {
        address: address_to_string(&wallet.address),
        mnemonic: mnemonic.to_string(),
        signature_account: Some(wallet.account().as_str().to_string()),
        public_key: Some(hex::encode(&wallet.public_key.bytes)),
        private_key: Some(hex::encode(wallet.signing_seed.to_bytes())),
        payment_address: Some(wallet.payment_address_string()),
        kem_public_key: Some(hex::encode(wallet.kem_public_key.as_bytes())),
        kem_private_key: Some(hex::encode(wallet.kem_seed.to_bytes())),
    };
    serde_json::to_vec_pretty(&wallet_file)
        .map(Zeroizing::new)
        .map_err(|error| format!("failed to encode wallet file: {error}"))
}

pub fn account_wallet_from_file_bytes(bytes: &[u8]) -> Result<AccountWallet, String> {
    let wallet_file: WalletFile = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;
    let account = wallet_file
        .signature_account
        .as_deref()
        .ok_or("wallet file does not contain a signature account")?
        .parse::<Signature>()
        .map_err(str::to_string)?;
    let mut wallet = account_wallet_from_bip39_mnemonic(&wallet_file.mnemonic, account)?;
    let stored_address = address_from_string(&wallet_file.address)
        .map_err(|error| format!("invalid wallet address: {error}"))?;
    if wallet.address != stored_address {
        return Err("wallet address does not match its mnemonic and signature account".to_string());
    }
    if let Some(public_key) = wallet_file.public_key.as_deref()
        && public_key != hex::encode(&wallet.public_key.bytes)
    {
        return Err("wallet public key does not match its mnemonic and signature account".into());
    }
    if let Some(private_key) = wallet_file.private_key.as_deref()
        && private_key != hex::encode(wallet.signing_seed.to_bytes())
    {
        return Err("wallet private key does not match its mnemonic and signature account".into());
    }
    if let Some(public_key) = wallet_file.kem_public_key.as_deref()
        && public_key != hex::encode(wallet.kem_public_key.as_bytes())
    {
        return Err("wallet KEM public key does not match its mnemonic".into());
    }
    if let Some(private_key) = wallet_file.kem_private_key.as_deref()
        && private_key != hex::encode(wallet.kem_seed.to_bytes())
    {
        return Err("wallet KEM private key does not match its mnemonic".into());
    }
    if let Some(payment_address) = wallet_file.payment_address.as_deref()
        && payment_address != wallet.payment_address_string()
    {
        return Err("wallet payment address does not match its mnemonic and keys".into());
    }
    wallet.mnemonic = Some(wallet_file.mnemonic.clone());
    Ok(wallet)
}

pub fn wallet_file_signature_account(bytes: &[u8]) -> Result<Option<Signature>, String> {
    let wallet_file: WalletFile = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;
    wallet_file
        .signature_account
        .as_deref()
        .map(|account| account.parse::<Signature>().map_err(str::to_string))
        .transpose()
}

pub fn generate_bip39_mnemonic(words: usize) -> Result<Zeroizing<String>, String> {
    let entropy_len = match words {
        12 => BIP39_MNEMONIC_12_ENTROPY_BYTES,
        24 => BIP39_MNEMONIC_24_ENTROPY_BYTES,
        _ => return Err("mnemonic words must be 12 or 24".to_string()),
    };
    let mut entropy = Zeroizing::new(vec![0_u8; entropy_len]);
    getrandom::fill(&mut entropy)
        .map_err(|error| format!("secure random generation failed: {error}"))?;
    encode_bip39_mnemonic(&entropy).map(Zeroizing::new)
}

pub fn account_wallet_from_bip39_mnemonic(
    phrase: &str,
    account: Signature,
) -> Result<AccountWallet, String> {
    let entropy = decode_bip39_mnemonic(phrase)?;
    let mut tag = Vec::from(b"XPARQ_WALLET_SIGNATURE_ACCOUNT".as_slice());
    tag.push(account as u8);
    let seed = tagged_wallet_hash(&tag, &entropy);
    let signing_seed = SigningSeed::new(account, seed);
    let public_key = signing_seed.public_key();
    let kem_seed = KemSeed::new(
        KeyExchange::MlKem768,
        tagged_wallet_hash64(b"XPARQ_WALLET_ML_KEM_768", &entropy),
    );
    let kem_public_key = kem_seed.public_key();
    Ok(AccountWallet {
        mnemonic: None,
        address: address_from_public_key(&public_key),
        public_key,
        signing_seed,
        kem_public_key,
        kem_seed,
    })
}

pub fn encode_bip39_mnemonic(entropy: &[u8]) -> Result<String, String> {
    Mnemonic::from_entropy_in(Language::English, entropy)
        .map(|mnemonic| mnemonic.to_string())
        .map_err(|error| format!("failed to encode mnemonic: {error}"))
}

pub fn decode_bip39_mnemonic(phrase: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let normalized = Zeroizing::new(
        phrase
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join(" "),
    );
    let word_count = normalized.split_whitespace().count();
    if !matches!(word_count, 12 | 24) {
        return Err("invalid bip39 mnemonic: expected 12 or 24 words".to_string());
    }
    Mnemonic::parse_in_normalized(Language::English, &normalized)
        .map(|mnemonic| Zeroizing::new(mnemonic.to_entropy()))
        .map_err(|error| format!("invalid bip39 mnemonic: {error}"))
}

fn tagged_wallet_hash(tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut payload = Zeroizing::new(Vec::with_capacity(tag.len() + bytes.len()));
    payload.extend_from_slice(tag);
    payload.extend_from_slice(bytes);
    hash_bytes(&payload).0
}

fn tagged_wallet_hash64(tag: &[u8], bytes: &[u8]) -> [u8; 64] {
    let mut first_tag = Zeroizing::new(Vec::with_capacity(tag.len() + 1));
    first_tag.extend_from_slice(tag);
    first_tag.push(0);
    let first = tagged_wallet_hash(&first_tag, bytes);

    let mut second_tag = Zeroizing::new(Vec::with_capacity(tag.len() + 1));
    second_tag.extend_from_slice(tag);
    second_tag.push(1);
    let second = tagged_wallet_hash(&second_tag, bytes);

    let mut seed = [0; 64];
    seed[..32].copy_from_slice(&first);
    seed[32..].copy_from_slice(&second);
    seed
}

impl AccountWallet {
    pub const fn account(&self) -> Signature {
        self.signing_seed.account()
    }

    pub fn payment_address(&self) -> PaymentAddress {
        payment_address_from_public_keys(self.public_key.clone(), self.kem_public_key.clone())
    }

    pub fn payment_address_string(&self) -> String {
        payment_address_to_string(&self.payment_address())
    }

    pub fn create_vault_output(
        recipient: &PaymentAddress,
        value: VaultValue,
    ) -> Result<(VaultOutput, VaultOpening), String> {
        value.validate().map_err(|error| error.to_string())?;
        let mut opening_bytes = [0_u8; 32];
        getrandom::fill(&mut opening_bytes)
            .map_err(|error| format!("secure vault opening generation failed: {error}"))?;
        let opening = VaultOpening::from_bytes(opening_bytes);
        let lock = VaultLock::derive(&recipient.spend_public_key, opening.as_bytes());
        let (ciphertext, shared) =
            encapsulate(&recipient.kem_public_key).map_err(|error| error.to_string())?;
        let context = vault_envelope_context(lock)?;
        let payload = seal_vault_opening(&shared, &context, &opening);
        let output = VaultOutput::new(value, lock, VaultEnvelope::new(ciphertext, payload))
            .map_err(|error| error.to_string())?;
        Ok((output, opening))
    }

    pub fn scan_vault(
        &self,
        id: VaultId,
        output: &VaultOutput,
    ) -> Result<Option<OwnedVault>, String> {
        if output.envelope.kem_ciphertext().kem() != self.kem_seed.kem() {
            return Ok(None);
        }
        let shared = decapsulate(&self.kem_seed, output.envelope.kem_ciphertext())
            .map_err(|error| error.to_string())?;
        let context = vault_envelope_context(output.lock)?;
        let opening =
            match open_vault_opening(&shared, &context, output.envelope.encrypted_payload()) {
                Ok(opening) => opening,
                Err(_) => return Ok(None),
            };
        if VaultLock::derive(&self.public_key, opening.as_bytes()) != output.lock {
            return Ok(None);
        }
        Ok(Some(OwnedVault {
            id,
            value: output.value,
            opening,
        }))
    }

    pub fn authorize_vault_spend(
        &self,
        intent: VaultSpendIntent,
        owned: &[OwnedVault],
        payment: Option<AuthorizedAccountIntent<kernel::transaction::SpendIntent>>,
    ) -> Result<AuthorizedVaultSpendTransaction, String> {
        intent.validate().map_err(|error| error.to_string())?;
        let chain = kernel::genesis::chain_context().map_err(|error| error.to_string())?;
        let commitment = intent
            .commitment(chain)
            .map_err(|error| error.to_string())?;
        let mut authorizations = Vec::with_capacity(intent.inputs.len());
        for id in &intent.inputs {
            let vault = owned.iter().find(|vault| vault.id == *id).ok_or_else(|| {
                format!("wallet does not own vault {}", hex::encode(id.as_bytes()))
            })?;
            authorizations.push(VaultAuthorization {
                vault: *id,
                public_key: self.public_key.clone(),
                opening: *vault.opening.as_bytes(),
                signature: self.signing_seed.sign(commitment.as_bytes()),
            });
        }
        Ok(AuthorizedVaultSpendTransaction {
            spend: intent,
            authorizations,
            payment,
        })
    }

    pub fn sign_account_intent<T: AccountIntent>(
        &self,
        intent: T,
        public_key_known: bool,
    ) -> Result<AuthorizedAccountIntent<T>, String> {
        let chain = kernel::genesis::chain_context().map_err(|error| error.to_string())?;
        let commitment = intent
            .commitment(chain)
            .map_err(|error| error.to_string())?;
        let signature = self.signing_seed.sign(commitment.as_bytes());
        let authorization = if public_key_known {
            AccountAuthorization::AccountKnown {
                account: self.account(),
                signature,
            }
        } else {
            AccountAuthorization::AccountReveal {
                public_key: self.public_key.clone(),
                signature,
            }
        };
        Ok(AuthorizedAccountIntent {
            intent,
            authorization,
        })
    }

    pub fn sign_asset_intent(
        &self,
        action: kernel::transaction::AssetInstruction,
        public_key_known: bool,
    ) -> Result<AuthorizedAccountIntent<kernel::transaction::AssetIntent>, String> {
        self.sign_account_intent(
            kernel::transaction::AssetIntent::new(action, self.address),
            public_key_known,
        )
    }
}

fn vault_envelope_context(lock: VaultLock) -> Result<Vec<u8>, String> {
    let chain = kernel::genesis::chain_context().map_err(|error| error.to_string())?;
    kernel::crypto::canonical_bytes(&(chain.genesis_hash, lock))
        .map_err(|error| format!("vault envelope context encoding failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_address_vault_is_discovered_only_by_recipient() {
        let alice_phrase = encode_bip39_mnemonic(&[21; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let bob_phrase = encode_bip39_mnemonic(&[22; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let alice = account_wallet_from_bip39_mnemonic(&alice_phrase, Signature::MlDsa44).unwrap();
        let bob = account_wallet_from_bip39_mnemonic(&bob_phrase, Signature::MlDsa44).unwrap();
        let (output, opening) = AccountWallet::create_vault_output(
            &bob.payment_address(),
            VaultValue::coin(kernel::native::coin::Zeno::from_zeno(10)),
        )
        .unwrap();
        let id = VaultId::from_bytes([8; 32]);
        let discovered = bob.scan_vault(id, &output).unwrap().unwrap();
        assert_eq!(discovered.id, id);
        assert_eq!(discovered.opening().as_bytes(), opening.as_bytes());
        assert!(alice.scan_vault(id, &output).unwrap().is_none());

        let mut payload = output.envelope.encrypted_payload().to_vec();
        payload[0] ^= 1;
        let corrupted = VaultOutput::new(
            output.value,
            output.lock,
            VaultEnvelope::new(output.envelope.kem_ciphertext().clone(), payload),
        )
        .unwrap();
        assert!(bob.scan_vault(id, &corrupted).unwrap().is_none());
    }

    /* Legacy wallet tests removed with the account-only chain reset.
    #[test]
    fn wallet_file_roundtrip_preserves_signing_identity() {
        let mnemonic = encode_bip39_mnemonic(&[7; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let mut wallet = wallet_from_bip39_mnemonic(&mnemonic).unwrap();
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
        let mnemonic = encode_bip39_mnemonic(&[8; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let wallet = wallet_from_bip39_mnemonic(&mnemonic).unwrap();
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
        let mnemonic = encode_bip39_mnemonic(&[9; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let mut first = wallet_from_bip39_mnemonic(&mnemonic).unwrap();
        first.mnemonic = Some(mnemonic.clone());
        let first_file = wallet_file_bytes(&first).unwrap();

        let mut restored = wallet_from_bip39_mnemonic(&mnemonic).unwrap();
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
        let mnemonic = encode_bip39_mnemonic(&[10; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let first = falcon_wallet_from_bip39_mnemonic(&mnemonic).unwrap();
        let restored = falcon_wallet_from_bip39_mnemonic(&mnemonic).unwrap();
        assert_eq!(first.address, restored.address);
        assert_eq!(first.public_key, restored.public_key);
        assert_eq!(first.secret_key, restored.secret_key);
    }

    */
    #[test]
    fn mnemonic_derives_distinct_recoverable_account_addresses() {
        let mnemonic = encode_bip39_mnemonic(&[12; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let accounts = [
            Signature::MlDsa44,
            Signature::MlDsa65,
            Signature::MlDsa87,
            Signature::Falcon512,
            Signature::Falcon1024,
        ];
        let first =
            accounts.map(|account| account_wallet_from_bip39_mnemonic(&mnemonic, account).unwrap());
        let second =
            accounts.map(|account| account_wallet_from_bip39_mnemonic(&mnemonic, account).unwrap());
        for (left, right) in first.iter().zip(&second) {
            assert_eq!(left.address, right.address);
        }
        let unique = first
            .iter()
            .map(|wallet| wallet.address)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), accounts.len());
    }

    #[test]
    fn account_wallet_file_roundtrip_preserves_account_and_identity() {
        let mnemonic = encode_bip39_mnemonic(&[13; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        for account in [
            Signature::MlDsa44,
            Signature::MlDsa65,
            Signature::MlDsa87,
            Signature::Falcon512,
            Signature::Falcon1024,
        ] {
            let mut wallet = account_wallet_from_bip39_mnemonic(&mnemonic, account).unwrap();
            wallet.mnemonic = Some(mnemonic.clone());
            let bytes = account_wallet_file_bytes(&wallet).unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["public_key"], hex::encode(&wallet.public_key.bytes));
            assert_eq!(
                json["private_key"],
                hex::encode(wallet.signing_seed.to_bytes())
            );
            assert_eq!(
                json["kem_public_key"],
                hex::encode(wallet.kem_public_key.as_bytes())
            );
            assert_eq!(
                json["kem_private_key"],
                hex::encode(wallet.kem_seed.to_bytes())
            );
            assert_eq!(json["payment_address"], wallet.payment_address_string());
            assert_eq!(
                wallet_file_signature_account(&bytes).unwrap(),
                Some(account)
            );
            let restored = account_wallet_from_file_bytes(&bytes).unwrap();
            assert_eq!(restored.account(), account);
            assert_eq!(restored.address, wallet.address);
            assert_eq!(restored.public_key, wallet.public_key);
        }
    }

    #[test]
    fn account_wallet_file_rejects_keys_that_do_not_match_recovery_material() {
        let mnemonic = encode_bip39_mnemonic(&[14; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let mut wallet = account_wallet_from_bip39_mnemonic(&mnemonic, Signature::MlDsa44).unwrap();
        wallet.mnemonic = Some(mnemonic);
        let bytes = account_wallet_file_bytes(&wallet).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        json["public_key"] = serde_json::Value::String("00".repeat(wallet.public_key.bytes.len()));
        let tampered_public = serde_json::to_vec(&json).unwrap();
        assert!(
            account_wallet_from_file_bytes(&tampered_public)
                .unwrap_err()
                .contains("public key does not match")
        );

        json["public_key"] = serde_json::Value::String(hex::encode(&wallet.public_key.bytes));
        json["private_key"] = serde_json::Value::String("00".repeat(32));
        let tampered_private = serde_json::to_vec(&json).unwrap();
        assert!(
            account_wallet_from_file_bytes(&tampered_private)
                .unwrap_err()
                .contains("private key does not match")
        );

        json["private_key"] =
            serde_json::Value::String(hex::encode(wallet.signing_seed.to_bytes()));
        json["kem_public_key"] =
            serde_json::Value::String("00".repeat(wallet.kem_public_key.as_bytes().len()));
        let tampered_kem_public = serde_json::to_vec(&json).unwrap();
        assert!(
            account_wallet_from_file_bytes(&tampered_kem_public)
                .unwrap_err()
                .contains("KEM public key does not match")
        );

        json["kem_public_key"] =
            serde_json::Value::String(hex::encode(wallet.kem_public_key.as_bytes()));
        json["kem_private_key"] = serde_json::Value::String("00".repeat(64));
        let tampered_kem_private = serde_json::to_vec(&json).unwrap();
        assert!(
            account_wallet_from_file_bytes(&tampered_kem_private)
                .unwrap_err()
                .contains("KEM private key does not match")
        );

        json["kem_private_key"] =
            serde_json::Value::String(hex::encode(wallet.kem_seed.to_bytes()));
        json["payment_address"] = serde_json::Value::String("Qp00".into());
        let tampered_payment_address = serde_json::to_vec(&json).unwrap();
        assert!(
            account_wallet_from_file_bytes(&tampered_payment_address)
                .unwrap_err()
                .contains("payment address does not match")
        );
    }

    #[test]
    fn wallet_without_kem_fields_recovers_them_from_mnemonic() {
        let mnemonic = encode_bip39_mnemonic(&[15; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();
        let mut wallet = account_wallet_from_bip39_mnemonic(&mnemonic, Signature::MlDsa44).unwrap();
        wallet.mnemonic = Some(mnemonic);
        let bytes = account_wallet_file_bytes(&wallet).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = json.as_object_mut().unwrap();
        object.remove("payment_address");
        object.remove("kem_public_key");
        object.remove("kem_private_key");

        let legacy = serde_json::to_vec(&json).unwrap();
        let recovered = account_wallet_from_file_bytes(&legacy).unwrap();
        assert_eq!(recovered.kem_public_key, wallet.kem_public_key);
        assert_eq!(recovered.payment_address(), wallet.payment_address());
    }
}
