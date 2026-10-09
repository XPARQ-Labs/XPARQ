use bip39::{Language, Mnemonic};

use kernel::crypto::{
    ProgramId, PublicKey, Signature, SigningSeed, hash_bytes, program_id_from_public_key,
    program_id_from_string, program_id_to_string,
};

use serde::{Deserialize, Serialize};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const WALLET_FILE_VERSION: u32 = 2;
pub const MAX_WALLET_ACCOUNTS: usize = 256;

pub const BIP39_MNEMONIC_DEFAULT_WORDS: usize = 12;

pub const BIP39_MNEMONIC_12_ENTROPY_BYTES: usize = 16;

pub const BIP39_MNEMONIC_24_ENTROPY_BYTES: usize = 32;

#[derive(Debug)]

pub struct AccountWallet {
    pub mnemonic: Option<String>,

    pub program_id: ProgramId,

    pub public_key: PublicKey,
    pub account_salt: kernel::crypto::AccountSalt,
    pub account_salts: Vec<kernel::crypto::AccountSalt>,

    signing_seed: SigningSeed,
}

impl Drop for AccountWallet {
    fn drop(&mut self) {
        self.mnemonic.zeroize();
    }
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]

struct WalletFile {
    version: u32,
    account_salt: String,
    account_salts: Vec<String>,
    program_id: String,

    mnemonic: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature_account: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
}

#[derive(Deserialize)]

struct WalletHeader {
    version: u32,
    program_id: String,
}

pub fn wallet_program_id_from_file_bytes(bytes: &[u8]) -> Result<ProgramId, String> {
    let header: WalletHeader = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;

    if header.version != WALLET_FILE_VERSION {
        return Err("unsupported wallet file version; restore with the new account salt".into());
    }
    program_id_from_string(&header.program_id)
        .map_err(|error| format!("invalid wallet program_id: {error}"))
}

pub fn account_wallet_file_bytes(wallet: &AccountWallet) -> Result<Zeroizing<Vec<u8>>, String> {
    let mnemonic = wallet
        .mnemonic
        .as_deref()
        .ok_or_else(|| "wallet has no mnemonic recovery material".to_string())?;

    decode_bip39_mnemonic(mnemonic)?;

    wallet.validate_account_metadata()?;
    let wallet_file = WalletFile {
        version: WALLET_FILE_VERSION,
        account_salt: hex::encode(wallet.account_salt),
        account_salts: wallet.account_salts.iter().map(hex::encode).collect(),
        program_id: program_id_to_string(&wallet.program_id),

        mnemonic: mnemonic.to_string(),

        signature_account: Some(wallet.account().as_str().to_string()),

        public_key: Some(hex::encode(&wallet.public_key.bytes)),

        private_key: Some({
            let seed = wallet.signing_seed.dangerous_export_seed();

            hex::encode(&seed[..])
        }),
    };

    serde_json::to_vec_pretty(&wallet_file)
        .map(Zeroizing::new)
        .map_err(|error| format!("failed to encode wallet file: {error}"))
}

pub fn account_wallet_from_file_bytes(bytes: &[u8]) -> Result<AccountWallet, String> {
    let wallet_file: WalletFile = serde_json::from_slice(bytes)
        .map_err(|error| format!("failed to parse wallet: {error}"))?;

    if wallet_file.version != WALLET_FILE_VERSION {
        return Err("unsupported wallet file version".into());
    }
    let salt = account_salt_from_string(&wallet_file.account_salt)?;
    let salts = wallet_file
        .account_salts
        .iter()
        .map(|salt| account_salt_from_string(salt))
        .collect::<Result<Vec<_>, _>>()?;
    let account = wallet_file
        .signature_account
        .as_deref()
        .ok_or("wallet file does not contain a signature account")?
        .parse::<Signature>()
        .map_err(str::to_string)?;

    let mut wallet = account_wallet_from_bip39_mnemonic(&wallet_file.mnemonic, account)?;

    wallet.account_salts = salts;
    wallet.account_salt = salt;
    wallet.program_id =
        kernel::crypto::program_id_from_public_key_with_salt(&wallet.public_key, &salt)
            .map_err(|error| error.to_string())?;
    wallet.validate_account_metadata()?;
    let stored_program_id = program_id_from_string(&wallet_file.program_id)
        .map_err(|error| format!("invalid wallet program_id: {error}"))?;

    if wallet.program_id != stored_program_id {
        return Err(
            "wallet program-id does not match its mnemonic and signature account".to_string(),
        );
    }

    if let Some(public_key) = wallet_file.public_key.as_deref()
        && public_key != hex::encode(&wallet.public_key.bytes)
    {
        return Err("wallet public key does not match its mnemonic and signature account".into());
    }

    if let Some(private_key) = wallet_file.private_key.as_deref() {
        let expected_private_key = {
            let seed = wallet.signing_seed.dangerous_export_seed();

            Zeroizing::new(hex::encode(&seed[..]))
        };

        if private_key != expected_private_key.as_str() {
            return Err(
                "wallet private key does not match its mnemonic and signature account".into(),
            );
        }
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

    tag.push(account.id());

    let seed = tagged_wallet_hash(&tag, &entropy);

    let mut boxed_seed = Box::new([0_u8; 32]);

    boxed_seed.copy_from_slice(seed.as_ref());

    let signing_seed = SigningSeed::new(account, boxed_seed);

    let public_key = signing_seed.public_key();

    Ok(AccountWallet {
        mnemonic: None,

        program_id: program_id_from_public_key(&public_key).map_err(|error| error.to_string())?,

        public_key,
        account_salt: kernel::crypto::DEFAULT_ACCOUNT_SALT,
        account_salts: vec![kernel::crypto::DEFAULT_ACCOUNT_SALT],
        signing_seed,
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

fn tagged_wallet_hash(tag: &[u8], bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut payload = Zeroizing::new(Vec::with_capacity(tag.len() + bytes.len()));

    payload.extend_from_slice(tag);

    payload.extend_from_slice(bytes);

    Zeroizing::new(hash_bytes(&payload).0)
}

pub fn account_salt_from_string(value: &str) -> Result<kernel::crypto::AccountSalt, String> {
    if value.len() != 64 {
        return Err("account salt must be 64 hexadecimal characters".into());
    }
    let mut salt = [0; 32];
    hex::decode_to_slice(value, &mut salt)
        .map_err(|_| "invalid hexadecimal account salt".to_string())?;
    Ok(salt)
}

impl AccountWallet {
    fn validate_account_metadata(&self) -> Result<(), String> {
        let unique: std::collections::BTreeSet<_> = self.account_salts.iter().collect();
        if self.account_salts.is_empty()
            || self.account_salts.len() > MAX_WALLET_ACCOUNTS
            || unique.len() != self.account_salts.len()
            || !self.account_salts.contains(&self.account_salt)
        {
            return Err("invalid wallet account salt list".into());
        }
        let expected = kernel::crypto::program_id_from_public_key_with_salt(
            &self.public_key,
            &self.account_salt,
        )
        .map_err(|error| error.to_string())?;
        if expected != self.program_id {
            return Err("wallet program-id does not match its public key and salt".into());
        }
        Ok(())
    }
    pub fn select_account(
        &mut self,
        salt: kernel::crypto::AccountSalt,
    ) -> Result<ProgramId, String> {
        self.validate_account_metadata()?;
        let id = kernel::crypto::program_id_from_public_key_with_salt(&self.public_key, &salt)
            .map_err(|error| error.to_string())?;
        if !self.account_salts.contains(&salt) {
            if self.account_salts.len() >= MAX_WALLET_ACCOUNTS {
                return Err("wallet account limit reached".into());
            }
            self.account_salts.push(salt);
        }
        self.account_salt = salt;
        self.program_id = id;
        Ok(id)
    }

    pub const fn account(&self) -> Signature {
        self.signing_seed.account()
    }

    /// Sign a native XPQ.Transfer ProgramCall, binding its transfer and fee.
    pub fn sign_xpq_transfer(
        &self,
        payment: kernel::program::CoinTransition,
    ) -> Result<kernel::program::AuthorizedProgramInvocation, String> {
        self.sign_program_call(extension::coin_program::transfer_call(), payment)
    }

    /// Bind the extension call and its XPQ payment in one authorization.
    pub fn sign_program_call(
        &self,
        call: extension::script::call::ProgramCall,
        payment: kernel::program::CoinTransition,
    ) -> Result<kernel::program::AuthorizedProgramInvocation, String> {
        self.validate_account_metadata()?;
        let chain = kernel::genesis::chain_context().map_err(|e| e.to_string())?;
        let commitment =
            kernel::program::program_invocation_commitment(self.program_id, &call, &payment, chain)
                .map_err(|e| e.to_string())?;
        Ok(kernel::program::AuthorizedProgramInvocation {
            signer: self.program_id,
            call,
            payment,
            authorization: kernel::program::AccountAuthorization {
                salt: self.account_salt,
                public_key: self.public_key.clone(),
                signature: self.signing_seed.sign(commitment.as_bytes()),
            },
        })
    }

    pub fn sign_deploy_program(
        &self,
        deploy: kernel::program::DeployProgram,
        payment: kernel::program::CoinTransition,
    ) -> Result<kernel::operation::AuthorizedDeployProgram, String> {
        if deploy.owner != self.program_id {
            return Err("deploy owner does not match wallet program_id".into());
        }
        self.validate_account_metadata()?;
        let chain = kernel::genesis::chain_context().map_err(|e| e.to_string())?;
        let mut signed = kernel::operation::AuthorizedDeployProgram {
            deploy,
            payment,
            authorization: kernel::program::AccountAuthorization {
                salt: self.account_salt,
                public_key: self.public_key.clone(),
                signature: kernel::crypto::AccountSignature {
                    account: self.account(),
                    bytes: vec![0; self.account().signature_size()],
                },
            },
        };
        let commitment = signed.commitment(chain).map_err(|e| e.to_string())?;
        signed.authorization.signature = self.signing_seed.sign(commitment.as_bytes());
        Ok(signed)
    }
}

#[cfg(test)]

mod tests {

    use super::*;

    /* Legacy wallet tests removed with the account-only chain reset.

    #[test]

    fn wallet_file_roundtrip_preserves_signing_identity() {

        let mnemonic = encode_bip39_mnemonic(&[7; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();

        let mut wallet = wallet_from_bip39_mnemonic(&mnemonic).unwrap();

        wallet.mnemonic = Some(mnemonic.clone());

        let encoded = wallet_file_bytes(&wallet).unwrap();

        let decoded = wallet_from_file_bytes(&encoded).unwrap();

        assert_eq!(decoded.program_id, wallet.program_id);

        assert_eq!(decoded.public_key, wallet.public_key);

        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(json.as_object().unwrap().len(), 2);

        assert_eq!(json.get("mnemonic").unwrap(), &mnemonic);

        assert_eq!(

            json.get("program_id").unwrap().as_str(),

            Some(wallet_program_id_string(&wallet).as_str())

        );

        assert!(json.get("secret_key").is_none());

        assert!(encoded.len() < 512);

    }

    #[test]

    fn wallet_program_id_reader_accepts_legacy_version_field() {

        let mnemonic = encode_bip39_mnemonic(&[8; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();

        let wallet = wallet_from_bip39_mnemonic(&mnemonic).unwrap();

        let encoded = serde_json::to_vec(&serde_json::json!({

            "version": 1,

            "program_id": wallet_program_id_string(&wallet),

            "mnemonic": mnemonic,

        }))

        .unwrap();

        assert_eq!(wallet_program_id_from_file_bytes(&encoded), Ok(wallet.program_id));

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

        assert_eq!(first.program_id, restored.program_id);

        assert_eq!(first.public_key, restored.public_key);

        assert_eq!(

            wallet_from_file_bytes(&first_file).unwrap().program_id,

            wallet_from_file_bytes(&restored_file).unwrap().program_id

        );

    }

    */

    #[test]
    fn one_key_restores_multiple_salted_accounts_and_rejects_invalid_metadata() {
        let phrase = encode_bip39_mnemonic(&[19; 16]).unwrap();
        for scheme in [Signature::MlDsa44, Signature::MlDsa65, Signature::MlDsa87] {
            let mut wallet = account_wallet_from_bip39_mnemonic(&phrase, scheme).unwrap();
            wallet.mnemonic = Some(phrase.clone());
            let key = wallet.public_key.clone();
            let first = wallet.program_id;
            let second = wallet.select_account([1; 32]).unwrap();
            let third = wallet.select_account([2; 32]).unwrap();
            assert_eq!(wallet.public_key, key);
            assert_eq!(
                [first, second, third]
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                3
            );
            let bytes = account_wallet_file_bytes(&wallet).unwrap();
            let mut restored = account_wallet_from_file_bytes(&bytes).unwrap();
            assert_eq!(restored.program_id, third);
            assert_eq!(restored.account_salts, vec![[0; 32], [1; 32], [2; 32]]);
            assert_eq!(restored.select_account([1; 32]).unwrap(), second);
            assert_eq!(restored.select_account([0; 32]).unwrap(), first);
            assert_eq!(restored.public_key, key);
            for case in 0..4 {
                let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                match case {
                    0 => json["account_salt"] = hex::encode([3; 32]).into(),
                    1 => json["account_salts"] = serde_json::json!([hex::encode([0; 32])]),
                    2 => {
                        json["account_salts"] =
                            serde_json::json!([hex::encode([2; 32]), hex::encode([2; 32])])
                    }
                    _ => json["version"] = 1.into(),
                }
                assert!(
                    account_wallet_from_file_bytes(&serde_json::to_vec(&json).unwrap()).is_err()
                );
            }
        }
    }

    #[test]
    fn salted_accounts_spend_and_deploy_end_to_end_without_cross_account_authority() {
        use borsh::BorshDeserialize;
        use kernel::{
            common::{Height, Owner},
            ledger::{CoinUtxo, LedgerState, UtxoSet},
            monetary::coin::{CoinOutput, CoinShare, Zeno},
            operation::BlockOperation,
            program::{CoinTransition, DeployProgram},
        };
        let phrase = encode_bip39_mnemonic(&[20; 16]).unwrap();
        let mut alice = account_wallet_from_bip39_mnemonic(&phrase, Signature::MlDsa44).unwrap();
        alice.select_account([1; 32]).unwrap();
        let mut bob = account_wallet_from_bip39_mnemonic(&phrase, Signature::MlDsa44).unwrap();
        bob.select_account([2; 32]).unwrap();
        assert_eq!(alice.public_key, bob.public_key);
        let input_a = CoinShare::from_bytes([1; 32]);
        let input_b = CoinShare::from_bytes([2; 32]);
        let coins = std::collections::BTreeMap::from([
            (
                input_a,
                CoinUtxo {
                    amount: Zeno::from_zeno(1_000_000),
                    owner: Owner::Program(alice.program_id),
                },
            ),
            (
                input_b,
                CoinUtxo {
                    amount: Zeno::from_zeno(1_000_000),
                    owner: Owner::Program(bob.program_id),
                },
            ),
        ]);
        let mut state = LedgerState::default();
        state.utxos =
            UtxoSet::try_from_slice(&borsh::to_vec(&(coins, Zeno::from_zeno(2_000_000))).unwrap())
                .unwrap();
        state.coin.total_mined = Zeno::from_zeno(2_000_000);
        state.audit_supply_invariants().unwrap();
        let chain = kernel::genesis::chain_context().unwrap();
        let payment = |signer, amount| {
            CoinTransition::coin(
                signer,
                vec![input_a],
                vec![CoinOutput::new(bob.program_id, Zeno::from_zeno(amount))],
            )
            .unwrap()
        };
        let provisional = alice
            .sign_xpq_transfer(payment(alice.program_id, 1_000_000))
            .unwrap();
        let burn =
            kernel::crypto::canonical_length(&BlockOperation::ProgramCall(Box::new(provisional)))
                .unwrap();
        let signed = alice
            .sign_xpq_transfer(payment(alice.program_id, 1_000_000 - burn))
            .unwrap();
        assert_eq!(signed.authorization.salt, [1; 32]);
        assert!(signed.verify_authorizations(chain, 1).unwrap());
        let mut forged = signed.clone();
        forged.authorization.salt = [2; 32];
        assert!(!forged.verify_authorizations(chain, 1).unwrap());
        let mut relabeled = signed.clone();
        relabeled.signer = bob.program_id;
        relabeled.payment.signer = bob.program_id;
        relabeled.authorization.salt = [2; 32];
        assert!(!relabeled.verify_authorizations(chain, 1).unwrap());
        let original = state.clone();
        assert!(
            state
                .apply_program_call_with_applications(
                    forged,
                    ProgramId::ZERO,
                    chain,
                    1,
                    &extension::SystemApplications
                )
                .is_err()
        );
        assert_eq!(state, original);
        let other = bob
            .sign_xpq_transfer(payment(bob.program_id, 1_000_000 - burn))
            .unwrap();
        assert!(other.verify_authorizations(chain, 1).unwrap());
        assert!(
            state
                .apply_program_call_with_applications(
                    other,
                    ProgramId::ZERO,
                    chain,
                    1,
                    &extension::SystemApplications
                )
                .is_err()
        );
        assert_eq!(state, original);
        state
            .apply_program_call_with_applications(
                signed,
                ProgramId::ZERO,
                chain,
                1,
                &extension::SystemApplications,
            )
            .unwrap();
        assert!(state.utxos.coin(&input_a).is_none());
        assert_eq!(
            state.utxos.coin(&input_b).unwrap().owner,
            Owner::Program(bob.program_id)
        );
        state.audit_supply_invariants().unwrap();
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend_from_slice(&7i64.to_le_bytes());
        code.push(3);
        let program = DeployProgram {
            owner: alice.program_id,
            nonce: 1,
            code: code.into(),
        };
        let deploy_payment = |amount| {
            CoinTransition::coin(
                alice.program_id,
                vec![input_a],
                vec![CoinOutput::new(alice.program_id, Zeno::from_zeno(amount))],
            )
            .unwrap()
        };
        let provisional = alice
            .sign_deploy_program(program.clone(), deploy_payment(1_000_000))
            .unwrap();
        let (id, cost) =
            kernel::consensus::quote_deploy_burn(&provisional, Height(1), &original).unwrap();
        let signed = alice
            .sign_deploy_program(program, deploy_payment(1_000_000 - cost.as_zeno()))
            .unwrap();
        assert_eq!(signed.authorization.salt, [1; 32]);
        let mut deployed = original;
        deployed
            .apply_deploy_with_applications(
                signed,
                ProgramId::ZERO,
                chain,
                Height(1),
                &extension::SystemApplications,
            )
            .unwrap();
        assert_eq!(
            deployed.programs.program(&id).unwrap().owner,
            alice.program_id
        );
        deployed.audit_supply_invariants().unwrap();
        // The same key, code and deploy nonce produce distinct instances under account B.
        let program_b = DeployProgram {
            owner: bob.program_id,
            nonce: 1,
            code: deployed.programs.program(&id).unwrap().code.clone(),
        };
        let payment_b = |amount| {
            CoinTransition::coin(
                bob.program_id,
                vec![input_b],
                vec![CoinOutput::new(bob.program_id, Zeno::from_zeno(amount))],
            )
            .unwrap()
        };
        let provisional = bob
            .sign_deploy_program(program_b.clone(), payment_b(1_000_000))
            .unwrap();
        let (id_b, burn_b) =
            kernel::consensus::quote_deploy_burn(&provisional, Height(1), &deployed).unwrap();
        assert_ne!(id_b, id);
        let signed_b = bob
            .sign_deploy_program(program_b, payment_b(1_000_000 - burn_b.as_zeno()))
            .unwrap();
        deployed
            .apply_deploy_with_applications(
                signed_b,
                ProgramId::ZERO,
                chain,
                Height(1),
                &extension::SystemApplications,
            )
            .unwrap();
        assert_eq!(
            deployed.programs.program(&id_b).unwrap().owner,
            bob.program_id
        );
        deployed.audit_supply_invariants().unwrap();
    }

    #[test]

    fn mnemonic_derives_distinct_recoverable_account_program_ids() {
        let mnemonic = encode_bip39_mnemonic(&[12; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();

        let accounts = [Signature::MlDsa44, Signature::MlDsa65, Signature::MlDsa87];

        let first =
            accounts.map(|account| account_wallet_from_bip39_mnemonic(&mnemonic, account).unwrap());

        let second =
            accounts.map(|account| account_wallet_from_bip39_mnemonic(&mnemonic, account).unwrap());

        for (left, right) in first.iter().zip(&second) {
            assert_eq!(left.program_id, right.program_id);
        }

        let unique = first
            .iter()
            .map(|wallet| wallet.program_id)
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(unique.len(), accounts.len());
    }

    #[test]

    fn account_wallet_file_roundtrip_preserves_account_and_identity() {
        let mnemonic = encode_bip39_mnemonic(&[13; BIP39_MNEMONIC_12_ENTROPY_BYTES]).unwrap();

        for account in [Signature::MlDsa44, Signature::MlDsa65, Signature::MlDsa87] {
            let mut wallet = account_wallet_from_bip39_mnemonic(&mnemonic, account).unwrap();

            wallet.mnemonic = Some(mnemonic.clone());

            let bytes = account_wallet_file_bytes(&wallet).unwrap();

            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

            assert_eq!(json["public_key"], hex::encode(&wallet.public_key.bytes));

            let expected_private_key = {
                let seed = wallet.signing_seed.dangerous_export_seed();

                Zeroizing::new(hex::encode(&seed[..]))
            };

            assert_eq!(
                json["private_key"].as_str(),
                Some(expected_private_key.as_str())
            );

            assert_eq!(
                wallet_file_signature_account(&bytes).unwrap(),
                Some(account)
            );

            let restored = account_wallet_from_file_bytes(&bytes).unwrap();

            assert_eq!(restored.account(), account);

            assert_eq!(restored.program_id, wallet.program_id);

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
    }
}

#[cfg(test)]
mod slh_wallet_tests {
    use super::*;
    #[test]
    fn slh_wallet_roundtrip_and_salted_transfer_authorization() {
        let mnemonic = encode_bip39_mnemonic(&[19; 32]).unwrap();
        let mut wallet =
            account_wallet_from_bip39_mnemonic(&mnemonic, Signature::SlhDsaShake128s).unwrap();
        wallet.mnemonic = Some(mnemonic);
        wallet.select_account([17; 32]).unwrap();
        let bytes = account_wallet_file_bytes(&wallet).unwrap();
        let restored = account_wallet_from_file_bytes(&bytes).unwrap();
        assert_eq!(restored.public_key, wallet.public_key);
        assert_eq!(restored.program_id, wallet.program_id);
        let payment = kernel::program::CoinTransition::coin_with_charges(
            wallet.program_id,
            vec![kernel::monetary::coin::CoinShare::from_bytes([18; 32])],
            vec![],
            kernel::program::CoinCharges::new(kernel::monetary::coin::Zeno::from_zeno(1)),
        )
        .unwrap();
        let mut signed = restored.sign_xpq_transfer(payment).unwrap();
        let chain = kernel::genesis::chain_context().unwrap();
        let commitment = kernel::program::program_invocation_commitment(
            signed.signer,
            &signed.call,
            &signed.payment,
            chain,
        )
        .unwrap();
        drop(restored);
        drop(wallet);
        assert!(
            signed
                .authorization
                .verify_commitment(signed.signer, &commitment, 0)
        );
        signed.authorization.salt[0] ^= 1;
        assert!(
            !signed
                .authorization
                .verify_commitment(signed.signer, &commitment, 0)
        );
    }
}
