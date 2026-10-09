use std::io::{self, Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::agility::{SignatureScheme, account_signature_scheme_supported};
pub use crate::mldsa::{
    ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE, ML_DSA_65_PUBLIC_KEY_SIZE,
    ML_DSA_65_SIGNATURE_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum AccountSignatureScheme {
    MlDsa44 = 1,
    MlDsa65 = 2,
    MlDsa87 = 3,
    SlhDsaShake128s = 5,
    SlhDsaShake192s = 6,
    SlhDsaShake256s = 7,
}

impl AccountSignatureScheme {
    pub const ALL: [Self; 6] = [
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
        Self::SlhDsaShake128s,
        Self::SlhDsaShake192s,
        Self::SlhDsaShake256s,
    ];
    pub const fn is_slh_dsa(self) -> bool {
        matches!(
            self,
            Self::SlhDsaShake128s | Self::SlhDsaShake192s | Self::SlhDsaShake256s
        )
    }

    /// Frozen protocol identifier. Never change or reuse an existing ID.
    pub const fn id(self) -> u8 {
        match self {
            Self::MlDsa44 => 1,
            Self::MlDsa65 => 2,
            Self::SlhDsaShake128s => 5,
            Self::SlhDsaShake192s => 6,
            Self::SlhDsaShake256s => 7,
            Self::MlDsa87 => 3,
        }
    }

    /// Canonical consensus-facing registry entry for this account scheme.
    pub const fn registry_scheme(self) -> SignatureScheme {
        match self {
            Self::MlDsa44 => SignatureScheme::MlDsa44,
            Self::MlDsa65 => SignatureScheme::MlDsa65,
            Self::SlhDsaShake128s => SignatureScheme::SlhDsaShake128s,
            Self::SlhDsaShake192s => SignatureScheme::SlhDsaShake192s,
            Self::SlhDsaShake256s => SignatureScheme::SlhDsaShake256s,
            Self::MlDsa87 => SignatureScheme::MlDsa87,
        }
    }
}

impl TryFrom<u8> for AccountSignatureScheme {
    type Error = crate::CryptoError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::MlDsa44),
            2 => Ok(Self::MlDsa65),
            5 => Ok(Self::SlhDsaShake128s),
            6 => Ok(Self::SlhDsaShake192s),
            7 => Ok(Self::SlhDsaShake256s),
            3 => Ok(Self::MlDsa87),
            _ => Err(crate::CryptoError::InvalidAccountScheme),
        }
    }
}

impl From<AccountSignatureScheme> for SignatureScheme {
    fn from(value: AccountSignatureScheme) -> Self {
        value.registry_scheme()
    }
}

impl TryFrom<SignatureScheme> for AccountSignatureScheme {
    type Error = &'static str;

    fn try_from(value: SignatureScheme) -> Result<Self, Self::Error> {
        match value {
            SignatureScheme::MlDsa44 => Ok(Self::MlDsa44),
            SignatureScheme::MlDsa65 => Ok(Self::MlDsa65),
            SignatureScheme::SlhDsaShake128s => Ok(Self::SlhDsaShake128s),
            SignatureScheme::SlhDsaShake192s => Ok(Self::SlhDsaShake192s),
            SignatureScheme::SlhDsaShake256s => Ok(Self::SlhDsaShake256s),
            SignatureScheme::MlDsa87 => Ok(Self::MlDsa87),
            SignatureScheme::SqisignLevel5 => {
                Err("signature scheme is not handled by the account signature API")
            }
        }
    }
}

/// Compatibility alias for code that still imports `Signature`.
/// New code should use `AccountSignatureScheme`.
pub type Signature = AccountSignatureScheme;

impl AccountSignatureScheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa44 => "mldsa44",
            Self::MlDsa65 => "mldsa65",
            Self::SlhDsaShake128s => "slhdsa-shake128s",
            Self::SlhDsaShake192s => "slhdsa-shake192s",
            Self::SlhDsaShake256s => "slhdsa-shake256s",
            Self::MlDsa87 => "mldsa87",
        }
    }

    pub const fn supported(self) -> bool {
        account_signature_scheme_supported(self.registry_scheme())
    }

    pub const fn public_key_size(self) -> usize {
        match self {
            Self::MlDsa44 => ML_DSA_44_PUBLIC_KEY_SIZE,
            Self::MlDsa65 => ML_DSA_65_PUBLIC_KEY_SIZE,
            Self::SlhDsaShake128s => 32,
            Self::SlhDsaShake192s => 48,
            Self::SlhDsaShake256s => 64,
            Self::MlDsa87 => ML_DSA_87_PUBLIC_KEY_SIZE,
        }
    }

    pub const fn signature_size(self) -> usize {
        match self {
            Self::MlDsa44 => ML_DSA_44_SIGNATURE_SIZE,
            Self::MlDsa65 => ML_DSA_65_SIGNATURE_SIZE,
            Self::SlhDsaShake128s => 7856,
            Self::SlhDsaShake192s => 16224,
            Self::SlhDsaShake256s => 29792,
            Self::MlDsa87 => ML_DSA_87_SIGNATURE_SIZE,
        }
    }
}

impl std::str::FromStr for AccountSignatureScheme {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "mldsa44" => Ok(Self::MlDsa44),
            "mldsa65" => Ok(Self::MlDsa65),
            "slhdsashake128s" => Ok(Self::SlhDsaShake128s),
            "slhdsashake192s" => Ok(Self::SlhDsaShake192s),
            "slhdsashake256s" => Ok(Self::SlhDsaShake256s),
            "mldsa87" => Ok(Self::MlDsa87),
            _ => Err("unknown signature scheme"),
        }
    }
}

impl std::fmt::Display for AccountSignatureScheme {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Serialized signature-scheme discriminator.
    /// Field name is retained for source compatibility; prefer `scheme()`.
    pub account: AccountSignatureScheme,
    pub bytes: Vec<u8>,
}

impl PublicKey {
    /// Signature scheme encoded by this public key.
    pub const fn scheme(&self) -> AccountSignatureScheme {
        self.account
    }

    pub fn is_valid_encoding(&self) -> bool {
        self.bytes.len() == self.scheme().public_key_size()
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if !self.is_valid_encoding() {
            return Err(invalid_length(
                "public key",
                self.account.public_key_size(),
                self.bytes.len(),
            ));
        }

        self.account.serialize(writer)?;
        self.bytes.serialize(writer)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let account = AccountSignatureScheme::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)? as usize;
        let expected = account.public_key_size();

        if length != expected {
            return Err(invalid_length("public key", expected, length));
        }

        let mut bytes = vec![0_u8; expected];
        reader.read_exact(&mut bytes)?;

        Ok(Self { account, bytes })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSignature {
    /// Serialized signature-scheme discriminator.
    /// Field name is retained for source compatibility; prefer `scheme()`.
    pub account: AccountSignatureScheme,
    pub bytes: Vec<u8>,
}

impl AccountSignature {
    /// Signature scheme encoded by this signature.
    pub const fn scheme(&self) -> AccountSignatureScheme {
        self.account
    }

    pub fn is_valid_encoding(&self) -> bool {
        self.bytes.len() == self.scheme().signature_size()
    }
}

impl BorshSerialize for AccountSignature {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if !self.is_valid_encoding() {
            return Err(invalid_length(
                "signature",
                self.account.signature_size(),
                self.bytes.len(),
            ));
        }

        self.account.serialize(writer)?;
        self.bytes.serialize(writer)
    }
}

impl BorshDeserialize for AccountSignature {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let account = AccountSignatureScheme::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)? as usize;
        let expected = account.signature_size();

        if length != expected {
            return Err(invalid_length("signature", expected, length));
        }

        let mut bytes = vec![0_u8; expected];
        reader.read_exact(&mut bytes)?;

        Ok(Self { account, bytes })
    }
}

enum PreparedSigningKey {
    MlDsa(crate::mldsa::PreparedKey),
    SlhDsa(crate::slhdsa::PreparedKey),
}

pub struct SigningSeed {
    account: AccountSignatureScheme,
    seed: Box<[u8; 32]>,
    prepared: std::sync::OnceLock<PreparedSigningKey>,
}

impl Drop for SigningSeed {
    fn drop(&mut self) {
        self.seed.as_mut().zeroize();
    }
}

impl ZeroizeOnDrop for SigningSeed {}

impl std::fmt::Debug for SigningSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningSeed")
            .field("scheme", &self.account)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

impl SigningSeed {
    pub fn new(account: AccountSignatureScheme, seed: Box<[u8; 32]>) -> Self {
        Self {
            account,
            seed,
            prepared: std::sync::OnceLock::new(),
        }
    }

    pub const fn scheme(&self) -> AccountSignatureScheme {
        self.account
    }

    /// Compatibility accessor. New code should use `scheme()`.
    pub const fn account(&self) -> AccountSignatureScheme {
        self.scheme()
    }

    pub fn public_key(&self) -> PublicKey {
        let bytes = match self.prepared_key() {
            PreparedSigningKey::MlDsa(key) => key.public_key_bytes(),
            PreparedSigningKey::SlhDsa(key) => key.public_key_bytes(),
        };
        PublicKey {
            account: self.account,
            bytes,
        }
    }

    pub fn sign(&self, message: &[u8]) -> AccountSignature {
        let bytes = match self.prepared_key() {
            PreparedSigningKey::MlDsa(key) => key.sign_bytes(message),
            PreparedSigningKey::SlhDsa(key) => key.sign_bytes(message),
        };
        AccountSignature {
            account: self.account,
            bytes,
        }
    }

    fn prepared_key(&self) -> &PreparedSigningKey {
        self.prepared.get_or_init(|| {
            if self.account.is_slh_dsa() {
                PreparedSigningKey::SlhDsa(crate::slhdsa::PreparedKey::new(
                    self.account,
                    &self.seed,
                ))
            } else {
                PreparedSigningKey::MlDsa(crate::mldsa::PreparedKey::new(self.account, &self.seed))
            }
        })
    }

    pub fn dangerous_export_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.seed)
    }

    pub fn destroy(self) {
        drop(self);
    }
}

pub fn public_key_from_seed(account: AccountSignatureScheme, seed: &[u8; 32]) -> PublicKey {
    if account.is_slh_dsa() {
        crate::slhdsa::public_key_from_seed(account, seed)
    } else {
        crate::mldsa::public_key_from_seed(account, seed)
    }
}
pub fn sign_from_seed(
    account: AccountSignatureScheme,
    seed: &[u8; 32],
    message: &[u8],
) -> AccountSignature {
    if account.is_slh_dsa() {
        crate::slhdsa::sign_from_seed(account, seed, message)
    } else {
        crate::mldsa::sign_from_seed(account, seed, message)
    }
}
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &AccountSignature) -> bool {
    if public_key.scheme() != signature.scheme()
        || !public_key.is_valid_encoding()
        || !signature.is_valid_encoding()
    {
        return false;
    }
    if public_key.scheme().is_slh_dsa() {
        crate::slhdsa::verify(public_key, message, signature)
    } else {
        crate::mldsa::verify(public_key, message, signature)
    }
}

fn invalid_length(kind: &str, expected: usize, actual: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid {kind} length: expected {expected}, got {actual}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_keys_reuse_one_session_and_preserve_wire_signatures() {
        fn zeroizes<T: ZeroizeOnDrop>() {}
        zeroizes::<ml_dsa::SigningKey<ml_dsa::MlDsa44>>();
        zeroizes::<ml_dsa::SigningKey<ml_dsa::MlDsa65>>();
        zeroizes::<ml_dsa::SigningKey<ml_dsa::MlDsa87>>();
        zeroizes::<slh_dsa::SigningKey<slh_dsa::Shake128s>>();
        zeroizes::<slh_dsa::SigningKey<slh_dsa::Shake192s>>();
        zeroizes::<slh_dsa::SigningKey<slh_dsa::Shake256s>>();
        for scheme in AccountSignatureScheme::ALL {
            let wallet = SigningSeed::new(scheme, Box::new([42; 32]));
            assert!(wallet.prepared.get().is_none());
            let public = wallet.public_key();
            let first = wallet.prepared_key() as *const PreparedSigningKey;
            assert_eq!(wallet.public_key(), public);
            let signature = wallet.sign(b"cached signing session");
            assert_eq!(first, wallet.prepared_key() as *const PreparedSigningKey);
            assert_eq!(
                signature,
                sign_from_seed(scheme, &[42; 32], b"cached signing session")
            );
            let changed = wallet.sign(b"another commitment");
            assert!(verify(&public, b"another commitment", &changed));
            assert!(!verify(&public, b"cached signing session", &changed));
            let debug = format!("{wallet:?}");
            assert!(debug.contains("REDACTED"));
            assert!(!debug.contains("PreparedKey"));
            drop(wallet);
            assert!(verify(&public, b"cached signing session", &signature));
        }
    }

    #[test]
    #[ignore = "manual signing-session timing; optimized crypto packages"]
    fn benchmark_slh256_signing_session() {
        let scheme = AccountSignatureScheme::SlhDsaShake256s;
        let start = std::time::Instant::now();
        let public = public_key_from_seed(scheme, &[42; 32]);
        let uncached: Vec<_> = (0..3)
            .map(|i| sign_from_seed(scheme, &[42; 32], &[i; 32]))
            .collect();
        let uncached_time = start.elapsed();
        let start = std::time::Instant::now();
        let wallet = SigningSeed::new(scheme, Box::new([42; 32]));
        assert_eq!(public, wallet.public_key());
        let cached: Vec<_> = (0..3).map(|i| wallet.sign(&[i; 32])).collect();
        let cached_time = start.elapsed();
        assert_eq!(uncached, cached);
        println!(
            "SHAKE256s public key + 3 signatures: uncached={uncached_time:?}, cached={cached_time:?}"
        );
    }

    #[test]
    fn all_account_derive_sign_and_reject_tampering() {
        for account in [
            AccountSignatureScheme::MlDsa44,
            AccountSignatureScheme::MlDsa65,
            AccountSignatureScheme::MlDsa87,
        ] {
            let seed = SigningSeed::new(account, Box::new([31; 32]));
            let public = seed.public_key();
            let signature = seed.sign(b"account message");

            assert!(public.is_valid_encoding());
            assert!(signature.is_valid_encoding());
            assert!(verify(&public, b"account message", &signature));
            assert!(!verify(&public, b"tampered", &signature));
        }
    }

    #[test]
    fn every_account_authorization_scheme_is_supported() {
        for account in [
            AccountSignatureScheme::MlDsa44,
            AccountSignatureScheme::MlDsa65,
            AccountSignatureScheme::MlDsa87,
        ] {
            assert!(account.supported());
        }
    }

    #[test]
    fn cross_scheme_signature_is_rejected() {
        let seed_44 = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([11; 32]));
        let seed_65 = SigningSeed::new(AccountSignatureScheme::MlDsa65, Box::new([22; 32]));

        let public_44 = seed_44.public_key();
        let signature_65 = seed_65.sign(b"message");

        assert!(!verify(&public_44, b"message", &signature_65));
    }

    #[test]
    fn malformed_public_key_length_is_rejected_during_deserialization() {
        let mut bytes = borsh::to_vec(&AccountSignatureScheme::MlDsa44).expect("serialize scheme");
        bytes.extend_from_slice(&((ML_DSA_44_PUBLIC_KEY_SIZE as u32) + 1).to_le_bytes());

        assert!(PublicKey::try_from_slice(&bytes).is_err());
    }

    #[test]
    fn malformed_signature_length_is_rejected_during_deserialization() {
        let mut bytes = borsh::to_vec(&AccountSignatureScheme::MlDsa44).expect("serialize scheme");
        bytes.extend_from_slice(&((ML_DSA_44_SIGNATURE_SIZE as u32) + 1).to_le_bytes());

        assert!(AccountSignature::try_from_slice(&bytes).is_err());
    }

    #[test]
    fn truncated_public_key_is_rejected() {
        let mut bytes = borsh::to_vec(&AccountSignatureScheme::MlDsa44).expect("serialize scheme");
        bytes.extend_from_slice(&(ML_DSA_44_PUBLIC_KEY_SIZE as u32).to_le_bytes());
        bytes.extend(std::iter::repeat_n(0_u8, ML_DSA_44_PUBLIC_KEY_SIZE - 1));

        assert!(PublicKey::try_from_slice(&bytes).is_err());
    }

    #[test]
    fn malformed_in_memory_values_cannot_be_serialized() {
        let invalid_public = PublicKey {
            account: AccountSignatureScheme::MlDsa44,
            bytes: vec![0_u8; 1],
        };
        let invalid_signature = AccountSignature {
            account: AccountSignatureScheme::MlDsa44,
            bytes: vec![0_u8; 1],
        };

        assert!(borsh::to_vec(&invalid_public).is_err());
        assert!(borsh::to_vec(&invalid_signature).is_err());
    }
    #[test]
    fn account_schemes_map_to_canonical_agility_registry() {
        for scheme in [
            AccountSignatureScheme::MlDsa44,
            AccountSignatureScheme::MlDsa65,
            AccountSignatureScheme::MlDsa87,
        ] {
            let registry = scheme.registry_scheme();
            assert_eq!(AccountSignatureScheme::try_from(registry), Ok(scheme));
        }

        assert!(AccountSignatureScheme::try_from(SignatureScheme::SqisignLevel5).is_err());
    }
}
#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn every_registered_scheme_has_bounded_canonical_encoding() {
        for scheme in AccountSignatureScheme::ALL {
            assert!(scheme.supported());
            assert_eq!(
                scheme.as_str().parse::<AccountSignatureScheme>().unwrap(),
                scheme
            );
            assert_eq!(
                AccountSignatureScheme::try_from(scheme.registry_scheme()).unwrap(),
                scheme
            );
            let public = PublicKey {
                account: scheme,
                bytes: vec![0; scheme.public_key_size()],
            };
            let signature = AccountSignature {
                account: scheme,
                bytes: vec![0; scheme.signature_size()],
            };
            assert_eq!(
                PublicKey::try_from_slice(&borsh::to_vec(&public).unwrap()).unwrap(),
                public
            );
            assert_eq!(
                AccountSignature::try_from_slice(&borsh::to_vec(&signature).unwrap()).unwrap(),
                signature
            );
            for size in [
                0u32,
                (scheme.signature_size() - 1) as u32,
                (scheme.signature_size() + 1) as u32,
                u32::MAX,
            ] {
                let mut bytes = vec![scheme.id()];
                bytes.extend_from_slice(&size.to_le_bytes());
                assert!(AccountSignature::try_from_slice(&bytes).is_err());
            }
        }
    }
    use borsh::BorshDeserialize;

    const MESSAGE: &[u8] = b"xparq signature hardening";

    fn schemes() -> [AccountSignatureScheme; 3] {
        [
            AccountSignatureScheme::MlDsa44,
            AccountSignatureScheme::MlDsa65,
            AccountSignatureScheme::MlDsa87,
        ]
    }

    fn seed_for(index: usize) -> Box<[u8; 32]> {
        Box::new([(index as u8).wrapping_add(41); 32])
    }

    #[test]
    fn every_cross_scheme_pair_is_rejected() {
        let materials = schemes()
            .into_iter()
            .enumerate()
            .map(|(index, scheme)| {
                let seed = SigningSeed::new(scheme, seed_for(index));
                (scheme, seed.public_key(), seed.sign(MESSAGE))
            })
            .collect::<Vec<_>>();

        for (public_scheme, public_key, _) in &materials {
            for (signature_scheme, _, signature) in &materials {
                if public_scheme == signature_scheme {
                    assert!(verify(public_key, MESSAGE, signature));
                } else {
                    assert!(!verify(public_key, MESSAGE, signature));
                }
            }
        }
    }

    #[test]
    fn correct_length_garbage_is_rejected() {
        for (index, scheme) in schemes().into_iter().enumerate() {
            let seed = SigningSeed::new(scheme, seed_for(index));
            let valid_public = seed.public_key();
            let valid_signature = seed.sign(MESSAGE);

            let garbage_public = PublicKey {
                account: scheme,
                bytes: vec![0_u8; scheme.public_key_size()],
            };
            let garbage_signature = AccountSignature {
                account: scheme,
                bytes: vec![0_u8; scheme.signature_size()],
            };

            // Length validation alone must not make malformed material valid.
            assert!(garbage_public.is_valid_encoding());
            assert!(garbage_signature.is_valid_encoding());
            assert!(!verify(&garbage_public, MESSAGE, &valid_signature));
            assert!(!verify(&valid_public, MESSAGE, &garbage_signature));
            assert!(!verify(&garbage_public, MESSAGE, &garbage_signature));
        }
    }

    #[test]
    fn bit_flips_in_valid_public_keys_and_signatures_are_rejected() {
        for (index, scheme) in schemes().into_iter().enumerate() {
            let seed = SigningSeed::new(scheme, seed_for(index));
            let public = seed.public_key();
            let signature = seed.sign(MESSAGE);

            assert!(verify(&public, MESSAGE, &signature));

            let mut corrupted_public = public.clone();
            let public_index = corrupted_public.bytes.len() / 2;
            corrupted_public.bytes[public_index] ^= 0x01;
            assert!(!verify(&corrupted_public, MESSAGE, &signature));

            let mut corrupted_signature = signature.clone();
            let signature_index = corrupted_signature.bytes.len() / 2;
            corrupted_signature.bytes[signature_index] ^= 0x01;
            assert!(!verify(&public, MESSAGE, &corrupted_signature));
        }
    }

    #[test]
    fn invalid_scheme_discriminants_are_rejected() {
        for discriminant in [0_u8, 4_u8, u8::MAX] {
            assert!(AccountSignatureScheme::try_from_slice(&[discriminant]).is_err());
        }
    }

    #[test]
    fn forged_scheme_tags_cannot_reinterpret_mldsa44_payloads() {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([77; 32]));

        let mut public_bytes = borsh::to_vec(&seed.public_key()).expect("serialize public key");
        let mut signature_bytes =
            borsh::to_vec(&seed.sign(MESSAGE)).expect("serialize account signature");

        // Borsh enum discriminants are the first byte. Re-labeling a 44 payload
        // as 65 must fail before the payload can be interpreted as another scheme.
        public_bytes[0] = AccountSignatureScheme::MlDsa65 as u8;
        signature_bytes[0] = AccountSignatureScheme::MlDsa65 as u8;

        assert!(PublicKey::try_from_slice(&public_bytes).is_err());
        assert!(AccountSignature::try_from_slice(&signature_bytes).is_err());
    }

    #[test]
    fn absurd_declared_lengths_are_rejected_before_payload_allocation() {
        for scheme in schemes() {
            let mut public = borsh::to_vec(&scheme).expect("serialize scheme");
            public.extend_from_slice(&u32::MAX.to_le_bytes());
            assert!(PublicKey::try_from_slice(&public).is_err());

            let mut signature = borsh::to_vec(&scheme).expect("serialize scheme");
            signature.extend_from_slice(&u32::MAX.to_le_bytes());
            assert!(AccountSignature::try_from_slice(&signature).is_err());
        }
    }

    #[test]
    fn truncated_signature_payload_is_rejected() {
        for scheme in schemes() {
            let mut bytes = borsh::to_vec(&scheme).expect("serialize scheme");
            bytes.extend_from_slice(&(scheme.signature_size() as u32).to_le_bytes());
            bytes.extend(std::iter::repeat_n(0_u8, scheme.signature_size() - 1));

            assert!(AccountSignature::try_from_slice(&bytes).is_err());
        }
    }

    #[test]
    fn borsh_round_trip_preserves_scheme_and_exact_wire_lengths() {
        for (index, scheme) in schemes().into_iter().enumerate() {
            let seed = SigningSeed::new(scheme, seed_for(index));
            let public = seed.public_key();
            let signature = seed.sign(MESSAGE);

            let public_bytes = borsh::to_vec(&public).expect("serialize public key");
            let signature_bytes = borsh::to_vec(&signature).expect("serialize signature");

            // 1-byte scheme discriminant + 4-byte Borsh Vec length + payload.
            assert_eq!(public_bytes.len(), 1 + 4 + scheme.public_key_size());
            assert_eq!(signature_bytes.len(), 1 + 4 + scheme.signature_size());

            let decoded_public =
                PublicKey::try_from_slice(&public_bytes).expect("deserialize public key");
            let decoded_signature = AccountSignature::try_from_slice(&signature_bytes)
                .expect("deserialize account signature");

            assert_eq!(decoded_public, public);
            assert_eq!(decoded_signature, signature);
            assert_eq!(decoded_public.scheme(), scheme);
            assert_eq!(decoded_signature.scheme(), scheme);
            assert!(verify(&decoded_public, MESSAGE, &decoded_signature));
        }
    }

    #[test]
    fn trailing_bytes_are_not_accepted_as_canonical_encoding() {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([91; 32]));

        let mut public = borsh::to_vec(&seed.public_key()).expect("serialize public key");
        public.push(0);
        assert!(PublicKey::try_from_slice(&public).is_err());

        let mut signature = borsh::to_vec(&seed.sign(MESSAGE)).expect("serialize signature");
        signature.push(0);
        assert!(AccountSignature::try_from_slice(&signature).is_err());
    }

    #[test]
    fn account_support_matches_canonical_agility_registry() {
        for scheme in schemes() {
            assert_eq!(
                scheme.supported(),
                account_signature_scheme_supported(scheme.registry_scheme())
            );
        }
    }
}
