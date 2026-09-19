use std::io::{self, Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::agility::{SignatureScheme, account_signature_scheme_supported};
use ml_dsa::{
    Keypair, MlDsa44, MlDsa65, MlDsa87, SignatureEncoding, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const ML_DSA_44_PUBLIC_KEY_SIZE: usize = 1312;
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
pub const ML_DSA_87_PUBLIC_KEY_SIZE: usize = 2592;

pub const ML_DSA_44_SIGNATURE_SIZE: usize = 2420;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum AccountSignatureScheme {
    MlDsa44 = 1,
    MlDsa65 = 2,
    MlDsa87 = 3,
}

impl AccountSignatureScheme {
    /// Canonical consensus-facing registry entry for this ML-DSA account scheme.
    pub const fn registry_scheme(self) -> SignatureScheme {
        match self {
            Self::MlDsa44 => SignatureScheme::MlDsa44,
            Self::MlDsa65 => SignatureScheme::MlDsa65,
            Self::MlDsa87 => SignatureScheme::MlDsa87,
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
            SignatureScheme::MlDsa87 => Ok(Self::MlDsa87),
            SignatureScheme::SqisignLevel5 => {
                Err("signature scheme is not handled by the ML-DSA account API")
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
            Self::MlDsa87 => ML_DSA_87_PUBLIC_KEY_SIZE,
        }
    }

    pub const fn signature_size(self) -> usize {
        match self {
            Self::MlDsa44 => ML_DSA_44_SIGNATURE_SIZE,
            Self::MlDsa65 => ML_DSA_65_SIGNATURE_SIZE,
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

pub struct SigningSeed {
    account: AccountSignatureScheme,
    seed: Box<[u8; 32]>,
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
        Self { account, seed }
    }

    pub const fn scheme(&self) -> AccountSignatureScheme {
        self.account
    }

    /// Compatibility accessor. New code should use `scheme()`.
    pub const fn account(&self) -> AccountSignatureScheme {
        self.scheme()
    }

    pub fn public_key(&self) -> PublicKey {
        public_key_from_seed(self.account, self.seed.as_ref())
    }

    pub fn sign(&self, message: &[u8]) -> AccountSignature {
        sign_from_seed(self.account, self.seed.as_ref(), message)
    }

    pub fn dangerous_export_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.seed)
    }

    pub fn destroy(self) {
        drop(self);
    }
}

pub fn public_key_from_seed(account: AccountSignatureScheme, seed: &[u8; 32]) -> PublicKey {
    let seed = Zeroizing::new((*seed).into());
    let bytes = match account {
        AccountSignatureScheme::MlDsa44 => SigningKey::<MlDsa44>::from_seed(&seed)
            .verifying_key()
            .encode()
            .to_vec(),
        AccountSignatureScheme::MlDsa65 => SigningKey::<MlDsa65>::from_seed(&seed)
            .verifying_key()
            .encode()
            .to_vec(),
        AccountSignatureScheme::MlDsa87 => SigningKey::<MlDsa87>::from_seed(&seed)
            .verifying_key()
            .encode()
            .to_vec(),
    };

    debug_assert_eq!(bytes.len(), account.public_key_size());

    PublicKey { account, bytes }
}

pub fn sign_from_seed(
    account: AccountSignatureScheme,
    seed: &[u8; 32],
    message: &[u8],
) -> AccountSignature {
    let seed = Zeroizing::new((*seed).into());
    let bytes = match account {
        AccountSignatureScheme::MlDsa44 => {
            let key = SigningKey::<MlDsa44>::from_seed(&seed);
            let sig: ml_dsa::Signature<MlDsa44> = key.sign(message);
            sig.to_bytes().to_vec()
        }
        AccountSignatureScheme::MlDsa65 => {
            let key = SigningKey::<MlDsa65>::from_seed(&seed);
            let sig: ml_dsa::Signature<MlDsa65> = key.sign(message);
            sig.to_bytes().to_vec()
        }
        AccountSignatureScheme::MlDsa87 => {
            let key = SigningKey::<MlDsa87>::from_seed(&seed);
            let sig: ml_dsa::Signature<MlDsa87> = key.sign(message);
            sig.to_bytes().to_vec()
        }
    };

    debug_assert_eq!(bytes.len(), account.signature_size());

    AccountSignature { account, bytes }
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &AccountSignature) -> bool {
    if public_key.scheme() != signature.scheme() {
        return false;
    }

    if !public_key.is_valid_encoding() || !signature.is_valid_encoding() {
        return false;
    }

    macro_rules! verify_ml {
        ($params:ty, $pk_size:expr, $sig_size:expr) => {{
            let Ok(public): Result<[u8; $pk_size], _> = public_key.bytes.as_slice().try_into()
            else {
                return false;
            };

            let Ok(encoded_signature): Result<[u8; $sig_size], _> =
                signature.bytes.as_slice().try_into()
            else {
                return false;
            };

            let key = VerifyingKey::<$params>::decode(&public.into());
            let Some(decoded) = ml_dsa::Signature::<$params>::decode(&encoded_signature.into())
            else {
                return false;
            };

            key.verify(message, &decoded).is_ok()
        }};
    }

    match public_key.scheme() {
        AccountSignatureScheme::MlDsa44 => {
            verify_ml!(MlDsa44, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE)
        }
        AccountSignatureScheme::MlDsa65 => {
            verify_ml!(MlDsa65, ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE)
        }
        AccountSignatureScheme::MlDsa87 => {
            verify_ml!(MlDsa87, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE)
        }
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
