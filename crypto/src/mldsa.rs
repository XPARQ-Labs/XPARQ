//! ML-DSA backend; protocol types and dispatch live in `signature`.
use crate::signature::{AccountSignature, AccountSignatureScheme, PublicKey};
use ml_dsa::{
    Keypair, MlDsa44, MlDsa65, MlDsa87, SignatureEncoding, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use zeroize::Zeroizing;

pub const ML_DSA_44_PUBLIC_KEY_SIZE: usize = 1312;
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
pub const ML_DSA_87_PUBLIC_KEY_SIZE: usize = 2592;

pub const ML_DSA_44_SIGNATURE_SIZE: usize = 2420;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;

/// Expanded secret material stays local to a signing session; each typed key zeroizes on drop.
pub(crate) enum PreparedKey {
    MlDsa44(Box<SigningKey<MlDsa44>>),
    MlDsa65(Box<SigningKey<MlDsa65>>),
    MlDsa87(Box<SigningKey<MlDsa87>>),
}
impl PreparedKey {
    pub(crate) fn new(account: AccountSignatureScheme, seed: &[u8; 32]) -> Self {
        match account {
            AccountSignatureScheme::MlDsa44 => Self::MlDsa44(Box::new(
                SigningKey::<MlDsa44>::from_seed(&Zeroizing::new((*seed).into())),
            )),
            AccountSignatureScheme::MlDsa65 => Self::MlDsa65(Box::new(
                SigningKey::<MlDsa65>::from_seed(&Zeroizing::new((*seed).into())),
            )),
            AccountSignatureScheme::MlDsa87 => Self::MlDsa87(Box::new(
                SigningKey::<MlDsa87>::from_seed(&Zeroizing::new((*seed).into())),
            )),
            _ => unreachable!("wrong signature family"),
        }
    }
    pub(crate) fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::MlDsa44(key) => key.verifying_key().encode().to_vec(),
            Self::MlDsa65(key) => key.verifying_key().encode().to_vec(),
            Self::MlDsa87(key) => key.verifying_key().encode().to_vec(),
        }
    }
    pub(crate) fn sign_bytes(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::MlDsa44(key) => {
                let signature: ml_dsa::Signature<MlDsa44> = key.sign(message);
                signature.to_bytes().to_vec()
            }
            Self::MlDsa65(key) => {
                let signature: ml_dsa::Signature<MlDsa65> = key.sign(message);
                signature.to_bytes().to_vec()
            }
            Self::MlDsa87(key) => {
                let signature: ml_dsa::Signature<MlDsa87> = key.sign(message);
                signature.to_bytes().to_vec()
            }
        }
    }
}

pub(crate) fn public_key_from_seed(account: AccountSignatureScheme, seed: &[u8; 32]) -> PublicKey {
    PublicKey {
        account,
        bytes: PreparedKey::new(account, seed).public_key_bytes(),
    }
}
pub(crate) fn sign_from_seed(
    account: AccountSignatureScheme,
    seed: &[u8; 32],
    message: &[u8],
) -> AccountSignature {
    AccountSignature {
        account,
        bytes: PreparedKey::new(account, seed).sign_bytes(message),
    }
}

pub(crate) fn verify(public_key: &PublicKey, message: &[u8], signature: &AccountSignature) -> bool {
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
        _ => false,
    }
}
