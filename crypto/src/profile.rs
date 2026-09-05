use borsh::{BorshDeserialize, BorshSerialize};
use ml_dsa::{
    Keypair, MlDsa44, MlDsa65, MlDsa87, SignatureEncoding, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FalconLevel, falcon_keypair_from_seed, falcon_sign, falcon_verify};

pub const SIGNATURE_ACTIVATION_HEIGHT: u64 = 0;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum Signature {
    MlDsa44 = 1,
    MlDsa65 = 2,
    MlDsa87 = 3,
    Falcon512 = 4,
    Falcon1024 = 5,
}

impl Signature {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa44 => "mldsa44",
            Self::MlDsa65 => "mldsa65",
            Self::MlDsa87 => "mldsa87",
            Self::Falcon512 => "falcon512",
            Self::Falcon1024 => "falcon1024",
        }
    }

    pub const fn activation_height(self) -> u64 {
        SIGNATURE_ACTIVATION_HEIGHT
    }

    pub const fn active_at_height(self, height: u64) -> bool {
        height >= self.activation_height()
    }
}

impl std::str::FromStr for Signature {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "mldsa44" => Ok(Self::MlDsa44),
            "mldsa65" => Ok(Self::MlDsa65),
            "mldsa87" => Ok(Self::MlDsa87),
            "falcon512" => Ok(Self::Falcon512),
            "falcon1024" => Ok(Self::Falcon1024),
            _ => Err("unknown signature account"),
        }
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PublicKey {
    pub account: Signature,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountSignature {
    pub account: Signature,
    pub bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct SigningSeed {
    #[zeroize(skip)]
    account: Signature,
    seed: [u8; 32],
}

impl std::fmt::Debug for SigningSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningSeed")
            .field("account", &self.account)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

impl SigningSeed {
    pub const fn new(account: Signature, seed: [u8; 32]) -> Self {
        Self { account, seed }
    }

    pub const fn account(&self) -> Signature {
        self.account
    }

    /// Returns the deterministic 32-byte private signing seed.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public_key(&self) -> PublicKey {
        public_key_from_seed(self.account, &self.seed)
    }

    pub fn sign(&self, message: &[u8]) -> AccountSignature {
        sign_from_seed(self.account, &self.seed, message)
    }
}

pub fn public_key_from_seed(account: Signature, seed: &[u8; 32]) -> PublicKey {
    let bytes = match account {
        Signature::MlDsa44 => SigningKey::<MlDsa44>::from_seed(&(*seed).into())
            .verifying_key()
            .encode()
            .to_vec(),
        Signature::MlDsa65 => SigningKey::<MlDsa65>::from_seed(&(*seed).into())
            .verifying_key()
            .encode()
            .to_vec(),
        Signature::MlDsa87 => SigningKey::<MlDsa87>::from_seed(&(*seed).into())
            .verifying_key()
            .encode()
            .to_vec(),
        Signature::Falcon512 => falcon_keypair_from_seed(FalconLevel::Level1, seed)
            .expect("Falcon-512 seed keygen")
            .public_key
            .as_bytes()
            .to_vec(),
        Signature::Falcon1024 => falcon_keypair_from_seed(FalconLevel::Level5, seed)
            .expect("Falcon-1024 seed keygen")
            .public_key
            .as_bytes()
            .to_vec(),
    };
    PublicKey { account, bytes }
}

pub fn sign_from_seed(account: Signature, seed: &[u8; 32], message: &[u8]) -> AccountSignature {
    let bytes = match account {
        Signature::MlDsa44 => {
            let key = SigningKey::<MlDsa44>::from_seed(&(*seed).into());
            let sig: ml_dsa::Signature<MlDsa44> = key.sign(message);
            sig.to_bytes().to_vec()
        }
        Signature::MlDsa65 => {
            let key = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
            let sig: ml_dsa::Signature<MlDsa65> = key.sign(message);
            sig.to_bytes().to_vec()
        }
        Signature::MlDsa87 => {
            let key = SigningKey::<MlDsa87>::from_seed(&(*seed).into());
            let sig: ml_dsa::Signature<MlDsa87> = key.sign(message);
            sig.to_bytes().to_vec()
        }
        Signature::Falcon512 => {
            let key = falcon_keypair_from_seed(FalconLevel::Level1, seed)
                .expect("Falcon-512 seed keygen");
            falcon_sign(&key.secret_key, message)
                .expect("Falcon-512 sign")
                .as_bytes()
                .to_vec()
        }
        Signature::Falcon1024 => {
            let key = falcon_keypair_from_seed(FalconLevel::Level5, seed)
                .expect("Falcon-1024 seed keygen");
            falcon_sign(&key.secret_key, message)
                .expect("Falcon-1024 sign")
                .as_bytes()
                .to_vec()
        }
    };
    AccountSignature { account, bytes }
}

pub fn verify(public_key: &PublicKey, message: &[u8], signature: &AccountSignature) -> bool {
    if public_key.account != signature.account {
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
    match public_key.account {
        Signature::MlDsa44 => verify_ml!(MlDsa44, 1312, 2420),
        Signature::MlDsa65 => verify_ml!(MlDsa65, 1952, 3309),
        Signature::MlDsa87 => verify_ml!(MlDsa87, 2592, 4627),
        Signature::Falcon512 | Signature::Falcon1024 => {
            let level = if public_key.account == Signature::Falcon512 {
                FalconLevel::Level1
            } else {
                FalconLevel::Level5
            };
            let Ok(pk) = crate::FalconPublicKey::from_bytes(level, public_key.bytes.clone()) else {
                return false;
            };
            let Ok(sig) = crate::FalconSignature::from_bytes(level, signature.bytes.clone()) else {
                return false;
            };
            falcon_verify(&pk, message, &sig).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_account_derive_sign_and_reject_tampering() {
        for account in [
            Signature::MlDsa44,
            Signature::MlDsa65,
            Signature::MlDsa87,
            Signature::Falcon512,
            Signature::Falcon1024,
        ] {
            let seed = SigningSeed::new(account, [31; 32]);
            let public = seed.public_key();
            let signature = seed.sign(b"account message");
            assert!(verify(&public, b"account message", &signature));
            assert!(!verify(&public, b"tampered", &signature));
        }
    }

    #[test]
    fn every_account_authorization_is_active_from_genesis() {
        for account in [
            Signature::MlDsa44,
            Signature::MlDsa65,
            Signature::MlDsa87,
            Signature::Falcon512,
            Signature::Falcon1024,
        ] {
            assert!(account.active_at_height(0));
        }
    }
}
