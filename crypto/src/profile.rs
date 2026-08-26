use borsh::{BorshDeserialize, BorshSerialize};
use ml_dsa::{
    Keypair, MlDsa44, MlDsa65, MlDsa87, SignatureEncoding, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FalconLevel, falcon_keypair_from_seed, falcon_sign, falcon_verify};

pub const SIGNATURE_PROFILE_ACTIVATION_HEIGHT: u64 = 10_000;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum SignatureProfile {
    MlDsa44 = 0,
    MlDsa65 = 1,
    MlDsa87 = 2,
    Falcon512 = 3,
    Falcon1024 = 4,
}

impl SignatureProfile {
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
        SIGNATURE_PROFILE_ACTIVATION_HEIGHT
    }

    pub const fn active_at_height(self, height: u64) -> bool {
        height >= self.activation_height()
    }
}

impl std::str::FromStr for SignatureProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "mldsa44" => Ok(Self::MlDsa44),
            "mldsa65" => Ok(Self::MlDsa65),
            "mldsa87" => Ok(Self::MlDsa87),
            "falcon512" => Ok(Self::Falcon512),
            "falcon1024" => Ok(Self::Falcon1024),
            _ => Err("unknown signature profile"),
        }
    }
}

impl std::fmt::Display for SignatureProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProfilePublicKey {
    pub profile: SignatureProfile,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ProfileSignature {
    pub profile: SignatureProfile,
    pub bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct ProfileSigningSeed {
    #[zeroize(skip)]
    profile: SignatureProfile,
    seed: [u8; 32],
}

impl std::fmt::Debug for ProfileSigningSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileSigningSeed")
            .field("profile", &self.profile)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

impl ProfileSigningSeed {
    pub const fn new(profile: SignatureProfile, seed: [u8; 32]) -> Self {
        Self { profile, seed }
    }

    pub const fn profile(&self) -> SignatureProfile {
        self.profile
    }

    pub fn public_key(&self) -> ProfilePublicKey {
        profile_public_key_from_seed(self.profile, &self.seed)
    }

    pub fn sign(&self, message: &[u8]) -> ProfileSignature {
        profile_sign_from_seed(self.profile, &self.seed, message)
    }
}

pub fn profile_public_key_from_seed(
    profile: SignatureProfile,
    seed: &[u8; 32],
) -> ProfilePublicKey {
    let bytes = match profile {
        SignatureProfile::MlDsa44 => SigningKey::<MlDsa44>::from_seed(&(*seed).into())
            .verifying_key()
            .encode()
            .to_vec(),
        SignatureProfile::MlDsa65 => SigningKey::<MlDsa65>::from_seed(&(*seed).into())
            .verifying_key()
            .encode()
            .to_vec(),
        SignatureProfile::MlDsa87 => SigningKey::<MlDsa87>::from_seed(&(*seed).into())
            .verifying_key()
            .encode()
            .to_vec(),
        SignatureProfile::Falcon512 => falcon_keypair_from_seed(FalconLevel::Level1, seed)
            .expect("Falcon-512 seed keygen")
            .public_key
            .as_bytes()
            .to_vec(),
        SignatureProfile::Falcon1024 => falcon_keypair_from_seed(FalconLevel::Level5, seed)
            .expect("Falcon-1024 seed keygen")
            .public_key
            .as_bytes()
            .to_vec(),
    };
    ProfilePublicKey { profile, bytes }
}

pub fn profile_sign_from_seed(
    profile: SignatureProfile,
    seed: &[u8; 32],
    message: &[u8],
) -> ProfileSignature {
    let bytes = match profile {
        SignatureProfile::MlDsa44 => {
            let key = SigningKey::<MlDsa44>::from_seed(&(*seed).into());
            let sig: ml_dsa::Signature<MlDsa44> = key.sign(message);
            sig.to_bytes().to_vec()
        }
        SignatureProfile::MlDsa65 => {
            let key = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
            let sig: ml_dsa::Signature<MlDsa65> = key.sign(message);
            sig.to_bytes().to_vec()
        }
        SignatureProfile::MlDsa87 => {
            let key = SigningKey::<MlDsa87>::from_seed(&(*seed).into());
            let sig: ml_dsa::Signature<MlDsa87> = key.sign(message);
            sig.to_bytes().to_vec()
        }
        SignatureProfile::Falcon512 => {
            let key = falcon_keypair_from_seed(FalconLevel::Level1, seed)
                .expect("Falcon-512 seed keygen");
            falcon_sign(&key.secret_key, message)
                .expect("Falcon-512 sign")
                .as_bytes()
                .to_vec()
        }
        SignatureProfile::Falcon1024 => {
            let key = falcon_keypair_from_seed(FalconLevel::Level5, seed)
                .expect("Falcon-1024 seed keygen");
            falcon_sign(&key.secret_key, message)
                .expect("Falcon-1024 sign")
                .as_bytes()
                .to_vec()
        }
    };
    ProfileSignature { profile, bytes }
}

pub fn profile_verify(
    public_key: &ProfilePublicKey,
    message: &[u8],
    signature: &ProfileSignature,
) -> bool {
    if public_key.profile != signature.profile {
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
    match public_key.profile {
        SignatureProfile::MlDsa44 => verify_ml!(MlDsa44, 1312, 2420),
        SignatureProfile::MlDsa65 => verify_ml!(MlDsa65, 1952, 3309),
        SignatureProfile::MlDsa87 => verify_ml!(MlDsa87, 2592, 4627),
        SignatureProfile::Falcon512 | SignatureProfile::Falcon1024 => {
            let level = if public_key.profile == SignatureProfile::Falcon512 {
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
    fn all_profiles_derive_sign_and_reject_tampering() {
        for profile in [
            SignatureProfile::MlDsa44,
            SignatureProfile::MlDsa65,
            SignatureProfile::MlDsa87,
            SignatureProfile::Falcon512,
            SignatureProfile::Falcon1024,
        ] {
            let seed = ProfileSigningSeed::new(profile, [31; 32]);
            let public = seed.public_key();
            let signature = seed.sign(b"profile message");
            assert!(profile_verify(&public, b"profile message", &signature));
            assert!(!profile_verify(&public, b"tampered", &signature));
        }
    }

    #[test]
    fn every_profile_authorization_activates_at_height_10_000() {
        for profile in [
            SignatureProfile::MlDsa44,
            SignatureProfile::MlDsa65,
            SignatureProfile::MlDsa87,
            SignatureProfile::Falcon512,
            SignatureProfile::Falcon1024,
        ] {
            assert!(!profile.active_at_height(SIGNATURE_PROFILE_ACTIVATION_HEIGHT - 1));
            assert!(profile.active_at_height(SIGNATURE_PROFILE_ACTIVATION_HEIGHT));
        }
    }
}
