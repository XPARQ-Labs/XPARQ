use std::{error::Error, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use ml_kem::{
    EncapsulationKey512, EncapsulationKey768, EncapsulationKey1024, MlKem512, MlKem768, MlKem1024,
    Seed,
    kem::{Ciphertext, Decapsulate, Encapsulate, FromSeed, Kem, Key, KeyExport},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEM_ACTIVATION_HEIGHT: u64 = 0;

pub const ML_KEM_SEED_SIZE: usize = 64;
pub const ML_KEM_SHARED_SECRET_SIZE: usize = 32;

pub const ML_KEM_512_PUBLIC_KEY_SIZE: usize = 800;
pub const ML_KEM_512_CIPHERTEXT_SIZE: usize = 768;

pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;

pub const ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;
pub const ML_KEM_1024_CIPHERTEXT_SIZE: usize = 1568;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum KeyExchange {
    MlKem512 = 1,
    MlKem768 = 2,
    MlKem1024 = 3,
}

impl KeyExchange {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MlKem512 => "mlkem512",
            Self::MlKem768 => "mlkem768",
            Self::MlKem1024 => "mlkem1024",
        }
    }

    pub const fn activation_height(self) -> u64 {
        KEM_ACTIVATION_HEIGHT
    }

    pub const fn active_at_height(self, height: u64) -> bool {
        height >= self.activation_height()
    }

    pub const fn public_key_size(self) -> usize {
        match self {
            Self::MlKem512 => ML_KEM_512_PUBLIC_KEY_SIZE,
            Self::MlKem768 => ML_KEM_768_PUBLIC_KEY_SIZE,
            Self::MlKem1024 => ML_KEM_1024_PUBLIC_KEY_SIZE,
        }
    }

    pub const fn ciphertext_size(self) -> usize {
        match self {
            Self::MlKem512 => ML_KEM_512_CIPHERTEXT_SIZE,
            Self::MlKem768 => ML_KEM_768_CIPHERTEXT_SIZE,
            Self::MlKem1024 => ML_KEM_1024_CIPHERTEXT_SIZE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemError {
    InvalidPublicKey,
    InvalidCiphertext,
}

impl fmt::Display for KemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => formatter.write_str("ML-KEM public key is invalid"),
            Self::InvalidCiphertext => formatter.write_str("ML-KEM ciphertext is invalid"),
        }
    }
}

impl Error for KemError {}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KemSharedSecret([u8; ML_KEM_SHARED_SECRET_SIZE]);

impl KemSharedSecret {
    pub const fn from_bytes(bytes: [u8; ML_KEM_SHARED_SECRET_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; ML_KEM_SHARED_SECRET_SIZE] {
        &self.0
    }

    fn from_slice(bytes: &[u8]) -> Self {
        let mut secret = [0; ML_KEM_SHARED_SECRET_SIZE];
        secret.copy_from_slice(bytes);
        Self(secret)
    }
}

impl fmt::Debug for KemSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KemSharedSecret([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct KemPublicKey {
    kem: KeyExchange,
    bytes: Vec<u8>,
}

impl KemPublicKey {
    pub fn from_bytes(kem: KeyExchange, bytes: Vec<u8>) -> Result<Self, KemError> {
        if bytes.len() != kem.public_key_size() {
            return Err(KemError::InvalidPublicKey);
        }

        validate_public_key(kem, &bytes)?;

        Ok(Self { kem, bytes })
    }

    pub const fn kem(&self) -> KeyExchange {
        self.kem
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl BorshDeserialize for KemPublicKey {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let kem = KeyExchange::deserialize_reader(reader)?;
        let bytes = Vec::<u8>::deserialize_reader(reader)?;

        Self::from_bytes(kem, bytes)
            .map_err(|error| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, error))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct KemCiphertext {
    kem: KeyExchange,
    bytes: Vec<u8>,
}

impl KemCiphertext {
    pub fn from_bytes(kem: KeyExchange, bytes: Vec<u8>) -> Result<Self, KemError> {
        if bytes.len() != kem.ciphertext_size() {
            return Err(KemError::InvalidCiphertext);
        }

        Ok(Self { kem, bytes })
    }

    pub const fn kem(&self) -> KeyExchange {
        self.kem
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl BorshDeserialize for KemCiphertext {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let kem = KeyExchange::deserialize_reader(reader)?;
        let bytes = Vec::<u8>::deserialize_reader(reader)?;

        Self::from_bytes(kem, bytes)
            .map_err(|error| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, error))
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct KemSeed {
    #[zeroize(skip)]
    kem: KeyExchange,
    seed: [u8; ML_KEM_SEED_SIZE],
}

impl fmt::Debug for KemSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KemSeed")
            .field("kem", &self.kem)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

impl KemSeed {
    pub fn generate(kem: KeyExchange) -> Self {
        let seed = match kem {
            KeyExchange::MlKem512 => {
                let (secret_key, _) = MlKem512::generate_keypair();
                secret_key.to_bytes().into()
            }

            KeyExchange::MlKem768 => {
                let (secret_key, _) = MlKem768::generate_keypair();
                secret_key.to_bytes().into()
            }

            KeyExchange::MlKem1024 => {
                let (secret_key, _) = MlKem1024::generate_keypair();
                secret_key.to_bytes().into()
            }
        };

        Self { kem, seed }
    }

    pub const fn new(kem: KeyExchange, seed: [u8; ML_KEM_SEED_SIZE]) -> Self {
        Self { kem, seed }
    }

    pub const fn kem(&self) -> KeyExchange {
        self.kem
    }

    pub const fn to_bytes(&self) -> [u8; ML_KEM_SEED_SIZE] {
        self.seed
    }

    pub fn public_key(&self) -> KemPublicKey {
        kem_public_key_from_seed(self.kem, &self.seed)
    }
}

pub fn kem_public_key_from_seed(kem: KeyExchange, seed: &[u8; ML_KEM_SEED_SIZE]) -> KemPublicKey {
    let bytes = match kem {
        KeyExchange::MlKem512 => {
            let (_, public_key) = MlKem512::from_seed(&Seed::from(*seed));

            public_key.to_bytes().as_slice().to_vec()
        }

        KeyExchange::MlKem768 => {
            let (_, public_key) = MlKem768::from_seed(&Seed::from(*seed));

            public_key.to_bytes().as_slice().to_vec()
        }

        KeyExchange::MlKem1024 => {
            let (_, public_key) = MlKem1024::from_seed(&Seed::from(*seed));

            public_key.to_bytes().as_slice().to_vec()
        }
    };

    KemPublicKey { kem, bytes }
}

pub fn encapsulate(
    public_key: &KemPublicKey,
) -> Result<(KemCiphertext, KemSharedSecret), KemError> {
    match public_key.kem() {
        KeyExchange::MlKem512 => {
            let encoded = Key::<EncapsulationKey512>::try_from(public_key.as_bytes())
                .map_err(|_| KemError::InvalidPublicKey)?;

            let public_key =
                EncapsulationKey512::new(&encoded).map_err(|_| KemError::InvalidPublicKey)?;

            let (ciphertext, shared_key) = public_key.encapsulate();

            let shared_secret = KemSharedSecret::from_slice(shared_key.as_slice());

            Ok((
                KemCiphertext {
                    kem: KeyExchange::MlKem512,
                    bytes: ciphertext.as_slice().to_vec(),
                },
                shared_secret,
            ))
        }

        KeyExchange::MlKem768 => {
            let encoded = Key::<EncapsulationKey768>::try_from(public_key.as_bytes())
                .map_err(|_| KemError::InvalidPublicKey)?;

            let public_key =
                EncapsulationKey768::new(&encoded).map_err(|_| KemError::InvalidPublicKey)?;

            let (ciphertext, shared_key) = public_key.encapsulate();

            let shared_secret = KemSharedSecret::from_slice(shared_key.as_slice());

            Ok((
                KemCiphertext {
                    kem: KeyExchange::MlKem768,
                    bytes: ciphertext.as_slice().to_vec(),
                },
                shared_secret,
            ))
        }

        KeyExchange::MlKem1024 => {
            let encoded = Key::<EncapsulationKey1024>::try_from(public_key.as_bytes())
                .map_err(|_| KemError::InvalidPublicKey)?;

            let public_key =
                EncapsulationKey1024::new(&encoded).map_err(|_| KemError::InvalidPublicKey)?;

            let (ciphertext, shared_key) = public_key.encapsulate();

            let shared_secret = KemSharedSecret::from_slice(shared_key.as_slice());

            Ok((
                KemCiphertext {
                    kem: KeyExchange::MlKem1024,
                    bytes: ciphertext.as_slice().to_vec(),
                },
                shared_secret,
            ))
        }
    }
}

pub fn decapsulate(
    seed: &KemSeed,
    ciphertext: &KemCiphertext,
) -> Result<KemSharedSecret, KemError> {
    if seed.kem != ciphertext.kem {
        return Err(KemError::InvalidCiphertext);
    }

    match seed.kem {
        KeyExchange::MlKem512 => {
            let (secret_key, _) = MlKem512::from_seed(&Seed::from(seed.seed));

            let encoded = Ciphertext::<MlKem512>::try_from(ciphertext.as_bytes())
                .map_err(|_| KemError::InvalidCiphertext)?;

            let shared_key = secret_key.decapsulate(&encoded);

            let shared_secret = KemSharedSecret::from_slice(shared_key.as_slice());

            Ok(shared_secret)
        }

        KeyExchange::MlKem768 => {
            let (secret_key, _) = MlKem768::from_seed(&Seed::from(seed.seed));

            let encoded = Ciphertext::<MlKem768>::try_from(ciphertext.as_bytes())
                .map_err(|_| KemError::InvalidCiphertext)?;

            let shared_key = secret_key.decapsulate(&encoded);

            let shared_secret = KemSharedSecret::from_slice(shared_key.as_slice());

            Ok(shared_secret)
        }

        KeyExchange::MlKem1024 => {
            let (secret_key, _) = MlKem1024::from_seed(&Seed::from(seed.seed));

            let encoded = Ciphertext::<MlKem1024>::try_from(ciphertext.as_bytes())
                .map_err(|_| KemError::InvalidCiphertext)?;

            let shared_key = secret_key.decapsulate(&encoded);

            let shared_secret = KemSharedSecret::from_slice(shared_key.as_slice());

            Ok(shared_secret)
        }
    }
}

fn validate_public_key(kem: KeyExchange, bytes: &[u8]) -> Result<(), KemError> {
    match kem {
        KeyExchange::MlKem512 => {
            let encoded = Key::<EncapsulationKey512>::try_from(bytes)
                .map_err(|_| KemError::InvalidPublicKey)?;

            EncapsulationKey512::new(&encoded).map_err(|_| KemError::InvalidPublicKey)?;

            Ok(())
        }

        KeyExchange::MlKem768 => {
            let encoded = Key::<EncapsulationKey768>::try_from(bytes)
                .map_err(|_| KemError::InvalidPublicKey)?;

            EncapsulationKey768::new(&encoded).map_err(|_| KemError::InvalidPublicKey)?;

            Ok(())
        }

        KeyExchange::MlKem1024 => {
            let encoded = Key::<EncapsulationKey1024>::try_from(bytes)
                .map_err(|_| KemError::InvalidPublicKey)?;

            EncapsulationKey1024::new(&encoded).map_err(|_| KemError::InvalidPublicKey)?;

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(kem: KeyExchange) {
        let seed = KemSeed::new(kem, [7; ML_KEM_SEED_SIZE]);

        let public_key = seed.public_key();

        let (ciphertext, sent_secret) = encapsulate(&public_key).unwrap();

        let received_secret = decapsulate(&seed, &ciphertext).unwrap();

        assert_eq!(public_key.as_bytes().len(), kem.public_key_size(),);

        assert_eq!(ciphertext.as_bytes().len(), kem.ciphertext_size(),);

        assert_eq!(sent_secret, received_secret);
    }

    #[test]
    fn ml_kem_512_round_trip_from_seed() {
        round_trip(KeyExchange::MlKem512);
    }

    #[test]
    fn ml_kem_768_round_trip_from_seed() {
        round_trip(KeyExchange::MlKem768);
    }

    #[test]
    fn ml_kem_1024_round_trip_from_seed() {
        round_trip(KeyExchange::MlKem1024);
    }

    #[test]
    fn rejects_wrong_public_key_lengths() {
        for kem in [
            KeyExchange::MlKem512,
            KeyExchange::MlKem768,
            KeyExchange::MlKem1024,
        ] {
            assert_eq!(
                KemPublicKey::from_bytes(kem, vec![0; 1],),
                Err(KemError::InvalidPublicKey),
            );
        }
    }

    #[test]
    fn rejects_wrong_ciphertext_lengths() {
        for kem in [
            KeyExchange::MlKem512,
            KeyExchange::MlKem768,
            KeyExchange::MlKem1024,
        ] {
            assert_eq!(
                KemCiphertext::from_bytes(kem, vec![0; 1],),
                Err(KemError::InvalidCiphertext),
            );
        }
    }

    #[test]
    fn rejects_invalid_borsh_public_key_encoding() {
        for kem in [
            KeyExchange::MlKem512,
            KeyExchange::MlKem768,
            KeyExchange::MlKem1024,
        ] {
            let invalid = borsh::to_vec(&(kem, vec![0_u8; 1])).unwrap();

            assert!(KemPublicKey::try_from_slice(&invalid).is_err());
        }
    }

    #[test]
    fn rejects_invalid_borsh_ciphertext_encoding() {
        for kem in [
            KeyExchange::MlKem512,
            KeyExchange::MlKem768,
            KeyExchange::MlKem1024,
        ] {
            let invalid = borsh::to_vec(&(kem, vec![0_u8; 1])).unwrap();

            assert!(KemCiphertext::try_from_slice(&invalid).is_err());
        }
    }

    #[test]
    fn rejects_mismatched_kem_ciphertext() {
        let seed = KemSeed::new(KeyExchange::MlKem512, [7; ML_KEM_SEED_SIZE]);

        let other_seed = KemSeed::new(KeyExchange::MlKem768, [9; ML_KEM_SEED_SIZE]);

        let public_key = other_seed.public_key();

        let (ciphertext, _) = encapsulate(&public_key).unwrap();

        assert_eq!(
            decapsulate(&seed, &ciphertext),
            Err(KemError::InvalidCiphertext),
        );
    }

    #[test]
    fn shared_secret_is_redacted_and_zeroizable() {
        let mut secret = KemSharedSecret::from_bytes([7; ML_KEM_SHARED_SECRET_SIZE]);

        assert_eq!(format!("{secret:?}"), "KemSharedSecret([REDACTED])");
        secret.zeroize();
        assert_eq!(secret.as_bytes(), &[0; ML_KEM_SHARED_SECRET_SIZE]);
    }
}
