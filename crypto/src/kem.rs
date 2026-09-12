use std::{error::Error, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use ml_kem::{
    EncapsulationKey768, MlKem768, Seed,
    kem::{Ciphertext, Decapsulate, Encapsulate, FromSeed, Kem, Key, KeyExport},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEM_ACTIVATION_HEIGHT: u64 = 0;
pub const ML_KEM_SEED_SIZE: usize = 64;
pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
pub const ML_KEM_SHARED_SECRET_SIZE: usize = 32;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum KeyExchange {
    MlKem768 = 1,
}

impl KeyExchange {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MlKem768 => "mlkem768",
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
            Self::MlKem768 => ML_KEM_768_PUBLIC_KEY_SIZE,
        }
    }

    pub const fn ciphertext_size(self) -> usize {
        match self {
            Self::MlKem768 => ML_KEM_768_CIPHERTEXT_SIZE,
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
        decode_public_key(&bytes)?;
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

impl BorshDeserialize for KemCiphertext {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let kem = KeyExchange::deserialize_reader(reader)?;
        let bytes = Vec::<u8>::deserialize_reader(reader)?;
        Self::from_bytes(kem, bytes)
            .map_err(|error| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, error))
    }
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
        let (secret_key, _) = MlKem768::generate_keypair();
        Self {
            kem,
            seed: secret_key.to_bytes().into(),
        }
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
    let (_, public_key) = MlKem768::from_seed(&Seed::from(*seed));
    KemPublicKey {
        kem,
        bytes: public_key.to_bytes().as_slice().to_vec(),
    }
}

pub fn encapsulate(
    public_key: &KemPublicKey,
) -> Result<(KemCiphertext, [u8; ML_KEM_SHARED_SECRET_SIZE]), KemError> {
    let decoded = decode_public_key(public_key.as_bytes())?;
    let (ciphertext, shared_key) = decoded.encapsulate();
    let mut shared_secret = [0; ML_KEM_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(shared_key.as_slice());
    Ok((
        KemCiphertext {
            kem: public_key.kem,
            bytes: ciphertext.as_slice().to_vec(),
        },
        shared_secret,
    ))
}

pub fn decapsulate(
    seed: &KemSeed,
    ciphertext: &KemCiphertext,
) -> Result<[u8; ML_KEM_SHARED_SECRET_SIZE], KemError> {
    if seed.kem != ciphertext.kem {
        return Err(KemError::InvalidCiphertext);
    }
    let (secret_key, _) = MlKem768::from_seed(&Seed::from(seed.seed));
    let encoded = Ciphertext::<MlKem768>::try_from(ciphertext.as_bytes())
        .map_err(|_| KemError::InvalidCiphertext)?;
    let shared_key = secret_key.decapsulate(&encoded);
    let mut shared_secret = [0; ML_KEM_SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(shared_key.as_slice());
    Ok(shared_secret)
}

fn decode_public_key(bytes: &[u8]) -> Result<EncapsulationKey768, KemError> {
    let encoded =
        Key::<EncapsulationKey768>::try_from(bytes).map_err(|_| KemError::InvalidPublicKey)?;
    EncapsulationKey768::new(&encoded).map_err(|_| KemError::InvalidPublicKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_768_round_trip_from_seed() {
        let seed = KemSeed::new(KeyExchange::MlKem768, [7; ML_KEM_SEED_SIZE]);
        let public_key = seed.public_key();
        let (ciphertext, sent_secret) = encapsulate(&public_key).unwrap();
        let received_secret = decapsulate(&seed, &ciphertext).unwrap();

        assert_eq!(public_key.as_bytes().len(), ML_KEM_768_PUBLIC_KEY_SIZE);
        assert_eq!(ciphertext.as_bytes().len(), ML_KEM_768_CIPHERTEXT_SIZE);
        assert_eq!(sent_secret, received_secret);
    }

    #[test]
    fn rejects_wrong_public_key_and_ciphertext_lengths() {
        assert_eq!(
            KemPublicKey::from_bytes(KeyExchange::MlKem768, vec![0; 1]),
            Err(KemError::InvalidPublicKey),
        );
        assert_eq!(
            KemCiphertext::from_bytes(KeyExchange::MlKem768, vec![0; 1]),
            Err(KemError::InvalidCiphertext),
        );

        let invalid_key_encoding = borsh::to_vec(&(KeyExchange::MlKem768, vec![0_u8; 1])).unwrap();
        assert!(KemPublicKey::try_from_slice(&invalid_key_encoding).is_err());

        let invalid_ciphertext_encoding =
            borsh::to_vec(&(KeyExchange::MlKem768, vec![0_u8; 1])).unwrap();
        assert!(KemCiphertext::try_from_slice(&invalid_ciphertext_encoding).is_err());
    }
}
