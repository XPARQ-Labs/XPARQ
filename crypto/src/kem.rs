use borsh::{BorshDeserialize, BorshSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEM_ACTIVATION_HEIGHT: u64 = 0;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
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
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct KemPublicKey {
    pub kem: KeyExchange,
    pub bytes: Vec<u8>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Ciphertext {
    pub kem: KeyExchange,
    pub bytes: Vec<u8>,
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Zeroize,
    ZeroizeOnDrop,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct KemSeed {
    #[zeroize(skip)]
    kem: KeyExchange,

    seed: [u8; 64],
}

impl KemSeed {
    pub const fn new(kem: KeyExchange, seed: [u8; 64]) -> Self {
        Self { kem, seed }
    }

    pub const fn kem(&self) -> Kem {
        self.kem
    }

    pub const fn to_bytes(&self) -> [u8; 64] {
        self.seed
    }

    pub fn public_key(&self) -> KemPublicKey {
        kem_public_key_from_seed(self.kem, &self.seed)
    }
}

pub fn kem_public_key_from_seed(
    kem: KeyExchange,
    seed: &[u8; 64],
) -> KemPublicKey

pub fn encapsulate(
    public_key: &KemPublicKey,
) -> Result<(KemCiphertext, [u8; 32]), KemError>

pub fn decapsulate(
    seed: &KemSeed,
    ciphertext: &KemCiphertext,
) -> Result<[u8; 32], KemError>

