use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidAddressEncoding,
    InvalidKeyDerivationParameters,
    InvalidPublicKey,
    InvalidSignatureEncoding,
    InvalidPoWParameters,
    PoWHashFailed,
    VerificationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidAddressEncoding => f.write_str("address string is invalid"),
            CryptoError::InvalidKeyDerivationParameters => {
                f.write_str("key derivation parameters are invalid")
            }
            CryptoError::InvalidPublicKey => f.write_str("public key bytes are invalid"),
            CryptoError::InvalidSignatureEncoding => {
                #[cfg(feature = "sqisign-blockchain-test")]
                return f.write_str("signature bytes are not valid SQIsign Level 5 encoding");
                #[cfg(not(feature = "sqisign-blockchain-test"))]
                f.write_str("signature bytes are not valid ML-DSA-44 encoding")
            }
            CryptoError::InvalidPoWParameters => {
                f.write_str("proof-of-work hash parameters are invalid")
            }
            CryptoError::PoWHashFailed => f.write_str("proof-of-work hash failed"),
            CryptoError::VerificationFailed => f.write_str("signature verification failed"),
        }
    }
}

impl Error for CryptoError {}
