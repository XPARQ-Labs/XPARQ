use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidProgramIdEncoding,
    InvalidKeyDerivationParameters,
    InvalidPublicKey,
    InvalidPublicKeyLength,
    InvalidAccountScheme,
    InvalidSignatureEncoding,
    InvalidPoWParameters,
    PoWHashFailed,
    VerificationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProgramIdEncoding => {
                f.write_str("program ID must contain 64 hexadecimal characters")
            }
            Self::InvalidKeyDerivationParameters => {
                f.write_str("key derivation parameters are invalid")
            }
            Self::InvalidPublicKeyLength => {
                f.write_str("public key length does not match account scheme")
            }
            Self::InvalidAccountScheme => f.write_str("account scheme identifier is invalid"),
            Self::InvalidPublicKey => f.write_str("public key bytes are invalid"),
            Self::InvalidSignatureEncoding => {
                #[cfg(feature = "sqisign-blockchain-test")]
                return f.write_str("signature bytes are not valid SQIsign Level 5 encoding");

                #[cfg(not(feature = "sqisign-blockchain-test"))]
                f.write_str("signature bytes are not valid Signature encoding")
            }
            Self::InvalidPoWParameters => f.write_str("proof-of-work hash parameters are invalid"),
            Self::PoWHashFailed => f.write_str("proof-of-work hash failed"),
            Self::VerificationFailed => f.write_str("signature verification failed"),
        }
    }
}

impl Error for CryptoError {}
