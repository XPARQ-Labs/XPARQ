use std::{error::Error, fmt};

use crate::{QCash, QCashSigningSeed};
use borsh::{BorshDeserialize, BorshSerialize};
use xparq_crypto::{HASH_SIZE, HashDomain, domain_hash};
use zeroize::Zeroizing;

pub const QCASH_FILE_MAGIC: [u8; 8] = *b"XPQCASH1";
pub const MAX_QCASH_FILE_SIZE: usize = 1024;
const PAYLOAD_LENGTH_SIZE: usize = size_of::<u32>();

/// Returns the canonical portable filename for a QCash bearer file.
pub fn canonical_qcash_file_name(qcash: QCash) -> String {
    qcash_file_name(qcash, 1)
}

/// Returns an amount-based filename, adding `(N)` for the second and later files.
pub fn qcash_file_name(qcash: QCash, sequence: usize) -> String {
    assert!(sequence >= 1, "QCash filename sequence starts at one");
    let amount = qcash.amount().as_zeno();
    let whole = amount / xparq_coin::COIN;
    let fractional = amount % xparq_coin::COIN;
    let amount = if fractional == 0 {
        whole.to_string()
    } else {
        let fractional = format!("{fractional:06}");
        format!("{whole}.{}", fractional.trim_end_matches('0'))
    };
    if sequence == 1 {
        format!("{amount}XPQ.QCash")
    } else {
        format!("{amount}XPQ({sequence}).QCash")
    }
}

/// Requires the local filename to match the amount and optional collision sequence.
pub fn validate_qcash_file_name(file_name: &str, qcash: QCash) -> Result<(), QCashFileNameError> {
    let expected = canonical_qcash_file_name(qcash);
    let stem = expected
        .strip_suffix(".QCash")
        .expect("canonical QCash filename has a fixed extension");
    let valid_sequence = file_name
        .strip_prefix(stem)
        .and_then(|suffix| suffix.strip_suffix(".QCash"))
        .and_then(|suffix| suffix.strip_prefix('('))
        .and_then(|suffix| suffix.strip_suffix(')'))
        .filter(|sequence| !sequence.starts_with('0'))
        .and_then(|sequence| sequence.parse::<usize>().ok())
        .is_some_and(|sequence| sequence >= 2);
    if file_name == expected || valid_sequence {
        Ok(())
    } else {
        Err(QCashFileNameError { expected })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QCashFileNameError {
    expected: String,
}

impl QCashFileNameError {
    pub fn expected(&self) -> &str {
        &self.expected
    }
}

impl fmt::Display for QCashFileNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "QCash filename does not match file contents; expected `{}` or its numbered form",
            self.expected
        )
    }
}

impl Error for QCashFileNameError {}

/// Data carried by one portable `.QCash` bearer file.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct QCashFile {
    pub qcash: QCash,
    pub signing_seed: QCashSigningSeed,
}

impl QCashFile {
    pub const fn new(qcash: QCash, signing_seed: QCashSigningSeed) -> Self {
        Self {
            qcash,
            signing_seed,
        }
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, QCashFileError> {
        let payload = Zeroizing::new(borsh::to_vec(self).map_err(|_| QCashFileError::Encoding)?);
        let payload_length = u32::try_from(payload.len()).map_err(|_| QCashFileError::TooLarge)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            QCASH_FILE_MAGIC.len() + PAYLOAD_LENGTH_SIZE + payload.len() + HASH_SIZE,
        ));
        bytes.extend_from_slice(&QCASH_FILE_MAGIC);
        bytes.extend_from_slice(&payload_length.to_le_bytes());
        bytes.extend_from_slice(&payload);
        let checksum = domain_hash(HashDomain::QCashFile, &bytes);
        bytes.extend_from_slice(&checksum.0);
        if bytes.len() > MAX_QCASH_FILE_SIZE {
            return Err(QCashFileError::TooLarge);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QCashFileError> {
        if bytes.len() > MAX_QCASH_FILE_SIZE {
            return Err(QCashFileError::TooLarge);
        }
        let body = bytes
            .strip_prefix(&QCASH_FILE_MAGIC)
            .ok_or(QCashFileError::InvalidMagic)?;
        let length_bytes = body
            .get(..PAYLOAD_LENGTH_SIZE)
            .ok_or(QCashFileError::Truncated)?;
        let payload_length = u32::from_le_bytes(
            length_bytes
                .try_into()
                .map_err(|_| QCashFileError::Truncated)?,
        ) as usize;
        let expected_length = QCASH_FILE_MAGIC
            .len()
            .checked_add(PAYLOAD_LENGTH_SIZE)
            .and_then(|length| length.checked_add(payload_length))
            .and_then(|length| length.checked_add(HASH_SIZE))
            .ok_or(QCashFileError::TooLarge)?;
        if bytes.len() != expected_length {
            return Err(QCashFileError::InvalidLength);
        }
        let checksum_offset = expected_length - HASH_SIZE;
        let expected_checksum = domain_hash(HashDomain::QCashFile, &bytes[..checksum_offset]);
        if bytes[checksum_offset..] != expected_checksum.0 {
            return Err(QCashFileError::ChecksumMismatch);
        }
        let payload = &bytes[QCASH_FILE_MAGIC.len() + PAYLOAD_LENGTH_SIZE..checksum_offset];
        Self::try_from_slice(payload).map_err(|_| QCashFileError::Encoding)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QCashFileError {
    InvalidMagic,
    Truncated,
    InvalidLength,
    ChecksumMismatch,
    TooLarge,
    Encoding,
}

impl fmt::Display for QCashFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMagic => "invalid QCash file magic",
            Self::Truncated => "QCash file is truncated",
            Self::InvalidLength => "QCash file length does not match its header",
            Self::ChecksumMismatch => "QCash file checksum mismatch",
            Self::TooLarge => "QCash file exceeds maximum size",
            Self::Encoding => "invalid QCash file encoding",
        })
    }
}

impl Error for QCashFileError {}

impl fmt::Debug for QCashFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QCashFile")
            .field("qcash", &self.qcash)
            .field("signing_seed", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xparq_coin::{Amount, COIN, CoinHash};

    fn qcash(amount: u64) -> QCash {
        QCash::new(
            CoinHash::from_bytes([0xab; CoinHash::SIZE]),
            Amount::from_zeno(amount),
        )
    }

    #[test]
    fn canonical_filename_contains_amount() {
        assert_eq!(canonical_qcash_file_name(qcash(5 * COIN)), "5XPQ.QCash");
        assert_eq!(
            canonical_qcash_file_name(qcash(29 * COIN + 900_000)),
            "29.9XPQ.QCash"
        );
        assert_eq!(canonical_qcash_file_name(qcash(1)), "0.000001XPQ.QCash");
        assert_eq!(qcash_file_name(qcash(5 * COIN), 2), "5XPQ(2).QCash");
        assert_eq!(qcash_file_name(qcash(5 * COIN), 3), "5XPQ(3).QCash");
    }

    #[test]
    fn filename_validation_rejects_renamed_or_mismatched_files() {
        let qcash = qcash(5 * COIN);
        let expected = canonical_qcash_file_name(qcash);
        assert_eq!(validate_qcash_file_name(&expected, qcash), Ok(()));
        assert_eq!(validate_qcash_file_name("5XPQ(2).QCash", qcash), Ok(()));
        assert_eq!(validate_qcash_file_name("5XPQ(27).QCash", qcash), Ok(()));

        let error = validate_qcash_file_name("6XPQ_wrong.QCash", qcash).unwrap_err();
        assert_eq!(error.expected(), expected);
        assert!(validate_qcash_file_name("5XPQ(1).QCash", qcash).is_err());
        assert!(validate_qcash_file_name("5XPQ(02).QCash", qcash).is_err());
    }

    #[test]
    fn file_roundtrip_preserves_plaintext_signing_seed() {
        let file = QCashFile::new(qcash(5 * COIN), QCashSigningSeed::from_bytes([9; 32]));
        let encoded = file.encode().unwrap();
        let decoded = QCashFile::decode(&encoded).unwrap();
        assert_eq!(decoded.qcash, file.qcash);
        assert_eq!(decoded.signing_seed.as_bytes(), &[9; 32]);
    }

    #[test]
    fn checksum_rejects_corruption_truncation_and_trailing_bytes() {
        let file = QCashFile::new(qcash(5 * COIN), QCashSigningSeed::from_bytes([9; 32]));
        let encoded = file.encode().unwrap();

        let mut corrupted = encoded.to_vec();
        corrupted[QCASH_FILE_MAGIC.len() + PAYLOAD_LENGTH_SIZE] ^= 1;
        assert_eq!(
            QCashFile::decode(&corrupted),
            Err(QCashFileError::ChecksumMismatch)
        );

        assert_eq!(
            QCashFile::decode(&encoded[..encoded.len() - 1]),
            Err(QCashFileError::InvalidLength)
        );

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            QCashFile::decode(&trailing),
            Err(QCashFileError::InvalidLength)
        );
    }
}
