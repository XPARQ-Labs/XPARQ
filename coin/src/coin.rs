use borsh::{BorshDeserialize, BorshSerialize};
use std::{fmt, str::FromStr};

use crate::CoinIdParseError;

pub const COIN_NAME: &str = "XPQ";
pub const UNIT_NAME: &str = "zeno";
pub const UNIT: u64 = 1;
pub const COIN: u64 = 1_000_000;
pub const DECIMALS: u8 = 6;

const _: () = assert!(COIN == 1_000_000);
const _: () = assert!(UNIT == 1);

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Amount {
    zeno: u64,
}

impl Amount {
    pub const fn from_zeno(zeno: u64) -> Self {
        Self { zeno }
    }

    pub const fn as_zeno(self) -> u64 {
        self.zeno
    }

    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.zeno.checked_add(rhs.zeno) {
            Some(zeno) => Some(Self { zeno }),
            None => None,
        }
    }

    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.zeno.checked_sub(rhs.zeno) {
            Some(zeno) => Some(Self { zeno }),
            None => None,
        }
    }
}

pub const COIN_ID_SIZE: usize = blake3::OUT_LEN;
pub const COIN_ID_PREFIX: &str = "XPQ:";
const COIN_ID_CONTEXT: &str = "XPARQ Native Coin";
const TRANSACTION_OUTPUT_DOMAIN: &[u8] = b"XPARQ transaction output v1";

/// Protocol-defined origin of a transaction-created Coin or QCash identifier.
///
/// The byte tags are consensus compatibility values. Callers select a typed
/// origin but cannot supply arbitrary hash fields or invent a new tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionOutputKind {
    AccountSpendOutput,
    WithdrawQCash,
    WithdrawChange,
    RedeemQCashChange,
    RedeemCoin,
    MergeQCash,
    MergePublicOutput,
    SplitQCash,
    SplitPublicOutput,
}

impl TransactionOutputKind {
    const fn tag(self) -> &'static [u8] {
        match self {
            Self::AccountSpendOutput => b"onchain",
            Self::WithdrawQCash => b"qcash",
            Self::WithdrawChange => b"change",
            Self::RedeemQCashChange => b"redeem-change",
            Self::RedeemCoin => b"redeem",
            Self::MergeQCash => b"merge",
            Self::MergePublicOutput => b"merge-miner",
            Self::SplitQCash => b"split",
            Self::SplitPublicOutput => b"split-miner",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct CoinId([u8; COIN_ID_SIZE]);

impl CoinId {
    pub const SIZE: usize = COIN_ID_SIZE;

    /// Derives the canonical CoinId for a block-emission output.
    pub fn from_emission_origin(origin: &[u8; COIN_ID_SIZE]) -> Self {
        Self::derive(&[b"XPARQ emission output v1", origin])
    }

    /// Derives the canonical CoinId for a transaction-created output.
    pub fn from_transaction_output(
        kind: TransactionOutputKind,
        commitment: &[u8; COIN_ID_SIZE],
        index: u32,
    ) -> Self {
        Self::derive(&[
            TRANSACTION_OUTPUT_DOMAIN,
            kind.tag(),
            commitment,
            &index.to_le_bytes(),
        ])
    }

    /// Low-level length-delimited derivation. Consensus callers must use one
    /// of the typed constructors above so field order and domain tags cannot
    /// be chosen independently.
    fn derive(fields: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(COIN_ID_CONTEXT);
        for field in fields {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        Self(*hasher.finalize().as_bytes())
    }

    pub const fn from_bytes(bytes: [u8; COIN_ID_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; COIN_ID_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; COIN_ID_SIZE] {
        self.0
    }
}

impl fmt::Display for CoinId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(COIN_ID_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for CoinId {
    type Err = CoinIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.strip_prefix(COIN_ID_PREFIX).ok_or(CoinIdParseError)?;
        if value.len() != COIN_ID_SIZE * 2 {
            return Err(CoinIdParseError);
        }

        let encoded = value.as_bytes();
        let mut bytes = [0; COIN_ID_SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            let high = hex_nibble(encoded[offset]).ok_or(CoinIdParseError)?;
            let low = hex_nibble(encoded[offset + 1]).ok_or(CoinIdParseError)?;
            *byte = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A minimal coin primitive: an immutable identifier paired with an amount.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct Coin {
    pub id: CoinId,
    pub amount: Amount,
}

impl Coin {
    pub const fn new(id: CoinId, amount: Amount) -> Self {
        Self { id, amount }
    }

    pub const fn is_zero(self) -> bool {
        self.amount.as_zeno() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_checked_arithmetic_preserves_the_amount_type() {
        let amount = Amount::from_zeno(7);
        assert_eq!(amount.as_zeno(), 7);
        assert_eq!(borsh::to_vec(&amount).unwrap(), 7_u64.to_le_bytes());
        assert_eq!(
            Amount::try_from_slice(&7_u64.to_le_bytes()).unwrap(),
            amount
        );
        assert_eq!(
            Amount::from_zeno(2).checked_add(Amount::from_zeno(3)),
            Some(Amount::from_zeno(5))
        );
        assert_eq!(
            Amount::from_zeno(u64::MAX).checked_add(Amount::from_zeno(1)),
            None
        );
        assert_eq!(
            Amount::from_zeno(5).checked_sub(Amount::from_zeno(3)),
            Some(Amount::from_zeno(2))
        );
        assert_eq!(Amount::from_zeno(0).checked_sub(Amount::from_zeno(1)), None);
    }

    #[test]
    fn coin_id_text_round_trips() {
        let id = CoinId::from_transaction_output(
            TransactionOutputKind::AccountSpendOutput,
            &[7; COIN_ID_SIZE],
            3,
        );
        assert!(id.to_string().starts_with(COIN_ID_PREFIX));
        assert_eq!(id.to_string().parse::<CoinId>(), Ok(id));
    }

    #[test]
    fn typed_derivation_preserves_consensus_tags_and_field_order() {
        let origin = [9; COIN_ID_SIZE];
        assert_eq!(
            CoinId::from_emission_origin(&origin),
            CoinId::derive(&[b"XPARQ emission output v1", &origin])
        );

        let commitment = [4; COIN_ID_SIZE];
        let index = 12_u32;
        for (kind, tag) in [
            (
                TransactionOutputKind::AccountSpendOutput,
                b"onchain".as_slice(),
            ),
            (TransactionOutputKind::WithdrawQCash, b"qcash"),
            (TransactionOutputKind::WithdrawChange, b"change"),
            (TransactionOutputKind::RedeemQCashChange, b"redeem-change"),
            (TransactionOutputKind::RedeemCoin, b"redeem"),
            (TransactionOutputKind::MergeQCash, b"merge"),
            (TransactionOutputKind::MergePublicOutput, b"merge-miner"),
            (TransactionOutputKind::SplitQCash, b"split"),
            (TransactionOutputKind::SplitPublicOutput, b"split-miner"),
        ] {
            assert_eq!(
                CoinId::from_transaction_output(kind, &commitment, index),
                CoinId::derive(&[
                    b"XPARQ transaction output v1",
                    tag,
                    &commitment,
                    &index.to_le_bytes(),
                ])
            );
        }
    }

    #[test]
    fn coin_id_parser_requires_exact_xpq_prefix() {
        let encoded = "00".repeat(COIN_ID_SIZE);
        assert_eq!(encoded.parse::<CoinId>(), Err(CoinIdParseError));
        assert_eq!(
            format!("xpq:{encoded}").parse::<CoinId>(),
            Err(CoinIdParseError)
        );
        assert_eq!(
            format!("XPQ:{encoded}").parse::<CoinId>(),
            Ok(CoinId::from_bytes([0; COIN_ID_SIZE]))
        );
    }

    #[test]
    fn coin_id_parser_rejects_non_ascii_without_panicking() {
        let non_ascii_with_valid_byte_length =
            format!("{COIN_ID_PREFIX}{}{}", "0".repeat(61), "\u{20ac}");
        assert_eq!(
            non_ascii_with_valid_byte_length.len(),
            COIN_ID_PREFIX.len() + COIN_ID_SIZE * 2
        );
        assert_eq!(
            non_ascii_with_valid_byte_length.parse::<CoinId>(),
            Err(CoinIdParseError)
        );
    }
}
