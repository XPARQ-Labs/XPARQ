use crate::consensus::supply::{Amount, XPQ};
use crate::crypto::{
    Address, HashDomain, PublicKey, Signature, TransactionHash, domain_hash, public_key_from_seed,
    sign_from_seed, verify,
};
use crate::genesis::CURRENT_CHAIN_PARAMS;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const QCASH_FILE_MAGIC: [u8; 8] = *b"XPQCASH1";
pub const QCASH_FILE_VERSION: u8 = 1;
pub const MAX_QCASH_FILE_SIZE: usize = 1024;
pub const MAX_QCASH_WITHDRAW_OUTPUTS: usize = 256;
pub const MAX_QCASH_DEPOSIT_INPUTS: usize = 4;

/// Supported cash denominations, expressed in whole XPQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum QCashDenomination {
    One = 1,
    Two = 2,
    Five = 5,
    Ten = 10,
    Twenty = 20,
    Fifty = 50,
    OneHundred = 100,
    FiveHundred = 500,
    OneThousand = 1000,
    FiveThousand = 5_000,
    TenThousand = 10_000,
    FiftyThousand = 50_000,
    OneHundredThousand = 100_000,
    FiveHundredThousand = 500_000,
    OneMillion = 1_000_000,
}

impl QCashDenomination {
    pub const DESCENDING: [Self; 15] = [
        Self::OneMillion,
        Self::FiveHundredThousand,
        Self::OneHundredThousand,
        Self::FiftyThousand,
        Self::TenThousand,
        Self::FiveThousand,
        Self::OneThousand,
        Self::FiveHundred,
        Self::OneHundred,
        Self::Fifty,
        Self::Twenty,
        Self::Ten,
        Self::Five,
        Self::Two,
        Self::One,
    ];

    pub const fn xpq(self) -> u64 {
        self as u32 as u64
    }

    pub const fn amount(self) -> Amount {
        Amount(self.xpq() * XPQ)
    }
}

impl BorshSerialize for QCashDenomination {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&(self.xpq() as u32), writer)
    }
}

impl BorshDeserialize for QCashDenomination {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        match u32::deserialize_reader(reader)? {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            5 => Ok(Self::Five),
            10 => Ok(Self::Ten),
            20 => Ok(Self::Twenty),
            50 => Ok(Self::Fifty),
            100 => Ok(Self::OneHundred),
            500 => Ok(Self::FiveHundred),
            1000 => Ok(Self::OneThousand),
            5_000 => Ok(Self::FiveThousand),
            10_000 => Ok(Self::TenThousand),
            50_000 => Ok(Self::FiftyThousand),
            100_000 => Ok(Self::OneHundredThousand),
            500_000 => Ok(Self::FiveHundredThousand),
            1_000_000 => Ok(Self::OneMillion),
            value => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported QCash denomination {value}"),
            )),
        }
    }
}

/// A compact run of identical QCash coins.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct QCashCoin {
    pub denomination: QCashDenomination,
    pub count: u64,
}

/// One consensus-visible output created by a withdraw transaction.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct QCashOutput {
    pub coin_index: u32,
    pub denomination: QCashDenomination,
    /// Commitment to wallet-held secret material; the secret is never put on-chain.
    pub commitment: [u8; 32],
}

/// Explicit outputs committed by one withdraw transaction.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct QCashWithdrawMetadata {
    pub outputs: Vec<QCashOutput>,
}

/// Automatic whole-XPQ cash selection with the unconverted on-chain remainder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QCashWithdrawalPlan {
    pub requested_amount: Amount,
    pub qcash_amount: Amount,
    pub remainder: Amount,
    pub denominations: Vec<QCashDenomination>,
}

/// Portable bearer coin data stored by the wallet in a `.XPQ` file.
#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct QCashCoinFile {
    pub version: u8,
    /// Opaque state lookup key. The originating transaction hash is not stored
    /// in the portable bearer file.
    pub coin_id: [u8; 32],
    pub denomination: QCashDenomination,
    pub opening_secret: [u8; 32],
}

impl Drop for QCashCoinFile {
    fn drop(&mut self) {
        self.opening_secret.zeroize();
    }
}

impl fmt::Debug for QCashCoinFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QCashCoinFile")
            .field("version", &self.version)
            .field("coin_id", &self.coin_id)
            .field("denomination", &self.denomination)
            .field("opening_secret", &"[REDACTED]")
            .finish()
    }
}

/// Public proof authorizing exactly one QCash coin to be credited to one recipient.
/// The wallet-held opening secret is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct QCashDepositInput {
    pub version: u8,
    pub coin_id: [u8; 32],
    pub denomination: QCashDenomination,
    pub spend_public_key: PublicKey,
    pub authorization: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct QCashDepositMetadata {
    pub inputs: Vec<QCashDepositInput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QCashError {
    ZeroAmount,
    FractionalXpQ,
    EmptyCoins,
    ZeroCoinCount,
    NonCanonicalCoins,
    AmountOverflow,
    EmptyOutputs,
    InvalidCoinIndex,
    DuplicateCommitment,
    CommitmentCountMismatch,
    DenominationAmountMismatch,
    NoCashableAmount,
    UnsupportedQCashFileVersion,
    EmptyDepositInputs,
    DuplicateDepositInput,
    InvalidCommitment,
    InvalidDepositAuthorization,
    InvalidQCashFile,
    QCashFileTooLarge,
    TooManyWithdrawOutputs,
    TooManyDepositInputs,
    Serialization,
}

impl fmt::Display for QCashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroAmount => f.write_str("QCash amount must be greater than zero"),
            Self::FractionalXpQ => f.write_str("QCash amount must use whole XPQ units"),
            Self::EmptyCoins => f.write_str("QCash metadata must contain at least one coin"),
            Self::ZeroCoinCount => f.write_str("QCash coin count must be greater than zero"),
            Self::NonCanonicalCoins => {
                f.write_str("QCash coins must be unique and ordered by descending denomination")
            }
            Self::AmountOverflow => f.write_str("QCash amount exceeds the supported amount range"),
            Self::EmptyOutputs => f.write_str("withdraw must contain at least one QCash output"),
            Self::InvalidCoinIndex => {
                f.write_str("QCash output indexes must be contiguous from zero")
            }
            Self::DuplicateCommitment => f.write_str("QCash output commitments must be unique"),
            Self::CommitmentCountMismatch => {
                f.write_str("wallet commitment count does not match QCash coin count")
            }
            Self::DenominationAmountMismatch => {
                f.write_str("QCash output denominations do not match withdraw amount")
            }
            Self::NoCashableAmount => {
                f.write_str("requested amount contains less than one whole XPQ for QCash")
            }
            Self::UnsupportedQCashFileVersion => {
                f.write_str("QCash coin file version is unsupported")
            }
            Self::EmptyDepositInputs => {
                f.write_str("QCash deposit must contain at least one input")
            }
            Self::DuplicateDepositInput => {
                f.write_str("QCash deposit contains a duplicate coin reference")
            }
            Self::InvalidCommitment => {
                f.write_str("QCash coin spending key does not match commitment")
            }
            Self::InvalidDepositAuthorization => {
                f.write_str("QCash deposit authorization is invalid for its recipient")
            }
            Self::InvalidQCashFile => f.write_str("QCash coin file is malformed or corrupted"),
            Self::QCashFileTooLarge => f.write_str("QCash coin file exceeds maximum size"),
            Self::TooManyWithdrawOutputs => f.write_str("withdraw creates too many QCash outputs"),
            Self::TooManyDepositInputs => f.write_str("QCash deposit contains too many inputs"),
            Self::Serialization => f.write_str("failed to serialize QCash data"),
        }
    }
}

pub fn qcash_coin_commitment(opening_secret: &[u8; 32]) -> [u8; 32] {
    qcash_spend_public_key_commitment(&public_key_from_seed(opening_secret))
}

pub fn qcash_spend_public_key_commitment(public_key: &PublicKey) -> [u8; 32] {
    domain_hash(HashDomain::QCashCommitment, &public_key.0).0
}

fn deposit_authorization_bytes(
    coin_id: [u8; 32],
    denomination: QCashDenomination,
    recipient: Address,
    transaction_commitment: [u8; 32],
) -> Result<Vec<u8>, QCashError> {
    #[derive(BorshSerialize)]
    struct DepositAuthorizationPayload {
        chain_id: u32,
        protocol_version: u8,
        operation: u8,
        coin_id: [u8; 32],
        denomination: QCashDenomination,
        recipient: Address,
        transaction_commitment: [u8; 32],
    }

    let payload = DepositAuthorizationPayload {
        chain_id: CURRENT_CHAIN_PARAMS.chain_id,
        protocol_version: CURRENT_CHAIN_PARAMS.protocol_version,
        operation: 1,
        coin_id,
        denomination,
        recipient,
        transaction_commitment,
    };
    Ok(domain_hash(
        HashDomain::QCashDepositAuthorization,
        &crate::codec::canonical_bytes(&payload).map_err(|_| QCashError::Serialization)?,
    )
    .0
    .to_vec())
}

/// Derives the opaque identifier shared by consensus state and the bearer file.
pub fn qcash_coin_id_bytes(
    withdraw_tx_hash: TransactionHash,
    output: &QCashOutput,
) -> Result<[u8; 32], QCashError> {
    let payload = crate::codec::canonical_bytes(&(withdraw_tx_hash, output))
        .map_err(|_| QCashError::Serialization)?;
    Ok(domain_hash(HashDomain::QCashCoin, &payload).0)
}

/// Encodes one bearer coin using the only supported `.XPQ` binary format.
pub fn encode_qcash_coin_file(file: &QCashCoinFile) -> Result<Zeroizing<Vec<u8>>, QCashError> {
    if file.version != QCASH_FILE_VERSION {
        return Err(QCashError::UnsupportedQCashFileVersion);
    }
    let payload =
        Zeroizing::new(crate::codec::canonical_bytes(file).map_err(|_| QCashError::Serialization)?);
    let payload_len = u32::try_from(payload.len()).map_err(|_| QCashError::QCashFileTooLarge)?;
    let checksum = domain_hash(HashDomain::QCashFile, &payload).0;
    let mut bytes = Vec::with_capacity(8 + 4 + payload.len() + checksum.len());
    bytes.extend_from_slice(&QCASH_FILE_MAGIC);
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&checksum);
    if bytes.len() > MAX_QCASH_FILE_SIZE {
        return Err(QCashError::QCashFileTooLarge);
    }
    Ok(Zeroizing::new(bytes))
}

/// Strictly decodes and checks a canonical `.XPQ` bearer coin file.
pub fn decode_qcash_coin_file(bytes: &[u8]) -> Result<QCashCoinFile, QCashError> {
    const PREFIX_LEN: usize = 12;
    const CHECKSUM_LEN: usize = 32;
    if bytes.len() > MAX_QCASH_FILE_SIZE || bytes.len() < PREFIX_LEN + CHECKSUM_LEN {
        return Err(if bytes.len() > MAX_QCASH_FILE_SIZE {
            QCashError::QCashFileTooLarge
        } else {
            QCashError::InvalidQCashFile
        });
    }
    if bytes[..8] != QCASH_FILE_MAGIC {
        return Err(QCashError::InvalidQCashFile);
    }
    let payload_len = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| QCashError::InvalidQCashFile)?,
    ) as usize;
    let expected_len = PREFIX_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(CHECKSUM_LEN))
        .ok_or(QCashError::InvalidQCashFile)?;
    if bytes.len() != expected_len {
        return Err(QCashError::InvalidQCashFile);
    }

    let payload = &bytes[PREFIX_LEN..PREFIX_LEN + payload_len];
    let checksum = &bytes[PREFIX_LEN + payload_len..];
    if checksum != domain_hash(HashDomain::QCashFile, payload).0 {
        return Err(QCashError::InvalidQCashFile);
    }
    let file: QCashCoinFile =
        crate::codec::canonical_deserialize(payload).map_err(|_| QCashError::InvalidQCashFile)?;
    if file.version != QCASH_FILE_VERSION
        || crate::codec::canonical_bytes(&file).map_err(|_| QCashError::Serialization)? != payload
    {
        return Err(QCashError::InvalidQCashFile);
    }
    Ok(file)
}

impl QCashCoinFile {
    pub fn new(
        withdraw_tx_hash: TransactionHash,
        output: &QCashOutput,
        opening_secret: [u8; 32],
    ) -> Result<Self, QCashError> {
        let file = Self {
            version: QCASH_FILE_VERSION,
            coin_id: qcash_coin_id_bytes(withdraw_tx_hash, output)?,
            denomination: output.denomination,
            opening_secret,
        };
        if qcash_coin_commitment(&file.opening_secret) != output.commitment {
            return Err(QCashError::InvalidCommitment);
        }
        Ok(file)
    }

    pub fn deposit_input_for_transaction(
        &self,
        recipient: Address,
        transaction_commitment: [u8; 32],
    ) -> Result<QCashDepositInput, QCashError> {
        if self.version != QCASH_FILE_VERSION {
            return Err(QCashError::UnsupportedQCashFileVersion);
        }
        QCashDepositInput::authorize(
            self.coin_id,
            self.denomination,
            &self.opening_secret,
            recipient,
            transaction_commitment,
        )
    }

    pub fn commitment(&self) -> [u8; 32] {
        qcash_coin_commitment(&self.opening_secret)
    }
}

impl QCashDepositMetadata {
    pub fn from_inputs(inputs: Vec<QCashDepositInput>) -> Result<Self, QCashError> {
        let metadata = Self { inputs };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn new_for_transaction(
        files: &[QCashCoinFile],
        recipient: Address,
        transaction_commitment: [u8; 32],
    ) -> Result<Self, QCashError> {
        let inputs = files
            .iter()
            .map(|file| file.deposit_input_for_transaction(recipient, transaction_commitment))
            .collect::<Result<Vec<_>, _>>()?;
        let metadata = Self { inputs };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn validate_authorizations_for_transaction(
        &self,
        recipient: Address,
        transaction_commitment: [u8; 32],
    ) -> Result<(), QCashError> {
        self.validate()?;
        for input in &self.inputs {
            let message = deposit_authorization_bytes(
                input.coin_id,
                input.denomination,
                recipient,
                transaction_commitment,
            )?;
            if !verify(&input.spend_public_key, &message, &input.authorization) {
                return Err(QCashError::InvalidDepositAuthorization);
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), QCashError> {
        use std::collections::BTreeSet;
        if self.inputs.is_empty() {
            return Err(QCashError::EmptyDepositInputs);
        }
        if self.inputs.len() > MAX_QCASH_DEPOSIT_INPUTS {
            return Err(QCashError::TooManyDepositInputs);
        }
        let mut references = BTreeSet::new();
        for input in &self.inputs {
            if input.version != QCASH_FILE_VERSION {
                return Err(QCashError::UnsupportedQCashFileVersion);
            }
            if !references.insert(input.coin_id) {
                return Err(QCashError::DuplicateDepositInput);
            }
        }
        self.amount().map(|_| ())
    }

    pub fn amount(&self) -> Result<Amount, QCashError> {
        self.inputs.iter().try_fold(Amount(0), |total, input| {
            total
                .0
                .checked_add(input.denomination.amount().0)
                .map(Amount)
                .ok_or(QCashError::AmountOverflow)
        })
    }
}

impl QCashDepositInput {
    /// Builds the public authorization consumed by consensus. Wallet layers
    /// call this after decoding their private bearer-file format.
    pub fn authorize(
        coin_id: [u8; 32],
        denomination: QCashDenomination,
        opening_secret: &[u8; 32],
        recipient: Address,
        transaction_commitment: [u8; 32],
    ) -> Result<Self, QCashError> {
        let spend_public_key = public_key_from_seed(opening_secret);
        let message =
            deposit_authorization_bytes(coin_id, denomination, recipient, transaction_commitment)?;
        Ok(Self {
            version: QCASH_FILE_VERSION,
            coin_id,
            denomination,
            spend_public_key,
            authorization: sign_from_seed(opening_secret, &message),
        })
    }

    pub fn commitment(&self) -> [u8; 32] {
        qcash_spend_public_key_commitment(&self.spend_public_key)
    }
}

impl QCashWithdrawMetadata {
    /// Plans automatic denomination selection. Fractions remain on-chain.
    pub fn plan_automatic(amount: Amount) -> Result<QCashWithdrawalPlan, QCashError> {
        let qcash_amount = Amount(amount.0 - (amount.0 % XPQ));
        let remainder = Amount(amount.0 % XPQ);
        if qcash_amount.0 == 0 {
            return Err(QCashError::NoCashableAmount);
        }

        let runs = format_qcash_coins(qcash_amount)?;
        let mut denominations = Vec::new();
        for run in runs {
            let count = usize::try_from(run.count).map_err(|_| QCashError::AmountOverflow)?;
            if denominations.len().saturating_add(count) > MAX_QCASH_WITHDRAW_OUTPUTS {
                return Err(QCashError::TooManyWithdrawOutputs);
            }
            denominations.extend(std::iter::repeat_n(run.denomination, count));
        }
        Ok(QCashWithdrawalPlan {
            requested_amount: amount,
            qcash_amount,
            remainder,
            denominations,
        })
    }

    pub fn from_automatic_plan(
        plan: &QCashWithdrawalPlan,
        commitments: &[[u8; 32]],
    ) -> Result<Self, QCashError> {
        Self::with_denominations(plan.qcash_amount, &plan.denominations, commitments)
    }

    pub fn new(amount: Amount, commitments: &[[u8; 32]]) -> Result<Self, QCashError> {
        let runs = format_qcash_coins(amount)?;
        let coin_count = runs.iter().try_fold(0u64, |total, run| {
            total
                .checked_add(run.count)
                .ok_or(QCashError::AmountOverflow)
        })?;
        if coin_count != commitments.len() as u64 {
            return Err(QCashError::CommitmentCountMismatch);
        }
        let coin_count = usize::try_from(coin_count).map_err(|_| QCashError::AmountOverflow)?;
        if coin_count > MAX_QCASH_WITHDRAW_OUTPUTS {
            return Err(QCashError::TooManyWithdrawOutputs);
        }

        let mut outputs = Vec::with_capacity(commitments.len());
        let mut coin_index = 0u32;
        for run in runs {
            for _ in 0..run.count {
                outputs.push(QCashOutput {
                    coin_index,
                    denomination: run.denomination,
                    commitment: commitments[coin_index as usize],
                });
                coin_index = coin_index
                    .checked_add(1)
                    .ok_or(QCashError::AmountOverflow)?;
            }
        }
        let metadata = Self { outputs };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn with_denominations(
        amount: Amount,
        denominations: &[QCashDenomination],
        commitments: &[[u8; 32]],
    ) -> Result<Self, QCashError> {
        if denominations.len() != commitments.len() {
            return Err(QCashError::CommitmentCountMismatch);
        }
        if denominations.len() > MAX_QCASH_WITHDRAW_OUTPUTS {
            return Err(QCashError::TooManyWithdrawOutputs);
        }
        let outputs = denominations
            .iter()
            .copied()
            .zip(commitments.iter().copied())
            .enumerate()
            .map(|(coin_index, (denomination, commitment))| QCashOutput {
                coin_index: coin_index as u32,
                denomination,
                commitment,
            })
            .collect();
        let metadata = Self { outputs };
        metadata.validate_amount(amount)?;
        Ok(metadata)
    }

    /// Builds withdraw metadata from exact user-selected denominations.
    pub fn with_selected_denominations(
        denominations: &[QCashDenomination],
        commitments: &[[u8; 32]],
    ) -> Result<Self, QCashError> {
        if denominations.len() != commitments.len() {
            return Err(QCashError::CommitmentCountMismatch);
        }
        let expected = denominations
            .iter()
            .try_fold(Amount(0), |total, denomination| {
                total
                    .0
                    .checked_add(denomination.amount().0)
                    .map(Amount)
                    .ok_or(QCashError::AmountOverflow)
            })?;
        Self::with_denominations(expected, denominations, commitments)
    }

    pub fn validate(&self) -> Result<(), QCashError> {
        use std::collections::BTreeSet;

        if self.outputs.is_empty() {
            return Err(QCashError::EmptyOutputs);
        }
        if self.outputs.len() > MAX_QCASH_WITHDRAW_OUTPUTS {
            return Err(QCashError::TooManyWithdrawOutputs);
        }
        let mut commitments = BTreeSet::new();
        for (index, output) in self.outputs.iter().enumerate() {
            if output.coin_index as usize != index {
                return Err(QCashError::InvalidCoinIndex);
            }
            if !commitments.insert(output.commitment) {
                return Err(QCashError::DuplicateCommitment);
            }
            if index > 0 && output.denomination > self.outputs[index - 1].denomination {
                return Err(QCashError::NonCanonicalCoins);
            }
        }
        self.amount().map(|_| ())
    }

    pub fn amount(&self) -> Result<Amount, QCashError> {
        self.outputs.iter().try_fold(Amount(0), |total, output| {
            total
                .0
                .checked_add(output.denomination.amount().0)
                .map(Amount)
                .ok_or(QCashError::AmountOverflow)
        })
    }

    pub fn validate_amount(&self, expected: Amount) -> Result<(), QCashError> {
        self.validate()?;
        if self.amount()? != expected {
            return Err(QCashError::DenominationAmountMismatch);
        }
        Ok(())
    }
}

impl Error for QCashError {}

/// Formats a whole-XPQ amount using the fewest supported coins.
pub fn format_qcash_coins(amount: Amount) -> Result<Vec<QCashCoin>, QCashError> {
    if amount.0 == 0 {
        return Err(QCashError::ZeroAmount);
    }
    if !amount.0.is_multiple_of(XPQ) {
        return Err(QCashError::FractionalXpQ);
    }

    let mut remaining = amount.0 / XPQ;
    let mut coins = Vec::with_capacity(QCashDenomination::DESCENDING.len());
    for denomination in QCashDenomination::DESCENDING {
        let count = remaining / denomination.xpq();
        if count > 0 {
            coins.push(QCashCoin {
                denomination,
                count,
            });
            remaining %= denomination.xpq();
        }
    }
    Ok(coins)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_denominations_can_use_large_cash_notes() {
        let commitments = [[1_u8; 32]];
        let metadata = QCashWithdrawMetadata::with_selected_denominations(
            &[QCashDenomination::OneThousand],
            &commitments,
        )
        .unwrap();

        assert_eq!(metadata.outputs.len(), 1);
        assert_eq!(
            metadata.outputs[0].denomination,
            QCashDenomination::OneThousand
        );
        assert_eq!(metadata.amount(), Ok(Amount(1000 * XPQ)));
    }

    #[test]
    fn automatic_selection_prefers_new_largest_denominations() {
        let coins = format_qcash_coins(Amount(1500 * XPQ)).unwrap();

        assert_eq!(
            coins,
            vec![
                QCashCoin {
                    denomination: QCashDenomination::OneThousand,
                    count: 1,
                },
                QCashCoin {
                    denomination: QCashDenomination::FiveHundred,
                    count: 1,
                },
            ]
        );
    }

    #[test]
    fn one_million_denomination_roundtrips_and_uses_one_output() {
        let denomination = QCashDenomination::OneMillion;
        let bytes = crate::codec::canonical_bytes(&denomination);
        let decoded =
            crate::codec::canonical_deserialize::<QCashDenomination>(&bytes.unwrap()).unwrap();
        assert_eq!(decoded, denomination);

        let plan = QCashWithdrawMetadata::plan_automatic(Amount(1_000_000 * XPQ)).unwrap();
        assert_eq!(plan.denominations, vec![QCashDenomination::OneMillion]);
        assert_eq!(plan.remainder, Amount(0));
    }
}
