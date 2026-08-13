use super::{AuthorizationProof, ValidityWindow, chain_bound_signing_bytes};
use crate::block::BlockHeight;
use crate::codec::canonical_bytes;
use crate::consensus::supply::Amount;
use crate::crypto::{
    Address, HashDomain, PublicKey, Signature, TransactionHash, address_from_public_key,
    domain_hash, verify,
};
use crate::error::TransactionError;
use crate::qcash::{QCashCoinFile, QCashError, QCashRedeemMetadata, QCashWithdrawalMetadata};
use crate::state::XpqCoinId;
use crate::transaction::{OutputTarget, TransferOutput};
use borsh::{BorshDeserialize, BorshSerialize};

pub const QCASH_TRANSACTION_VERSION: u8 = 1;
/// QCash carries one or more post-quantum coin authorizations in addition to
/// the transaction authorization proof, so it needs a dedicated bounded envelope.
pub const MAX_QCASH_TX_SIZE: usize = 64 * 1024;
const QCASH_SIGNATURE_DOMAIN: &[u8] = b"XPARQ_SHARKSPHERE_QCASH_TX_V1";

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QCashTransactionKind {
    Withdraw {
        inputs: Vec<XpqCoinId>,
        outputs: Vec<TransferOutput>,
        amount: Amount,
        metadata: QCashWithdrawalMetadata,
    },
    Redeem {
        outputs: Vec<TransferOutput>,
        qcash_outputs: Option<QCashWithdrawalMetadata>,
        metadata: QCashRedeemMetadata,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct QCashTransaction {
    pub version: u8,
    pub signer: Address,
    pub kind: QCashTransactionKind,
    pub validity: ValidityWindow,
}

#[derive(BorshSerialize)]
struct RedeemTransactionCommitmentInput {
    version: u8,
    coin_id: [u8; 32],
    amount: Amount,
    redeem_public_key: PublicKey,
}

#[derive(BorshSerialize)]
struct RedeemTransactionCommitmentPayload {
    version: u8,
    signer: Address,
    outputs: Vec<TransferOutput>,
    qcash_outputs: Option<QCashWithdrawalMetadata>,
    validity: ValidityWindow,
    inputs: Vec<RedeemTransactionCommitmentInput>,
}

impl QCashTransaction {
    pub fn withdraw(
        signer: Address,
        inputs: Vec<XpqCoinId>,
        outputs: Vec<TransferOutput>,
        amount: Amount,
        metadata: QCashWithdrawalMetadata,
    ) -> Self {
        Self {
            version: QCASH_TRANSACTION_VERSION,
            signer,
            kind: QCashTransactionKind::Withdraw {
                inputs,
                outputs,
                amount,
                metadata,
            },
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn redeem(
        signer: Address,
        outputs: Vec<TransferOutput>,
        metadata: QCashRedeemMetadata,
    ) -> Self {
        Self {
            version: QCASH_TRANSACTION_VERSION,
            signer,
            kind: QCashTransactionKind::Redeem {
                outputs,
                qcash_outputs: None,
                metadata,
            },
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn redeem_from_files(
        signer: Address,
        outputs: Vec<TransferOutput>,
        files: &[QCashCoinFile],
    ) -> Result<Self, QCashError> {
        Self::transform_from_files(signer, outputs, None, files)
    }

    pub fn transform_from_files(
        signer: Address,
        outputs: Vec<TransferOutput>,
        qcash_outputs: Option<QCashWithdrawalMetadata>,
        files: &[QCashCoinFile],
    ) -> Result<Self, QCashError> {
        let authorization_address = redeem_recipient(&outputs).unwrap_or(signer);
        let placeholder_inputs = files
            .iter()
            .map(|file| file.redeem_input_for_transaction(authorization_address, [0; 32]))
            .collect::<Result<Vec<_>, _>>()?;
        let mut transaction = Self {
            version: QCASH_TRANSACTION_VERSION,
            signer,
            kind: QCashTransactionKind::Redeem {
                outputs: outputs.clone(),
                qcash_outputs: qcash_outputs.clone(),
                metadata: QCashRedeemMetadata::from_inputs(placeholder_inputs)?,
            },
            validity: ValidityWindow::UNBOUNDED,
        };
        let commitment = transaction
            .redeem_transaction_commitment()
            .map_err(|_| QCashError::Serialization)?
            .ok_or(QCashError::InvalidCommitment)?;
        transaction.kind = QCashTransactionKind::Redeem {
            outputs,
            qcash_outputs,
            metadata: QCashRedeemMetadata::new_for_transaction(
                files,
                authorization_address,
                commitment,
            )?,
        };
        Ok(transaction)
    }

    pub fn with_validity_window(mut self, validity: ValidityWindow) -> Self {
        self.validity = validity;
        self
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.version != QCASH_TRANSACTION_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        match &self.kind {
            QCashTransactionKind::Withdraw {
                inputs,
                outputs,
                amount,
                metadata,
            } => {
                if inputs.is_empty() {
                    return Err(TransactionError::EmptyInputs);
                }
                if outputs.iter().any(|output| output.amount.0 == 0) {
                    return Err(TransactionError::ZeroAmount);
                }
                let mut unique = std::collections::BTreeSet::new();
                if inputs.iter().any(|input| !unique.insert(*input)) {
                    return Err(TransactionError::DuplicateInput);
                }
                if amount.0 == 0 {
                    return Err(TransactionError::ZeroAmount);
                }
                metadata
                    .validate_amount(*amount)
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
            }
            QCashTransactionKind::Redeem {
                outputs,
                qcash_outputs,
                metadata,
            } => {
                let authorization_address = redeem_recipient(outputs).unwrap_or(self.signer);
                if outputs.len() > 2
                    || outputs.iter().any(|output| output.amount.0 == 0)
                    || outputs
                        .iter()
                        .filter(|output| output.to == OutputTarget::BlockMiner)
                        .count()
                        > 1
                {
                    return Err(TransactionError::InvalidQCashOutputs);
                }
                if outputs
                    .iter()
                    .filter_map(|output| output.to.address())
                    .count()
                    > 1
                {
                    return Err(TransactionError::InvalidQCashOutputs);
                }
                let qcash_output_total = match qcash_outputs {
                    Some(metadata) => {
                        metadata
                            .validate()
                            .map_err(|_| TransactionError::InvalidQCashMetadata)?;
                        metadata
                            .amount()
                            .map_err(|_| TransactionError::InvalidQCashMetadata)?
                    }
                    None => Amount(0),
                };
                if outputs.is_empty() && qcash_output_total.0 == 0 {
                    return Err(TransactionError::InvalidQCashOutputs);
                }
                let output_total = outputs
                    .iter()
                    .try_fold(0_u64, |total, output| total.checked_add(output.amount.0));
                let qcash_total = metadata
                    .amount()
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
                if output_total.and_then(|total| total.checked_add(qcash_output_total.0))
                    != Some(qcash_total.0)
                {
                    return Err(TransactionError::InvalidQCashOutputs);
                }
                metadata
                    .validate_authorizations_for_transaction(
                        authorization_address,
                        self.redeem_transaction_commitment()?
                            .ok_or(TransactionError::InvalidQCashMetadata)?,
                    )
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
                if authorization_address == Address::ZERO {
                    return Err(TransactionError::InvalidQCashRecipient);
                }
            }
        }
        self.validity.validate()
    }

    pub fn validate_for_height(&self, height: BlockHeight) -> Result<(), TransactionError> {
        self.validate()?;
        self.validity.validate_at(height)
    }

    pub fn amount(&self) -> Result<Amount, TransactionError> {
        match &self.kind {
            QCashTransactionKind::Withdraw { amount, .. } => Ok(*amount),
            QCashTransactionKind::Redeem { metadata, .. } => metadata
                .amount()
                .map_err(|_| TransactionError::InvalidQCashMetadata),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        canonical_bytes(self)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        chain_bound_signing_bytes(QCASH_SIGNATURE_DOMAIN, self.to_bytes()?)
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        Ok(TransactionHash(
            domain_hash(HashDomain::Transaction, &self.to_bytes()?).0,
        ))
    }

    pub fn redeem_transaction_commitment(
        &self,
    ) -> Result<Option<[u8; 32]>, crate::error::CodecError> {
        let (outputs, qcash_outputs, metadata) = match &self.kind {
            QCashTransactionKind::Redeem {
                outputs,
                qcash_outputs,
                metadata,
            } => (outputs, qcash_outputs, metadata),
            QCashTransactionKind::Withdraw { .. } => return Ok(None),
        };
        let payload = RedeemTransactionCommitmentPayload {
            version: self.version,
            signer: self.signer,
            outputs: outputs.clone(),
            qcash_outputs: qcash_outputs.clone(),
            validity: self.validity,
            inputs: metadata
                .inputs
                .iter()
                .map(|input| RedeemTransactionCommitmentInput {
                    version: input.version,
                    coin_id: input.coin_id,
                    amount: input.amount,
                    redeem_public_key: input.redeem_public_key,
                })
                .collect(),
        };
        Ok(Some(
            domain_hash(
                HashDomain::QCashRedeemTransaction,
                &canonical_bytes(&payload)?,
            )
            .0,
        ))
    }

    pub fn redeem_recipient(&self) -> Option<(Address, Amount)> {
        let QCashTransactionKind::Redeem { outputs, .. } = &self.kind else {
            return None;
        };
        outputs
            .iter()
            .find_map(|output| output.to.address().map(|address| (address, output.amount)))
    }

    pub fn qcash_change_amount(&self) -> Result<Amount, TransactionError> {
        let QCashTransactionKind::Redeem { qcash_outputs, .. } = &self.kind else {
            return Ok(Amount(0));
        };
        qcash_outputs
            .as_ref()
            .map(QCashWithdrawalMetadata::amount)
            .transpose()
            .map_err(|_| TransactionError::InvalidQCashMetadata)
            .map(|amount| amount.unwrap_or(Amount(0)))
    }

    pub fn redeem_authorization_address(&self) -> Option<Address> {
        matches!(self.kind, QCashTransactionKind::Redeem { .. }).then(|| {
            self.redeem_recipient()
                .map_or(self.signer, |(address, _)| address)
        })
    }

    pub fn miner_bounty(&self) -> Amount {
        let outputs = match &self.kind {
            QCashTransactionKind::Withdraw { outputs, .. }
            | QCashTransactionKind::Redeem { outputs, .. } => outputs,
        };
        Amount(
            outputs
                .iter()
                .filter(|output| output.to == OutputTarget::BlockMiner)
                .fold(0_u64, |total, output| total.saturating_add(output.amount.0)),
        )
    }
}

fn redeem_recipient(outputs: &[TransferOutput]) -> Option<Address> {
    let mut recipients = outputs.iter().filter_map(|output| output.to.address());
    let recipient = recipients.next()?;
    recipients.next().is_none().then_some(recipient)
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedQCashTransaction {
    pub transaction: QCashTransaction,
    pub authorization_proof: AuthorizationProof,
}

impl SignedQCashTransaction {
    pub fn new(transaction: QCashTransaction, public_key: PublicKey, signature: Signature) -> Self {
        Self {
            transaction,
            authorization_proof: AuthorizationProof::new(public_key, signature),
        }
    }

    pub fn new_stored(transaction: QCashTransaction, signature: Signature) -> Self {
        Self {
            transaction,
            authorization_proof: AuthorizationProof::new_stored(signature),
        }
    }

    pub fn validate_signed(&self) -> Result<(), TransactionError> {
        self.transaction.validate()?;
        self.validate_registration_authorization_at_height(crate::block::Height(0))
    }

    fn validate_registration_authorization_at_height(
        &self,
        _height: BlockHeight,
    ) -> Result<(), TransactionError> {
        if self.to_bytes()?.len() > MAX_QCASH_TX_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        if self
            .authorization_proof
            .public_key
            .0
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self
            .authorization_proof
            .signature
            .0
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(TransactionError::EmptySignature);
        }
        if address_from_public_key(&self.authorization_proof.public_key) != self.transaction.signer
        {
            return Err(TransactionError::SenderAddressMismatch);
        }
        let payload = self.transaction.signing_bytes()?;
        if !verify(
            &self.authorization_proof.public_key,
            &payload,
            &self.authorization_proof.signature,
        ) {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(())
    }

    pub fn validate_stored_keys_for_height(
        &self,
        height: crate::block::BlockHeight,
        public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        if self.to_bytes()?.len() > MAX_QCASH_TX_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        if !self.authorization_proof.uses_stored_keys() {
            return Err(TransactionError::InvalidAuthorizationProofEncoding);
        }
        if self
            .authorization_proof
            .signature
            .0
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(TransactionError::EmptySignature);
        }
        let payload = self.transaction.signing_bytes()?;
        if !verify(public_key, &payload, &self.authorization_proof.signature) {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(())
    }

    pub fn validate_signed_for_height(&self, height: BlockHeight) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        self.validate_registration_authorization_at_height(height)
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        self.transaction.hash()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        canonical_bytes(self)
    }
}

#[cfg(test)]
mod recovery_regression_tests {
    use super::*;

    fn cash_file() -> QCashCoinFile {
        let secret = [0x41; 32];
        let metadata = QCashWithdrawalMetadata::with_selected_amounts(
            &[Amount(crate::consensus::supply::XPQ)],
            &[crate::qcash::qcash_redeem_key_commitment_from_secret(
                &secret,
            )],
        )
        .unwrap();
        QCashCoinFile::new(TransactionHash([0x42; 32]), &metadata.outputs[0], secret).unwrap()
    }

    #[test]
    fn redeem_outputs_conserve_qcash_value_and_allow_one_miner_output() {
        let recipient = Address([0x43; crate::crypto::ADDRESS_SIZE]);
        let fee = Amount(10_000);
        let transaction = QCashTransaction::redeem_from_files(
            Address([0x44; crate::crypto::ADDRESS_SIZE]),
            vec![
                TransferOutput::new(recipient, Amount(crate::consensus::supply::XPQ - fee.0)),
                TransferOutput::new(OutputTarget::BlockMiner, fee),
            ],
            &[cash_file()],
        )
        .unwrap();

        assert_eq!(transaction.validate(), Ok(()));
        assert_eq!(
            transaction.redeem_recipient(),
            Some((recipient, Amount(990_000)))
        );
        assert_eq!(transaction.miner_bounty(), fee);
    }

    #[test]
    fn one_transform_supports_partial_redeem_and_qcash_change() {
        let recipient = Address([0x51; crate::crypto::ADDRESS_SIZE]);
        let change_secret = [0x52; 32];
        let change = QCashWithdrawalMetadata::with_selected_amounts(
            &[Amount(600_000)],
            &[crate::qcash::qcash_redeem_key_commitment_from_secret(
                &change_secret,
            )],
        )
        .unwrap();
        let transaction = QCashTransaction::transform_from_files(
            Address([0x53; crate::crypto::ADDRESS_SIZE]),
            vec![
                TransferOutput::new(recipient, Amount(390_000)),
                TransferOutput::new(OutputTarget::BlockMiner, Amount(10_000)),
            ],
            Some(change),
            &[cash_file()],
        )
        .unwrap();

        assert_eq!(transaction.validate(), Ok(()));
        assert_eq!(
            transaction.redeem_recipient(),
            Some((recipient, Amount(390_000)))
        );
        assert_eq!(transaction.qcash_change_amount(), Ok(Amount(600_000)));
    }

    #[test]
    fn pure_split_has_no_redeem_recipient_and_conserves_value() {
        let signer = Address([0x54; crate::crypto::ADDRESS_SIZE]);
        let commitments = [
            crate::qcash::qcash_redeem_key_commitment_from_secret(&[0x55; 32]),
            crate::qcash::qcash_redeem_key_commitment_from_secret(&[0x56; 32]),
        ];
        let children = QCashWithdrawalMetadata::with_selected_amounts(
            &[Amount(600_000), Amount(390_000)],
            &commitments,
        )
        .unwrap();
        let transaction = QCashTransaction::transform_from_files(
            signer,
            vec![TransferOutput::new(
                OutputTarget::BlockMiner,
                Amount(10_000),
            )],
            Some(children),
            &[cash_file()],
        )
        .unwrap();

        assert_eq!(transaction.validate(), Ok(()));
        assert_eq!(transaction.redeem_recipient(), None);
        assert_eq!(transaction.qcash_change_amount(), Ok(Amount(990_000)));
        assert_eq!(transaction.redeem_authorization_address(), Some(signer));
    }

    #[test]
    fn redeem_rejects_value_mismatch_and_multiple_miner_outputs() {
        let recipient = Address([0x45; crate::crypto::ADDRESS_SIZE]);
        let mismatch = QCashTransaction::redeem_from_files(
            Address([0x46; crate::crypto::ADDRESS_SIZE]),
            vec![TransferOutput::new(recipient, Amount(999_999))],
            &[cash_file()],
        )
        .unwrap();
        assert_eq!(
            mismatch.validate(),
            Err(TransactionError::InvalidQCashOutputs)
        );

        let duplicate_miner = QCashTransaction::redeem_from_files(
            Address([0x46; crate::crypto::ADDRESS_SIZE]),
            vec![
                TransferOutput::new(recipient, Amount(999_998)),
                TransferOutput::new(OutputTarget::BlockMiner, Amount(1)),
                TransferOutput::new(OutputTarget::BlockMiner, Amount(1)),
            ],
            &[cash_file()],
        )
        .unwrap();
        assert_eq!(
            duplicate_miner.validate(),
            Err(TransactionError::InvalidQCashOutputs)
        );
    }

    #[test]
    fn rejects_removed_on_chain_recovery_variant() {
        // QCashTransaction encodes version, signer, then the transaction-kind
        // enum tag. Tags 0 and 1 remain Withdraw and Redeem. The former
        // RecoverRedeem tag 2 must fail during decoding before any embedded
        // header-chain proof can trigger Argon2 work.
        let mut encoded = vec![QCASH_TRANSACTION_VERSION];
        encoded.extend_from_slice(&[0; crate::crypto::ADDRESS_SIZE]);
        encoded.push(2);

        assert!(crate::codec::decode_qcash_transaction(&encoded).is_err());
    }
}
