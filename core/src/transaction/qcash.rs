use super::{AuthorizationProof, ValidityWindow, chain_bound_signing_bytes};
use crate::block::BlockHeight;
use crate::codec::canonical_bytes;
use crate::consensus::supply::Amount;
use crate::crypto::{
    Address, HashDomain, PublicKey, Signature, TransactionHash, domain_hash,
    dual_address_from_public_keys, verify,
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
    denomination: crate::qcash::QCashDenomination,
    redeem_public_key: PublicKey,
}

#[derive(BorshSerialize)]
struct RedeemTransactionCommitmentPayload {
    version: u8,
    signer: Address,
    outputs: Vec<TransferOutput>,
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
            kind: QCashTransactionKind::Redeem { outputs, metadata },
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn redeem_from_files(
        signer: Address,
        outputs: Vec<TransferOutput>,
        files: &[QCashCoinFile],
    ) -> Result<Self, QCashError> {
        let recipient = redeem_recipient(&outputs).ok_or(QCashError::InvalidRedeemAuthorization)?;
        let placeholder_inputs = files
            .iter()
            .map(|file| file.redeem_input_for_transaction(recipient, [0; 32]))
            .collect::<Result<Vec<_>, _>>()?;
        let mut transaction = Self::redeem(
            signer,
            outputs.clone(),
            QCashRedeemMetadata::from_inputs(placeholder_inputs)?,
        );
        let commitment = transaction
            .redeem_transaction_commitment()
            .map_err(|_| QCashError::Serialization)?
            .ok_or(QCashError::InvalidCommitment)?;
        transaction.kind = QCashTransactionKind::Redeem {
            outputs,
            metadata: QCashRedeemMetadata::new_for_transaction(files, recipient, commitment)?,
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
            QCashTransactionKind::Redeem { outputs, metadata } => {
                let recipient =
                    redeem_recipient(outputs).ok_or(TransactionError::InvalidQCashRecipient)?;
                if outputs.is_empty()
                    || outputs.len() > 2
                    || outputs.iter().any(|output| output.amount.0 == 0)
                    || outputs
                        .iter()
                        .filter(|output| output.to == OutputTarget::BlockMiner)
                        .count()
                        > 1
                {
                    return Err(TransactionError::InvalidQCashOutputs);
                }
                let output_total = outputs
                    .iter()
                    .try_fold(0_u64, |total, output| total.checked_add(output.amount.0));
                let qcash_total = metadata
                    .amount()
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
                if output_total != Some(qcash_total.0) {
                    return Err(TransactionError::InvalidQCashOutputs);
                }
                metadata
                    .validate_authorizations_for_transaction(
                        recipient,
                        self.redeem_transaction_commitment()?
                            .ok_or(TransactionError::InvalidQCashMetadata)?,
                    )
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
                if recipient == Address([0; 20]) {
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
        let (outputs, metadata) = match &self.kind {
            QCashTransactionKind::Redeem { outputs, metadata } => (outputs, metadata),
            QCashTransactionKind::Withdraw { .. } => return Ok(None),
        };
        let payload = RedeemTransactionCommitmentPayload {
            version: self.version,
            signer: self.signer,
            outputs: outputs.clone(),
            validity: self.validity,
            inputs: metadata
                .inputs
                .iter()
                .map(|input| RedeemTransactionCommitmentInput {
                    version: input.version,
                    coin_id: input.coin_id,
                    denomination: input.denomination,
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

    pub fn new_authorized(
        transaction: QCashTransaction,
        public_key: PublicKey,
        signature: Signature,
        auth_public_key: PublicKey,
        auth_signature: Signature,
    ) -> Self {
        Self {
            transaction,
            authorization_proof: AuthorizationProof::new_authorized(
                public_key,
                signature,
                auth_public_key,
                auth_signature,
            ),
        }
    }

    pub fn new_stored_authorized(
        transaction: QCashTransaction,
        signature: Signature,
        auth_signature: Signature,
    ) -> Self {
        Self {
            transaction,
            authorization_proof: AuthorizationProof::new_stored(signature, auth_signature),
        }
    }

    pub fn validate_signed(&self) -> Result<(), TransactionError> {
        self.transaction.validate()?;
        self.validate_registration_authorization_at_height(crate::block::Height(0))
    }

    fn validate_registration_authorization_at_height(
        &self,
        height: BlockHeight,
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
        if self
            .authorization_proof
            .auth_signature
            .0
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(TransactionError::EmptyAuthorizationSignature);
        }
        if dual_address_from_public_keys(
            &self.authorization_proof.public_key,
            &self.authorization_proof.auth_public_key,
        ) != self.transaction.signer
        {
            return Err(TransactionError::SenderAddressMismatch);
        }
        let payload = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = crate::crypto::verify_dual_parallel_at_height(
            height,
            &self.authorization_proof.public_key,
            &self.authorization_proof.auth_public_key,
            &payload,
            &self.authorization_proof.signature,
            &self.authorization_proof.auth_signature,
        );
        if !owner_valid {
            return Err(TransactionError::InvalidSignature);
        }
        if !auth_valid {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        Ok(())
    }

    pub fn validate_stored_keys_for_height(
        &self,
        height: crate::block::BlockHeight,
        owner_public_key: &PublicKey,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        if self.to_bytes()?.len() > MAX_QCASH_TX_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        if !self.authorization_proof.uses_stored_keys() {
            return Err(TransactionError::InvalidAuthorizationSignature);
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
        if self
            .authorization_proof
            .auth_signature
            .0
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(TransactionError::EmptyAuthorizationSignature);
        }
        let payload = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = crate::crypto::verify_dual_parallel_at_height(
            height,
            owner_public_key,
            auth_public_key,
            &payload,
            &self.authorization_proof.signature,
            &self.authorization_proof.auth_signature,
        );
        if !owner_valid {
            return Err(TransactionError::InvalidSignature);
        }
        if !auth_valid {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        Ok(())
    }

    pub fn verify_authorization(
        &self,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        if verify(
            auth_public_key,
            &self.transaction.signing_bytes()?,
            &self.authorization_proof.auth_signature,
        ) {
            Ok(())
        } else {
            Err(TransactionError::InvalidAuthorizationSignature)
        }
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
        let metadata = QCashWithdrawalMetadata::with_selected_denominations(
            &[crate::qcash::QCashDenomination::One],
            &[crate::qcash::qcash_redeem_key_commitment_from_secret(
                &secret,
            )],
        )
        .unwrap();
        QCashCoinFile::new(TransactionHash([0x42; 32]), &metadata.outputs[0], secret).unwrap()
    }

    #[test]
    fn redeem_outputs_conserve_qcash_value_and_allow_one_miner_output() {
        let recipient = Address([0x43; 20]);
        let fee = Amount(10_000);
        let transaction = QCashTransaction::redeem_from_files(
            Address([0x44; 20]),
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
    fn redeem_rejects_value_mismatch_and_multiple_miner_outputs() {
        let recipient = Address([0x45; 20]);
        let mismatch = QCashTransaction::redeem_from_files(
            Address([0x46; 20]),
            vec![TransferOutput::new(recipient, Amount(999_999))],
            &[cash_file()],
        )
        .unwrap();
        assert_eq!(
            mismatch.validate(),
            Err(TransactionError::InvalidQCashOutputs)
        );

        let duplicate_miner = QCashTransaction::redeem_from_files(
            Address([0x46; 20]),
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
        encoded.extend_from_slice(&[0; 20]);
        encoded.push(2);

        assert!(crate::codec::decode_qcash_transaction(&encoded).is_err());
    }
}
