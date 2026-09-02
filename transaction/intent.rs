use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_coin::{Amount, COIN_HASH_SIZE, CoinHash};
use xparq_common::{ExtensionHash, canonical_bytes};
use xparq_crypto::{ADDRESS_SIZE, Address, HASH_SIZE, QCashPublicKey};
use xparq_qcash::QCash;

use crate::IntentError;

const REDEEM_COMMITMENT_CONTEXT: &str = "XPARQ QCash RedeemIntent";
const MERGE_COMMITMENT_CONTEXT: &str = "XPARQ QCash MergeIntent";
const SPLIT_COMMITMENT_CONTEXT: &str = "XPARQ QCash SplitIntent";
const ONCHAIN_SPEND_COMMITMENT_CONTEXT: &str = "XPARQ OnChain SpendIntent";
const WITHDRAW_COMMITMENT_CONTEXT: &str = "XPARQ QCash WithdrawIntent";

/// Genesis identity supplied by consensus, not serialized inside transactions.
///
/// The genesis hash commits the transaction signature to one chain. Individual
/// chain parameters must not be repeated or independently validated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ChainContext {
    pub genesis_hash: [u8; HASH_SIZE],
}

impl ChainContext {
    pub const fn new(genesis_hash: [u8; HASH_SIZE]) -> Self {
        Self { genesis_hash }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum OutputTarget {
    Address(Address),
    BlockMiner,
    Burn,
    Extension(ExtensionHash),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct SpendOutput {
    pub target: OutputTarget,
    pub amount: Amount,
}

impl SpendOutput {
    pub const fn new(recipient: Address, amount: Amount) -> Self {
        Self {
            target: OutputTarget::Address(recipient),
            amount,
        }
    }

    pub const fn block_miner(amount: Amount) -> Self {
        Self {
            target: OutputTarget::BlockMiner,
            amount,
        }
    }

    pub const fn burn(amount: Amount) -> Self {
        Self {
            target: OutputTarget::Burn,
            amount,
        }
    }

    pub const fn extension(extension: ExtensionHash, amount: Amount) -> Self {
        Self {
            target: OutputTarget::Extension(extension),
            amount,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct QCashOutput {
    pub amount: Amount,
    pub public_key: QCashPublicKey,
}

pub trait QCashIntent {
    fn qcash_inputs(&self) -> Vec<QCash>;
    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError>;
}

impl QCashOutput {
    pub const fn new(amount: Amount, public_key: QCashPublicKey) -> Self {
        Self { amount, public_key }
    }
}

/// XPQ UTXO spend intent. Input amounts and ownership come from ledger state.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OnChainSpendIntent {
    pub sender: Address,
    pub inputs: Vec<CoinHash>,
    pub outputs: Vec<SpendOutput>,
}

impl OnChainSpendIntent {
    pub fn new(
        sender: Address,
        inputs: Vec<CoinHash>,
        outputs: Vec<SpendOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            sender,
            inputs,
            outputs,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        validate_input_ids(&self.inputs)?;
        validate_public_outputs(&self.outputs, false)
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        chain_bound_bytes(chain, self)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        Ok(SpendCommitment(blake3::derive_key(
            ONCHAIN_SPEND_COMMITMENT_CONTEXT,
            &self.signing_bytes(chain)?,
        )))
    }
}

/// Converts active XPQ UTXOs into QCash bearer outputs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WithdrawIntent {
    pub sender: Address,
    pub inputs: Vec<CoinHash>,
    pub qcash_outputs: Vec<QCashOutput>,
    pub outputs: Vec<SpendOutput>,
}

impl WithdrawIntent {
    pub fn new(
        sender: Address,
        inputs: Vec<CoinHash>,
        qcash_outputs: Vec<QCashOutput>,
        outputs: Vec<SpendOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            sender,
            inputs,
            qcash_outputs,
            outputs,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        validate_input_ids(&self.inputs)?;
        if self.qcash_outputs.is_empty() {
            return Err(IntentError::EmptyOutputs);
        }
        if self
            .qcash_outputs
            .iter()
            .any(|output| output.amount.as_zeno() == 0)
        {
            return Err(IntentError::ZeroAmount);
        }
        validate_public_outputs(&self.outputs, true)
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        chain_bound_bytes(chain, self)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        Ok(SpendCommitment(blake3::derive_key(
            WITHDRAW_COMMITMENT_CONTEXT,
            &self.signing_bytes(chain)?,
        )))
    }
}

fn validate_input_ids(inputs: &[CoinHash]) -> Result<(), IntentError> {
    if inputs.is_empty() {
        return Err(IntentError::EmptyInputs);
    }
    let mut unique = BTreeSet::new();
    if inputs.iter().any(|id| !unique.insert(*id)) {
        return Err(IntentError::DuplicateInput);
    }
    Ok(())
}

fn chain_bound_bytes<T: BorshSerialize>(
    chain: ChainContext,
    intent: &T,
) -> Result<Vec<u8>, IntentError> {
    canonical_bytes(&(chain, intent)).map_err(IntentError::Encoding)
}

fn validate_public_outputs(outputs: &[SpendOutput], allow_empty: bool) -> Result<(), IntentError> {
    if outputs.is_empty() && !allow_empty {
        return Err(IntentError::EmptyOutputs);
    }
    if outputs.iter().any(|output| output.amount.as_zeno() == 0) {
        return Err(IntentError::ZeroAmount);
    }
    if outputs
        .iter()
        .filter(|output| output.target == OutputTarget::BlockMiner)
        .count()
        > 1
    {
        return Err(IntentError::InvalidMinerOutput);
    }
    if outputs
        .iter()
        .filter(|output| output.target == OutputTarget::Burn)
        .count()
        > 1
    {
        return Err(IntentError::InvalidBurnOutput);
    }
    Ok(())
}

/// Complete QCash redemption intent, signed by every QCash input key.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RedeemIntent {
    pub inputs: Vec<QCash>,
    pub outputs: Vec<SpendOutput>,
    pub qcash_outputs: Vec<QCashOutput>,
}

impl RedeemIntent {
    pub fn new(
        inputs: Vec<QCash>,
        outputs: Vec<SpendOutput>,
        qcash_outputs: Vec<QCashOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            inputs,
            outputs,
            qcash_outputs,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        if self.inputs.is_empty() {
            return Err(IntentError::EmptyInputs);
        }
        if self.outputs.is_empty() && self.qcash_outputs.is_empty() {
            return Err(IntentError::EmptyOutputs);
        }
        if self.inputs.iter().any(|coin| coin.is_zero())
            || self
                .outputs
                .iter()
                .any(|output| output.amount.as_zeno() == 0)
            || self
                .qcash_outputs
                .iter()
                .any(|output| output.amount.as_zeno() == 0)
        {
            return Err(IntentError::ZeroAmount);
        }

        let mut coin_ids = BTreeSet::new();
        if self.inputs.iter().any(|qcash| !coin_ids.insert(qcash.id())) {
            return Err(IntentError::DuplicateInput);
        }

        let input_amount = checked_sum(self.inputs.iter().map(|qcash| qcash.amount()))?;
        let public_output_amount = checked_sum(self.outputs.iter().map(|output| output.amount))?;
        let qcash_output_amount =
            checked_sum(self.qcash_outputs.iter().map(|output| output.amount))?;
        let output_amount = public_output_amount
            .checked_add(qcash_output_amount)
            .ok_or(IntentError::AmountOverflow)?;
        if input_amount != output_amount {
            return Err(IntentError::ValueMismatch);
        }
        Ok(())
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        chain_bound_bytes(chain, self)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        let bytes = self.signing_bytes(chain)?;
        let hash = blake3::derive_key(REDEEM_COMMITMENT_CONTEXT, &bytes);
        Ok(SpendCommitment(hash))
    }
}

impl QCashIntent for RedeemIntent {
    fn qcash_inputs(&self) -> Vec<QCash> {
        self.inputs.clone()
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MergeIntent {
    pub inputs: Vec<QCash>,
    pub output: QCashOutput,
    pub public_outputs: Vec<SpendOutput>,
}

impl MergeIntent {
    pub fn new(
        inputs: Vec<QCash>,
        output: QCashOutput,
        public_outputs: Vec<SpendOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            inputs,
            output,
            public_outputs,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        if self.inputs.len() < 2 {
            return Err(IntentError::InvalidMergeShape);
        }
        validate_transform(
            &self.inputs,
            std::slice::from_ref(&self.output),
            &self.public_outputs,
        )
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        chain_bound_bytes(chain, self)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        Ok(SpendCommitment(blake3::derive_key(
            MERGE_COMMITMENT_CONTEXT,
            &self.signing_bytes(chain)?,
        )))
    }
}

impl QCashIntent for MergeIntent {
    fn qcash_inputs(&self) -> Vec<QCash> {
        self.inputs.clone()
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SplitIntent {
    pub input: QCash,
    pub outputs: Vec<QCashOutput>,
    pub public_outputs: Vec<SpendOutput>,
}

impl SplitIntent {
    pub fn new(
        input: QCash,
        outputs: Vec<QCashOutput>,
        public_outputs: Vec<SpendOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            input,
            outputs,
            public_outputs,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        if self.outputs.len() < 2 {
            return Err(IntentError::InvalidSplitShape);
        }
        validate_transform(
            std::slice::from_ref(&self.input),
            &self.outputs,
            &self.public_outputs,
        )
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        chain_bound_bytes(chain, self)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        Ok(SpendCommitment(blake3::derive_key(
            SPLIT_COMMITMENT_CONTEXT,
            &self.signing_bytes(chain)?,
        )))
    }
}

impl QCashIntent for SplitIntent {
    fn qcash_inputs(&self) -> Vec<QCash> {
        vec![self.input]
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain)
    }
}

fn validate_transform(
    inputs: &[QCash],
    outputs: &[QCashOutput],
    public_outputs: &[SpendOutput],
) -> Result<(), IntentError> {
    if inputs.iter().any(|coin| coin.is_zero())
        || outputs.iter().any(|output| output.amount.as_zeno() == 0)
        || public_outputs
            .iter()
            .any(|output| output.amount.as_zeno() == 0)
    {
        return Err(IntentError::ZeroAmount);
    }
    validate_public_outputs(public_outputs, true)?;
    if public_outputs
        .iter()
        .any(|output| matches!(output.target, OutputTarget::Address(_)))
    {
        return Err(IntentError::InvalidTransformOutput);
    }

    let mut coin_ids = BTreeSet::new();
    if inputs.iter().any(|qcash| !coin_ids.insert(qcash.id())) {
        return Err(IntentError::DuplicateInput);
    }
    let mut bearer_keys = BTreeSet::new();
    if outputs
        .iter()
        .any(|output| !bearer_keys.insert(output.public_key))
    {
        return Err(IntentError::DuplicateBearerOutput);
    }

    let input_amount = checked_sum(inputs.iter().map(|qcash| qcash.amount()))?;
    let qcash_amount = checked_sum(outputs.iter().map(|output| output.amount))?;
    let public_amount = checked_sum(public_outputs.iter().map(|output| output.amount))?;
    let output_amount = qcash_amount
        .checked_add(public_amount)
        .ok_or(IntentError::AmountOverflow)?;
    if input_amount != output_amount {
        return Err(IntentError::ValueMismatch);
    }
    Ok(())
}

fn checked_sum(mut amounts: impl Iterator<Item = Amount>) -> Result<Amount, IntentError> {
    amounts
        .try_fold(Amount::from_zeno(0), Amount::checked_add)
        .ok_or(IntentError::AmountOverflow)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct SpendCommitment([u8; blake3::OUT_LEN]);

impl SpendCommitment {
    pub const fn from_bytes(bytes: [u8; blake3::OUT_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; blake3::OUT_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; blake3::OUT_LEN] {
        self.0
    }
}

const _: () = assert!(COIN_HASH_SIZE == blake3::OUT_LEN);
const _: () = assert!(ADDRESS_SIZE > 0);

#[cfg(test)]
mod tests {
    use super::*;

    fn qcash_key(byte: u8) -> QCashPublicKey {
        QCashPublicKey([byte; xparq_crypto::QCASH_PUBLIC_KEY_SIZE])
    }

    #[test]
    fn split_rejects_reused_output_bearer_keys() {
        let input = QCash::new(
            CoinHash::from_bytes([1; COIN_HASH_SIZE]),
            Amount::from_zeno(10),
        );
        let repeated = qcash_key(7);
        assert_eq!(
            SplitIntent::new(
                input,
                vec![
                    QCashOutput::new(Amount::from_zeno(4), repeated),
                    QCashOutput::new(Amount::from_zeno(6), repeated),
                ],
                vec![],
            ),
            Err(IntentError::DuplicateBearerOutput)
        );
    }

    #[test]
    fn qcash_commitment_binds_outputs() {
        let input = QCash::new(
            CoinHash::from_bytes([2; COIN_HASH_SIZE]),
            Amount::from_zeno(10),
        );
        let first = SplitIntent::new(
            input,
            vec![
                QCashOutput::new(Amount::from_zeno(4), qcash_key(3)),
                QCashOutput::new(Amount::from_zeno(6), qcash_key(4)),
            ],
            vec![],
        )
        .unwrap();
        let second = SplitIntent::new(
            input,
            vec![
                QCashOutput::new(Amount::from_zeno(4), qcash_key(5)),
                QCashOutput::new(Amount::from_zeno(6), qcash_key(6)),
            ],
            vec![],
        )
        .unwrap();
        let chain = ChainContext::new([7; 32]);
        let first = first.commitment(chain).unwrap();
        let second = second.commitment(chain).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn partial_redeem_deducts_recipient_change_and_miner_from_bearer_input() {
        let input = QCash::new(
            CoinHash::from_bytes([9; COIN_HASH_SIZE]),
            Amount::from_zeno(100),
        );
        assert!(
            RedeemIntent::new(
                vec![input],
                vec![
                    SpendOutput::new(Address::ZERO, Amount::from_zeno(40)),
                    SpendOutput::block_miner(Amount::from_zeno(1)),
                ],
                vec![QCashOutput::new(Amount::from_zeno(59), qcash_key(8))],
            )
            .is_ok()
        );
        assert_eq!(
            RedeemIntent::new(
                vec![input],
                vec![
                    SpendOutput::new(Address::ZERO, Amount::from_zeno(40)),
                    SpendOutput::block_miner(Amount::from_zeno(1)),
                ],
                vec![QCashOutput::new(Amount::from_zeno(60), qcash_key(8))],
            ),
            Err(IntentError::ValueMismatch)
        );
    }
}
