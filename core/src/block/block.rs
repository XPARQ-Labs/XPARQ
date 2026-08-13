use crate::codec::{HashDomain, block_bytes, block_header_hash, canonical_bytes, domain_hash};
use crate::consensus::supply::Amount;
use crate::crypto::{
    Address, BlockHash, HASH_SIZE, Hash, MerkleHash, PreviousHash, StateRoot, TransactionHash,
};
pub use crate::error::BlockError;
use crate::transaction::{
    QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction, SignedTransfer, Transfer,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Error as IoError, ErrorKind, Read};

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Height(pub u64);

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Nonce(pub u64);

pub type BlockHeight = Height;
pub type BlockNonce = Nonce;

pub const MAX_BLOCK_SIZE: usize = 5 * 1024 * 1024;
pub const BLOCK_VERSION: u8 = 1;
/// Header version permanently assigned to height zero.
///
/// Active block-version upgrades must not silently rewrite the configured
/// genesis identity.
pub const GENESIS_BLOCK_VERSION: u8 = 1;
/// Difficulty permanently assigned to height zero. Production difficulty
/// tuning begins after genesis and must not alter the genesis hash.
pub const GENESIS_BLOCK_DIFFICULTY: u32 = 1;
/// WBDA and block admission use the complete canonical serialized size.
pub const MAX_BLOCK_WEIGHT: usize = MAX_BLOCK_SIZE;
/// A maximum-sized transaction cannot practically fill more than this count
/// within `MAX_BLOCK_WEIGHT`. Keep this explicit so hostile length prefixes
/// cannot amplify a small wire message into multi-gigabyte allocations.
pub const MAX_BLOCK_DECODE_ITEMS: usize = 4_096;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    pub version: u8,
    pub previous_hash: PreviousHash,
    pub merkle_root: MerkleHash,
    pub state_root: StateRoot,
    pub difficulty: u32,
    pub block_weight: u32,
    pub nonce: BlockNonce,
}

impl Header {
    pub fn new(
        previous_hash: PreviousHash,
        merkle_root: MerkleHash,
        state_root: StateRoot,
        difficulty: u32,
        block_weight: u32,
        nonce: BlockNonce,
    ) -> Self {
        Self {
            version: BLOCK_VERSION,
            previous_hash,
            merkle_root,
            state_root,
            difficulty,
            block_weight,
            nonce,
        }
    }

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        block_header_hash(self)
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Body {
    pub emission: Option<EmissionTransaction>,
    pub transactions: Vec<SignedProtocolTransaction>,
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Block {
    pub header: Header,
    /// Chain position is validated against the parent but is deliberately not
    /// part of the PoW/header hash.
    pub height: BlockHeight,
    pub body: Body,
}

// Box indirection keeps the in-memory enum compact. The explicit 4,096-item
// decode cap independently bounds hostile count prefixes.
#[derive(BorshSerialize, BorshDeserialize)]
enum ProtocolPayload {
    Transfer(Box<Transfer>),
    QCash(Box<QCashTransaction>),
}

static_assertions::const_assert!(
    std::mem::size_of::<ProtocolPayload>() <= 2 * std::mem::size_of::<usize>()
);

impl BorshDeserialize for Block {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let header = Header::deserialize_reader(reader)?;
        let height = Height::deserialize_reader(reader)?;
        let emission = Option::<EmissionTransaction>::deserialize_reader(reader)?;

        let transactions = deserialize_limited_vec::<SignedProtocolTransaction, _>(
            reader,
            MAX_BLOCK_DECODE_ITEMS,
        )?;
        Ok(Self {
            header,
            height,
            body: Body {
                emission,
                transactions,
            },
        })
    }
}

fn deserialize_limited_vec<T, R>(reader: &mut R, limit: usize) -> std::io::Result<Vec<T>>
where
    T: BorshDeserialize,
    R: Read,
{
    let length = u32::deserialize_reader(reader)? as usize;
    if length > limit {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "block section length exceeds limit",
        ));
    }

    // Never reserve the attacker-provided length up front. Large protocol
    // enums make wire-length-to-memory amplification otherwise severe.
    let mut values = Vec::new();
    values
        .try_reserve(length.min(64))
        .map_err(|_| IoError::new(ErrorKind::OutOfMemory, "block section allocation failed"))?;
    for _ in 0..length {
        values.push(T::deserialize_reader(reader)?);
    }
    Ok(values)
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct EmissionTransaction {
    pub to: Address,
    pub subsidy: Amount,
}

impl EmissionTransaction {
    pub fn new(to: Address, subsidy: Amount) -> Self {
        Self { to, subsidy }
    }

    pub fn total(&self) -> Amount {
        self.subsidy
    }

    pub fn checked_total(&self) -> Result<Amount, BlockError> {
        Ok(self.subsidy)
    }

    pub fn hash(&self) -> Result<Hash, crate::error::CodecError> {
        Ok(domain_hash(HashDomain::Emission, &canonical_bytes(self)?))
    }
}

impl Block {
    pub fn emission(&self) -> Option<&EmissionTransaction> {
        self.body.emission.as_ref()
    }

    /// Compatibility accessor for network crates migrating to Emission naming.
    pub fn coinbase(&self) -> Option<&EmissionTransaction> {
        self.emission()
    }

    pub fn transactions(&self) -> &[SignedProtocolTransaction] {
        &self.body.transactions
    }

    pub fn transfer_transactions(&self) -> impl Iterator<Item = &SignedTransfer> {
        self.body.transactions.iter().filter_map(|tx| match tx {
            SignedProtocolTransaction::Transfer(tx) => Some(tx.as_ref()),
            _ => None,
        })
    }

    pub fn qcash_transactions(&self) -> impl Iterator<Item = &SignedQCashTransaction> {
        self.body.transactions.iter().filter_map(|tx| match tx {
            SignedProtocolTransaction::QCash(tx) => Some(tx.as_ref()),
            _ => None,
        })
    }

    pub fn genesis() -> Result<Self, crate::error::CodecError> {
        let mut block = Self::from_protocol_transactions(
            Height(0),
            PreviousHash::ZERO,
            GENESIS_BLOCK_DIFFICULTY,
            Nonce(0),
            None,
            vec![],
        )?;
        block.header.version = GENESIS_BLOCK_VERSION;
        Ok(block)
    }

    pub fn from_header(height: BlockHeight, header: Header) -> Self {
        Self {
            header,
            height,
            body: Body {
                emission: None,
                transactions: Vec::new(),
            },
        }
    }

    /// Constructs a block from one consensus-ordered protocol transaction list.
    #[allow(clippy::too_many_arguments)]
    pub fn from_protocol_transactions(
        height: BlockHeight,
        previous_hash: impl Into<PreviousHash>,
        difficulty: u32,
        nonce: BlockNonce,
        emission: Option<EmissionTransaction>,
        transactions: Vec<SignedProtocolTransaction>,
    ) -> Result<Self, crate::error::CodecError> {
        let previous_hash = previous_hash.into();
        let merkle_root = calculate_merkle_root(emission.as_ref(), &transactions)?;
        let state_root = StateRoot::ZERO;
        let mut block = Self {
            header: Header::new(previous_hash, merkle_root, state_root, difficulty, 0, nonce),
            height,
            body: Body {
                emission,
                transactions,
            },
        };
        block.refresh_block_weight()?;
        Ok(block)
    }

    /// Validates deterministic block-local rules only.
    pub fn validate_structure(&self) -> Result<(), BlockError> {
        let expected_version = if self.is_genesis() {
            GENESIS_BLOCK_VERSION
        } else {
            BLOCK_VERSION
        };
        if self.header.version != expected_version {
            return Err(BlockError::UnsupportedVersion);
        }

        if self.is_genesis() {
            if self.body.emission.is_some() {
                return Err(BlockError::UnexpectedEmission);
            }
            if self.transaction_count() != 0 {
                return Err(BlockError::InvalidTransaction);
            }
        } else if self.body.emission.is_none() {
            return Err(BlockError::MissingEmission);
        }

        if self.transaction_count() > MAX_BLOCK_DECODE_ITEMS {
            return Err(BlockError::TooManyTransactions);
        }
        if has_duplicate_transactions(&self.body.transactions)? {
            return Err(BlockError::DuplicateTransaction);
        }

        if let Some(emission) = &self.body.emission {
            emission.checked_total()?;
        }

        if self.stripped_size()? > MAX_BLOCK_SIZE {
            return Err(BlockError::BlockTooLarge);
        }
        if self.weight()? > MAX_BLOCK_WEIGHT {
            return Err(BlockError::BlockTooHeavy);
        }
        if self.header.block_weight as usize != self.weight()? {
            return Err(BlockError::InvalidBlockWeight);
        }

        if !signed_transactions_are_valid_for_height(&self.body.transactions, self.height()) {
            return Err(BlockError::InvalidTransaction);
        }
        if self.header.merkle_root
            != calculate_merkle_root(self.body.emission.as_ref(), &self.body.transactions)?
        {
            return Err(BlockError::InvalidMerkleRoot);
        }

        Ok(())
    }

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        self.header.hash()
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn previous_hash(&self) -> PreviousHash {
        self.header.previous_hash
    }

    /// Returns the emission recipient for mined blocks. Genesis has no miner
    /// and therefore resolves to the zero address for compatibility with
    /// indexing and display code.
    pub fn miner_address(&self) -> Address {
        self.body
            .emission
            .as_ref()
            .map(|emission| emission.to)
            .unwrap_or(Address([0; crate::crypto::ADDRESS_SIZE]))
    }

    pub fn state_root(&self) -> StateRoot {
        self.header.state_root
    }

    pub fn set_state_root(&mut self, state_root: impl Into<StateRoot>) {
        self.header.state_root = state_root.into();
    }

    pub fn difficulty(&self) -> u32 {
        self.header.difficulty
    }

    pub fn block_weight(&self) -> u32 {
        self.header.block_weight
    }

    pub fn transaction_count(&self) -> usize {
        self.body.transactions.len()
    }

    pub fn is_genesis(&self) -> bool {
        self.height.0 == 0 && self.header.previous_hash == Hash([0; HASH_SIZE])
    }

    pub fn serialized_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len())
    }

    pub fn stripped_size(&self) -> Result<usize, crate::error::CodecError> {
        self.serialized_size()
    }

    pub fn authorization_proof_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(0)
    }

    pub fn weight(&self) -> Result<usize, crate::error::CodecError> {
        self.serialized_size()
    }

    pub fn refresh_block_weight(&mut self) -> Result<(), crate::error::CodecError> {
        self.header.block_weight = 0;
        let weight = self.weight()?;
        self.header.block_weight =
            u32::try_from(weight).map_err(|_| crate::error::CodecError::EncodeFailed)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        block_bytes(self)
    }

    pub fn calculate_merkle_root(&self) -> Result<MerkleHash, crate::error::CodecError> {
        calculate_merkle_root(self.body.emission.as_ref(), &self.body.transactions)
    }

    pub fn transaction_inclusion_proofs(
        &self,
        transaction_index: usize,
    ) -> Result<crate::block::merkle::MerkleInclusionProof, crate::error::CodecError> {
        if transaction_index >= self.body.transactions.len() {
            return Err(crate::error::CodecError::InvalidBlock);
        }
        let mut transaction_leaves = Vec::with_capacity(
            usize::from(self.body.emission.is_some()) + self.body.transactions.len(),
        );
        if let Some(emission) = &self.body.emission {
            transaction_leaves.push(emission.hash()?);
        }
        transaction_leaves.extend(
            self.body
                .transactions
                .iter()
                .map(|transaction| transaction.hash().map(TransactionHash::as_hash))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let leaf_index = usize::from(self.body.emission.is_some()) + transaction_index;
        crate::block::merkle::MerkleInclusionProof::create(
            &transaction_leaves,
            leaf_index,
            HashDomain::MerkleNode,
        )
        .ok_or(crate::error::CodecError::InvalidBlock)
    }

    pub fn refresh_merkle_root(&mut self) -> Result<(), crate::error::CodecError> {
        self.refresh_commitments()
    }

    pub fn refresh_commitments(&mut self) -> Result<(), crate::error::CodecError> {
        self.header.merkle_root = self.calculate_merkle_root()?;
        self.refresh_block_weight()?;
        Ok(())
    }

    pub fn push_transaction(
        &mut self,
        transaction: SignedTransfer,
    ) -> Result<(), crate::error::CodecError> {
        self.body
            .transactions
            .push(SignedProtocolTransaction::from(transaction));
        self.refresh_merkle_root()
    }
}

fn calculate_merkle_root(
    emission: Option<&EmissionTransaction>,
    transactions: &[SignedProtocolTransaction],
) -> Result<MerkleHash, crate::error::CodecError> {
    if emission.is_none() && transactions.is_empty() {
        return Ok(MerkleHash::ZERO);
    }

    let mut hashes = Vec::with_capacity(usize::from(emission.is_some()) + transactions.len());
    if let Some(emission) = emission {
        hashes.push(emission.hash()?);
    }
    for transaction in transactions {
        hashes.push(transaction.hash()?.as_hash());
    }

    while hashes.len() > 1 {
        hashes = merkle_parent_level(hashes, HashDomain::MerkleNode);
    }

    Ok(MerkleHash(hashes[0].0))
}

fn merkle_parent_level(hashes: Vec<Hash>, domain: HashDomain) -> Vec<Hash> {
    let mut parents = Vec::with_capacity(hashes.len().div_ceil(2));
    let mut pairs = hashes.chunks_exact(2);
    for pair in &mut pairs {
        let mut bytes = Vec::with_capacity(HASH_SIZE * 2);
        bytes.extend_from_slice(&pair[0].0);
        bytes.extend_from_slice(&pair[1].0);
        parents.push(domain_hash(domain, &bytes));
    }
    if let [last] = pairs.remainder() {
        parents.push(*last);
    }
    parents
}

fn has_duplicate_transactions(
    transactions: &[SignedProtocolTransaction],
) -> Result<bool, crate::error::CodecError> {
    let mut seen = HashSet::with_capacity(transactions.len());
    for transaction in transactions {
        if !seen.insert(transaction.hash()?.as_hash()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn signed_transactions_are_valid_for_height(
    transactions: &[SignedProtocolTransaction],
    height: BlockHeight,
) -> bool {
    transactions
        .iter()
        .all(|tx| tx.validate_envelope_for_height(height).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::DIFFICULTY_START;
    use crate::crypto::{Signature, address_from_public_key, generate_keypair, sign};
    use std::io::Cursor;

    #[test]
    fn canonical_header_size_is_113_bytes() {
        let header = Header::new(
            PreviousHash::ZERO,
            MerkleHash::ZERO,
            StateRoot::ZERO,
            DIFFICULTY_START,
            0,
            Nonce(0),
        );
        assert_eq!(borsh::to_vec(&header).unwrap().len(), 113);
    }

    #[test]
    fn zero_fee_transaction_is_valid_block_structure() {
        let owner = generate_keypair();
        let sender = address_from_public_key(&owner.public_key);
        let transaction = Transfer::new(
            sender,
            vec![crate::state::XpqCoinId([0x31; crate::crypto::HASH_SIZE])],
            Address([0x32; crate::crypto::ADDRESS_SIZE]),
            Amount(100_000),
        );
        let payload = transaction.signing_bytes().unwrap();
        let signed = SignedTransfer::new(
            transaction,
            owner.public_key,
            sign(&owner.secret_key, &payload),
        );
        let block = Block::from_protocol_transactions(
            Height(1),
            PreviousHash([0x33; HASH_SIZE]),
            DIFFICULTY_START,
            Nonce(0),
            Some(EmissionTransaction::new(
                Address([0x34; crate::crypto::ADDRESS_SIZE]),
                Amount(0),
            )),
            vec![signed.into()],
        )
        .unwrap();

        assert_eq!(block.validate_structure(), Ok(()));
    }

    fn invalid_signed_transfer(seed: u64, input_count: usize) -> SignedTransfer {
        let inputs = (0..input_count)
            .map(|input_index| {
                let mut coin_id = [0_u8; crate::crypto::HASH_SIZE];
                coin_id[..8].copy_from_slice(&seed.to_le_bytes());
                coin_id[8..16].copy_from_slice(&(input_index as u64).to_le_bytes());
                crate::state::XpqCoinId(coin_id)
            })
            .collect();
        let transaction = Transfer::new(
            Address([0xff; crate::crypto::ADDRESS_SIZE]),
            inputs,
            Address([seed as u8; crate::crypto::ADDRESS_SIZE]),
            Amount(1),
        );
        SignedTransfer::new_stored(transaction, Signature([1; crate::crypto::SIGNATURE_SIZE]))
    }

    #[test]
    fn oversized_transaction_count_hits_block_size_limit() {
        let minimum_encoded_size = MAX_BLOCK_WEIGHT / MAX_BLOCK_DECODE_ITEMS + 1;
        let mut input_count = 1;
        let encoded_size = loop {
            let size = SignedProtocolTransaction::from(invalid_signed_transfer(0, input_count))
                .to_bytes()
                .unwrap()
                .len();
            if size >= minimum_encoded_size {
                break size;
            }
            input_count += 1;
        };
        let transaction_count = (MAX_BLOCK_WEIGHT / encoded_size).saturating_add(2);
        assert!(transaction_count <= MAX_BLOCK_DECODE_ITEMS);
        let transactions: Vec<SignedTransfer> = (0..transaction_count as u64)
            .map(|seed| invalid_signed_transfer(seed, input_count))
            .collect();
        let miner = Address([4; crate::crypto::ADDRESS_SIZE]);
        let block = Block::from_protocol_transactions(
            Height(1),
            PreviousHash([9; HASH_SIZE]),
            DIFFICULTY_START,
            Nonce(0),
            Some(EmissionTransaction::new(miner, Amount(0))),
            transactions.into_iter().map(Into::into).collect(),
        )
        .unwrap();

        assert_eq!(block.validate_structure(), Err(BlockError::BlockTooLarge));
    }

    #[test]
    fn hostile_section_length_fails_without_full_preallocation() {
        let mut encoded_length = Cursor::new((MAX_BLOCK_DECODE_ITEMS as u32).to_le_bytes());
        assert!(
            deserialize_limited_vec::<ProtocolPayload, _>(
                &mut encoded_length,
                MAX_BLOCK_DECODE_ITEMS
            )
            .is_err()
        );

        let mut excessive = Cursor::new(((MAX_BLOCK_DECODE_ITEMS + 1) as u32).to_le_bytes());
        assert!(
            deserialize_limited_vec::<ProtocolPayload, _>(&mut excessive, MAX_BLOCK_DECODE_ITEMS)
                .is_err()
        );
    }
}
