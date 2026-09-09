use std::{
    collections::HashSet,
    io::{Error as IoError, ErrorKind, Read},
};

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{
    Address, BlockHash, Hash, HashDomain, MerkleHash, PreviousHash, StateRoot,
    canonical_bytes, domain,
};

use crate::native::coin::Zeno;
use crate::transaction::Transaction;

pub use crypto::{BlockHeight, BlockNonce, Height, Nonce};

use crate::blockchain::error::{BlockError, CodecError};
use crate::blockchain::merkle::{MerkleInclusionProof, merkle_root};

pub const MAX_BLOCK_SIZE: usize = 2 * 1024 * 1024;
pub const GENESIS_BLOCK_DIFFICULTY: u32 = 1;

// Lower bound for a direct coin transaction with one input, one block-miner
// output, and an empty known-account signature byte vector.
const MIN_TRANSACTION_BYTES: usize = 79;
const MAX_BLOCK_TRANSACTIONS: usize = MAX_BLOCK_SIZE / MIN_TRANSACTION_BYTES;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    pub previous_hash: PreviousHash,
    pub merkle_root: MerkleHash,
    pub state_root: StateRoot,
    pub difficulty: u32,
    /// Canonical serialized block size plus any ledger execution reservation.
    pub block_weight: u32,
    pub nonce: Nonce,
}

impl Header {
    pub const fn new(
        previous_hash: PreviousHash,
        merkle_root: MerkleHash,
        state_root: StateRoot,
        difficulty: u32,
        block_weight: u32,
        nonce: Nonce,
    ) -> Self {
        Self {
            previous_hash,
            merkle_root,
            state_root,
            difficulty,
            block_weight,
            nonce,
        }
    }

    pub fn hash(&self) -> Result<BlockHash, CodecError> {
        block_header_hash(self)
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub emission: Option<Emission>,
    pub transactions: Vec<Transaction>,
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub height: Height,
    pub body: Body,
}

// Bounded decoding avoids trusting a serialized Vec length before the block-size
// limit and block-local invariants have been checked.
impl BorshDeserialize for Block {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let header = Header::deserialize_reader(reader)?;
        let height = Height::deserialize_reader(reader)?;
        let emission = Option::<Emission>::deserialize_reader(reader)?;
        let transactions = deserialize_block_transactions(reader)?;

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

fn deserialize_block_transactions<R: Read>(reader: &mut R) -> std::io::Result<Vec<Transaction>> {
    let length = u32::deserialize_reader(reader)? as usize;
    if length > MAX_BLOCK_TRANSACTIONS {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "block transaction count exceeds canonical bound",
        ));
    }

    let mut transactions = Vec::new();
    transactions
        .try_reserve(length.min(64))
        .map_err(|_| IoError::new(ErrorKind::OutOfMemory, "block allocation failed"))?;

    for _ in 0..length {
        transactions.push(Transaction::deserialize_reader(reader)?);
    }

    Ok(transactions)
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Emission {
    pub to: Address,
    pub subsidy: Zeno,
}

impl Emission {
    pub const fn new(to: Address, subsidy: Zeno) -> Self {
        Self { to, subsidy }
    }

    pub fn hash(&self) -> Result<Hash, CodecError> {
        let bytes = canonical_bytes(self).map_err(|_| CodecError::EncodeFailed)?;
        Ok(domain(HashDomain::Emission, &bytes))
    }
}

impl Block {
    pub fn emission(&self) -> Option<&Emission> {
        self.body.emission.as_ref()
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.body.transactions
    }

    /// Compatibility accessor retained for callers that still use coinbase naming.
    pub fn coinbase(&self) -> Option<&Emission> {
        self.emission()
    }

    pub fn genesis() -> Result<Self, CodecError> {
        Self::from_protocol_transactions(
            Height(0),
            PreviousHash::ZERO,
            GENESIS_BLOCK_DIFFICULTY,
            Nonce(0),
            None,
            vec![],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_protocol_transactions(
        height: Height,
        previous_hash: impl Into<PreviousHash>,
        difficulty: u32,
        nonce: Nonce,
        emission: Option<Emission>,
        transactions: Vec<Transaction>,
    ) -> Result<Self, CodecError> {
        let previous_hash = previous_hash.into();
        let merkle_root = calculate_merkle_root(emission.as_ref(), &transactions)?;

        let mut block = Self {
            header: Header::new(
                previous_hash,
                merkle_root,
                StateRoot::ZERO,
                difficulty,
                0,
                nonce,
            ),
            height,
            body: Body {
                emission,
                transactions,
            },
        };

        block.refresh_block_weight()?;
        Ok(block)
    }

    /// Validates only deterministic rules that depend on the block itself.
    /// Signatures, values, state burn, and state root execution remain
    /// consensus/ledger responsibilities.
    pub fn validate_structure(&self) -> Result<(), BlockError> {
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

        if has_duplicate_transactions(&self.body.transactions)? {
            return Err(BlockError::DuplicateTransaction);
        }

        let serialized_weight = self.weight()?;
        if serialized_weight > MAX_BLOCK_SIZE || self.header.block_weight as usize > MAX_BLOCK_SIZE
        {
            return Err(BlockError::BlockTooHeavy);
        }
        if (self.header.block_weight as usize) < serialized_weight {
            return Err(BlockError::InvalidBlockWeight);
        }

        if !transactions_are_structurally_valid(&self.body.transactions) {
            return Err(BlockError::InvalidTransaction);
        }

        if self.header.merkle_root
            != calculate_merkle_root(self.body.emission.as_ref(), &self.body.transactions)?
        {
            return Err(BlockError::InvalidMerkleRoot);
        }

        Ok(())
    }

    pub fn hash(&self) -> Result<BlockHash, CodecError> {
        self.header.hash()
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn previous_hash(&self) -> PreviousHash {
        self.header.previous_hash
    }

    pub fn miner_address(&self) -> Address {
        self.body
            .emission
            .as_ref()
            .map(|emission| emission.to)
            .unwrap_or(Address([0; crypto::ADDRESS_SIZE]))
    }

    pub const fn state_root(&self) -> StateRoot {
        self.header.state_root
    }

    pub fn set_state_root(&mut self, state_root: impl Into<StateRoot>) {
        self.header.state_root = state_root.into();
    }

    pub fn set_block_weight(&mut self, block_weight: u32) {
        self.header.block_weight = block_weight;
    }

    pub const fn difficulty(&self) -> u32 {
        self.header.difficulty
    }

    pub const fn block_weight(&self) -> u32 {
        self.header.block_weight
    }

    pub fn transaction_count(&self) -> usize {
        self.body.transactions.len()
    }

    pub fn is_genesis(&self) -> bool {
        self.height.0 == 0
    }

    pub fn serialized_size(&self) -> Result<usize, CodecError> {
        Ok(self.to_bytes()?.len())
    }

    pub fn weight(&self) -> Result<usize, CodecError> {
        self.serialized_size()
    }

    pub fn refresh_block_weight(&mut self) -> Result<(), CodecError> {
        self.header.block_weight = 0;
        let weight = self.weight()?;
        self.header.block_weight = u32::try_from(weight).map_err(|_| CodecError::EncodeFailed)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        block_bytes(self)
    }

    pub fn calculate_merkle_root(&self) -> Result<MerkleHash, CodecError> {
        calculate_merkle_root(self.body.emission.as_ref(), &self.body.transactions)
    }

    pub fn transaction_inclusion_proof(
        &self,
        transaction_index: usize,
    ) -> Result<MerkleInclusionProof, CodecError> {
        if transaction_index >= self.body.transactions.len() {
            return Err(CodecError::InvalidBlock);
        }

        let leaves = merkle_leaves(self.body.emission.as_ref(), &self.body.transactions)?;
        let leaf_index = usize::from(self.body.emission.is_some()) + transaction_index;

        MerkleInclusionProof::create(&leaves, leaf_index, HashDomain::MerkleNode)
            .ok_or(CodecError::InvalidBlock)
    }

    /// Backward-compatible plural name used by older callers.
    pub fn transaction_inclusion_proofs(
        &self,
        transaction_index: usize,
    ) -> Result<MerkleInclusionProof, CodecError> {
        self.transaction_inclusion_proof(transaction_index)
    }

    pub fn refresh_merkle_root(&mut self) -> Result<(), CodecError> {
        self.refresh_commitments()
    }

    pub fn refresh_commitments(&mut self) -> Result<(), CodecError> {
        self.header.merkle_root = self.calculate_merkle_root()?;
        self.refresh_block_weight()?;
        Ok(())
    }

    pub fn push_transaction(&mut self, transaction: Transaction) -> Result<(), CodecError> {
        self.body.transactions.push(transaction);
        self.refresh_commitments()
    }
}

fn merkle_leaves(
    emission: Option<&Emission>,
    transactions: &[Transaction],
) -> Result<Vec<Hash>, CodecError> {
    let mut leaves = Vec::with_capacity(usize::from(emission.is_some()) + transactions.len());

    if let Some(emission) = emission {
        leaves.push(emission.hash()?);
    }

    for transaction in transactions {
        leaves.push(Hash(
            transaction.id().map_err(|_| CodecError::EncodeFailed)?,
        ));
    }

    Ok(leaves)
}

fn calculate_merkle_root(
    emission: Option<&Emission>,
    transactions: &[Transaction],
) -> Result<MerkleHash, CodecError> {
    if emission.is_none() && transactions.is_empty() {
        return Ok(MerkleHash::ZERO);
    }

    let leaves = merkle_leaves(emission, transactions)?;
    merkle_root(&leaves, HashDomain::MerkleNode)
        .map(|root| MerkleHash(root.into_bytes()))
        .ok_or(CodecError::InvalidBlock)
}

fn has_duplicate_transactions(transactions: &[Transaction]) -> Result<bool, CodecError> {
    let mut seen = HashSet::with_capacity(transactions.len());

    for transaction in transactions {
        let id = Hash(transaction.id().map_err(|_| CodecError::EncodeFailed)?);
        if !seen.insert(id) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn transactions_are_structurally_valid(transactions: &[Transaction]) -> bool {
    transactions
        .iter()
        .all(|transaction| transaction.validate_structure().is_ok())
}

pub fn block_header_bytes(header: &Header) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(header).map_err(|_| CodecError::EncodeFailed)
}

pub fn block_bytes(block: &Block) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(block).map_err(|_| CodecError::EncodeFailed)
}

pub fn block_header_hash(header: &Header) -> Result<BlockHash, CodecError> {
    Ok(BlockHash(
        domain(HashDomain::Header, &block_header_bytes(header)?).into_bytes(),
    ))
}

pub fn decode_block(bytes: &[u8]) -> Result<Block, CodecError> {
    if bytes.len() > MAX_BLOCK_SIZE {
        return Err(CodecError::InvalidBlock);
    }

    let block = Block::try_from_slice(bytes).map_err(|_| CodecError::InvalidBlock)?;
    block
        .validate_structure()
        .map_err(|_| CodecError::InvalidBlock)?;
    Ok(block)
}
