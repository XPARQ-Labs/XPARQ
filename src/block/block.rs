use crate::codec::{HashDomain, block_bytes, block_header_hash, canonical_bytes, domain_hash};
use crate::consensus::GENESIS_DIFFICULTY;
use crate::consensus::supply::Amount;
use crate::crypto::{
    Address, BlockHash, HASH_SIZE, Hash, MerkleHash, PreviousHash, StateRoot, TransactionHash,
};
pub use crate::error::BlockError;
use crate::transaction::{
    QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction, SignedTransaction,
    Transaction,
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

pub const MAX_BLOCK_SIZE: usize = 2 * 1024 * 1024;
pub const BLOCK_VERSION: u8 = 1;
/// WBDA and block admission use the complete canonical serialized size.
pub const MAX_BLOCK_WEIGHT: usize = MAX_BLOCK_SIZE;
/// A dual-signature transaction cannot practically fill more than this count
/// within `MAX_BLOCK_WEIGHT`. Keep this explicit so hostile length prefixes
/// cannot amplify a small wire message into multi-gigabyte allocations.
pub const MAX_BLOCK_DECODE_ITEMS: usize = 4_096;
pub const MAX_GENESIS_ALLOCATIONS: usize = 4_096;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub version: u8,
    pub height: BlockHeight,
    pub previous_hash: PreviousHash,
    pub merkle_root: MerkleHash,
    pub state_root: StateRoot,
    pub chain_commitment: Hash,
    pub miner_address: Address,
    pub difficulty: u32,
    /// Complete canonical serialized block size in bytes.
    ///
    /// Paqus weight equals raw canonical block size.
    pub block_weight: u32,
}

impl BlockHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: BlockHeight,
        previous_hash: PreviousHash,
        merkle_root: MerkleHash,
        state_root: StateRoot,
        chain_commitment: Hash,
        miner_address: Address,
        difficulty: u32,
        block_weight: u32,
    ) -> Self {
        Self {
            version: BLOCK_VERSION,
            height,
            previous_hash,
            merkle_root,
            state_root,
            chain_commitment,
            miner_address,
            difficulty,
            block_weight,
        }
    }

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        block_header_hash(self)
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockBody {
    pub genesis_allocations: Vec<GenesisAllocation>,
    pub coinbase: Option<CoinbaseTransaction>,
    pub transactions: Vec<SignedProtocolTransaction>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockProof {
    pub nonce: BlockNonce,
}

impl BlockProof {
    pub fn new(nonce: BlockNonce) -> Self {
        Self { nonce }
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Block {
    pub header: BlockHeader,
    pub body: BlockBody,
    pub proof: BlockProof,
}

// Box indirection keeps the in-memory enum compact. The explicit 4,096-item
// decode cap independently bounds hostile count prefixes.
#[derive(BorshSerialize, BorshDeserialize)]
enum ProtocolPayload {
    Transfer(Box<Transaction>),
    QCash(Box<QCashTransaction>),
}

static_assertions::const_assert!(
    std::mem::size_of::<ProtocolPayload>() <= 2 * std::mem::size_of::<usize>()
);

impl BorshDeserialize for Block {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let header = BlockHeader::deserialize_reader(reader)?;
        let genesis_allocations =
            deserialize_limited_vec::<GenesisAllocation, _>(reader, MAX_GENESIS_ALLOCATIONS)?;
        let coinbase = Option::<CoinbaseTransaction>::deserialize_reader(reader)?;

        let transactions = deserialize_limited_vec::<SignedProtocolTransaction, _>(
            reader,
            MAX_BLOCK_DECODE_ITEMS,
        )?;
        let proof = BlockProof::deserialize_reader(reader)?;

        Ok(Self {
            header,
            body: BlockBody {
                genesis_allocations,
                coinbase,
                transactions,
            },
            proof,
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
pub struct GenesisAllocation {
    pub to: Address,
    pub amount: Amount,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoinbaseTransaction {
    pub to: Address,
    pub subsidy: Amount,
}

impl GenesisAllocation {
    pub fn new(to: Address, amount: Amount) -> Self {
        Self { to, amount }
    }

    pub fn hash(&self) -> Result<Hash, crate::error::CodecError> {
        Ok(domain_hash(
            HashDomain::GenesisAllocation,
            &canonical_bytes(self)?,
        ))
    }
}

impl CoinbaseTransaction {
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
        Ok(domain_hash(HashDomain::Coinbase, &canonical_bytes(self)?))
    }
}

impl Block {
    pub fn genesis_allocations(&self) -> &[GenesisAllocation] {
        &self.body.genesis_allocations
    }

    pub fn coinbase(&self) -> Option<&CoinbaseTransaction> {
        self.body.coinbase.as_ref()
    }

    pub fn transactions(&self) -> &[SignedProtocolTransaction] {
        &self.body.transactions
    }

    pub fn transfer_transactions(&self) -> impl Iterator<Item = &SignedTransaction> {
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

    pub fn genesis(
        miner_address: Address,
        allocations: Vec<GenesisAllocation>,
    ) -> Result<Self, crate::error::CodecError> {
        Self::genesis_with_chain_commitment(miner_address, Hash([0; HASH_SIZE]), allocations)
    }

    pub fn from_header_with_proof(header: BlockHeader, proof: BlockProof) -> Self {
        Self {
            header,
            body: BlockBody {
                genesis_allocations: Vec::new(),
                coinbase: None,
                transactions: Vec::new(),
            },
            proof,
        }
    }

    pub fn genesis_with_chain_commitment(
        miner_address: Address,
        chain_commitment: Hash,
        allocations: Vec<GenesisAllocation>,
    ) -> Result<Self, crate::error::CodecError> {
        Self::from_protocol_transactions_with_chain_commitment(
            Height(0),
            PreviousHash::ZERO,
            miner_address,
            GENESIS_DIFFICULTY,
            Nonce(0),
            chain_commitment,
            allocations,
            None,
            vec![],
        )
    }

    /// Constructs a block from one consensus-ordered protocol transaction list.
    #[allow(clippy::too_many_arguments)]
    pub fn from_protocol_transactions(
        height: BlockHeight,
        previous_hash: impl Into<PreviousHash>,
        miner_address: Address,
        difficulty: u32,
        nonce: BlockNonce,
        genesis_allocations: Vec<GenesisAllocation>,
        coinbase: Option<CoinbaseTransaction>,
        transactions: Vec<SignedProtocolTransaction>,
    ) -> Result<Self, crate::error::CodecError> {
        Self::from_protocol_transactions_with_chain_commitment(
            height,
            previous_hash,
            miner_address,
            difficulty,
            nonce,
            Hash([0; HASH_SIZE]),
            genesis_allocations,
            coinbase,
            transactions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_protocol_transactions_with_chain_commitment(
        height: BlockHeight,
        previous_hash: impl Into<PreviousHash>,
        miner_address: Address,
        difficulty: u32,
        nonce: BlockNonce,
        chain_commitment: Hash,
        genesis_allocations: Vec<GenesisAllocation>,
        coinbase: Option<CoinbaseTransaction>,
        transactions: Vec<SignedProtocolTransaction>,
    ) -> Result<Self, crate::error::CodecError> {
        let previous_hash = previous_hash.into();
        let merkle_root =
            calculate_merkle_root(&genesis_allocations, coinbase.as_ref(), &transactions)?;
        let state_root = StateRoot::ZERO;
        let mut block = Self {
            header: BlockHeader::new(
                height,
                previous_hash,
                merkle_root,
                state_root,
                chain_commitment,
                miner_address,
                difficulty,
                0,
            ),
            body: BlockBody {
                genesis_allocations,
                coinbase,
                transactions,
            },
            proof: BlockProof::new(nonce),
        };
        block.refresh_block_weight()?;
        Ok(block)
    }

    /// Validates deterministic block-local rules only.
    pub fn validate_structure(&self) -> Result<(), BlockError> {
        if self.header.version != BLOCK_VERSION {
            return Err(BlockError::UnsupportedVersion);
        }

        if self.is_genesis() {
            if self.body.coinbase.is_some() {
                return Err(BlockError::UnexpectedCoinbase);
            }
            if self.transaction_count() != 0 {
                return Err(BlockError::InvalidTransaction);
            }
            // Mainnet is a consensus-enforced fair launch. An empty allocation
            // list is required, rather than merely relying on the canonical
            // builder to happen to produce no premine.
            #[cfg(feature = "mainnet")]
            if !self.body.genesis_allocations.is_empty() {
                return Err(BlockError::InvalidGenesisAllocation);
            }
        } else if self.body.coinbase.is_none() {
            return Err(BlockError::MissingCoinbase);
        } else if !self.body.genesis_allocations.is_empty() {
            return Err(BlockError::UnexpectedGenesisAllocation);
        }

        if self.transaction_count() > MAX_BLOCK_DECODE_ITEMS {
            return Err(BlockError::TooManyTransactions);
        }
        if self.body.genesis_allocations.len() > MAX_GENESIS_ALLOCATIONS {
            return Err(BlockError::InvalidGenesisAllocation);
        }

        if has_duplicate_transactions(&self.body.transactions)? {
            return Err(BlockError::DuplicateTransaction);
        }

        if let Some(coinbase) = &self.body.coinbase {
            coinbase.checked_total()?;
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

        if let Some(coinbase) = &self.body.coinbase
            && coinbase.to != self.header.miner_address
        {
            return Err(BlockError::InvalidCoinbase);
        }

        if self
            .body
            .genesis_allocations
            .iter()
            .any(|allocation| allocation.amount.0 == 0)
        {
            return Err(BlockError::InvalidGenesisAllocation);
        }

        if self.header.merkle_root
            != calculate_merkle_root(
                &self.body.genesis_allocations,
                self.body.coinbase.as_ref(),
                &self.body.transactions,
            )?
        {
            return Err(BlockError::InvalidMerkleRoot);
        }

        Ok(())
    }

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        self.header.hash()
    }

    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    pub fn previous_hash(&self) -> PreviousHash {
        self.header.previous_hash
    }

    pub fn miner_address(&self) -> Address {
        self.header.miner_address
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
        self.header.height.0 == 0 && self.header.previous_hash == Hash([0; HASH_SIZE])
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
        calculate_merkle_root(
            &self.body.genesis_allocations,
            self.body.coinbase.as_ref(),
            &self.body.transactions,
        )
    }

    pub fn transaction_inclusion_proofs(
        &self,
        transaction_index: usize,
    ) -> Result<crate::block::merkle::MerkleInclusionProof, crate::error::CodecError> {
        if transaction_index >= self.body.transactions.len() {
            return Err(crate::error::CodecError::InvalidBlock);
        }
        let mut transaction_leaves = Vec::with_capacity(
            self.body.genesis_allocations.len()
                + usize::from(self.body.coinbase.is_some())
                + self.body.transactions.len(),
        );
        for allocation in &self.body.genesis_allocations {
            transaction_leaves.push(allocation.hash()?);
        }
        if let Some(coinbase) = &self.body.coinbase {
            transaction_leaves.push(coinbase.hash()?);
        }
        transaction_leaves.extend(
            self.body
                .transactions
                .iter()
                .map(|transaction| transaction.hash().map(TransactionHash::as_hash))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let leaf_index = self.body.genesis_allocations.len()
            + usize::from(self.body.coinbase.is_some())
            + transaction_index;
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
        transaction: SignedTransaction,
    ) -> Result<(), crate::error::CodecError> {
        self.body
            .transactions
            .push(SignedProtocolTransaction::from(transaction));
        self.refresh_merkle_root()
    }
}

fn calculate_merkle_root(
    genesis_allocations: &[GenesisAllocation],
    coinbase: Option<&CoinbaseTransaction>,
    transactions: &[SignedProtocolTransaction],
) -> Result<MerkleHash, crate::error::CodecError> {
    if genesis_allocations.is_empty() && coinbase.is_none() && transactions.is_empty() {
        return Ok(MerkleHash::ZERO);
    }

    let mut hashes = Vec::with_capacity(
        genesis_allocations.len() + usize::from(coinbase.is_some()) + transactions.len(),
    );
    for allocation in genesis_allocations {
        hashes.push(allocation.hash()?);
    }
    if let Some(coinbase) = coinbase {
        hashes.push(coinbase.hash()?);
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
    use crate::crypto::Signature;
    use crate::transaction::TransferOutput;
    use std::io::Cursor;

    fn invalid_signed_transfer(seed: u64) -> SignedTransaction {
        let mut last_state = [0_u8; crate::crypto::HASH_SIZE];
        last_state[..8].copy_from_slice(&seed.to_le_bytes());
        let transaction = Transaction::new(
            Address([0xff; crate::crypto::ADDRESS_SIZE]),
            vec![TransferOutput {
                to: (Address([seed as u8; crate::crypto::ADDRESS_SIZE])).into(),
                amount: Amount(1),
            }],
        )
        .with_last_state(Hash(last_state));
        SignedTransaction::new_stored_authorized(
            transaction,
            Signature([1; crate::crypto::SIGNATURE_SIZE]),
            Signature([2; crate::crypto::SIGNATURE_SIZE]),
        )
    }

    #[test]
    fn oversized_transaction_count_hits_block_size_limit() {
        let transactions: Vec<SignedTransaction> = (0..501).map(invalid_signed_transfer).collect();
        let miner = Address([4; crate::crypto::ADDRESS_SIZE]);
        let block = Block::from_protocol_transactions(
            Height(1),
            PreviousHash([9; HASH_SIZE]),
            miner,
            DIFFICULTY_START,
            Nonce(0),
            Vec::new(),
            Some(CoinbaseTransaction::new(miner, Amount(0))),
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
