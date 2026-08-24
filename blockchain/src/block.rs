#[path = "merkle.rs"]
pub mod merkle;

use crate::codec::{HashDomain, block_bytes, block_header_hash, canonical_bytes, domain_hash};
#[cfg(test)]
use crate::crypto::HASH_SIZE;
use crate::crypto::{Address, BlockHash, Hash, MerkleHash, PreviousHash, StateRoot};
pub use crate::error::BlockError;
use crate::transaction::AuthorizedTransaction;
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::HashSet;
use std::io::{Error as IoError, ErrorKind, Read};
use xparq_coin::Amount;
pub use xparq_common::{Height, Nonce};

pub type BlockHeader = Header;
pub type BlockBody = Body;
pub type BlockHeight = Height;
pub type BlockNonce = Nonce;

pub const MAX_BLOCK_WEIGHT: usize = 5 * 1024 * 1024;
/// Difficulty permanently assigned to height zero. Production difficulty
/// tuning begins after genesis and must not alter the genesis hash.
pub const GENESIS_BLOCK_DIFFICULTY: u32 = 1;
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    pub previous_hash: PreviousHash,
    pub merkle_root: MerkleHash,
    pub state_root: StateRoot,
    pub difficulty: u32,
    /// Canonical serialized block size committed by this header.
    pub block_weight: u32,
    pub nonce: Nonce,
}

impl Header {
    pub fn new(
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

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        block_header_hash(self)
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub emission: Option<Emission>,
    pub transactions: Vec<AuthorizedTransaction>,
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub height: Height,
    pub body: Body,
}

static_assertions::const_assert!(
    std::mem::size_of::<AuthorizedTransaction>() <= 2 * std::mem::size_of::<usize>()
);

// This trait implementation performs bounded decoding only. Untrusted block
// bytes must enter through `crate::decode_block`, which also validates all
// deterministic block-local invariants.
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

fn deserialize_block_transactions<R>(reader: &mut R) -> std::io::Result<Vec<AuthorizedTransaction>>
where
    R: Read,
{
    let length = u32::deserialize_reader(reader)? as usize;
    let mut values = Vec::new();
    values
        .try_reserve(length.min(64))
        .map_err(|_| IoError::new(ErrorKind::OutOfMemory, "block section allocation failed"))?;
    for _ in 0..length {
        values.push(AuthorizedTransaction::deserialize_reader(reader)?);
    }
    Ok(values)
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Emission {
    // rename Emission
    pub to: Address,
    pub subsidy: Amount,
}

impl Emission {
    pub fn new(to: Address, subsidy: Amount) -> Self {
        Self { to, subsidy }
    }

    pub fn hash(&self) -> Result<Hash, crate::error::CodecError> {
        Ok(domain_hash(HashDomain::Emission, &canonical_bytes(self)?))
    }
}

impl Block {
    pub fn emission(&self) -> Option<&Emission> {
        self.body.emission.as_ref()
    }

    /// Compatibility accessor for network crates migrating to Emission naming.
    pub fn coinbase(&self) -> Option<&Emission> {
        self.emission()
    }

    pub fn transactions(&self) -> &[AuthorizedTransaction] {
        &self.body.transactions
    }

    pub fn genesis() -> Result<Self, crate::error::CodecError> {
        Self::from_protocol_transactions(
            Height(0),
            PreviousHash::ZERO,
            GENESIS_BLOCK_DIFFICULTY,
            Nonce(0),
            None,
            vec![],
        )
    }

    /// Constructs a block from one consensus-ordered protocol transaction list.
    #[allow(clippy::too_many_arguments)]
    pub fn from_protocol_transactions(
        height: Height,
        previous_hash: impl Into<PreviousHash>,
        difficulty: u32,
        nonce: Nonce,
        emission: Option<Emission>,
        transactions: Vec<AuthorizedTransaction>,
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

    pub fn height(&self) -> Height {
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
        self.height.0 == 0
    }

    pub fn serialized_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len())
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
                .map(|transaction| {
                    transaction
                        .id()
                        .map(Hash)
                        .map_err(|_| crate::error::CodecError::EncodeFailed)
                })
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
        transaction: AuthorizedTransaction,
    ) -> Result<(), crate::error::CodecError> {
        self.body.transactions.push(transaction);
        self.refresh_merkle_root()
    }
}

fn calculate_merkle_root(
    emission: Option<&Emission>,
    transactions: &[AuthorizedTransaction],
) -> Result<MerkleHash, crate::error::CodecError> {
    if emission.is_none() && transactions.is_empty() {
        return Ok(MerkleHash::ZERO);
    }

    let mut hashes = Vec::with_capacity(usize::from(emission.is_some()) + transactions.len());
    if let Some(emission) = emission {
        hashes.push(emission.hash()?);
    }
    for transaction in transactions {
        hashes.push(Hash(
            transaction
                .id()
                .map_err(|_| crate::error::CodecError::EncodeFailed)?,
        ));
    }

    crate::block::merkle::merkle_root(&hashes, HashDomain::MerkleNode)
        .map(|root| MerkleHash(root.0))
        .ok_or(crate::error::CodecError::InvalidBlock)
}

fn has_duplicate_transactions(
    transactions: &[AuthorizedTransaction],
) -> Result<bool, crate::error::CodecError> {
    let mut seen = HashSet::with_capacity(transactions.len());
    for transaction in transactions {
        if !seen.insert(Hash(
            transaction
                .id()
                .map_err(|_| crate::error::CodecError::EncodeFailed)?,
        )) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn signed_transactions_are_valid_for_height(
    transactions: &[AuthorizedTransaction],
    height: Height,
) -> bool {
    transactions
        .iter()
        .all(|tx| tx.expiry_height() >= height.0 && tx.validate_structure().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Signature, address_from_public_key, generate_keypair, sign};
    use std::io::Cursor;
    use xparq_coin::CoinId;
    use xparq_transaction::{
        AccountAuthorization, AuthorizedAccountIntent, OnChainSpendIntent, SpendOutput,
    };

    #[test]
    fn canonical_header_size_is_112_bytes() {
        let header = Header::new(
            PreviousHash::ZERO,
            MerkleHash::ZERO,
            StateRoot::ZERO,
            GENESIS_BLOCK_DIFFICULTY,
            0,
            Nonce(0),
        );
        assert_eq!(borsh::to_vec(&header).unwrap().len(), 112);
    }

    #[test]
    fn zero_fee_transaction_is_valid_block_structure() {
        let owner = generate_keypair();
        let sender = address_from_public_key(&owner.public_key);
        let transaction = OnChainSpendIntent::new(
            sender,
            vec![CoinId::from_bytes([0x31; crate::crypto::HASH_SIZE])],
            vec![SpendOutput::new(
                Address([0x32; crate::crypto::ADDRESS_SIZE]),
                Amount(100_000),
            )],
            1,
        )
        .unwrap();
        let signature = sign(&owner.secret_key, b"block structure test");
        let signed = AuthorizedAccountIntent {
            intent: transaction,
            authorization: AccountAuthorization::Reveal {
                public_key: owner.public_key,
                signature,
            },
        };
        let block = Block::from_protocol_transactions(
            Height(1),
            PreviousHash([0x33; HASH_SIZE]),
            GENESIS_BLOCK_DIFFICULTY,
            Nonce(0),
            Some(Emission::new(
                Address([0x34; crate::crypto::ADDRESS_SIZE]),
                Amount(0),
            )),
            vec![AuthorizedTransaction::OnChainSpend(Box::new(signed))],
        )
        .unwrap();

        assert_eq!(block.validate_structure(), Ok(()));
    }

    fn stored_spend(seed: u64, input_count: usize) -> AuthorizedTransaction {
        let inputs = (0..input_count)
            .map(|input_index| {
                let mut coin_id = [0_u8; crate::crypto::HASH_SIZE];
                coin_id[..8].copy_from_slice(&seed.to_le_bytes());
                coin_id[8..16].copy_from_slice(&(input_index as u64).to_le_bytes());
                CoinId::from_bytes(coin_id)
            })
            .collect();
        let transaction = OnChainSpendIntent::new(
            Address([0xff; crate::crypto::ADDRESS_SIZE]),
            inputs,
            vec![SpendOutput::new(
                Address([seed as u8; crate::crypto::ADDRESS_SIZE]),
                Amount(1),
            )],
            u64::MAX,
        )
        .unwrap();
        AuthorizedTransaction::OnChainSpend(Box::new(AuthorizedAccountIntent {
            intent: transaction,
            authorization: AccountAuthorization::Known {
                signature: Signature([1; crate::crypto::SIGNATURE_SIZE]),
            },
        }))
    }

    #[test]
    fn oversized_transaction_count_hits_block_size_limit() {
        let minimum_encoded_size = MAX_BLOCK_WEIGHT / 2 + 1;
        let mut input_count = 1;
        let encoded_size = loop {
            let size = borsh::to_vec(&stored_spend(0, input_count)).unwrap().len();
            if size >= minimum_encoded_size {
                break size;
            }
            input_count = input_count.saturating_mul(2);
        };
        let transaction_count = (MAX_BLOCK_WEIGHT / encoded_size).saturating_add(2);
        let transactions: Vec<AuthorizedTransaction> = (0..transaction_count as u64)
            .map(|seed| stored_spend(seed, input_count))
            .collect();
        let miner = Address([4; crate::crypto::ADDRESS_SIZE]);
        let block = Block::from_protocol_transactions(
            Height(1),
            PreviousHash([9; HASH_SIZE]),
            GENESIS_BLOCK_DIFFICULTY,
            Nonce(0),
            Some(Emission::new(miner, Amount(0))),
            transactions,
        )
        .unwrap();

        assert_eq!(block.validate_structure(), Err(BlockError::BlockTooHeavy));
    }

    #[test]
    fn hostile_section_length_fails_without_full_preallocation() {
        let mut encoded_length = Cursor::new(u32::MAX.to_le_bytes());
        assert!(deserialize_block_transactions(&mut encoded_length).is_err());
    }
}
