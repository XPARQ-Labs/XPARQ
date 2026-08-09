use crate::block::{BlockHeight, Header};
use crate::codec::{HashDomain, canonical_bytes, domain_hash};
use crate::crypto::ADDRESS_SIZE;
use crate::crypto::Address;
use crate::crypto::{BlockHash, HASH_SIZE, Hash, StateRoot};
use crate::state::{
    Account, BlockStateCommitment, QCashCoinId, QCashStateProof, QCashUtxo, empty_qcash_state_root,
    verify_qcash_state_proof,
};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

const ADDRESS_BITS: usize = ADDRESS_SIZE * 8;
pub const ACCOUNT_STATE_PROOF_BUNDLE_VERSION: u8 = 1;
/// In-memory limit for the final state/Merkle proof only. Header history is
/// transferred and verified in bounded chunks, so chain height is unlimited.
pub const MAX_STATE_PROOF_BUNDLE_SIZE: usize = 4 * 1024 * 1024;

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofSide {
    Left,
    Right,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateProofNode {
    pub side: ProofSide,
    pub hash: Hash,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountStateProof {
    pub address: Address,
    pub account: Account,
    pub siblings: Vec<StateProofNode>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountNonMembershipProof {
    pub address: Address,
    pub terminal_depth: u16,
    pub siblings: Vec<StateProofNode>,
}

/// An account proof bound to a separately streamed and PoW-validated tip.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountStateProofBundle {
    pub version: u8,
    pub state_commitment: BlockStateCommitment,
    pub account_proof: AccountStateProof,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AccountNonMembershipProofBundle {
    pub version: u8,
    pub state_commitment: BlockStateCommitment,
    pub account_proof: AccountNonMembershipProof,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct QCashStateProofBundle {
    pub version: u8,
    pub state_commitment: BlockStateCommitment,
    pub qcash_proof: QCashStateProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccountState {
    pub height: BlockHeight,
    pub block_hash: BlockHash,
    pub account: Account,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountStateProofBundleError {
    UnsupportedVersion,
    BundleSizeExceeded,
    CommitmentHeightMismatch,
    CommitmentBlockHashMismatch,
    CommitmentProtocolRootMismatch,
    InvalidProtocolCommitment,
    InvalidAccountProof,
    Serialization(crate::error::CodecError),
}

impl fmt::Display for AccountStateProofBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedVersion => "unsupported account state proof bundle version",
            Self::BundleSizeExceeded => "account proof bundle size limit exceeded",
            Self::CommitmentHeightMismatch => {
                "state commitment height does not match the proven tip"
            }
            Self::CommitmentBlockHashMismatch => {
                "state commitment block hash does not match the proven tip"
            }
            Self::CommitmentProtocolRootMismatch => {
                "state commitment protocol root does not match the proven tip"
            }
            Self::InvalidProtocolCommitment => {
                "protocol state commitment components do not match its root"
            }
            Self::InvalidAccountProof => "account proof does not match the committed account root",
            Self::Serialization(_) => "account state proof bundle serialization failed",
        };
        match self {
            Self::Serialization(error) => write!(f, "{message}: {error}"),
            _ => f.write_str(message),
        }
    }
}

impl Error for AccountStateProofBundleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl AccountStateProofBundle {
    pub fn verify_against_tip(
        &self,
        tip_height: BlockHeight,
        tip: &Header,
    ) -> Result<VerifiedAccountState, AccountStateProofBundleError> {
        if self.version != ACCOUNT_STATE_PROOF_BUNDLE_VERSION {
            return Err(AccountStateProofBundleError::UnsupportedVersion);
        }
        let block_hash = tip
            .hash()
            .map_err(AccountStateProofBundleError::Serialization)?;
        self.verify_state_binding(tip_height, tip, block_hash)?;
        Ok(VerifiedAccountState {
            height: tip_height,
            block_hash,
            account: self.account_proof.account.clone(),
        })
    }

    /// Verifies the commitment and account layers against a header whose hash
    /// and chain validity were established separately.
    pub fn verify_state_binding(
        &self,
        tip_height: BlockHeight,
        tip: &Header,
        block_hash: BlockHash,
    ) -> Result<(), AccountStateProofBundleError> {
        if self.state_commitment.height != tip_height {
            return Err(AccountStateProofBundleError::CommitmentHeightMismatch);
        }
        if self.state_commitment.block_hash != block_hash {
            return Err(AccountStateProofBundleError::CommitmentBlockHashMismatch);
        }
        let committed_root = if tip_height.0 == 0 {
            self.state_commitment.account_state_root
        } else {
            self.state_commitment.protocol_state_root
        };
        if committed_root != tip.state_root {
            return Err(AccountStateProofBundleError::CommitmentProtocolRootMismatch);
        }
        if !self
            .state_commitment
            .matches_protocol_root()
            .map_err(AccountStateProofBundleError::Serialization)?
        {
            return Err(AccountStateProofBundleError::InvalidProtocolCommitment);
        }
        if !verify_account_state_proof(
            self.state_commitment.account_state_root,
            &self.account_proof,
        )
        .map_err(AccountStateProofBundleError::Serialization)?
        {
            return Err(AccountStateProofBundleError::InvalidAccountProof);
        }
        Ok(())
    }
}

impl AccountNonMembershipProofBundle {
    pub fn verify_against_tip(
        &self,
        tip_height: BlockHeight,
        tip: &Header,
    ) -> Result<VerifiedAccountAbsence, AccountStateProofBundleError> {
        if self.version != ACCOUNT_STATE_PROOF_BUNDLE_VERSION {
            return Err(AccountStateProofBundleError::UnsupportedVersion);
        }
        let block_hash = tip
            .hash()
            .map_err(AccountStateProofBundleError::Serialization)?;
        self.verify_state_binding(tip_height, tip, block_hash)?;
        Ok(VerifiedAccountAbsence {
            height: tip_height,
            block_hash,
            address: self.account_proof.address,
        })
    }

    /// Verifies absence against a header whose hash and chain validity were
    /// established separately.
    pub fn verify_state_binding(
        &self,
        tip_height: BlockHeight,
        tip: &Header,
        block_hash: BlockHash,
    ) -> Result<(), AccountStateProofBundleError> {
        if self.state_commitment.height != tip_height {
            return Err(AccountStateProofBundleError::CommitmentHeightMismatch);
        }
        if self.state_commitment.block_hash != block_hash {
            return Err(AccountStateProofBundleError::CommitmentBlockHashMismatch);
        }
        let committed_root = if tip_height.0 == 0 {
            self.state_commitment.account_state_root
        } else {
            self.state_commitment.protocol_state_root
        };
        if committed_root != tip.state_root {
            return Err(AccountStateProofBundleError::CommitmentProtocolRootMismatch);
        }
        if !self
            .state_commitment
            .matches_protocol_root()
            .map_err(AccountStateProofBundleError::Serialization)?
        {
            return Err(AccountStateProofBundleError::InvalidProtocolCommitment);
        }
        if !verify_account_non_membership_proof(
            self.state_commitment.account_state_root,
            &self.account_proof,
        ) {
            return Err(AccountStateProofBundleError::InvalidAccountProof);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccountAbsence {
    pub height: BlockHeight,
    pub block_hash: BlockHash,
    pub address: Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedQCashState {
    pub height: BlockHeight,
    pub block_hash: BlockHash,
    pub coin_id: QCashCoinId,
    pub coin: Option<QCashUtxo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QCashStateProofBundleError {
    UnsupportedVersion,
    BundleSizeExceeded,
    CommitmentHeightMismatch,
    CommitmentBlockHashMismatch,
    CommitmentProtocolRootMismatch,
    InvalidProtocolCommitment,
    InvalidQCashProof,
    Serialization(crate::error::CodecError),
}

impl fmt::Display for QCashStateProofBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedVersion => "unsupported QCash state proof bundle version",
            Self::BundleSizeExceeded => "QCash proof bundle size limit exceeded",
            Self::CommitmentHeightMismatch => {
                "state commitment height does not match the proven tip"
            }
            Self::CommitmentBlockHashMismatch => {
                "state commitment block hash does not match the proven tip"
            }
            Self::CommitmentProtocolRootMismatch => {
                "state commitment protocol root does not match the proven tip"
            }
            Self::InvalidProtocolCommitment => {
                "protocol state commitment components do not match its root"
            }
            Self::InvalidQCashProof => "QCash proof does not match the committed QCash root",
            Self::Serialization(_) => "QCash state proof bundle serialization failed",
        };
        match self {
            Self::Serialization(error) => write!(f, "{message}: {error}"),
            _ => f.write_str(message),
        }
    }
}

impl Error for QCashStateProofBundleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl QCashStateProofBundle {
    pub fn verify_against_tip(
        &self,
        tip_height: BlockHeight,
        tip: &Header,
    ) -> Result<VerifiedQCashState, QCashStateProofBundleError> {
        if self.version != ACCOUNT_STATE_PROOF_BUNDLE_VERSION {
            return Err(QCashStateProofBundleError::UnsupportedVersion);
        }
        let block_hash = tip
            .hash()
            .map_err(QCashStateProofBundleError::Serialization)?;
        self.verify_state_binding(tip_height, tip, block_hash)?;
        Ok(VerifiedQCashState {
            height: tip_height,
            block_hash,
            coin_id: self.qcash_proof.coin_id,
            coin: self.qcash_proof.coin.clone(),
        })
    }

    pub fn verify_state_binding(
        &self,
        tip_height: BlockHeight,
        tip: &Header,
        block_hash: BlockHash,
    ) -> Result<(), QCashStateProofBundleError> {
        if self.state_commitment.height != tip_height {
            return Err(QCashStateProofBundleError::CommitmentHeightMismatch);
        }
        if self.state_commitment.block_hash != block_hash {
            return Err(QCashStateProofBundleError::CommitmentBlockHashMismatch);
        }
        if tip_height.0 == 0 {
            let empty_root =
                empty_qcash_state_root().map_err(QCashStateProofBundleError::Serialization)?;
            if self.state_commitment.qcash_state_root != StateRoot(empty_root.0)
                || self.qcash_proof.coin.is_some()
            {
                return Err(QCashStateProofBundleError::CommitmentProtocolRootMismatch);
            }
        } else if self.state_commitment.protocol_state_root != tip.state_root {
            return Err(QCashStateProofBundleError::CommitmentProtocolRootMismatch);
        }
        if !self
            .state_commitment
            .matches_protocol_root()
            .map_err(QCashStateProofBundleError::Serialization)?
        {
            return Err(QCashStateProofBundleError::InvalidProtocolCommitment);
        }
        if !verify_qcash_state_proof(
            Hash(self.state_commitment.qcash_state_root.0),
            &self.qcash_proof,
        )
        .map_err(QCashStateProofBundleError::Serialization)?
        {
            return Err(QCashStateProofBundleError::InvalidQCashProof);
        }
        Ok(())
    }
}

/// Decodes an untrusted proof bundle with an outer byte-size bound. Call
/// [`AccountStateProofBundle::verify`] before using any contained account data.
pub fn decode_account_state_proof_bundle(
    bytes: &[u8],
) -> Result<AccountStateProofBundle, AccountStateProofBundleError> {
    if bytes.len() > MAX_STATE_PROOF_BUNDLE_SIZE {
        return Err(AccountStateProofBundleError::BundleSizeExceeded);
    }
    let bundle: AccountStateProofBundle = crate::codec::canonical_deserialize(bytes)
        .map_err(AccountStateProofBundleError::Serialization)?;
    if bundle.version != ACCOUNT_STATE_PROOF_BUNDLE_VERSION {
        return Err(AccountStateProofBundleError::UnsupportedVersion);
    }
    Ok(bundle)
}

pub fn decode_account_non_membership_proof_bundle(
    bytes: &[u8],
) -> Result<AccountNonMembershipProofBundle, AccountStateProofBundleError> {
    if bytes.len() > MAX_STATE_PROOF_BUNDLE_SIZE {
        return Err(AccountStateProofBundleError::BundleSizeExceeded);
    }
    let bundle: AccountNonMembershipProofBundle = crate::codec::canonical_deserialize(bytes)
        .map_err(AccountStateProofBundleError::Serialization)?;
    if bundle.version != ACCOUNT_STATE_PROOF_BUNDLE_VERSION {
        return Err(AccountStateProofBundleError::UnsupportedVersion);
    }
    Ok(bundle)
}

pub fn decode_qcash_state_proof_bundle(
    bytes: &[u8],
) -> Result<QCashStateProofBundle, QCashStateProofBundleError> {
    if bytes.len() > MAX_STATE_PROOF_BUNDLE_SIZE {
        return Err(QCashStateProofBundleError::BundleSizeExceeded);
    }
    let bundle: QCashStateProofBundle = crate::codec::canonical_deserialize(bytes)
        .map_err(QCashStateProofBundleError::Serialization)?;
    if bundle.version != ACCOUNT_STATE_PROOF_BUNDLE_VERSION {
        return Err(QCashStateProofBundleError::UnsupportedVersion);
    }
    Ok(bundle)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseStateTree {
    nodes: BTreeMap<(usize, [u8; ADDRESS_SIZE]), Hash>,
    root: StateRoot,
    leaves: usize,
}

impl Default for SparseStateTree {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            root: StateRoot::ZERO,
            leaves: 0,
        }
    }
}

impl SparseStateTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_accounts(
        accounts: &BTreeMap<Address, Account>,
    ) -> Result<Self, crate::error::CodecError> {
        let mut tree = Self::new();
        for account in accounts.values() {
            tree.update_account(account)?;
        }
        Ok(tree)
    }

    pub fn root(&self) -> StateRoot {
        self.root
    }

    pub fn update_account(&mut self, account: &Account) -> Result<(), crate::error::CodecError> {
        if self
            .nodes
            .insert(
                (ADDRESS_BITS, account.address.0),
                account_leaf_hash(account)?,
            )
            .is_none()
        {
            self.leaves += 1;
        }

        self.recalculate_path(account.address);
        Ok(())
    }

    pub fn remove_account(&mut self, address: &Address) {
        if self.nodes.remove(&(ADDRESS_BITS, address.0)).is_none() {
            return;
        }
        self.leaves -= 1;
        if self.leaves == 0 {
            self.nodes.clear();
            self.root = StateRoot::ZERO;
            return;
        }
        self.recalculate_path(*address);
    }

    pub fn create_account_proof(&self, account: &Account) -> AccountStateProof {
        let mut siblings = Vec::with_capacity(ADDRESS_BITS);
        for depth in 0..ADDRESS_BITS {
            let parent_prefix = address_prefix(&account.address, depth);
            let bit = address_bit(&account.address, depth);
            let sibling_prefix = child_prefix(parent_prefix, depth, !bit);
            siblings.push(StateProofNode {
                side: if bit {
                    ProofSide::Left
                } else {
                    ProofSide::Right
                },
                hash: self
                    .nodes
                    .get(&(depth + 1, sibling_prefix))
                    .copied()
                    .unwrap_or_else(|| empty_subtree_hash(depth + 1)),
            });
        }
        AccountStateProof {
            address: account.address,
            account: account.clone(),
            siblings,
        }
    }

    pub fn create_account_non_membership_proof(
        &self,
        address: Address,
    ) -> AccountNonMembershipProof {
        if self.root == StateRoot::ZERO {
            return AccountNonMembershipProof {
                address,
                terminal_depth: 0,
                siblings: Vec::new(),
            };
        }
        let mut siblings = Vec::with_capacity(ADDRESS_BITS);
        for depth in 0..ADDRESS_BITS {
            let parent_prefix = address_prefix(&address, depth);
            let bit = address_bit(&address, depth);
            let sibling_prefix = child_prefix(parent_prefix, depth, !bit);
            siblings.push(StateProofNode {
                side: if bit {
                    ProofSide::Left
                } else {
                    ProofSide::Right
                },
                hash: self
                    .nodes
                    .get(&(depth + 1, sibling_prefix))
                    .copied()
                    .unwrap_or_else(|| empty_subtree_hash(depth + 1)),
            });
            let target_prefix = child_prefix(parent_prefix, depth, bit);
            if !self.nodes.contains_key(&(depth + 1, target_prefix)) {
                return AccountNonMembershipProof {
                    address,
                    terminal_depth: (depth + 1) as u16,
                    siblings,
                };
            }
        }
        AccountNonMembershipProof {
            address,
            terminal_depth: ADDRESS_BITS as u16,
            siblings,
        }
    }

    fn recalculate_path(&mut self, address: Address) {
        for depth in (0..ADDRESS_BITS).rev() {
            let parent_prefix = address_prefix(&address, depth);
            let left_prefix = child_prefix(parent_prefix, depth, false);
            let right_prefix = child_prefix(parent_prefix, depth, true);
            let left = self.nodes.get(&(depth + 1, left_prefix)).copied();
            let right = self.nodes.get(&(depth + 1, right_prefix)).copied();
            if left.is_none() && right.is_none() {
                self.nodes.remove(&(depth, parent_prefix));
            } else {
                self.nodes.insert(
                    (depth, parent_prefix),
                    parent_hash(
                        left.unwrap_or_else(|| empty_subtree_hash(depth + 1)),
                        right.unwrap_or_else(|| empty_subtree_hash(depth + 1)),
                    ),
                );
            }
        }

        self.root = self
            .nodes
            .get(&(0, [0; ADDRESS_SIZE]))
            .copied()
            .map(|hash| StateRoot(hash.0))
            .unwrap_or(StateRoot::ZERO);
    }
}

pub fn calculate_state_root(
    accounts: &BTreeMap<Address, Account>,
) -> Result<StateRoot, crate::error::CodecError> {
    if accounts.is_empty() {
        return Ok(StateRoot::ZERO);
    }

    Ok(SparseStateTree::from_accounts(accounts)?.root())
}

pub fn create_account_state_proof(
    accounts: &BTreeMap<Address, Account>,
    address: &Address,
) -> Result<Option<AccountStateProof>, crate::error::CodecError> {
    let Some(account) = accounts.get(address).cloned() else {
        return Ok(None);
    };
    let siblings = sparse_proof(accounts, address)?;

    Ok(Some(AccountStateProof {
        address: *address,
        account,
        siblings,
    }))
}

pub fn verify_account_state_proof(
    root: StateRoot,
    proof: &AccountStateProof,
) -> Result<bool, crate::error::CodecError> {
    if proof.account.address != proof.address {
        return Ok(false);
    }

    let mut current = account_leaf_hash(&proof.account)?;
    for sibling in proof.siblings.iter().rev() {
        current = match sibling.side {
            ProofSide::Left => parent_hash(sibling.hash, current),
            ProofSide::Right => parent_hash(current, sibling.hash),
        };
    }

    Ok(current == root)
}

pub fn verify_account_non_membership_proof(
    root: StateRoot,
    proof: &AccountNonMembershipProof,
) -> bool {
    let terminal_depth = usize::from(proof.terminal_depth);
    if terminal_depth > ADDRESS_BITS || proof.siblings.len() != terminal_depth {
        return false;
    }
    if proof.siblings.iter().enumerate().any(|(depth, sibling)| {
        let expected = if address_bit(&proof.address, depth) {
            ProofSide::Left
        } else {
            ProofSide::Right
        };
        sibling.side != expected
    }) {
        return false;
    }
    let mut current = empty_subtree_hash(terminal_depth);
    for sibling in proof.siblings.iter().rev() {
        current = match sibling.side {
            ProofSide::Left => parent_hash(sibling.hash, current),
            ProofSide::Right => parent_hash(current, sibling.hash),
        };
    }
    current == root || (root == StateRoot::ZERO && terminal_depth == 0)
}

fn sparse_root(
    accounts: &[(&Address, &Account)],
    depth: usize,
) -> Result<Hash, crate::error::CodecError> {
    if accounts.is_empty() {
        return Ok(empty_subtree_hash(depth));
    }
    if depth == ADDRESS_BITS {
        return account_leaf_hash(accounts[0].1);
    }

    let split = accounts.partition_point(|(address, _)| !address_bit(address, depth));
    Ok(parent_hash(
        sparse_root(&accounts[..split], depth + 1)?,
        sparse_root(&accounts[split..], depth + 1)?,
    ))
}

fn sparse_proof(
    accounts: &BTreeMap<Address, Account>,
    address: &Address,
) -> Result<Vec<StateProofNode>, crate::error::CodecError> {
    let nodes: Vec<(&Address, &Account)> = accounts.iter().collect();
    let mut current = nodes.as_slice();
    let mut siblings = Vec::with_capacity(ADDRESS_BITS);

    for depth in 0..ADDRESS_BITS {
        let split = current.partition_point(|(candidate, _)| !address_bit(candidate, depth));
        let bit = address_bit(address, depth);
        let (same, sibling, side) = if bit {
            (&current[split..], &current[..split], ProofSide::Left)
        } else {
            (&current[..split], &current[split..], ProofSide::Right)
        };
        siblings.push(StateProofNode {
            side,
            hash: sparse_root(sibling, depth + 1)?,
        });
        current = same;
    }

    Ok(siblings)
}

fn account_leaf_hash(account: &Account) -> Result<Hash, crate::error::CodecError> {
    Ok(domain_hash(
        HashDomain::AccountState,
        &canonical_bytes(account)?,
    ))
}

fn empty_subtree_hash(depth: usize) -> Hash {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&(depth as u64).to_le_bytes());
    domain_hash(HashDomain::StateNode, &bytes)
}

fn address_bit(address: &Address, depth: usize) -> bool {
    let byte = address.0[depth / 8];
    let mask = 0x80_u8 >> (depth % 8);
    byte & mask != 0
}

fn address_prefix(address: &Address, depth: usize) -> [u8; ADDRESS_SIZE] {
    let mut prefix = address.0;
    clear_bits_from(&mut prefix, depth);
    prefix
}

fn child_prefix(
    mut parent_prefix: [u8; ADDRESS_SIZE],
    depth: usize,
    right: bool,
) -> [u8; ADDRESS_SIZE] {
    clear_bits_from(&mut parent_prefix, depth);
    if right {
        let byte = depth / 8;
        let mask = 0x80_u8 >> (depth % 8);
        parent_prefix[byte] |= mask;
    }
    clear_bits_from(&mut parent_prefix, depth + 1);
    parent_prefix
}

fn clear_bits_from(bytes: &mut [u8; ADDRESS_SIZE], depth: usize) {
    if depth >= ADDRESS_BITS {
        return;
    }

    let byte_index = depth / 8;
    let bit_index = depth % 8;
    if bit_index == 0 {
        bytes[byte_index] = 0;
    } else {
        let keep_mask = 0xff_u8 << (8 - bit_index);
        bytes[byte_index] &= keep_mask;
    }
    for byte in &mut bytes[(byte_index + 1)..] {
        *byte = 0;
    }
}

fn parent_hash(left: Hash, right: Hash) -> Hash {
    let mut bytes = Vec::with_capacity(HASH_SIZE * 2);
    bytes.extend_from_slice(&left.0);
    bytes.extend_from_slice(&right.0);
    domain_hash(HashDomain::StateNode, &bytes)
}

#[cfg(test)]
mod bundle_tests {
    use super::*;

    fn state_bound_bundle() -> (AccountStateProofBundle, Header, BlockHash) {
        let address = Address([7; ADDRESS_SIZE]);
        let account = Account::new(address);
        let mut accounts = BTreeMap::new();
        accounts.insert(address, account);
        let account_state_root = calculate_state_root(&accounts).unwrap();
        let xpq_state_root = StateRoot([3; HASH_SIZE]);
        let qcash_state_root = StateRoot([2; HASH_SIZE]);
        let protocol_state_root = crate::ledger::calculate_protocol_state_root_from_roots(
            account_state_root,
            xpq_state_root,
            qcash_state_root,
        )
        .unwrap();
        let block_hash = BlockHash([9; HASH_SIZE]);
        let genesis = crate::genesis::genesis_block().unwrap();
        let mut tip = genesis.header;
        tip.state_root = protocol_state_root;
        let bundle = AccountStateProofBundle {
            version: ACCOUNT_STATE_PROOF_BUNDLE_VERSION,
            state_commitment: BlockStateCommitment::new(
                crate::block::Height(1),
                block_hash,
                account_state_root,
                xpq_state_root,
                qcash_state_root,
                protocol_state_root,
            ),
            account_proof: create_account_state_proof(&accounts, &address)
                .unwrap()
                .unwrap(),
        };
        (bundle, tip, block_hash)
    }

    #[test]
    fn account_bundle_roundtrip_preserves_verified_state_binding() {
        let (bundle, tip, block_hash) = state_bound_bundle();
        let bytes = canonical_bytes(&bundle).unwrap();
        let decoded: AccountStateProofBundle = crate::codec::canonical_deserialize(&bytes).unwrap();

        assert_eq!(decoded, bundle);
        assert_eq!(
            decoded.verify_state_binding(crate::block::Height(1), &tip, block_hash),
            Ok(())
        );
    }

    #[test]
    fn account_bundle_rejects_account_state_tampering() {
        let (mut bundle, tip, block_hash) = state_bound_bundle();
        bundle.account_proof.account.address.0[0] ^= 1;

        assert_eq!(
            bundle.verify_state_binding(crate::block::Height(1), &tip, block_hash),
            Err(AccountStateProofBundleError::InvalidAccountProof)
        );
    }

    #[test]
    fn account_bundle_rejects_protocol_commitment_tampering() {
        let (mut bundle, tip, block_hash) = state_bound_bundle();
        bundle.state_commitment.qcash_state_root.0[0] ^= 1;

        assert_eq!(
            bundle.verify_state_binding(crate::block::Height(1), &tip, block_hash),
            Err(AccountStateProofBundleError::InvalidProtocolCommitment)
        );
    }

    #[test]
    fn account_bundle_rejects_tip_state_root_tampering() {
        let (mut bundle, tip, block_hash) = state_bound_bundle();
        bundle.state_commitment.protocol_state_root.0[0] ^= 1;

        assert_eq!(
            bundle.verify_state_binding(crate::block::Height(1), &tip, block_hash),
            Err(AccountStateProofBundleError::CommitmentProtocolRootMismatch)
        );
    }

    #[test]
    fn non_membership_proof_verifies_for_missing_account() {
        let existing = Account::new(Address([1; ADDRESS_SIZE]));
        let missing = Address([2; ADDRESS_SIZE]);
        let mut accounts = BTreeMap::new();
        accounts.insert(existing.address, existing);
        let tree = SparseStateTree::from_accounts(&accounts).unwrap();
        let proof = tree.create_account_non_membership_proof(missing);

        assert!(verify_account_non_membership_proof(tree.root(), &proof));
    }

    #[test]
    fn non_membership_proof_rejects_relabel_and_existing_account() {
        let existing = Account::new(Address([1; ADDRESS_SIZE]));
        let missing = Address([2; ADDRESS_SIZE]);
        let mut accounts = BTreeMap::new();
        accounts.insert(existing.address, existing.clone());
        let tree = SparseStateTree::from_accounts(&accounts).unwrap();
        let mut proof = tree.create_account_non_membership_proof(missing);
        proof.address = existing.address;
        assert!(!verify_account_non_membership_proof(tree.root(), &proof));

        let existing_proof = tree.create_account_non_membership_proof(existing.address);
        assert!(!verify_account_non_membership_proof(
            tree.root(),
            &existing_proof
        ));
    }

    #[test]
    fn non_membership_proof_supports_empty_account_tree() {
        let tree = SparseStateTree::new();
        let proof = tree.create_account_non_membership_proof(Address([8; ADDRESS_SIZE]));

        assert!(verify_account_non_membership_proof(tree.root(), &proof));
    }

    #[test]
    fn qcash_absence_bundle_verifies_from_configured_genesis() {
        let ledger = crate::genesis::genesis_ledger().unwrap();
        let block = crate::genesis::genesis_block().unwrap();
        let height = block.height();
        let coin_id = QCashCoinId([0x55; HASH_SIZE]);
        let bundle = QCashStateProofBundle {
            version: ACCOUNT_STATE_PROOF_BUNDLE_VERSION,
            state_commitment: ledger.tip_state_commitment().unwrap().unwrap(),
            qcash_proof: ledger.qcash_utxos.create_state_proof(coin_id).unwrap(),
        };

        let verified = bundle.verify_against_tip(height, &block.header).unwrap();
        assert_eq!(verified.coin_id, coin_id);
        assert!(verified.coin.is_none());
    }

    #[test]
    fn qcash_bundle_rejects_absence_path_tampering() {
        let ledger = crate::genesis::genesis_ledger().unwrap();
        let block = crate::genesis::genesis_block().unwrap();
        let height = block.height();
        let mut bundle = QCashStateProofBundle {
            version: ACCOUNT_STATE_PROOF_BUNDLE_VERSION,
            state_commitment: ledger.tip_state_commitment().unwrap().unwrap(),
            qcash_proof: ledger
                .qcash_utxos
                .create_state_proof(QCashCoinId([0x66; HASH_SIZE]))
                .unwrap(),
        };
        bundle.qcash_proof.terminal_depth = 1;

        assert_eq!(
            bundle.verify_against_tip(height, &block.header),
            Err(QCashStateProofBundleError::InvalidQCashProof)
        );
    }
}
