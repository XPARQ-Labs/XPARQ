use crate::crypto::{HASH_SIZE, Hash, HashDomain, domain_hash};
use borsh::{BorshDeserialize, BorshSerialize};

pub use crate::crypto::MerkleHash;

pub(crate) fn merkle_root(leaves: &[Hash], domain: HashDomain) -> Option<Hash> {
    if leaves.is_empty() {
        return None;
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = merkle_parent_level(&level, domain);
    }
    level.first().copied()
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct MerkleInclusionProof {
    pub leaf_index: u32,
    pub leaf_count: u32,
    pub siblings: Vec<Hash>,
}

impl MerkleInclusionProof {
    pub fn create(leaves: &[Hash], leaf_index: usize, domain: HashDomain) -> Option<Self> {
        if leaves.is_empty() || leaf_index >= leaves.len() {
            return None;
        }
        let leaf_index_u32 = u32::try_from(leaf_index).ok()?;
        let leaf_count = u32::try_from(leaves.len()).ok()?;
        let mut level = leaves.to_vec();
        let mut index = leaf_index;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let sibling_index = if index.is_multiple_of(2) {
                index.checked_add(1)
            } else {
                Some(index - 1)
            };
            if let Some(sibling_index) = sibling_index
                && let Some(sibling) = level.get(sibling_index)
            {
                siblings.push(*sibling);
            }
            level = merkle_parent_level(&level, domain);
            index /= 2;
        }
        Some(Self {
            leaf_index: leaf_index_u32,
            leaf_count,
            siblings,
        })
    }

    pub fn verify(&self, leaf: Hash, root: Hash, domain: HashDomain) -> bool {
        let Ok(mut index) = usize::try_from(self.leaf_index) else {
            return false;
        };
        let Ok(mut width) = usize::try_from(self.leaf_count) else {
            return false;
        };
        if width == 0 || index >= width || self.siblings.len() > 64 {
            return false;
        }
        let mut hash = leaf;
        let mut sibling_index = 0;
        while width > 1 {
            let has_sibling = index % 2 == 1 || index + 1 < width;
            if has_sibling {
                let Some(sibling) = self.siblings.get(sibling_index) else {
                    return false;
                };
                sibling_index += 1;
                hash = if index % 2 == 0 {
                    merkle_parent(hash, *sibling, domain)
                } else {
                    merkle_parent(*sibling, hash, domain)
                };
            }
            index /= 2;
            width = width.div_ceil(2);
        }
        sibling_index == self.siblings.len() && hash == root
    }
}

fn merkle_parent(left: Hash, right: Hash, domain: HashDomain) -> Hash {
    let mut bytes = Vec::with_capacity(HASH_SIZE * 2);
    bytes.extend_from_slice(&left.0);
    bytes.extend_from_slice(&right.0);
    domain_hash(domain, &bytes)
}

fn merkle_parent_level(level: &[Hash], domain: HashDomain) -> Vec<Hash> {
    let mut parents = Vec::with_capacity(level.len().div_ceil(2));
    let mut pairs = level.chunks_exact(2);
    for pair in &mut pairs {
        parents.push(merkle_parent(pair[0], pair[1], domain));
    }
    if let [last] = pairs.remainder() {
        parents.push(*last);
    }
    parents
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inclusion_proofs_cover_even_and_promoted_odd_leaves() {
        let leaves = vec![Hash([1; 32]), Hash([2; 32]), Hash([3; 32])];
        let root = merkle_parent(
            merkle_parent(leaves[0], leaves[1], HashDomain::MerkleNode),
            leaves[2],
            HashDomain::MerkleNode,
        );
        for index in 0..leaves.len() {
            let proof =
                MerkleInclusionProof::create(&leaves, index, HashDomain::MerkleNode).unwrap();
            assert!(proof.verify(leaves[index], root, HashDomain::MerkleNode));
        }
    }

    #[test]
    fn inclusion_proof_rejects_tampered_leaf_sibling_and_domain() {
        let leaves = vec![Hash([1; 32]), Hash([2; 32]), Hash([3; 32])];
        let proof = MerkleInclusionProof::create(&leaves, 1, HashDomain::MerkleNode).unwrap();
        let root = merkle_parent(
            merkle_parent(leaves[0], leaves[1], HashDomain::MerkleNode),
            leaves[2],
            HashDomain::MerkleNode,
        );
        assert!(!proof.verify(Hash([9; 32]), root, HashDomain::MerkleNode));
        let mut tampered = proof.clone();
        tampered.siblings[0] = Hash([8; 32]);
        assert!(!tampered.verify(leaves[1], root, HashDomain::MerkleNode));
        assert!(!proof.verify(leaves[1], root, HashDomain::Transaction));
    }
}
