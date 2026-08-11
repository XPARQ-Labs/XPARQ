//! Canonical proof-of-stake data boundaries for the experimental XPARQ
//! sidechain.
//!
//! This crate intentionally stops short of defining a complete consensus
//! protocol. It provides validated parameters, validator-set commitments,
//! block-header hashes, and SQIsign vote verification without inventing
//! undeclared staking, slashing, leader-selection, or bridge rules.

use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeSet;
use thiserror::Error;
use xparq_sidechain_primitives::{
    Address, Hash256, HashDomain, PROTOCOL_VERSION, PublicKey, Signature, SignatureError,
    domain_hash, verify,
};

pub const CONSENSUS_VERSION: u8 = 1;

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Stake(pub u64);

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConsensusParams {
    pub version: u8,
    pub chain_id: u32,
    pub epoch_length: u64,
    pub quorum_numerator: u32,
    pub quorum_denominator: u32,
    pub minimum_validator_stake: Stake,
    pub maximum_validators: u32,
}

impl ConsensusParams {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u32,
        epoch_length: u64,
        quorum_numerator: u32,
        quorum_denominator: u32,
        minimum_validator_stake: Stake,
        maximum_validators: u32,
    ) -> Result<Self, ConsensusError> {
        let params = Self {
            version: CONSENSUS_VERSION,
            chain_id,
            epoch_length,
            quorum_numerator,
            quorum_denominator,
            minimum_validator_stake,
            maximum_validators,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn validate(&self) -> Result<(), ConsensusError> {
        if self.version != CONSENSUS_VERSION || self.version != PROTOCOL_VERSION {
            return Err(ConsensusError::UnsupportedVersion);
        }
        if self.chain_id == 0 {
            return Err(ConsensusError::InvalidChainId);
        }
        if self.epoch_length == 0 {
            return Err(ConsensusError::InvalidEpochLength);
        }
        if self.quorum_denominator == 0
            || self.quorum_numerator == 0
            || self.quorum_numerator > self.quorum_denominator
        {
            return Err(ConsensusError::InvalidQuorum);
        }
        if self.minimum_validator_stake.0 == 0 || self.maximum_validators == 0 {
            return Err(ConsensusError::InvalidValidatorLimits);
        }
        Ok(())
    }

    pub fn reaches_quorum(&self, signed_stake: Stake, total_stake: Stake) -> bool {
        if total_stake.0 == 0 || signed_stake.0 > total_stake.0 {
            return false;
        }
        let signed = signed_stake.0 as u128 * self.quorum_denominator as u128;
        let required = total_stake.0 as u128 * self.quorum_numerator as u128;
        signed >= required
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Validator {
    /// Dual-authorization operator/reward address with the L1-shaped encoding.
    pub operator_address: Address,
    /// SQIsign Level 5 key used to verify consensus messages.
    pub consensus_public_key: PublicKey,
    pub stake: Stake,
}

impl Validator {
    pub fn validate(&self, params: &ConsensusParams) -> Result<(), ConsensusError> {
        if self.operator_address == Address::ZERO {
            return Err(ConsensusError::InvalidValidatorAddress);
        }
        self.consensus_public_key.validate()?;
        if self.stake < params.minimum_validator_stake {
            return Err(ConsensusError::InsufficientValidatorStake);
        }
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    total_stake: Stake,
}

impl ValidatorSet {
    pub fn new(
        params: &ConsensusParams,
        mut validators: Vec<Validator>,
    ) -> Result<Self, ConsensusError> {
        params.validate()?;
        if validators.is_empty() || validators.len() > params.maximum_validators as usize {
            return Err(ConsensusError::InvalidValidatorCount);
        }
        validators.sort_by_key(|validator| validator.operator_address);

        let mut addresses = BTreeSet::new();
        let mut consensus_keys = BTreeSet::new();
        let mut total_stake = 0_u64;
        for validator in &validators {
            validator.validate(params)?;
            if !addresses.insert(validator.operator_address)
                || !consensus_keys.insert(validator.consensus_public_key)
            {
                return Err(ConsensusError::DuplicateValidator);
            }
            total_stake = total_stake
                .checked_add(validator.stake.0)
                .ok_or(ConsensusError::StakeOverflow)?;
        }

        Ok(Self {
            validators,
            total_stake: Stake(total_stake),
        })
    }

    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    pub const fn total_stake(&self) -> Stake {
        self.total_stake
    }

    pub fn root(&self) -> Result<Hash256, ConsensusError> {
        canonical_domain_hash(HashDomain::ValidatorSet, self)
    }

    pub fn validator(&self, address: Address) -> Option<&Validator> {
        self.validators
            .binary_search_by_key(&address, |validator| validator.operator_address)
            .ok()
            .map(|index| &self.validators[index])
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub version: u8,
    pub chain_id: u32,
    pub height: u64,
    pub epoch: u64,
    pub round: u32,
    pub previous_hash: Hash256,
    pub transaction_root: Hash256,
    pub state_root: Hash256,
    pub validator_set_root: Hash256,
    pub proposer: Address,
}

impl BlockHeader {
    pub fn hash(&self, params: &ConsensusParams) -> Result<Hash256, ConsensusError> {
        if self.version != CONSENSUS_VERSION || self.chain_id != params.chain_id {
            return Err(ConsensusError::HeaderIdentityMismatch);
        }
        canonical_domain_hash(HashDomain::BlockHeader, self)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum VoteKind {
    Prevote = 1,
    Precommit = 2,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Vote {
    pub version: u8,
    pub chain_id: u32,
    pub height: u64,
    pub round: u32,
    pub kind: VoteKind,
    pub block_hash: Hash256,
    pub validator: Address,
}

impl Vote {
    pub fn signing_root(&self, params: &ConsensusParams) -> Result<Hash256, ConsensusError> {
        if self.version != CONSENSUS_VERSION || self.chain_id != params.chain_id {
            return Err(ConsensusError::VoteIdentityMismatch);
        }
        canonical_domain_hash(HashDomain::Vote, self)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignedVote {
    pub vote: Vote,
    pub signature: Signature,
}

impl SignedVote {
    pub fn verify(
        &self,
        params: &ConsensusParams,
        validators: &ValidatorSet,
    ) -> Result<(), ConsensusError> {
        let validator = validators
            .validator(self.vote.validator)
            .ok_or(ConsensusError::UnknownValidator)?;
        let root = self.vote.signing_root(params)?;
        verify(&validator.consensus_public_key, &root.0, &self.signature)?;
        Ok(())
    }
}

fn canonical_domain_hash<T: BorshSerialize>(
    domain: HashDomain,
    value: &T,
) -> Result<Hash256, ConsensusError> {
    let bytes =
        borsh::to_vec(value).map_err(|error| ConsensusError::Encoding(error.to_string()))?;
    Ok(domain_hash(domain, &bytes))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("unsupported sidechain consensus version")]
    UnsupportedVersion,
    #[error("sidechain chain ID must be nonzero")]
    InvalidChainId,
    #[error("epoch length must be nonzero")]
    InvalidEpochLength,
    #[error("quorum fraction is invalid")]
    InvalidQuorum,
    #[error("validator stake and count limits must be nonzero")]
    InvalidValidatorLimits,
    #[error("validator count is outside configured bounds")]
    InvalidValidatorCount,
    #[error("validator operator address is invalid")]
    InvalidValidatorAddress,
    #[error("validator stake is below the configured minimum")]
    InsufficientValidatorStake,
    #[error("validator address or consensus key is duplicated")]
    DuplicateValidator,
    #[error("total validator stake overflow")]
    StakeOverflow,
    #[error("block header does not match configured chain identity")]
    HeaderIdentityMismatch,
    #[error("vote does not match configured chain identity")]
    VoteIdentityMismatch,
    #[error("vote references an unknown validator")]
    UnknownValidator,
    #[error("canonical encoding failed: {0}")]
    Encoding(String),
    #[error(transparent)]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqisign_rs::{Level5, generate};
    use std::sync::OnceLock;
    use xparq_sidechain_primitives::{PUBLIC_KEY_SIZE, dual_address_from_public_keys};

    fn params() -> ConsensusParams {
        ConsensusParams::new(9_001, 1_024, 2, 3, Stake(100), 100).unwrap()
    }

    fn public_key(byte: u8) -> PublicKey {
        PublicKey([byte; PUBLIC_KEY_SIZE])
    }

    fn consensus_keys() -> &'static [PublicKey; 2] {
        static KEYS: OnceLock<[PublicKey; 2]> = OnceLock::new();
        KEYS.get_or_init(|| {
            let mut rng = rand_10::rng();
            let (first, _) = generate::<Level5>(&mut rng);
            let (second, _) = generate::<Level5>(&mut rng);
            [
                PublicKey(first.to_bytes().as_slice().try_into().unwrap()),
                PublicKey(second.to_bytes().as_slice().try_into().unwrap()),
            ]
        })
    }

    fn validator(byte: u8, consensus_key_index: usize, stake: u64) -> Validator {
        let owner = public_key(byte);
        let authorization = public_key(byte.saturating_add(1));
        Validator {
            operator_address: dual_address_from_public_keys(
                params().chain_id,
                &owner,
                &authorization,
            )
            .unwrap(),
            consensus_public_key: consensus_keys()[consensus_key_index],
            stake: Stake(stake),
        }
    }

    #[test]
    fn quorum_math_uses_integer_cross_multiplication() {
        let params = params();
        assert!(!params.reaches_quorum(Stake(66), Stake(100)));
        assert!(params.reaches_quorum(Stake(67), Stake(100)));
        assert!(params.reaches_quorum(Stake(2), Stake(3)));
    }

    #[test]
    fn validator_set_is_sorted_before_commitment() {
        let params = params();
        let first =
            ValidatorSet::new(&params, vec![validator(10, 0, 100), validator(20, 1, 200)]).unwrap();
        let second =
            ValidatorSet::new(&params, vec![validator(20, 1, 200), validator(10, 0, 100)]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.root().unwrap(), second.root().unwrap());
        assert_eq!(first.total_stake(), Stake(300));
    }

    #[test]
    fn consensus_parameters_do_not_hide_defaults() {
        assert_eq!(
            ConsensusParams::new(0, 1_024, 2, 3, Stake(100), 100),
            Err(ConsensusError::InvalidChainId)
        );
        assert_eq!(
            ConsensusParams::new(9_001, 0, 2, 3, Stake(100), 100),
            Err(ConsensusError::InvalidEpochLength)
        );
        assert_eq!(
            ConsensusParams::new(9_001, 1_024, 4, 3, Stake(100), 100),
            Err(ConsensusError::InvalidQuorum)
        );
    }
}
