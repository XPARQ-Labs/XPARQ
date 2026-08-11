//! Backed wXPQ accounting for the experimental XPARQ sidechain.
//!
//! This crate enforces conservation after the L1-finality verification
//! boundary. It does not implement that verifier, an L1 escrow, relayers, or
//! release proofs. A production integration must supply an independent
//! [`FinalizedL1DepositVerifier`] and must not construct balances by any other
//! path.

use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use xparq_sidechain_primitives::{Address, Hash256, HashDomain, PROTOCOL_VERSION, domain_hash};

pub const WXPQ_VERSION: u8 = 1;
pub const WXPQ_SYMBOL: &str = "wXPQ";
pub const WXPQ_DECIMALS: u8 = 6;
pub const PAQS_PER_WXPQ: u64 = 1_000_000;

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Amount(pub u64);

impl Amount {
    pub const ZERO: Self = Self(0);
}

/// Raw 20-byte XPARQ L1 destination.
///
/// This is intentionally distinct from the sidechain [`Address`] type even
/// though both share the same byte length and Bech32 shape.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct L1Address(pub [u8; 20]);

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct L1DepositClaim {
    pub version: u8,
    /// XPARQ L1 chain identity whose escrow and finality rules are verified.
    pub l1_chain_id: u32,
    pub sidechain_chain_id: u32,
    pub l1_block_hash: Hash256,
    pub l1_block_height: u64,
    pub deposit_index: u32,
    pub recipient: Address,
    /// Amount locked on L1 and minted on the sidechain, measured in paqs.
    pub amount: Amount,
}

impl L1DepositClaim {
    pub fn deposit_id(&self) -> Result<Hash256, WxpqError> {
        if self.version != WXPQ_VERSION || self.version != PROTOCOL_VERSION {
            return Err(WxpqError::UnsupportedVersion);
        }
        if self.l1_chain_id == 0
            || self.sidechain_chain_id == 0
            || self.l1_block_hash == Hash256::ZERO
            || self.recipient == Address::ZERO
            || self.amount == Amount::ZERO
        {
            return Err(WxpqError::InvalidDepositClaim);
        }
        canonical_hash(HashDomain::WxpqDeposit, self)
    }
}

/// Trust boundary for proving that an XPQ deposit exists in finalized L1 state
/// and is locked by the canonical bridge escrow.
///
/// The sidechain scaffold deliberately provides no permissive default
/// implementation.
pub trait FinalizedL1DepositVerifier<Proof> {
    fn verify_finalized_deposit(&self, claim: &L1DepositClaim, proof: &Proof) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedL1Deposit {
    claim: L1DepositClaim,
    deposit_id: Hash256,
}

impl VerifiedL1Deposit {
    pub const fn claim(&self) -> &L1DepositClaim {
        &self.claim
    }

    pub const fn deposit_id(&self) -> Hash256 {
        self.deposit_id
    }
}

pub fn verify_finalized_l1_deposit<Proof, Verifier>(
    claim: L1DepositClaim,
    proof: &Proof,
    verifier: &Verifier,
) -> Result<VerifiedL1Deposit, WxpqError>
where
    Verifier: FinalizedL1DepositVerifier<Proof>,
{
    let deposit_id = claim.deposit_id()?;
    if !verifier.verify_finalized_deposit(&claim, proof) {
        return Err(WxpqError::L1DepositNotVerified);
    }
    Ok(VerifiedL1Deposit { claim, deposit_id })
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WithdrawalIntent {
    pub version: u8,
    pub sidechain_chain_id: u32,
    pub nonce: u64,
    pub sender: Address,
    pub l1_recipient: L1Address,
    pub amount: Amount,
    pub withdrawal_id: Hash256,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct WxpqLedger {
    chain_id: u32,
    balances: BTreeMap<Address, Amount>,
    consumed_deposits: BTreeSet<Hash256>,
    pending_withdrawals: BTreeMap<Hash256, WithdrawalIntent>,
    token_issuance_burns: BTreeMap<Hash256, Amount>,
    total_supply: Amount,
    total_finalized_l1_locked: Amount,
    total_pending_withdrawals: Amount,
    total_token_issuance_burned: Amount,
    next_withdrawal_nonce: u64,
}

impl WxpqLedger {
    pub fn new(chain_id: u32) -> Result<Self, WxpqError> {
        if chain_id == 0 {
            return Err(WxpqError::InvalidChainId);
        }
        Ok(Self {
            chain_id,
            balances: BTreeMap::new(),
            consumed_deposits: BTreeSet::new(),
            pending_withdrawals: BTreeMap::new(),
            token_issuance_burns: BTreeMap::new(),
            total_supply: Amount::ZERO,
            total_finalized_l1_locked: Amount::ZERO,
            total_pending_withdrawals: Amount::ZERO,
            total_token_issuance_burned: Amount::ZERO,
            next_withdrawal_nonce: 0,
        })
    }

    pub const fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub const fn total_supply(&self) -> Amount {
        self.total_supply
    }

    pub const fn total_finalized_l1_locked(&self) -> Amount {
        self.total_finalized_l1_locked
    }

    pub const fn total_pending_withdrawals(&self) -> Amount {
        self.total_pending_withdrawals
    }

    pub const fn total_token_issuance_burned(&self) -> Amount {
        self.total_token_issuance_burned
    }

    pub fn balance(&self, address: Address) -> Amount {
        self.balances.get(&address).copied().unwrap_or(Amount::ZERO)
    }

    pub fn pending_withdrawal(&self, id: Hash256) -> Option<&WithdrawalIntent> {
        self.pending_withdrawals.get(&id)
    }

    /// Commit balances, replay protection, pending withdrawals, backing, and
    /// supply accounting into one domain-separated SHA3-256 root.
    pub fn state_root(&self) -> Result<Hash256, WxpqError> {
        self.validate_invariants()?;
        canonical_hash(HashDomain::WxpqState, self)
    }

    /// Mint wXPQ only after the caller's L1 verifier has authenticated a
    /// finalized escrow deposit. Each deposit ID can be consumed once.
    pub fn mint_from_finalized_deposit(
        &mut self,
        deposit: VerifiedL1Deposit,
    ) -> Result<Hash256, WxpqError> {
        let claim = deposit.claim;
        if claim.sidechain_chain_id != self.chain_id {
            return Err(WxpqError::ChainIdMismatch);
        }
        if self.consumed_deposits.contains(&deposit.deposit_id) {
            return Err(WxpqError::DepositAlreadyConsumed);
        }

        let old_balance = self.balance(claim.recipient).0;
        let new_balance = old_balance
            .checked_add(claim.amount.0)
            .ok_or(WxpqError::AmountOverflow)?;
        let new_supply = self
            .total_supply
            .0
            .checked_add(claim.amount.0)
            .ok_or(WxpqError::AmountOverflow)?;
        let new_locked = self
            .total_finalized_l1_locked
            .0
            .checked_add(claim.amount.0)
            .ok_or(WxpqError::AmountOverflow)?;

        self.balances.insert(claim.recipient, Amount(new_balance));
        self.consumed_deposits.insert(deposit.deposit_id);
        self.total_supply = Amount(new_supply);
        self.total_finalized_l1_locked = Amount(new_locked);
        self.validate_invariants()?;
        Ok(deposit.deposit_id)
    }

    /// Apply a transfer only after transaction authorization has been checked
    /// by the sidechain execution layer.
    pub fn transfer_after_authorization(
        &mut self,
        sender: Address,
        recipient: Address,
        amount: Amount,
    ) -> Result<(), WxpqError> {
        validate_transfer_parties(sender, recipient, amount)?;
        let sender_balance = self.balance(sender).0;
        let new_sender = sender_balance
            .checked_sub(amount.0)
            .ok_or(WxpqError::InsufficientBalance)?;
        let new_recipient = self
            .balance(recipient)
            .0
            .checked_add(amount.0)
            .ok_or(WxpqError::AmountOverflow)?;

        set_balance(&mut self.balances, sender, Amount(new_sender));
        set_balance(&mut self.balances, recipient, Amount(new_recipient));
        self.validate_invariants()
    }

    /// Permanently burn wXPQ as the one-time backing cost for a user-created
    /// token issuance. The issuance commitment is consumed once.
    pub fn burn_for_token_issuance_after_authorization(
        &mut self,
        sender: Address,
        issuance_commitment: Hash256,
        amount: Amount,
    ) -> Result<(), WxpqError> {
        if sender == Address::ZERO || issuance_commitment == Hash256::ZERO || amount == Amount::ZERO
        {
            return Err(WxpqError::InvalidTokenIssuanceBurn);
        }
        if self.token_issuance_burns.contains_key(&issuance_commitment) {
            return Err(WxpqError::TokenIssuanceAlreadyBurned);
        }

        let new_balance = self
            .balance(sender)
            .0
            .checked_sub(amount.0)
            .ok_or(WxpqError::InsufficientBalance)?;
        let new_supply = self
            .total_supply
            .0
            .checked_sub(amount.0)
            .ok_or(WxpqError::InsufficientBalance)?;
        let new_token_burned = self
            .total_token_issuance_burned
            .0
            .checked_add(amount.0)
            .ok_or(WxpqError::AmountOverflow)?;

        set_balance(&mut self.balances, sender, Amount(new_balance));
        self.total_supply = Amount(new_supply);
        self.total_token_issuance_burned = Amount(new_token_burned);
        self.token_issuance_burns
            .insert(issuance_commitment, amount);
        self.validate_invariants()
    }

    /// Burn wXPQ and create a pending request. L1 XPQ must not be released
    /// until a separate L1 verifier authenticates this finalized burn.
    pub fn burn_for_l1_withdrawal_after_authorization(
        &mut self,
        sender: Address,
        l1_recipient: L1Address,
        amount: Amount,
    ) -> Result<WithdrawalIntent, WxpqError> {
        if sender == Address::ZERO || l1_recipient == L1Address::default() || amount == Amount::ZERO
        {
            return Err(WxpqError::InvalidWithdrawal);
        }
        let new_balance = self
            .balance(sender)
            .0
            .checked_sub(amount.0)
            .ok_or(WxpqError::InsufficientBalance)?;
        let new_supply = self
            .total_supply
            .0
            .checked_sub(amount.0)
            .ok_or(WxpqError::InsufficientBalance)?;
        let new_pending = self
            .total_pending_withdrawals
            .0
            .checked_add(amount.0)
            .ok_or(WxpqError::AmountOverflow)?;
        let nonce = self.next_withdrawal_nonce;
        let next_nonce = nonce.checked_add(1).ok_or(WxpqError::AmountOverflow)?;
        let withdrawal_id = withdrawal_id(self.chain_id, nonce, sender, l1_recipient, amount)?;
        if self.pending_withdrawals.contains_key(&withdrawal_id) {
            return Err(WxpqError::DuplicateWithdrawal);
        }
        let intent = WithdrawalIntent {
            version: WXPQ_VERSION,
            sidechain_chain_id: self.chain_id,
            nonce,
            sender,
            l1_recipient,
            amount,
            withdrawal_id,
        };

        set_balance(&mut self.balances, sender, Amount(new_balance));
        self.total_supply = Amount(new_supply);
        self.total_pending_withdrawals = Amount(new_pending);
        self.next_withdrawal_nonce = next_nonce;
        self.pending_withdrawals.insert(withdrawal_id, intent);
        self.validate_invariants()?;
        Ok(intent)
    }

    /// Validate the accounting invariant while L1 release confirmation is not
    /// yet implemented:
    ///
    /// `sum(balances) + pending withdrawals + token burns == L1 backing`.
    pub fn validate_invariants(&self) -> Result<(), WxpqError> {
        let balance_sum = self.balances.values().try_fold(0_u64, |sum, amount| {
            sum.checked_add(amount.0).ok_or(WxpqError::AmountOverflow)
        })?;
        if balance_sum != self.total_supply.0 {
            return Err(WxpqError::SupplyInvariantViolation);
        }
        let represented = self
            .total_supply
            .0
            .checked_add(self.total_pending_withdrawals.0)
            .and_then(|value| value.checked_add(self.total_token_issuance_burned.0))
            .ok_or(WxpqError::AmountOverflow)?;
        if represented != self.total_finalized_l1_locked.0
            || self.total_supply.0 > self.total_finalized_l1_locked.0
        {
            return Err(WxpqError::BackingInvariantViolation);
        }
        Ok(())
    }
}

fn validate_transfer_parties(
    sender: Address,
    recipient: Address,
    amount: Amount,
) -> Result<(), WxpqError> {
    if sender == Address::ZERO
        || recipient == Address::ZERO
        || sender == recipient
        || amount == Amount::ZERO
    {
        return Err(WxpqError::InvalidTransfer);
    }
    Ok(())
}

fn set_balance(balances: &mut BTreeMap<Address, Amount>, address: Address, amount: Amount) {
    if amount == Amount::ZERO {
        balances.remove(&address);
    } else {
        balances.insert(address, amount);
    }
}

fn withdrawal_id(
    chain_id: u32,
    nonce: u64,
    sender: Address,
    l1_recipient: L1Address,
    amount: Amount,
) -> Result<Hash256, WxpqError> {
    canonical_hash(
        HashDomain::WxpqWithdrawal,
        &(WXPQ_VERSION, chain_id, nonce, sender, l1_recipient, amount),
    )
}

fn canonical_hash<T: BorshSerialize>(domain: HashDomain, value: &T) -> Result<Hash256, WxpqError> {
    let bytes = borsh::to_vec(value).map_err(|error| WxpqError::Encoding(error.to_string()))?;
    Ok(domain_hash(domain, &bytes))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WxpqError {
    #[error("unsupported wXPQ format version")]
    UnsupportedVersion,
    #[error("sidechain chain ID must be nonzero")]
    InvalidChainId,
    #[error("L1 deposit claim is invalid")]
    InvalidDepositClaim,
    #[error("L1 deposit did not pass finalized escrow verification")]
    L1DepositNotVerified,
    #[error("deposit targets a different sidechain chain ID")]
    ChainIdMismatch,
    #[error("L1 deposit was already consumed")]
    DepositAlreadyConsumed,
    #[error("amount arithmetic overflow")]
    AmountOverflow,
    #[error("wXPQ balance is insufficient")]
    InsufficientBalance,
    #[error("wXPQ transfer is invalid")]
    InvalidTransfer,
    #[error("wXPQ withdrawal is invalid")]
    InvalidWithdrawal,
    #[error("wXPQ withdrawal ID already exists")]
    DuplicateWithdrawal,
    #[error("wXPQ token issuance burn is invalid")]
    InvalidTokenIssuanceBurn,
    #[error("wXPQ was already burned for this token issuance")]
    TokenIssuanceAlreadyBurned,
    #[error("wXPQ balance sum does not match total supply")]
    SupplyInvariantViolation,
    #[error("wXPQ represented value exceeds or mismatches finalized L1 backing")]
    BackingInvariantViolation,
    #[error("canonical encoding failed: {0}")]
    Encoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN_ID: u32 = 9_001;

    struct TestVerifier;

    impl FinalizedL1DepositVerifier<[u8; 1]> for TestVerifier {
        fn verify_finalized_deposit(&self, _claim: &L1DepositClaim, proof: &[u8; 1]) -> bool {
            proof == &[1]
        }
    }

    fn address(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn claim(recipient: Address, amount: u64) -> L1DepositClaim {
        L1DepositClaim {
            version: WXPQ_VERSION,
            l1_chain_id: 747,
            sidechain_chain_id: CHAIN_ID,
            l1_block_hash: Hash256([7; 32]),
            l1_block_height: 100,
            deposit_index: 0,
            recipient,
            amount: Amount(amount),
        }
    }

    #[test]
    fn unverified_deposit_cannot_cross_the_mint_boundary() {
        assert_eq!(
            verify_finalized_l1_deposit(claim(address(1), 10), &[0], &TestVerifier),
            Err(WxpqError::L1DepositNotVerified)
        );
    }

    #[test]
    fn finalized_deposit_mints_once_and_preserves_backing() {
        let mut ledger = WxpqLedger::new(CHAIN_ID).unwrap();
        let deposit =
            verify_finalized_l1_deposit(claim(address(1), 10), &[1], &TestVerifier).unwrap();
        ledger.mint_from_finalized_deposit(deposit).unwrap();

        assert_eq!(ledger.balance(address(1)), Amount(10));
        assert_eq!(ledger.total_supply(), Amount(10));
        assert_eq!(ledger.total_finalized_l1_locked(), Amount(10));
        assert_eq!(ledger.validate_invariants(), Ok(()));
        assert_eq!(
            ledger.mint_from_finalized_deposit(deposit),
            Err(WxpqError::DepositAlreadyConsumed)
        );
    }

    #[test]
    fn transfer_and_burn_never_create_unbacked_wxpq() {
        let mut ledger = WxpqLedger::new(CHAIN_ID).unwrap();
        let deposit =
            verify_finalized_l1_deposit(claim(address(1), 1_000), &[1], &TestVerifier).unwrap();
        ledger.mint_from_finalized_deposit(deposit).unwrap();
        let minted_root = ledger.state_root().unwrap();
        ledger
            .transfer_after_authorization(address(1), address(2), Amount(400))
            .unwrap();
        let transferred_root = ledger.state_root().unwrap();
        let intent = ledger
            .burn_for_l1_withdrawal_after_authorization(address(2), L1Address([9; 20]), Amount(250))
            .unwrap();
        let withdrawal_root = ledger.state_root().unwrap();

        assert_eq!(ledger.balance(address(1)), Amount(600));
        assert_eq!(ledger.balance(address(2)), Amount(150));
        assert_eq!(ledger.total_supply(), Amount(750));
        assert_eq!(ledger.total_pending_withdrawals(), Amount(250));
        assert_eq!(ledger.total_finalized_l1_locked(), Amount(1_000));
        assert_eq!(
            ledger.pending_withdrawal(intent.withdrawal_id),
            Some(&intent)
        );
        assert_eq!(ledger.validate_invariants(), Ok(()));
        assert_ne!(minted_root, transferred_root);
        assert_ne!(transferred_root, withdrawal_root);
    }

    #[test]
    fn failed_state_transitions_leave_accounting_unchanged() {
        let mut ledger = WxpqLedger::new(CHAIN_ID).unwrap();
        let deposit =
            verify_finalized_l1_deposit(claim(address(1), 100), &[1], &TestVerifier).unwrap();
        ledger.mint_from_finalized_deposit(deposit).unwrap();
        let before = ledger.clone();

        assert_eq!(
            ledger.transfer_after_authorization(address(1), address(2), Amount(101)),
            Err(WxpqError::InsufficientBalance)
        );
        assert_eq!(ledger, before);
    }
}
