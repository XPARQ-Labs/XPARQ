//! Fixed-supply, user-created tokens for the experimental XPARQ sidechain.
//!
//! Creating a token permanently burns whole wXPQ and issues its complete supply
//! to the creator. The initial fixed rate is one wXPQ for 100,000,000
//! indivisible token units. No post-creation mint path exists in this crate.

use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;
use thiserror::Error;
use xparq_sidechain_primitives::{Address, Hash256, HashDomain, PROTOCOL_VERSION, domain_hash};
use xparq_sidechain_wxpq::{Amount as WxpqAmount, PAQS_PER_WXPQ, WxpqError, WxpqLedger};

pub const TOKEN_VERSION: u8 = 1;
pub const TOKEN_DECIMALS: u8 = 0;
pub const TOKEN_UNITS_PER_BURNED_WXPQ: u64 = 100_000_000;
pub const MAX_TOKEN_NAME_BYTES: usize = 64;
pub const MAX_TOKEN_SYMBOL_BYTES: usize = 12;
pub const MIN_TOKEN_SYMBOL_BYTES: usize = 2;

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
pub struct TokenAmount(pub u64);

impl TokenAmount {
    pub const ZERO: Self = Self(0);
}

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
pub struct TokenId(pub Hash256);

/// The permanent one-to-one receipt joining one wXPQ burn to one token's only
/// supply issuance.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenIssuanceEvent {
    pub version: u8,
    pub token_id: TokenId,
    pub wxpq_burn_commitment: Hash256,
    pub creator: Address,
    pub wxpq_burned: WxpqAmount,
    pub issued_supply: TokenAmount,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenMetadata {
    pub name: String,
    pub symbol: String,
}

impl TokenMetadata {
    pub fn new(name: impl Into<String>, symbol: impl Into<String>) -> Result<Self, TokenError> {
        let metadata = Self {
            name: name.into(),
            symbol: symbol.into(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn validate(&self) -> Result<(), TokenError> {
        let name = self.name.as_bytes();
        if name.is_empty()
            || name.len() > MAX_TOKEN_NAME_BYTES
            || self.name.trim() != self.name
            || self.name.chars().any(char::is_control)
        {
            return Err(TokenError::InvalidName);
        }

        let symbol = self.symbol.as_bytes();
        if symbol.len() < MIN_TOKEN_SYMBOL_BYTES
            || symbol.len() > MAX_TOKEN_SYMBOL_BYTES
            || !symbol
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            || !symbol[0].is_ascii_uppercase()
        {
            return Err(TokenError::InvalidSymbol);
        }
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenState {
    id: TokenId,
    creator: Address,
    metadata: TokenMetadata,
    wxpq_burned: WxpqAmount,
    total_supply: TokenAmount,
    balances: BTreeMap<Address, TokenAmount>,
}

impl TokenState {
    pub const fn id(&self) -> TokenId {
        self.id
    }

    pub const fn creator(&self) -> Address {
        self.creator
    }

    pub const fn metadata(&self) -> &TokenMetadata {
        &self.metadata
    }

    pub const fn wxpq_burned(&self) -> WxpqAmount {
        self.wxpq_burned
    }

    pub const fn total_supply(&self) -> TokenAmount {
        self.total_supply
    }

    pub fn balance(&self, address: Address) -> TokenAmount {
        self.balances
            .get(&address)
            .copied()
            .unwrap_or(TokenAmount::ZERO)
    }

    fn validate(&self) -> Result<(), TokenError> {
        if self.id == TokenId::default()
            || self.creator == Address::ZERO
            || self.wxpq_burned == WxpqAmount::ZERO
            || self.total_supply == TokenAmount::ZERO
        {
            return Err(TokenError::TokenInvariantViolation);
        }
        self.metadata.validate()?;
        let balance_sum = self.balances.values().try_fold(0_u64, |sum, balance| {
            sum.checked_add(balance.0).ok_or(TokenError::AmountOverflow)
        })?;
        if balance_sum != self.total_supply.0 {
            return Err(TokenError::TokenInvariantViolation);
        }
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenRegistry {
    chain_id: u32,
    tokens: BTreeMap<TokenId, TokenState>,
    issuance_events: BTreeMap<TokenId, TokenIssuanceEvent>,
    creator_nonces: BTreeMap<Address, u64>,
}

impl TokenRegistry {
    pub fn new(chain_id: u32) -> Result<Self, TokenError> {
        if chain_id == 0 {
            return Err(TokenError::InvalidChainId);
        }
        Ok(Self {
            chain_id,
            tokens: BTreeMap::new(),
            issuance_events: BTreeMap::new(),
            creator_nonces: BTreeMap::new(),
        })
    }

    pub const fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn token(&self, id: TokenId) -> Option<&TokenState> {
        self.tokens.get(&id)
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    pub fn issuance_event(&self, id: TokenId) -> Option<&TokenIssuanceEvent> {
        self.issuance_events.get(&id)
    }

    /// Atomically burn wXPQ and create one immutable-supply user token.
    ///
    /// Burn amount must be a positive whole-wXPQ multiple. The complete token
    /// supply is credited to `creator` and no later mint function is exposed.
    pub fn create_token_after_authorization(
        &mut self,
        wxpq: &mut WxpqLedger,
        creator: Address,
        metadata: TokenMetadata,
        burn_amount: WxpqAmount,
    ) -> Result<TokenIssuanceEvent, TokenError> {
        if wxpq.chain_id() != self.chain_id {
            return Err(TokenError::ChainIdMismatch);
        }
        if creator == Address::ZERO {
            return Err(TokenError::InvalidCreator);
        }
        metadata.validate()?;
        let issued_supply = issued_supply_for_burn(burn_amount)?;
        let nonce = self.creator_nonces.get(&creator).copied().unwrap_or(0);
        let next_nonce = nonce.checked_add(1).ok_or(TokenError::AmountOverflow)?;
        let token_id = derive_token_id(self.chain_id, creator, nonce, &metadata, burn_amount)?;
        if self.tokens.contains_key(&token_id) {
            return Err(TokenError::DuplicateToken);
        }

        // Apply the cross-ledger transition to clones first. Either both state
        // objects commit, or neither caller-visible object changes.
        let mut next_wxpq = wxpq.clone();
        next_wxpq.burn_for_token_issuance_after_authorization(creator, token_id.0, burn_amount)?;

        let mut balances = BTreeMap::new();
        balances.insert(creator, issued_supply);
        let state = TokenState {
            id: token_id,
            creator,
            metadata,
            wxpq_burned: burn_amount,
            total_supply: issued_supply,
            balances,
        };
        state.validate()?;
        let event = TokenIssuanceEvent {
            version: TOKEN_VERSION,
            token_id,
            wxpq_burn_commitment: token_id.0,
            creator,
            wxpq_burned: burn_amount,
            issued_supply,
        };

        let mut next_registry = self.clone();
        next_registry.tokens.insert(token_id, state);
        next_registry.issuance_events.insert(token_id, event);
        next_registry.creator_nonces.insert(creator, next_nonce);
        next_registry.validate_invariants()?;

        *wxpq = next_wxpq;
        *self = next_registry;
        Ok(event)
    }

    /// Move fixed-supply token units after the execution layer has verified
    /// the sender's transaction authorization.
    pub fn transfer_after_authorization(
        &mut self,
        token_id: TokenId,
        sender: Address,
        recipient: Address,
        amount: TokenAmount,
    ) -> Result<(), TokenError> {
        if sender == Address::ZERO
            || recipient == Address::ZERO
            || sender == recipient
            || amount == TokenAmount::ZERO
        {
            return Err(TokenError::InvalidTransfer);
        }

        let mut next = self.clone();
        let token = next
            .tokens
            .get_mut(&token_id)
            .ok_or(TokenError::UnknownToken)?;
        let sender_balance = token.balance(sender).0;
        let new_sender = sender_balance
            .checked_sub(amount.0)
            .ok_or(TokenError::InsufficientBalance)?;
        let new_recipient = token
            .balance(recipient)
            .0
            .checked_add(amount.0)
            .ok_or(TokenError::AmountOverflow)?;
        set_balance(&mut token.balances, sender, TokenAmount(new_sender));
        set_balance(&mut token.balances, recipient, TokenAmount(new_recipient));
        next.validate_invariants()?;
        *self = next;
        Ok(())
    }

    pub fn state_root(&self) -> Result<Hash256, TokenError> {
        self.validate_invariants()?;
        canonical_hash(HashDomain::UserTokenState, self)
    }

    pub fn validate_invariants(&self) -> Result<(), TokenError> {
        if TOKEN_VERSION != PROTOCOL_VERSION {
            return Err(TokenError::UnsupportedVersion);
        }
        if self.chain_id == 0 {
            return Err(TokenError::InvalidChainId);
        }
        if self.tokens.len() != self.issuance_events.len() {
            return Err(TokenError::TokenInvariantViolation);
        }
        for (id, token) in &self.tokens {
            if *id != token.id {
                return Err(TokenError::TokenInvariantViolation);
            }
            token.validate()?;
            let event = self
                .issuance_events
                .get(id)
                .ok_or(TokenError::TokenInvariantViolation)?;
            if event.version != TOKEN_VERSION
                || event.token_id != *id
                || event.wxpq_burn_commitment != id.0
                || event.creator != token.creator
                || event.wxpq_burned != token.wxpq_burned
                || event.issued_supply != token.total_supply
            {
                return Err(TokenError::TokenInvariantViolation);
            }
        }
        Ok(())
    }
}

pub fn issued_supply_for_burn(burn_amount: WxpqAmount) -> Result<TokenAmount, TokenError> {
    if burn_amount.0 < PAQS_PER_WXPQ || !burn_amount.0.is_multiple_of(PAQS_PER_WXPQ) {
        return Err(TokenError::BurnMustBeWholeWxpq);
    }
    let whole_wxpq = burn_amount.0 / PAQS_PER_WXPQ;
    whole_wxpq
        .checked_mul(TOKEN_UNITS_PER_BURNED_WXPQ)
        .map(TokenAmount)
        .ok_or(TokenError::AmountOverflow)
}

fn derive_token_id(
    chain_id: u32,
    creator: Address,
    creator_nonce: u64,
    metadata: &TokenMetadata,
    burn_amount: WxpqAmount,
) -> Result<TokenId, TokenError> {
    canonical_hash(
        HashDomain::UserToken,
        &(
            TOKEN_VERSION,
            chain_id,
            creator,
            creator_nonce,
            metadata,
            burn_amount,
        ),
    )
    .map(TokenId)
}

fn canonical_hash<T: BorshSerialize>(domain: HashDomain, value: &T) -> Result<Hash256, TokenError> {
    let bytes = borsh::to_vec(value).map_err(|error| TokenError::Encoding(error.to_string()))?;
    Ok(domain_hash(domain, &bytes))
}

fn set_balance(
    balances: &mut BTreeMap<Address, TokenAmount>,
    address: Address,
    amount: TokenAmount,
) {
    if amount == TokenAmount::ZERO {
        balances.remove(&address);
    } else {
        balances.insert(address, amount);
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("unsupported user-token format version")]
    UnsupportedVersion,
    #[error("sidechain chain ID must be nonzero")]
    InvalidChainId,
    #[error("wXPQ ledger belongs to another sidechain")]
    ChainIdMismatch,
    #[error("token creator address is invalid")]
    InvalidCreator,
    #[error("token name is invalid")]
    InvalidName,
    #[error("token symbol must contain 2-12 uppercase ASCII letters or digits")]
    InvalidSymbol,
    #[error("token creation burn must be a positive whole-wXPQ multiple")]
    BurnMustBeWholeWxpq,
    #[error("token amount arithmetic overflow")]
    AmountOverflow,
    #[error("derived token identifier already exists")]
    DuplicateToken,
    #[error("token does not exist")]
    UnknownToken,
    #[error("token balance is insufficient")]
    InsufficientBalance,
    #[error("token transfer is invalid")]
    InvalidTransfer,
    #[error("token state invariant is violated")]
    TokenInvariantViolation,
    #[error("canonical encoding failed: {0}")]
    Encoding(String),
    #[error(transparent)]
    Wxpq(#[from] WxpqError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use xparq_sidechain_wxpq::{
        FinalizedL1DepositVerifier, L1DepositClaim, WXPQ_VERSION, verify_finalized_l1_deposit,
    };

    const CHAIN_ID: u32 = 9_001;

    struct TestVerifier;

    impl FinalizedL1DepositVerifier<()> for TestVerifier {
        fn verify_finalized_deposit(&self, _claim: &L1DepositClaim, _proof: &()) -> bool {
            true
        }
    }

    fn address(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn funded_wxpq(amount: u64) -> WxpqLedger {
        let mut ledger = WxpqLedger::new(CHAIN_ID).unwrap();
        let claim = L1DepositClaim {
            version: WXPQ_VERSION,
            l1_chain_id: 747,
            sidechain_chain_id: CHAIN_ID,
            l1_block_hash: Hash256([7; 32]),
            l1_block_height: 100,
            deposit_index: 0,
            recipient: address(1),
            amount: WxpqAmount(amount),
        };
        let deposit = verify_finalized_l1_deposit(claim, &(), &TestVerifier).unwrap();
        ledger.mint_from_finalized_deposit(deposit).unwrap();
        ledger
    }

    fn metadata() -> TokenMetadata {
        TokenMetadata::new("Example Token", "EXM").unwrap()
    }

    #[test]
    fn one_wxpq_burn_creates_one_hundred_million_fixed_units() {
        let mut wxpq = funded_wxpq(PAQS_PER_WXPQ);
        let mut registry = TokenRegistry::new(CHAIN_ID).unwrap();
        let issuance = registry
            .create_token_after_authorization(
                &mut wxpq,
                address(1),
                metadata(),
                WxpqAmount(PAQS_PER_WXPQ),
            )
            .unwrap();
        let token_id = issuance.token_id;
        let token = registry.token(token_id).unwrap();

        assert_eq!(TOKEN_DECIMALS, 0);
        assert_eq!(token.total_supply(), TokenAmount(100_000_000));
        assert_eq!(token.balance(address(1)), TokenAmount(100_000_000));
        assert_eq!(token.wxpq_burned(), WxpqAmount(PAQS_PER_WXPQ));
        assert_eq!(issuance.wxpq_burn_commitment, token_id.0);
        assert_eq!(registry.issuance_event(token_id), Some(&issuance));
        assert_eq!(wxpq.total_supply(), WxpqAmount::ZERO);
        assert_eq!(
            wxpq.total_token_issuance_burned(),
            WxpqAmount(PAQS_PER_WXPQ)
        );
        assert_eq!(wxpq.validate_invariants(), Ok(()));
        assert_eq!(registry.validate_invariants(), Ok(()));
    }

    #[test]
    fn token_creation_is_atomic_when_burn_is_invalid() {
        let mut wxpq = funded_wxpq(PAQS_PER_WXPQ);
        let mut registry = TokenRegistry::new(CHAIN_ID).unwrap();
        let wxpq_before = wxpq.clone();
        let registry_before = registry.clone();

        assert_eq!(
            registry.create_token_after_authorization(
                &mut wxpq,
                address(1),
                metadata(),
                WxpqAmount(PAQS_PER_WXPQ / 2),
            ),
            Err(TokenError::BurnMustBeWholeWxpq)
        );
        assert_eq!(wxpq, wxpq_before);
        assert_eq!(registry, registry_before);
    }

    #[test]
    fn created_tokens_can_transfer_without_changing_supply() {
        let mut wxpq = funded_wxpq(PAQS_PER_WXPQ);
        let mut registry = TokenRegistry::new(CHAIN_ID).unwrap();
        let token_id = registry
            .create_token_after_authorization(
                &mut wxpq,
                address(1),
                metadata(),
                WxpqAmount(PAQS_PER_WXPQ),
            )
            .unwrap()
            .token_id;
        let before_root = registry.state_root().unwrap();

        registry
            .transfer_after_authorization(token_id, address(1), address(2), TokenAmount(40_000_000))
            .unwrap();
        let token = registry.token(token_id).unwrap();

        assert_eq!(token.balance(address(1)), TokenAmount(60_000_000));
        assert_eq!(token.balance(address(2)), TokenAmount(40_000_000));
        assert_eq!(token.total_supply(), TokenAmount(100_000_000));
        assert_ne!(before_root, registry.state_root().unwrap());
    }

    #[test]
    fn metadata_is_bounded_and_canonical() {
        assert_eq!(
            TokenMetadata::new("Example", "bad"),
            Err(TokenError::InvalidSymbol)
        );
        assert_eq!(
            TokenMetadata::new(" Example", "EXM"),
            Err(TokenError::InvalidName)
        );
    }

    #[test]
    fn one_burn_commitment_cannot_issue_the_same_token_twice() {
        let mut wxpq = funded_wxpq(PAQS_PER_WXPQ * 2);
        let mut registry = TokenRegistry::new(CHAIN_ID).unwrap();
        let issuance = registry
            .create_token_after_authorization(
                &mut wxpq,
                address(1),
                metadata(),
                WxpqAmount(PAQS_PER_WXPQ),
            )
            .unwrap();
        let token_supply = registry.token(issuance.token_id).unwrap().total_supply();
        let wxpq_before = wxpq.clone();

        assert_eq!(
            wxpq.burn_for_token_issuance_after_authorization(
                address(1),
                issuance.wxpq_burn_commitment,
                WxpqAmount(PAQS_PER_WXPQ),
            ),
            Err(WxpqError::TokenIssuanceAlreadyBurned)
        );
        assert_eq!(wxpq, wxpq_before);
        assert_eq!(
            registry.token(issuance.token_id).unwrap().total_supply(),
            token_supply
        );
        assert_eq!(registry.token_count(), 1);
    }
}
