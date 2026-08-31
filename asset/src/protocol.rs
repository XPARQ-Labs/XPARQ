use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::canonical_bytes;
use xparq_crypto::{Address, ProfilePublicKey, ProfileSignature, ProfileSigningSeed, address_from_profile_public_key, profile_verify};

use crate::AssetIdParseError;

pub const ASSET_NAME_MAX_LEN: usize = 64;
pub const ASSET_SYMBOL_MAX_LEN: usize = 16;
const ASSET_CALL_COMMITMENT_CONTEXT: &str = "XPARQ Native Asset Call v1";

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssetId([u8; 32]);

impl AssetId {
    pub fn derive(authority: Address, symbol: &str) -> Self {
        Self(crate::identifier::derive(&[&authority.0, symbol.as_bytes()]))
    }
    pub const fn from_bytes(bytes: [u8; 32]) -> Self { Self(bytes) }
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

impl fmt::Display for AssetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::identifier::fmt(&self.0, formatter)
    }
}

impl FromStr for AssetId {
    type Err = AssetIdParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> { crate::identifier::parse(value).map(Self) }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub max_supply: u128,
    pub mint_authority: Address,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum AssetAction {
    Register { name: String, symbol: String, decimals: u8, max_supply: u128, initial_mint: u128 },
    Mint { asset_id: AssetId, recipient: Address, amount: u128 },
    Burn { asset_id: AssetId, amount: u128 },
    Transfer { asset_id: AssetId, recipient: Address, amount: u128 },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetCall {
    pub action: AssetAction,
    pub signer: Address,
    pub nonce: u64,
    pub public_key: ProfilePublicKey,
    pub signature: ProfileSignature,
}

#[derive(BorshSerialize)]
struct UnsignedAssetCall<'a> { chain_id: [u8; 32], action: &'a AssetAction, signer: Address, nonce: u64 }

impl AssetCall {
    pub fn asset_id(&self) -> AssetId {
        match &self.action {
            AssetAction::Register { symbol, .. } => AssetId::derive(self.signer, symbol),
            AssetAction::Mint { asset_id, .. } | AssetAction::Burn { asset_id, .. } | AssetAction::Transfer { asset_id, .. } => *asset_id,
        }
    }

    pub fn sign(chain_id: [u8; 32], action: AssetAction, nonce: u64, signing_seed: &ProfileSigningSeed) -> Result<Self, AssetError> {
        let public_key = signing_seed.public_key();
        let signer = address_from_profile_public_key(&public_key);
        let signature = signing_seed.sign(&call_commitment(chain_id, &action, signer, nonce)?);
        Ok(Self { action, signer, nonce, public_key, signature })
    }

    pub fn validate(&self, chain_id: [u8; 32], state: &AssetState) -> Result<(), AssetError> {
        validate_authorization(chain_id, self)?;
        state.validate_transition(self)
    }

    pub fn created_state_weight(&self, state: &AssetState) -> Result<u64, AssetError> {
        let recipient_exists = match &self.action {
            AssetAction::Mint { asset_id, recipient, .. } | AssetAction::Transfer { asset_id, recipient, .. } => state.balances.contains_key(&(*asset_id, *recipient)),
            _ => false,
        };
        self.created_state_weight_from_presence(state.nonces.contains_key(&self.signer), recipient_exists)
    }

    pub fn created_state_weight_from_presence(&self, nonce_exists: bool, recipient_balance_exists: bool) -> Result<u64, AssetError> {
        let mut weight = 0;
        if !nonce_exists { weight = checked_entry_weight(weight, 1 + xparq_crypto::ADDRESS_SIZE, &0_u64)?; }
        match &self.action {
            AssetAction::Register { name, symbol, decimals, max_supply, initial_mint } => {
                let metadata = AssetMetadata { name: name.clone(), symbol: symbol.clone(), decimals: *decimals, max_supply: *max_supply, mint_authority: self.signer };
                weight = checked_entry_weight(weight, 33, &metadata)?;
                weight = checked_entry_weight(weight, 33, initial_mint)?;
                weight = checked_entry_weight(weight, 33 + xparq_crypto::ADDRESS_SIZE, initial_mint)?;
            }
            AssetAction::Mint { amount, .. } | AssetAction::Transfer { amount, .. } if !recipient_balance_exists => {
                weight = checked_entry_weight(weight, 33 + xparq_crypto::ADDRESS_SIZE, amount)?;
            }
            _ => {}
        }
        Ok(weight)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetState {
    metadata: BTreeMap<AssetId, AssetMetadata>,
    supplies: BTreeMap<AssetId, u128>,
    balances: BTreeMap<(AssetId, Address), u128>,
    nonces: BTreeMap<Address, u64>,
}

impl AssetState {
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty() && self.supplies.is_empty() && self.balances.is_empty() && self.nonces.is_empty()
    }

    pub fn state_root(&self) -> Result<[u8; 32], AssetError> {
        let bytes = canonical_bytes(self).map_err(|_| AssetError::Encoding)?;
        Ok(blake3::derive_key("xparq:native-asset-state:v1", &bytes))
    }

    pub fn metadata(&self, id: AssetId) -> Option<&AssetMetadata> { self.metadata.get(&id) }
    pub fn supply(&self, id: AssetId) -> u128 { self.supplies.get(&id).copied().unwrap_or(0) }
    pub fn balance(&self, id: AssetId, owner: Address) -> u128 { self.balances.get(&(id, owner)).copied().unwrap_or(0) }
    pub fn nonce(&self, owner: Address) -> u64 { self.nonces.get(&owner).copied().unwrap_or(0) }
    pub fn balances(&self) -> impl Iterator<Item = (AssetId, Address, u128)> + '_ { self.balances.iter().map(|(&(id, owner), &amount)| (id, owner, amount)) }
    pub fn metadata_entries(&self) -> impl Iterator<Item = (AssetId, &AssetMetadata)> + '_ { self.metadata.iter().map(|(&id, metadata)| (id, metadata)) }

    pub fn apply(&mut self, chain_id: [u8; 32], call: &AssetCall) -> Result<AssetRollbackJournal, AssetError> {
        call.validate(chain_id, self)?;
        let mut journal = AssetRollbackJournal::default();
        journal.nonces.push((call.signer, self.nonces.get(&call.signer).copied()));
        match &call.action {
            AssetAction::Register { name, symbol, decimals, max_supply, initial_mint } => {
                let id = AssetId::derive(call.signer, symbol);
                journal.metadata.push((id, self.metadata.get(&id).cloned()));
                journal.supplies.push((id, self.supplies.get(&id).copied()));
                journal.balances.push(((id, call.signer), self.balances.get(&(id, call.signer)).copied()));
                self.metadata.insert(id, AssetMetadata { name: name.clone(), symbol: symbol.clone(), decimals: *decimals, max_supply: *max_supply, mint_authority: call.signer });
                self.supplies.insert(id, *initial_mint);
                self.balances.insert((id, call.signer), *initial_mint);
            }
            AssetAction::Mint { asset_id, recipient, amount } => {
                journal.supplies.push((*asset_id, self.supplies.get(asset_id).copied()));
                journal.balances.push(((*asset_id, *recipient), self.balances.get(&(*asset_id, *recipient)).copied()));
                self.supplies.insert(*asset_id, self.supply(*asset_id) + amount);
                self.balances.insert((*asset_id, *recipient), self.balance(*asset_id, *recipient) + amount);
            }
            AssetAction::Burn { asset_id, amount } => {
                journal.supplies.push((*asset_id, self.supplies.get(asset_id).copied()));
                journal.balances.push(((*asset_id, call.signer), self.balances.get(&(*asset_id, call.signer)).copied()));
                self.supplies.insert(*asset_id, self.supply(*asset_id) - amount);
                let balance = self.balance(*asset_id, call.signer) - amount;
                set_balance(&mut self.balances, (*asset_id, call.signer), balance);
            }
            AssetAction::Transfer { asset_id, recipient, amount } => {
                for owner in [call.signer, *recipient] { journal.balances.push(((*asset_id, owner), self.balances.get(&(*asset_id, owner)).copied())); }
                let sender = self.balance(*asset_id, call.signer) - amount;
                let recipient_balance = self.balance(*asset_id, *recipient) + amount;
                set_balance(&mut self.balances, (*asset_id, call.signer), sender);
                self.balances.insert((*asset_id, *recipient), recipient_balance);
            }
        }
        self.nonces.insert(call.signer, call.nonce + 1);
        Ok(journal)
    }

    pub fn rollback(&mut self, journal: AssetRollbackJournal) {
        restore_map(&mut self.metadata, journal.metadata);
        restore_map(&mut self.supplies, journal.supplies);
        restore_map(&mut self.balances, journal.balances);
        restore_map(&mut self.nonces, journal.nonces);
    }

    fn validate_transition(&self, call: &AssetCall) -> Result<(), AssetError> {
        if call.nonce != self.nonce(call.signer) { return Err(AssetError::InvalidNonce); }
        match &call.action {
            AssetAction::Register { name, symbol, decimals, max_supply, initial_mint } => {
                validate_name(name)?; validate_symbol(symbol)?;
                if *decimals > 18 || *max_supply == 0 || *initial_mint == 0 || initial_mint > max_supply { return Err(AssetError::InvalidAction); }
                if self.metadata(AssetId::derive(call.signer, symbol)).is_some() { return Err(AssetError::AssetAlreadyExists); }
            }
            AssetAction::Mint { asset_id, amount, .. } => {
                ensure_nonzero(*amount)?;
                let metadata = self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;
                if metadata.mint_authority != call.signer { return Err(AssetError::Unauthorized); }
                if self.supply(*asset_id).checked_add(*amount).is_none_or(|supply| supply > metadata.max_supply) { return Err(AssetError::SupplyOverflow); }
            }
            AssetAction::Burn { asset_id, amount } => {
                ensure_nonzero(*amount)?; self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;
                if self.balance(*asset_id, call.signer) < *amount { return Err(AssetError::InsufficientBalance); }
            }
            AssetAction::Transfer { asset_id, recipient, amount } => {
                ensure_nonzero(*amount)?; self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;
                if *recipient == call.signer { return Err(AssetError::InvalidAction); }
                if self.balance(*asset_id, call.signer) < *amount { return Err(AssetError::InsufficientBalance); }
                self.balance(*asset_id, *recipient).checked_add(*amount).ok_or(AssetError::BalanceOverflow)?;
            }
        }
        call.nonce.checked_add(1).ok_or(AssetError::InvalidNonce)?;
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetRollbackJournal {
    metadata: Vec<(AssetId, Option<AssetMetadata>)>, supplies: Vec<(AssetId, Option<u128>)>,
    balances: Vec<((AssetId, Address), Option<u128>)>, nonces: Vec<(Address, Option<u64>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetError { Encoding, InvalidAuthorization, InvalidNonce, InvalidAction, AssetAlreadyExists, UnknownAsset, Unauthorized, SupplyOverflow, BalanceOverflow, InsufficientBalance }
impl fmt::Display for AssetError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "native asset operation failed: {self:?}") } }
impl Error for AssetError {}

fn validate_authorization(chain_id: [u8; 32], call: &AssetCall) -> Result<(), AssetError> {
    if address_from_profile_public_key(&call.public_key) != call.signer || call.public_key.profile != call.signature.profile { return Err(AssetError::InvalidAuthorization); }
    if !profile_verify(&call.public_key, &call_commitment(chain_id, &call.action, call.signer, call.nonce)?, &call.signature) { return Err(AssetError::InvalidAuthorization); }
    Ok(())
}
fn call_commitment(chain_id: [u8; 32], action: &AssetAction, signer: Address, nonce: u64) -> Result<[u8; 32], AssetError> {
    let bytes = canonical_bytes(&UnsignedAssetCall { chain_id, action, signer, nonce }).map_err(|_| AssetError::Encoding)?;
    Ok(blake3::derive_key(ASSET_CALL_COMMITMENT_CONTEXT, &bytes))
}
fn validate_symbol(value: &str) -> Result<(), AssetError> { if value.is_empty() || value.len() > ASSET_SYMBOL_MAX_LEN || !value.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) { Err(AssetError::InvalidAction) } else { Ok(()) } }
fn validate_name(value: &str) -> Result<(), AssetError> { if value.is_empty() || value.len() > ASSET_NAME_MAX_LEN || value.trim() != value || !value.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) { Err(AssetError::InvalidAction) } else { Ok(()) } }
fn ensure_nonzero(value: u128) -> Result<(), AssetError> { if value == 0 { Err(AssetError::InvalidAction) } else { Ok(()) } }
fn checked_entry_weight<T: BorshSerialize>(current: u64, key_len: usize, value: &T) -> Result<u64, AssetError> { let value_len = canonical_bytes(value).map_err(|_| AssetError::Encoding)?.len(); let entry = u64::try_from(key_len.checked_add(value_len).ok_or(AssetError::Encoding)?).map_err(|_| AssetError::Encoding)?; current.checked_add(entry).ok_or(AssetError::Encoding) }
fn set_balance(map: &mut BTreeMap<(AssetId, Address), u128>, key: (AssetId, Address), value: u128) { if value == 0 { map.remove(&key); } else { map.insert(key, value); } }
fn restore_map<K: Ord, V>(map: &mut BTreeMap<K, V>, entries: Vec<(K, Option<V>)>) { for (key, previous) in entries.into_iter().rev() { if let Some(value) = previous { map.insert(key, value); } else { map.remove(&key); } } }

#[cfg(test)]
mod tests {
    use super::*;
    use xparq_crypto::SignatureProfile;
    #[test]
    fn register_transfer_and_rollback_are_atomic() {
        let seed = ProfileSigningSeed::new(SignatureProfile::MlDsa44, [7; 32]);
        let recipient = Address([9; xparq_crypto::ADDRESS_SIZE]);
        let register = AssetCall::sign([3; 32], AssetAction::Register { name: "Gold".into(), symbol: "GOLD".into(), decimals: 2, max_supply: 1_000, initial_mint: 100 }, 0, &seed).unwrap();
        let id = register.asset_id(); let mut state = AssetState::default(); state.apply([3; 32], &register).unwrap();
        let transfer = AssetCall::sign([3; 32], AssetAction::Transfer { asset_id: id, recipient, amount: 25 }, 1, &seed).unwrap();
        let journal = state.apply([3; 32], &transfer).unwrap(); assert_eq!(state.balance(id, recipient), 25);
        state.rollback(journal); assert_eq!(state.balance(id, recipient), 0); assert_eq!(state.balance(id, register.signer), 100); assert_eq!(state.nonce(register.signer), 1);
    }
}
