use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::{ExtensionHash, canonical_bytes};
use xparq_crypto::Address;

use crate::AssetHashParseError;

pub const ASSET_NAME_MAX_LEN: usize = 64;
pub const ASSET_SYMBOL_MAX_LEN: usize = 16;
const ASSET_PROGRAM_COMMITMENT_CONTEXT: &str = "XPARQ Native Asset Call";

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct AssetHash([u8; 32]);

impl AssetHash {
    pub fn derive(authority: Address, symbol: &str) -> Self {
        Self(crate::identifier::derive(&[
            &authority.0,
            symbol.as_bytes(),
        ]))
    }
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AssetHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::identifier::fmt(&self.0, formatter)
    }
}

impl FromStr for AssetHash {
    type Err = AssetHashParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        crate::identifier::parse(value).map(Self)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetMetadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub max_supply: u128,
    pub creator: Address,
    pub mint_authority: Option<AssetAuthority>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetAuthority {
    Account(Address),
    Program(ExtensionHash),
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum AssetInstruction {
    Register {
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: u128,
        initial_mint: u128,
        mint_authority: Option<AssetAuthority>,
    },
    Mint {
        asset_id: AssetHash,
        recipient: Address,
        amount: u128,
    },
    Burn {
        asset_id: AssetHash,
        amount: u128,
    },
    Transfer {
        asset_id: AssetHash,
        recipient: Address,
        amount: u128,
    },
    TransferToExtension {
        asset_id: AssetHash,
        extension: ExtensionHash,
        amount: u128,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetCall {
    pub instruction: AssetInstruction,
    pub signer: Address,
    pub nonce: u64,
}

#[derive(BorshSerialize)]
struct UnsignedAssetCall<'a> {
    genesis_hash: [u8; 32],
    instruction: &'a AssetInstruction,
    signer: Address,
    nonce: u64,
}

impl AssetCall {
    pub fn asset_id(&self) -> AssetHash {
        match &self.instruction {
            AssetInstruction::Register { symbol, .. } => AssetHash::derive(self.signer, symbol),
            AssetInstruction::Mint { asset_id, .. }
            | AssetInstruction::Burn { asset_id, .. }
            | AssetInstruction::Transfer { asset_id, .. }
            | AssetInstruction::TransferToExtension { asset_id, .. } => *asset_id,
        }
    }

    pub const fn new(instruction: AssetInstruction, signer: Address, nonce: u64) -> Self {
        Self {
            instruction,
            signer,
            nonce,
        }
    }

    pub fn commitment(&self, genesis_hash: [u8; 32]) -> Result<[u8; 32], AssetError> {
        call_commitment(genesis_hash, &self.instruction, self.signer, self.nonce)
    }

    pub fn validate(&self, state: &AssetState) -> Result<(), AssetError> {
        self.validate_structure()?;
        state.validate_transition(self)
    }

    pub fn validate_structure(&self) -> Result<(), AssetError> {
        match &self.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority: _,
            } => {
                validate_name(name)?;
                validate_symbol(symbol)?;
                if *decimals > 18
                    || *max_supply == 0
                    || *initial_mint == 0
                    || initial_mint > max_supply
                {
                    return Err(AssetError::InvalidProgram);
                }
            }
            AssetInstruction::Mint { amount, .. } | AssetInstruction::Burn { amount, .. } => {
                ensure_nonzero(*amount)?;
            }
            AssetInstruction::Transfer {
                recipient, amount, ..
            } => {
                ensure_nonzero(*amount)?;
                if *recipient == self.signer {
                    return Err(AssetError::InvalidProgram);
                }
            }
            AssetInstruction::TransferToExtension { amount, .. } => ensure_nonzero(*amount)?,
        }
        self.nonce.checked_add(1).ok_or(AssetError::InvalidNonce)?;
        Ok(())
    }

    pub fn created_state_weight(&self, state: &AssetState) -> Result<u64, AssetError> {
        let recipient_exists = match &self.instruction {
            AssetInstruction::Mint {
                asset_id,
                recipient,
                ..
            }
            | AssetInstruction::Transfer {
                asset_id,
                recipient,
                ..
            } => state.balances.contains_key(&(*asset_id, *recipient)),
            AssetInstruction::TransferToExtension {
                asset_id,
                extension,
                ..
            } => state
                .extension_balances
                .contains_key(&(*asset_id, *extension)),
            _ => false,
        };
        self.created_state_weight_from_presence(
            state.nonces.contains_key(&self.signer),
            recipient_exists,
        )
    }

    pub fn created_state_weight_from_presence(
        &self,
        nonce_exists: bool,
        recipient_balance_exists: bool,
    ) -> Result<u64, AssetError> {
        let mut weight = 0;
        if !nonce_exists {
            weight = checked_entry_weight(weight, 1 + xparq_crypto::ADDRESS_SIZE, &0_u64)?;
        }
        match &self.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority,
            } => {
                let metadata = AssetMetadata {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    decimals: *decimals,
                    max_supply: *max_supply,
                    creator: self.signer,
                    mint_authority: *mint_authority,
                };
                weight = checked_entry_weight(weight, 33, &metadata)?;
                weight = checked_entry_weight(weight, 33, initial_mint)?;
                weight =
                    checked_entry_weight(weight, 33 + xparq_crypto::ADDRESS_SIZE, initial_mint)?;
            }
            AssetInstruction::Mint { amount, .. } | AssetInstruction::Transfer { amount, .. }
                if !recipient_balance_exists =>
            {
                weight = checked_entry_weight(weight, 33 + xparq_crypto::ADDRESS_SIZE, amount)?;
            }
            AssetInstruction::TransferToExtension { amount, .. } if !recipient_balance_exists => {
                weight = checked_entry_weight(weight, 33 + 32, amount)?;
            }
            _ => {}
        }
        Ok(weight)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetState {
    metadata: BTreeMap<AssetHash, AssetMetadata>,
    supplies: BTreeMap<AssetHash, u128>,
    balances: BTreeMap<(AssetHash, Address), u128>,
    extension_balances: BTreeMap<(AssetHash, ExtensionHash), u128>,
    nonces: BTreeMap<Address, u64>,
}

impl AssetState {
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty()
            && self.supplies.is_empty()
            && self.balances.is_empty()
            && self.extension_balances.is_empty()
            && self.nonces.is_empty()
    }

    pub fn state_root(&self) -> Result<[u8; 32], AssetError> {
        let bytes = canonical_bytes(self).map_err(|_| AssetError::Encoding)?;
        Ok(blake3::derive_key("xparq:native-asset-state:v1", &bytes))
    }

    pub fn metadata(&self, id: AssetHash) -> Option<&AssetMetadata> {
        self.metadata.get(&id)
    }
    pub fn supply(&self, id: AssetHash) -> u128 {
        self.supplies.get(&id).copied().unwrap_or(0)
    }
    pub fn balance(&self, id: AssetHash, owner: Address) -> u128 {
        self.balances.get(&(id, owner)).copied().unwrap_or(0)
    }
    pub fn extension_balance(&self, id: AssetHash, owner: ExtensionHash) -> u128 {
        self.extension_balances
            .get(&(id, owner))
            .copied()
            .unwrap_or(0)
    }
    pub fn nonce(&self, owner: Address) -> u64 {
        self.nonces.get(&owner).copied().unwrap_or(0)
    }
    pub fn balances(&self) -> impl Iterator<Item = (AssetHash, Address, u128)> + '_ {
        self.balances
            .iter()
            .map(|(&(id, owner), &amount)| (id, owner, amount))
    }
    pub fn metadata_entries(&self) -> impl Iterator<Item = (AssetHash, &AssetMetadata)> + '_ {
        self.metadata.iter().map(|(&id, metadata)| (id, metadata))
    }

    pub fn apply(&mut self, call: &AssetCall) -> Result<AssetRollbackJournal, AssetError> {
        call.validate(self)?;
        let mut journal = AssetRollbackJournal::default();
        journal
            .nonces
            .push((call.signer, self.nonces.get(&call.signer).copied()));
        match &call.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority,
            } => {
                let id = AssetHash::derive(call.signer, symbol);
                journal.metadata.push((id, self.metadata.get(&id).cloned()));
                journal.supplies.push((id, self.supplies.get(&id).copied()));
                journal.balances.push((
                    (id, call.signer),
                    self.balances.get(&(id, call.signer)).copied(),
                ));
                self.metadata.insert(
                    id,
                    AssetMetadata {
                        name: name.clone(),
                        symbol: symbol.clone(),
                        decimals: *decimals,
                        max_supply: *max_supply,
                        creator: call.signer,
                        mint_authority: *mint_authority,
                    },
                );
                self.supplies.insert(id, *initial_mint);
                self.balances.insert((id, call.signer), *initial_mint);
            }
            AssetInstruction::Mint {
                asset_id,
                recipient,
                amount,
            } => {
                journal
                    .supplies
                    .push((*asset_id, self.supplies.get(asset_id).copied()));
                journal.balances.push((
                    (*asset_id, *recipient),
                    self.balances.get(&(*asset_id, *recipient)).copied(),
                ));
                self.supplies
                    .insert(*asset_id, self.supply(*asset_id) + amount);
                self.balances.insert(
                    (*asset_id, *recipient),
                    self.balance(*asset_id, *recipient) + amount,
                );
            }
            AssetInstruction::Burn { asset_id, amount } => {
                journal
                    .supplies
                    .push((*asset_id, self.supplies.get(asset_id).copied()));
                journal.balances.push((
                    (*asset_id, call.signer),
                    self.balances.get(&(*asset_id, call.signer)).copied(),
                ));
                self.supplies
                    .insert(*asset_id, self.supply(*asset_id) - amount);
                let balance = self.balance(*asset_id, call.signer) - amount;
                set_balance(&mut self.balances, (*asset_id, call.signer), balance);
            }
            AssetInstruction::Transfer {
                asset_id,
                recipient,
                amount,
            } => {
                for owner in [call.signer, *recipient] {
                    journal.balances.push((
                        (*asset_id, owner),
                        self.balances.get(&(*asset_id, owner)).copied(),
                    ));
                }
                let sender = self.balance(*asset_id, call.signer) - amount;
                let recipient_balance = self.balance(*asset_id, *recipient) + amount;
                set_balance(&mut self.balances, (*asset_id, call.signer), sender);
                self.balances
                    .insert((*asset_id, *recipient), recipient_balance);
            }
            AssetInstruction::TransferToExtension {
                asset_id,
                extension,
                amount,
            } => {
                journal.balances.push((
                    (*asset_id, call.signer),
                    self.balances.get(&(*asset_id, call.signer)).copied(),
                ));
                journal.extension_balances.push((
                    (*asset_id, *extension),
                    self.extension_balances
                        .get(&(*asset_id, *extension))
                        .copied(),
                ));
                let sender = self.balance(*asset_id, call.signer) - amount;
                let recipient = self.extension_balance(*asset_id, *extension) + amount;
                set_balance(&mut self.balances, (*asset_id, call.signer), sender);
                self.extension_balances
                    .insert((*asset_id, *extension), recipient);
            }
        }
        self.nonces.insert(call.signer, call.nonce + 1);
        Ok(journal)
    }

    /// Applies a mint requested by the currently executing extension program.
    ///
    /// The ledger must supply `program` from its trusted execution context;
    /// it must never be accepted from an untrusted transaction payload.
    pub fn apply_program_mint(
        &mut self,
        program: ExtensionHash,
        asset_id: AssetHash,
        recipient: Address,
        amount: u128,
    ) -> Result<AssetRollbackJournal, AssetError> {
        ensure_nonzero(amount)?;
        let metadata = self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;
        if metadata.mint_authority != Some(AssetAuthority::Program(program)) {
            return Err(AssetError::Unauthorized);
        }
        let supply = self
            .supply(asset_id)
            .checked_add(amount)
            .filter(|supply| *supply <= metadata.max_supply)
            .ok_or(AssetError::SupplyOverflow)?;
        let balance = self
            .balance(asset_id, recipient)
            .checked_add(amount)
            .ok_or(AssetError::BalanceOverflow)?;
        let mut journal = AssetRollbackJournal::default();
        journal
            .supplies
            .push((asset_id, self.supplies.get(&asset_id).copied()));
        journal.balances.push((
            (asset_id, recipient),
            self.balances.get(&(asset_id, recipient)).copied(),
        ));
        self.supplies.insert(asset_id, supply);
        self.balances.insert((asset_id, recipient), balance);
        Ok(journal)
    }

    pub fn program_mint_created_state_weight(
        &self,
        program: ExtensionHash,
        asset_id: AssetHash,
        recipient: Address,
        amount: u128,
    ) -> Result<u64, AssetError> {
        ensure_nonzero(amount)?;
        let metadata = self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;
        if metadata.mint_authority != Some(AssetAuthority::Program(program)) {
            return Err(AssetError::Unauthorized);
        }
        self.supply(asset_id)
            .checked_add(amount)
            .filter(|supply| *supply <= metadata.max_supply)
            .ok_or(AssetError::SupplyOverflow)?;
        self.balance(asset_id, recipient)
            .checked_add(amount)
            .ok_or(AssetError::BalanceOverflow)?;
        if self.balances.contains_key(&(asset_id, recipient)) {
            Ok(0)
        } else {
            checked_entry_weight(0, 33 + xparq_crypto::ADDRESS_SIZE, &amount)
        }
    }

    /// Transfers assets held by the executing extension to an account.
    pub fn apply_program_transfer(
        &mut self,
        program: ExtensionHash,
        asset_id: AssetHash,
        recipient: Address,
        amount: u128,
    ) -> Result<AssetRollbackJournal, AssetError> {
        ensure_nonzero(amount)?;
        self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;
        let held = self.extension_balance(asset_id, program);
        if held < amount {
            return Err(AssetError::InsufficientBalance);
        }
        let recipient_balance = self
            .balance(asset_id, recipient)
            .checked_add(amount)
            .ok_or(AssetError::BalanceOverflow)?;
        let mut journal = AssetRollbackJournal::default();
        journal.extension_balances.push((
            (asset_id, program),
            self.extension_balances.get(&(asset_id, program)).copied(),
        ));
        journal.balances.push((
            (asset_id, recipient),
            self.balances.get(&(asset_id, recipient)).copied(),
        ));
        set_extension_balance(
            &mut self.extension_balances,
            (asset_id, program),
            held - amount,
        );
        self.balances
            .insert((asset_id, recipient), recipient_balance);
        Ok(journal)
    }

    pub fn program_transfer_created_state_weight(
        &self,
        program: ExtensionHash,
        asset_id: AssetHash,
        recipient: Address,
        amount: u128,
    ) -> Result<u64, AssetError> {
        ensure_nonzero(amount)?;
        self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;
        if self.extension_balance(asset_id, program) < amount {
            return Err(AssetError::InsufficientBalance);
        }
        self.balance(asset_id, recipient)
            .checked_add(amount)
            .ok_or(AssetError::BalanceOverflow)?;
        if self.balances.contains_key(&(asset_id, recipient)) {
            Ok(0)
        } else {
            checked_entry_weight(0, 33 + xparq_crypto::ADDRESS_SIZE, &amount)
        }
    }

    pub fn rollback(&mut self, journal: AssetRollbackJournal) {
        restore_map(&mut self.metadata, journal.metadata);
        restore_map(&mut self.supplies, journal.supplies);
        restore_map(&mut self.balances, journal.balances);
        restore_map(&mut self.extension_balances, journal.extension_balances);
        restore_map(&mut self.nonces, journal.nonces);
    }

    fn validate_transition(&self, call: &AssetCall) -> Result<(), AssetError> {
        if call.nonce != self.nonce(call.signer) {
            return Err(AssetError::InvalidNonce);
        }
        match &call.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority: _,
            } => {
                let _ = (name, decimals, max_supply, initial_mint);
                if self
                    .metadata(AssetHash::derive(call.signer, symbol))
                    .is_some()
                {
                    return Err(AssetError::AssetAlreadyExists);
                }
            }
            AssetInstruction::Mint {
                asset_id, amount, ..
            } => {
                let metadata = self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;
                if metadata.mint_authority != Some(AssetAuthority::Account(call.signer)) {
                    return Err(AssetError::Unauthorized);
                }
                if self
                    .supply(*asset_id)
                    .checked_add(*amount)
                    .is_none_or(|supply| supply > metadata.max_supply)
                {
                    return Err(AssetError::SupplyOverflow);
                }
            }
            AssetInstruction::Burn { asset_id, amount } => {
                self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;
                if self.balance(*asset_id, call.signer) < *amount {
                    return Err(AssetError::InsufficientBalance);
                }
            }
            AssetInstruction::Transfer {
                asset_id,
                recipient,
                amount,
            } => {
                self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;
                if self.balance(*asset_id, call.signer) < *amount {
                    return Err(AssetError::InsufficientBalance);
                }
                self.balance(*asset_id, *recipient)
                    .checked_add(*amount)
                    .ok_or(AssetError::BalanceOverflow)?;
            }
            AssetInstruction::TransferToExtension {
                asset_id,
                extension,
                amount,
            } => {
                self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;
                if self.balance(*asset_id, call.signer) < *amount {
                    return Err(AssetError::InsufficientBalance);
                }
                self.extension_balance(*asset_id, *extension)
                    .checked_add(*amount)
                    .ok_or(AssetError::BalanceOverflow)?;
            }
        }
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetRollbackJournal {
    metadata: Vec<(AssetHash, Option<AssetMetadata>)>,
    supplies: Vec<(AssetHash, Option<u128>)>,
    balances: Vec<((AssetHash, Address), Option<u128>)>,
    extension_balances: Vec<((AssetHash, ExtensionHash), Option<u128>)>,
    nonces: Vec<(Address, Option<u64>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetError {
    Encoding,
    InvalidNonce,
    InvalidProgram,
    AssetAlreadyExists,
    UnknownAsset,
    Unauthorized,
    SupplyOverflow,
    BalanceOverflow,
    InsufficientBalance,
}
impl fmt::Display for AssetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native asset operation failed: {self:?}")
    }
}
impl Error for AssetError {}

fn call_commitment(
    genesis_hash: [u8; 32],
    instruction: &AssetInstruction,
    signer: Address,
    nonce: u64,
) -> Result<[u8; 32], AssetError> {
    let bytes = canonical_bytes(&UnsignedAssetCall {
        genesis_hash,
        instruction,
        signer,
        nonce,
    })
    .map_err(|_| AssetError::Encoding)?;
    Ok(blake3::derive_key(ASSET_PROGRAM_COMMITMENT_CONTEXT, &bytes))
}
fn validate_symbol(value: &str) -> Result<(), AssetError> {
    if value.is_empty()
        || value.len() > ASSET_SYMBOL_MAX_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        Err(AssetError::InvalidProgram)
    } else {
        Ok(())
    }
}
fn validate_name(value: &str) -> Result<(), AssetError> {
    if value.is_empty()
        || value.len() > ASSET_NAME_MAX_LEN
        || value.trim() != value
        || !value.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
    {
        Err(AssetError::InvalidProgram)
    } else {
        Ok(())
    }
}
fn ensure_nonzero(value: u128) -> Result<(), AssetError> {
    if value == 0 {
        Err(AssetError::InvalidProgram)
    } else {
        Ok(())
    }
}
fn checked_entry_weight<T: BorshSerialize>(
    current: u64,
    key_len: usize,
    value: &T,
) -> Result<u64, AssetError> {
    let value_len = canonical_bytes(value)
        .map_err(|_| AssetError::Encoding)?
        .len();
    let entry = u64::try_from(key_len.checked_add(value_len).ok_or(AssetError::Encoding)?)
        .map_err(|_| AssetError::Encoding)?;
    current.checked_add(entry).ok_or(AssetError::Encoding)
}
fn set_balance(
    map: &mut BTreeMap<(AssetHash, Address), u128>,
    key: (AssetHash, Address),
    value: u128,
) {
    if value == 0 {
        map.remove(&key);
    } else {
        map.insert(key, value);
    }
}

fn set_extension_balance(
    map: &mut BTreeMap<(AssetHash, ExtensionHash), u128>,
    key: (AssetHash, ExtensionHash),
    value: u128,
) {
    if value == 0 {
        map.remove(&key);
    } else {
        map.insert(key, value);
    }
}
fn restore_map<K: Ord, V>(map: &mut BTreeMap<K, V>, entries: Vec<(K, Option<V>)>) {
    for (key, previous) in entries.into_iter().rev() {
        if let Some(value) = previous {
            map.insert(key, value);
        } else {
            map.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn register_transfer_and_rollback_are_atomic() {
        let signer = Address([7; xparq_crypto::ADDRESS_SIZE]);
        let recipient = Address([9; xparq_crypto::ADDRESS_SIZE]);
        let register = AssetCall::new(
            AssetInstruction::Register {
                name: "Gold".into(),
                symbol: "GOLD".into(),
                decimals: 2,
                max_supply: 1_000,
                initial_mint: 100,
                mint_authority: Some(AssetAuthority::Account(signer)),
            },
            signer,
            0,
        );
        let id = register.asset_id();
        let mut state = AssetState::default();
        state.apply(&register).unwrap();
        let metadata = state.metadata(id).unwrap();
        assert_eq!(metadata.creator, signer);
        assert_eq!(
            metadata.mint_authority,
            Some(AssetAuthority::Account(signer))
        );
        let transfer = AssetCall::new(
            AssetInstruction::Transfer {
                asset_id: id,
                recipient,
                amount: 25,
            },
            signer,
            1,
        );
        let journal = state.apply(&transfer).unwrap();
        assert_eq!(state.balance(id, recipient), 25);
        state.rollback(journal);
        assert_eq!(state.balance(id, recipient), 0);
        assert_eq!(state.balance(id, register.signer), 100);
        assert_eq!(state.nonce(register.signer), 1);
    }

    #[test]
    fn program_authority_can_only_mint_through_program_context() {
        let creator = Address([7; xparq_crypto::ADDRESS_SIZE]);
        let recipient = Address([9; xparq_crypto::ADDRESS_SIZE]);
        let program = ExtensionHash::derive("test.asset.minter");
        let register = AssetCall::new(
            AssetInstruction::Register {
                name: "Program Token".into(),
                symbol: "PRG".into(),
                decimals: 6,
                max_supply: 1_000,
                initial_mint: 100,
                mint_authority: Some(AssetAuthority::Program(program)),
            },
            creator,
            0,
        );
        let asset_id = register.asset_id();
        let mut state = AssetState::default();
        state.apply(&register).unwrap();

        let account_mint = AssetCall::new(
            AssetInstruction::Mint {
                asset_id,
                recipient,
                amount: 25,
            },
            creator,
            1,
        );
        assert_eq!(state.apply(&account_mint), Err(AssetError::Unauthorized));

        let journal = state
            .apply_program_mint(program, asset_id, recipient, 25)
            .unwrap();
        assert_eq!(state.supply(asset_id), 125);
        assert_eq!(state.balance(asset_id, recipient), 25);
        state.rollback(journal);
        assert_eq!(state.supply(asset_id), 100);
        assert_eq!(state.balance(asset_id, recipient), 0);
    }

    #[test]
    fn extension_can_receive_and_send_asset_balance() {
        let creator = Address([0x11; xparq_crypto::ADDRESS_SIZE]);
        let recipient = Address([0x12; xparq_crypto::ADDRESS_SIZE]);
        let program = ExtensionHash::derive("test.asset.vault");
        let register = AssetCall::new(
            AssetInstruction::Register {
                name: "Vault Token".into(),
                symbol: "VLT".into(),
                decimals: 0,
                max_supply: 100,
                initial_mint: 100,
                mint_authority: None,
            },
            creator,
            0,
        );
        let asset_id = register.asset_id();
        let mut state = AssetState::default();
        state.apply(&register).unwrap();
        state
            .apply(&AssetCall::new(
                AssetInstruction::TransferToExtension {
                    asset_id,
                    extension: program,
                    amount: 40,
                },
                creator,
                1,
            ))
            .unwrap();
        assert_eq!(state.extension_balance(asset_id, program), 40);

        let journal = state
            .apply_program_transfer(program, asset_id, recipient, 15)
            .unwrap();
        assert_eq!(state.extension_balance(asset_id, program), 25);
        assert_eq!(state.balance(asset_id, recipient), 15);
        state.rollback(journal);
        assert_eq!(state.extension_balance(asset_id, program), 40);
        assert_eq!(state.balance(asset_id, recipient), 0);
    }
}
