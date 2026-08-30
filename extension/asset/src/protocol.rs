use std::{fmt, str::FromStr};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::{
    Extension, ExtensionCall, ExtensionContext, ExtensionFailure, ExtensionId, ExtensionStateRead,
    ExtensionStateWrite, Height, canonical_bytes,
};
use xparq_crypto::{
    Address, ProfilePublicKey, ProfileSignature, ProfileSigningSeed,
    address_from_profile_public_key, profile_verify,
};

use crate::AssetIdParseError;

pub const ASSET_EXTENSION_NAME: &str = "xparq.asset.v1";
pub const ASSET_ACTIVATION_HEIGHT: Height = Height(0);
pub const ASSET_NAME_MAX_LEN: usize = 64;
pub const ASSET_SYMBOL_MAX_LEN: usize = 16;
const ASSET_CALL_COMMITMENT_CONTEXT: &str = "XPARQ Asset Call v1";
const ASSET_ID_CONTEXT: &str = "XPARQ Extension Asset Id v1";

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct AssetId([u8; 32]);

impl AssetId {
    pub fn derive(authority: Address, symbol: &str) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(ASSET_ID_CONTEXT);
        hasher.update(&authority.0);
        hasher.update(&(symbol.len() as u64).to_le_bytes());
        hasher.update(symbol.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", hex_string(&self.0))
    }
}

impl FromStr for AssetId {
    type Err = AssetIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AssetIdParseError);
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (nibble(value.as_bytes()[index * 2]).ok_or(AssetIdParseError)? << 4)
                | nibble(value.as_bytes()[index * 2 + 1]).ok_or(AssetIdParseError)?;
        }
        Ok(Self(bytes))
    }
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
    Register {
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: u128,
        initial_mint: u128,
    },
    Mint {
        asset_id: AssetId,
        recipient: Address,
        amount: u128,
    },
    Burn {
        asset_id: AssetId,
        amount: u128,
    },
    Transfer {
        asset_id: AssetId,
        recipient: Address,
        amount: u128,
    },
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
struct UnsignedAssetCall<'a> {
    chain_id: [u8; 32],
    action: &'a AssetAction,
    signer: Address,
    nonce: u64,
}

impl AssetCall {
    pub fn from_extension_call(call: &ExtensionCall) -> Result<Self, ExtensionFailure> {
        decode_call(call)
    }

    pub fn asset_id(&self) -> AssetId {
        match &self.action {
            AssetAction::Register { symbol, .. } => AssetId::derive(self.signer, symbol),
            AssetAction::Mint { asset_id, .. }
            | AssetAction::Burn { asset_id, .. }
            | AssetAction::Transfer { asset_id, .. } => *asset_id,
        }
    }

    /// Canonical key plus value bytes for every persistent entry this call creates.
    pub fn created_state_weight(
        &self,
        state: &dyn ExtensionStateRead,
    ) -> Result<u64, ExtensionFailure> {
        let mut weight = 0_u64;
        let nonce = nonce_key(self.signer);
        if state.get(&nonce)?.is_none() {
            let next_nonce = self
                .nonce
                .checked_add(1)
                .ok_or(ExtensionFailure::InvalidPayload)?;
            weight = checked_entry_weight(weight, nonce, &next_nonce)?;
        }
        match &self.action {
            AssetAction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
            } => {
                let id = AssetId::derive(self.signer, symbol);
                let metadata = AssetMetadata {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    decimals: *decimals,
                    max_supply: *max_supply,
                    mint_authority: self.signer,
                };
                weight = checked_absent_entry_weight(state, weight, metadata_key(id), &metadata)?;
                weight = checked_absent_entry_weight(state, weight, supply_key(id), initial_mint)?;
                weight = checked_absent_entry_weight(
                    state,
                    weight,
                    balance_key(id, self.signer),
                    initial_mint,
                )?;
            }
            AssetAction::Mint {
                asset_id,
                recipient,
                amount,
            }
            | AssetAction::Transfer {
                asset_id,
                recipient,
                amount,
            } => {
                weight = checked_absent_entry_weight(
                    state,
                    weight,
                    balance_key(*asset_id, *recipient),
                    amount,
                )?;
            }
            AssetAction::Burn { .. } => {}
        }
        Ok(weight)
    }

    /// Wallet-side equivalent using presence information obtained from RPC.
    pub fn created_state_weight_from_presence(
        &self,
        nonce_exists: bool,
        recipient_balance_exists: bool,
    ) -> Result<u64, ExtensionFailure> {
        let mut weight = 0_u64;
        if !nonce_exists {
            let next_nonce = self
                .nonce
                .checked_add(1)
                .ok_or(ExtensionFailure::InvalidPayload)?;
            weight = checked_entry_weight(weight, nonce_key(self.signer), &next_nonce)?;
        }
        match &self.action {
            AssetAction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
            } => {
                let id = AssetId::derive(self.signer, symbol);
                let metadata = AssetMetadata {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    decimals: *decimals,
                    max_supply: *max_supply,
                    mint_authority: self.signer,
                };
                weight = checked_entry_weight(weight, metadata_key(id), &metadata)?;
                weight = checked_entry_weight(weight, supply_key(id), initial_mint)?;
                weight = checked_entry_weight(weight, balance_key(id, self.signer), initial_mint)?;
            }
            AssetAction::Mint {
                asset_id,
                recipient,
                amount,
            }
            | AssetAction::Transfer {
                asset_id,
                recipient,
                amount,
            } if !recipient_balance_exists => {
                weight = checked_entry_weight(weight, balance_key(*asset_id, *recipient), amount)?;
            }
            AssetAction::Mint { .. } | AssetAction::Transfer { .. } | AssetAction::Burn { .. } => {}
        }
        Ok(weight)
    }

    pub fn sign(
        chain_id: [u8; 32],
        action: AssetAction,
        nonce: u64,
        signing_seed: &ProfileSigningSeed,
    ) -> Result<Self, ExtensionFailure> {
        let public_key = signing_seed.public_key();
        let signer = address_from_profile_public_key(&public_key);
        let commitment = call_commitment(chain_id, &action, signer, nonce)?;
        let signature = signing_seed.sign(&commitment);
        Ok(Self {
            action,
            signer,
            nonce,
            public_key,
            signature,
        })
    }

    pub fn into_extension_call(self) -> Result<ExtensionCall, ExtensionFailure> {
        let payload = canonical_bytes(&self).map_err(|_| ExtensionFailure::InvalidPayload)?;
        ExtensionCall::new(asset_extension_id(), payload)
    }
}

pub fn decode_asset_balance_entry(
    key: &[u8],
    value: &[u8],
) -> Result<Option<(AssetId, Address, u128)>, ExtensionFailure> {
    if key.len() != 1 + 32 + xparq_crypto::ADDRESS_SIZE || key.first() != Some(&b'b') {
        return Ok(None);
    }
    let asset_id = AssetId::from_bytes(
        key[1..33]
            .try_into()
            .map_err(|_| ExtensionFailure::InvalidState)?,
    );
    let owner = Address(
        key[33..]
            .try_into()
            .map_err(|_| ExtensionFailure::InvalidState)?,
    );
    let balance = u128::try_from_slice(value).map_err(|_| ExtensionFailure::InvalidState)?;
    Ok(Some((asset_id, owner, balance)))
}

pub fn decode_asset_metadata_entry(
    key: &[u8],
    value: &[u8],
) -> Result<Option<(AssetId, AssetMetadata)>, ExtensionFailure> {
    if key.len() != 33 || key.first() != Some(&b'm') {
        return Ok(None);
    }
    let asset_id = AssetId::from_bytes(
        key[1..]
            .try_into()
            .map_err(|_| ExtensionFailure::InvalidState)?,
    );
    let metadata =
        AssetMetadata::try_from_slice(value).map_err(|_| ExtensionFailure::InvalidState)?;
    Ok(Some((asset_id, metadata)))
}

pub struct AssetExtension {
    chain_id: [u8; 32],
    activation_height: Height,
}

impl AssetExtension {
    pub const fn new(chain_id: [u8; 32], activation_height: Height) -> Self {
        Self {
            chain_id,
            activation_height,
        }
    }
}

pub fn asset_extension_id() -> ExtensionId {
    ExtensionId::derive(ASSET_EXTENSION_NAME)
}

impl Extension for AssetExtension {
    fn id(&self) -> ExtensionId {
        asset_extension_id()
    }

    fn activation_height(&self) -> Height {
        self.activation_height
    }

    fn validate(
        &self,
        _context: ExtensionContext,
        call: &ExtensionCall,
        state: &dyn ExtensionStateRead,
    ) -> Result<(), ExtensionFailure> {
        let call = decode_call(call)?;
        validate_authorization(self.chain_id, &call)?;
        validate_transition(state, &call)
    }

    fn apply(
        &self,
        _context: ExtensionContext,
        call: &ExtensionCall,
        state: &mut dyn ExtensionStateWrite,
    ) -> Result<(), ExtensionFailure> {
        let call = decode_call(call)?;
        validate_authorization(self.chain_id, &call)?;
        validate_transition(state, &call)?;
        apply_transition(state, &call)
    }
}

pub fn asset_metadata(
    state: &dyn ExtensionStateRead,
    asset_id: AssetId,
) -> Result<Option<AssetMetadata>, ExtensionFailure> {
    read_value(state, &metadata_key(asset_id))
}

pub fn asset_supply(
    state: &dyn ExtensionStateRead,
    asset_id: AssetId,
) -> Result<u128, ExtensionFailure> {
    Ok(read_value(state, &supply_key(asset_id))?.unwrap_or(0))
}

pub fn asset_balance(
    state: &dyn ExtensionStateRead,
    asset_id: AssetId,
    owner: Address,
) -> Result<u128, ExtensionFailure> {
    Ok(read_value(state, &balance_key(asset_id, owner))?.unwrap_or(0))
}

pub fn asset_nonce(
    state: &dyn ExtensionStateRead,
    owner: Address,
) -> Result<u64, ExtensionFailure> {
    Ok(read_value(state, &nonce_key(owner))?.unwrap_or(0))
}

fn validate_authorization(chain_id: [u8; 32], call: &AssetCall) -> Result<(), ExtensionFailure> {
    if address_from_profile_public_key(&call.public_key) != call.signer
        || call.public_key.profile != call.signature.profile
    {
        return Err(ExtensionFailure::InvalidPayload);
    }
    let commitment = call_commitment(chain_id, &call.action, call.signer, call.nonce)?;
    if !profile_verify(&call.public_key, &commitment, &call.signature) {
        return Err(ExtensionFailure::InvalidPayload);
    }
    Ok(())
}

fn validate_transition(
    state: &dyn ExtensionStateRead,
    call: &AssetCall,
) -> Result<(), ExtensionFailure> {
    if call.nonce != asset_nonce(state, call.signer)? {
        return Err(ExtensionFailure::InvalidState);
    }
    match &call.action {
        AssetAction::Register {
            name,
            symbol,
            decimals,
            max_supply,
            initial_mint,
        } => {
            validate_name(name)?;
            validate_symbol(symbol)?;
            if *decimals > 18 || *max_supply == 0 || *initial_mint == 0 || initial_mint > max_supply
            {
                return Err(ExtensionFailure::InvalidPayload);
            }
            let id = AssetId::derive(call.signer, symbol);
            if asset_metadata(state, id)?.is_some() {
                return Err(ExtensionFailure::InvalidState);
            }
        }
        AssetAction::Mint {
            asset_id,
            recipient: _,
            amount,
        } => {
            ensure_nonzero(*amount)?;
            let metadata = require_metadata(state, *asset_id)?;
            if metadata.mint_authority != call.signer {
                return Err(ExtensionFailure::InvalidState);
            }
            let supply = asset_supply(state, *asset_id)?;
            if supply
                .checked_add(*amount)
                .is_none_or(|sum| sum > metadata.max_supply)
            {
                return Err(ExtensionFailure::InvalidState);
            }
        }
        AssetAction::Burn { asset_id, amount } => {
            ensure_nonzero(*amount)?;
            require_metadata(state, *asset_id)?;
            if asset_balance(state, *asset_id, call.signer)? < *amount {
                return Err(ExtensionFailure::InvalidState);
            }
        }
        AssetAction::Transfer {
            asset_id,
            recipient,
            amount,
        } => {
            ensure_nonzero(*amount)?;
            require_metadata(state, *asset_id)?;
            if *recipient == call.signer || asset_balance(state, *asset_id, call.signer)? < *amount
            {
                return Err(ExtensionFailure::InvalidState);
            }
            asset_balance(state, *asset_id, *recipient)?
                .checked_add(*amount)
                .ok_or(ExtensionFailure::InvalidState)?;
        }
    }
    call.nonce
        .checked_add(1)
        .ok_or(ExtensionFailure::InvalidState)?;
    Ok(())
}

fn apply_transition(
    state: &mut dyn ExtensionStateWrite,
    call: &AssetCall,
) -> Result<(), ExtensionFailure> {
    match &call.action {
        AssetAction::Register {
            name,
            symbol,
            decimals,
            max_supply,
            initial_mint,
        } => {
            let id = AssetId::derive(call.signer, symbol);
            write_value(
                state,
                metadata_key(id),
                &AssetMetadata {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    decimals: *decimals,
                    max_supply: *max_supply,
                    mint_authority: call.signer,
                },
            )?;
            write_value(state, supply_key(id), initial_mint)?;
            write_balance(state, id, call.signer, *initial_mint)?;
        }
        AssetAction::Mint {
            asset_id,
            recipient,
            amount,
        } => {
            let supply = asset_supply(state, *asset_id)? + amount;
            let balance = asset_balance(state, *asset_id, *recipient)? + amount;
            write_value(state, supply_key(*asset_id), &supply)?;
            write_balance(state, *asset_id, *recipient, balance)?;
        }
        AssetAction::Burn { asset_id, amount } => {
            let supply = asset_supply(state, *asset_id)? - amount;
            let balance = asset_balance(state, *asset_id, call.signer)? - amount;
            write_value(state, supply_key(*asset_id), &supply)?;
            write_balance(state, *asset_id, call.signer, balance)?;
        }
        AssetAction::Transfer {
            asset_id,
            recipient,
            amount,
        } => {
            let sender_balance = asset_balance(state, *asset_id, call.signer)? - amount;
            let recipient_balance = asset_balance(state, *asset_id, *recipient)? + amount;
            write_balance(state, *asset_id, call.signer, sender_balance)?;
            write_balance(state, *asset_id, *recipient, recipient_balance)?;
        }
    }
    write_value(state, nonce_key(call.signer), &(call.nonce + 1))
}

fn decode_call(call: &ExtensionCall) -> Result<AssetCall, ExtensionFailure> {
    if call.extension_id() != asset_extension_id() {
        return Err(ExtensionFailure::UnknownExtension);
    }
    AssetCall::try_from_slice(call.payload()).map_err(|_| ExtensionFailure::InvalidPayload)
}

fn call_commitment(
    chain_id: [u8; 32],
    action: &AssetAction,
    signer: Address,
    nonce: u64,
) -> Result<[u8; 32], ExtensionFailure> {
    let bytes = canonical_bytes(&UnsignedAssetCall {
        chain_id,
        action,
        signer,
        nonce,
    })
    .map_err(|_| ExtensionFailure::InvalidPayload)?;
    Ok(blake3::derive_key(ASSET_CALL_COMMITMENT_CONTEXT, &bytes))
}

fn require_metadata(
    state: &dyn ExtensionStateRead,
    asset_id: AssetId,
) -> Result<AssetMetadata, ExtensionFailure> {
    asset_metadata(state, asset_id)?.ok_or(ExtensionFailure::InvalidState)
}

fn validate_symbol(symbol: &str) -> Result<(), ExtensionFailure> {
    if symbol.is_empty()
        || symbol.len() > ASSET_SYMBOL_MAX_LEN
        || !symbol
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(ExtensionFailure::InvalidPayload);
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), ExtensionFailure> {
    if name.is_empty()
        || name.len() > ASSET_NAME_MAX_LEN
        || name.trim() != name
        || !name
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(ExtensionFailure::InvalidPayload);
    }
    Ok(())
}

fn ensure_nonzero(amount: u128) -> Result<(), ExtensionFailure> {
    if amount == 0 {
        Err(ExtensionFailure::InvalidPayload)
    } else {
        Ok(())
    }
}

fn metadata_key(asset_id: AssetId) -> Vec<u8> {
    prefixed_key(b'm', asset_id.as_bytes())
}

fn supply_key(asset_id: AssetId) -> Vec<u8> {
    prefixed_key(b's', asset_id.as_bytes())
}

fn balance_key(asset_id: AssetId, owner: Address) -> Vec<u8> {
    let mut key = prefixed_key(b'b', asset_id.as_bytes());
    key.extend_from_slice(&owner.0);
    key
}

fn nonce_key(owner: Address) -> Vec<u8> {
    prefixed_key(b'n', &owner.0)
}

fn prefixed_key(prefix: u8, bytes: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(bytes.len() + 1);
    key.push(prefix);
    key.extend_from_slice(bytes);
    key
}

fn read_value<T: BorshDeserialize>(
    state: &dyn ExtensionStateRead,
    key: &[u8],
) -> Result<Option<T>, ExtensionFailure> {
    state
        .get(key)?
        .map(|bytes| T::try_from_slice(&bytes).map_err(|_| ExtensionFailure::InvalidState))
        .transpose()
}

fn write_value<T: BorshSerialize>(
    state: &mut dyn ExtensionStateWrite,
    key: Vec<u8>,
    value: &T,
) -> Result<(), ExtensionFailure> {
    state.put(
        key,
        canonical_bytes(value).map_err(|_| ExtensionFailure::StateAccess)?,
    )
}

fn checked_entry_weight<T: BorshSerialize>(
    current: u64,
    key: Vec<u8>,
    value: &T,
) -> Result<u64, ExtensionFailure> {
    let value = canonical_bytes(value).map_err(|_| ExtensionFailure::InvalidPayload)?;
    let entry = key
        .len()
        .checked_add(value.len())
        .and_then(|weight| u64::try_from(weight).ok())
        .ok_or(ExtensionFailure::InvalidPayload)?;
    current
        .checked_add(entry)
        .ok_or(ExtensionFailure::InvalidPayload)
}

fn checked_absent_entry_weight<T: BorshSerialize>(
    state: &dyn ExtensionStateRead,
    current: u64,
    key: Vec<u8>,
    value: &T,
) -> Result<u64, ExtensionFailure> {
    if state.get(&key)?.is_some() {
        Ok(current)
    } else {
        checked_entry_weight(current, key, value)
    }
}

fn write_balance(
    state: &mut dyn ExtensionStateWrite,
    asset_id: AssetId,
    owner: Address,
    balance: u128,
) -> Result<(), ExtensionFailure> {
    let key = balance_key(asset_id, owner);
    if balance == 0 {
        state.delete(&key)
    } else {
        write_value(state, key, &balance)
    }
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use xparq_crypto::SignatureProfile;

    #[derive(Default)]
    struct MemoryState(BTreeMap<Vec<u8>, Vec<u8>>);

    impl ExtensionStateRead for MemoryState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure> {
            Ok(self.0.get(key).cloned())
        }

        fn entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ExtensionFailure> {
            Ok(self
                .0
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect())
        }

        fn get_extension(
            &self,
            _extension_id: ExtensionId,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>, ExtensionFailure> {
            self.get(key)
        }
    }

    impl ExtensionStateWrite for MemoryState {
        fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ExtensionFailure> {
            self.0.insert(key, value);
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), ExtensionFailure> {
            self.0.remove(key);
            Ok(())
        }
    }

    fn signed_call(seed: &ProfileSigningSeed, action: AssetAction, nonce: u64) -> ExtensionCall {
        AssetCall::sign([3; 32], action, nonce, seed)
            .unwrap()
            .into_extension_call()
            .unwrap()
    }

    #[test]
    fn created_state_weight_counts_only_new_persistent_entries() {
        let authority = ProfileSigningSeed::new(SignatureProfile::MlDsa44, [5; 32]);
        let alice = address_from_profile_public_key(&authority.public_key());
        let bob_seed = ProfileSigningSeed::new(SignatureProfile::Falcon512, [6; 32]);
        let bob = address_from_profile_public_key(&bob_seed.public_key());
        let extension = AssetExtension::new([3; 32], Height(0));
        let context = ExtensionContext { height: Height(0) };
        let mut state = MemoryState::default();
        let id = AssetId::derive(alice, "WEIGHT");

        let register = signed_call(
            &authority,
            AssetAction::Register {
                name: "State Weight".into(),
                symbol: "WEIGHT".into(),
                decimals: 8,
                max_supply: 1_000,
                initial_mint: 500,
            },
            0,
        );
        let decoded = AssetCall::from_extension_call(&register).unwrap();
        let metadata = AssetMetadata {
            name: "State Weight".into(),
            symbol: "WEIGHT".into(),
            decimals: 8,
            max_supply: 1_000,
            mint_authority: alice,
        };
        let expected_register = checked_entry_weight(0, nonce_key(alice), &1_u64)
            .and_then(|weight| checked_entry_weight(weight, metadata_key(id), &metadata))
            .and_then(|weight| checked_entry_weight(weight, supply_key(id), &500_u128))
            .and_then(|weight| checked_entry_weight(weight, balance_key(id, alice), &500_u128))
            .unwrap();
        assert_eq!(decoded.created_state_weight(&state), Ok(expected_register));
        extension.apply(context, &register, &mut state).unwrap();
        assert_eq!(decoded.created_state_weight(&state), Ok(0));

        let mint_new_balance = signed_call(
            &authority,
            AssetAction::Mint {
                asset_id: id,
                recipient: bob,
                amount: 100,
            },
            1,
        );
        let decoded = AssetCall::from_extension_call(&mint_new_balance).unwrap();
        let expected_balance = checked_entry_weight(0, balance_key(id, bob), &100_u128).unwrap();
        assert_eq!(decoded.created_state_weight(&state), Ok(expected_balance));
        extension
            .apply(context, &mint_new_balance, &mut state)
            .unwrap();

        let mint_existing_balance = signed_call(
            &authority,
            AssetAction::Mint {
                asset_id: id,
                recipient: bob,
                amount: 1,
            },
            2,
        );
        let decoded = AssetCall::from_extension_call(&mint_existing_balance).unwrap();
        assert_eq!(decoded.created_state_weight(&state), Ok(0));

        let burn_first_bob_call = signed_call(
            &bob_seed,
            AssetAction::Burn {
                asset_id: id,
                amount: 1,
            },
            0,
        );
        let decoded = AssetCall::from_extension_call(&burn_first_bob_call).unwrap();
        let expected_nonce = checked_entry_weight(0, nonce_key(bob), &1_u64).unwrap();
        assert_eq!(decoded.created_state_weight(&state), Ok(expected_nonce));
    }

    #[test]
    fn register_mint_transfer_and_burn_preserve_supply_and_authority() {
        let authority = ProfileSigningSeed::new(SignatureProfile::MlDsa44, [7; 32]);
        let alice = address_from_profile_public_key(&authority.public_key());
        let bob_seed = ProfileSigningSeed::new(SignatureProfile::Falcon512, [8; 32]);
        let bob = address_from_profile_public_key(&bob_seed.public_key());
        let extension = AssetExtension::new([3; 32], Height(0));
        let context = ExtensionContext { height: Height(0) };
        let mut state = MemoryState::default();
        let id = AssetId::derive(alice, "GOLD");

        let register = signed_call(
            &authority,
            AssetAction::Register {
                name: "Gold Token".into(),
                symbol: "GOLD".into(),
                decimals: 2,
                max_supply: 1_000,
                initial_mint: 500,
            },
            0,
        );
        extension.apply(context, &register, &mut state).unwrap();

        let mint = signed_call(
            &authority,
            AssetAction::Mint {
                asset_id: id,
                recipient: alice,
                amount: 100,
            },
            1,
        );
        extension.apply(context, &mint, &mut state).unwrap();

        let transfer = signed_call(
            &authority,
            AssetAction::Transfer {
                asset_id: id,
                recipient: bob,
                amount: 250,
            },
            2,
        );
        extension.apply(context, &transfer, &mut state).unwrap();

        let burn = signed_call(
            &bob_seed,
            AssetAction::Burn {
                asset_id: id,
                amount: 50,
            },
            0,
        );
        extension.apply(context, &burn, &mut state).unwrap();

        assert_eq!(asset_supply(&state, id), Ok(550));
        assert_eq!(asset_balance(&state, id, alice), Ok(350));
        assert_eq!(asset_balance(&state, id, bob), Ok(200));
        assert_eq!(asset_nonce(&state, alice), Ok(3));
        assert_eq!(asset_nonce(&state, bob), Ok(1));
        assert!(state.0.iter().any(|(key, value)| {
            decode_asset_balance_entry(key, value)
                .ok()
                .flatten()
                .is_some_and(|(asset_id, owner, balance)| {
                    asset_id == id && owner == bob && balance == 200
                })
        }));
        assert!(state.0.iter().any(|(key, value)| {
            decode_asset_metadata_entry(key, value)
                .ok()
                .flatten()
                .is_some_and(|(asset_id, metadata)| asset_id == id && metadata.name == "Gold Token")
        }));
        assert_eq!(
            extension.validate(context, &mint, &state),
            Err(ExtensionFailure::InvalidState)
        );
    }

    #[test]
    fn non_authority_cannot_mint() {
        let authority = ProfileSigningSeed::new(SignatureProfile::MlDsa44, [11; 32]);
        let stranger = ProfileSigningSeed::new(SignatureProfile::MlDsa44, [12; 32]);
        let owner = address_from_profile_public_key(&authority.public_key());
        let extension = AssetExtension::new([3; 32], Height(0));
        let context = ExtensionContext { height: Height(0) };
        let mut state = MemoryState::default();
        let id = AssetId::derive(owner, "SILVER");
        extension
            .apply(
                context,
                &signed_call(
                    &authority,
                    AssetAction::Register {
                        name: "Silver Token".into(),
                        symbol: "SILVER".into(),
                        decimals: 0,
                        max_supply: 10,
                        initial_mint: 1,
                    },
                    0,
                ),
                &mut state,
            )
            .unwrap();
        let unauthorized = signed_call(
            &stranger,
            AssetAction::Mint {
                asset_id: id,
                recipient: owner,
                amount: 1,
            },
            0,
        );
        assert_eq!(
            extension.validate(context, &unauthorized, &state),
            Err(ExtensionFailure::InvalidState)
        );
    }

    #[test]
    fn canonical_action_tags_are_stable() {
        let id = AssetId::from_bytes([1; 32]);
        assert_eq!(
            borsh::to_vec(&AssetAction::Register {
                name: "Asset A".into(),
                symbol: "A".into(),
                decimals: 0,
                max_supply: 1,
                initial_mint: 1,
            })
            .unwrap()[0],
            0
        );
        assert_eq!(
            borsh::to_vec(&AssetAction::Mint {
                asset_id: id,
                recipient: Address::ZERO,
                amount: 1,
            })
            .unwrap()[0],
            1
        );
        assert_eq!(
            borsh::to_vec(&AssetAction::Burn {
                asset_id: id,
                amount: 1,
            })
            .unwrap()[0],
            2
        );
        assert_eq!(
            borsh::to_vec(&AssetAction::Transfer {
                asset_id: id,
                recipient: Address::ZERO,
                amount: 1,
            })
            .unwrap()[0],
            3
        );
    }
}
