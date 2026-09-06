use std::{collections::BTreeMap, error::Error, fmt};

use crate::asset::{
    AssetError, AssetHash, AssetMetadata, AssetShare, AssetShareHash, AssetShareOutput,
    AssetShareOwner, Unit, asset_domain_hash, checked_asset_entry_weight,
    ensure_nonzero_asset_amount, ensure_unique_asset_inputs,
};
use crate::coin::{Coin, CoinHash};
use crate::common::{Input, Output, canonical_bytes};
use crate::transaction::{AssetInstruction, AssetIntent};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, PublicKey};

/// Owner of a native coin UTXO.
///
/// Coin is controlled by an account address.
pub type CoinOwner = Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinUtxo {
    pub coin: Coin,
    pub owner: CoinOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinOutput {
    pub amount: crate::coin::Zeno,
    pub owner: CoinOwner,
}

pub type UtxoId = Input<CoinHash, AssetShareHash>;
pub type Utxo = Output<CoinOutput, AssetShare>;

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UtxoSet {
    entries: BTreeMap<UtxoId, Utxo>,
}

impl UtxoSet {
    pub fn get(&self, id: &CoinHash) -> Option<CoinUtxo> {
        match self.entries.get(&UtxoId::Coin(*id)) {
            Some(Utxo::Coin(output)) => Some(CoinUtxo {
                coin: Coin::new(*id, output.amount),
                owner: output.owner,
            }),
            _ => None,
        }
    }

    pub fn insert(&mut self, utxo: CoinUtxo) -> Result<(), UtxoError> {
        let id = UtxoId::Coin(utxo.coin.utxo);
        if self.entries.contains_key(&id) {
            return Err(UtxoError::CoinHashCollision);
        }
        self.entries.insert(
            id,
            Utxo::Coin(CoinOutput {
                amount: utxo.coin.amount,
                owner: utxo.owner,
            }),
        );
        Ok(())
    }

    pub fn consume(&mut self, id: &CoinHash) -> Result<CoinUtxo, UtxoError> {
        match self.entries.remove(&UtxoId::Coin(*id)) {
            Some(Utxo::Coin(output)) => Ok(CoinUtxo {
                coin: Coin::new(*id, output.amount),
                owner: output.owner,
            }),
            _ => Err(UtxoError::UtxoNotFound),
        }
    }

    pub fn restore(&mut self, utxo: CoinUtxo) -> Result<(), UtxoError> {
        self.insert(utxo)
    }

    pub fn iter(&self) -> impl Iterator<Item = CoinUtxo> + '_ {
        self.entries
            .iter()
            .filter_map(|(id, output)| match (id, output) {
                (UtxoId::Coin(id), Utxo::Coin(output)) => Some(CoinUtxo {
                    coin: Coin::new(*id, output.amount),
                    owner: output.owner,
                }),
                _ => None,
            })
    }

    pub fn owned_by(&self, owner: CoinOwner) -> impl Iterator<Item = CoinUtxo> + '_ {
        self.iter().filter(move |utxo| utxo.owner == owner)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn asset(&self, id: AssetShareHash) -> Option<&AssetShare> {
        match self.entries.get(&UtxoId::Asset(id)) {
            Some(Utxo::Asset(utxo)) => Some(utxo),
            _ => None,
        }
    }

    pub fn assets(&self) -> impl Iterator<Item = (AssetShareHash, &AssetShare)> + '_ {
        self.entries
            .iter()
            .filter_map(|(id, output)| match (id, output) {
                (UtxoId::Asset(id), Utxo::Asset(utxo)) => Some((*id, utxo)),
                _ => None,
            })
    }

    fn insert_asset(&mut self, id: AssetShareHash, utxo: AssetShare) -> Option<AssetShare> {
        match self.entries.insert(UtxoId::Asset(id), Utxo::Asset(utxo)) {
            Some(Utxo::Asset(previous)) => Some(previous),
            _ => None,
        }
    }

    fn remove_asset(&mut self, id: AssetShareHash) -> Option<AssetShare> {
        match self.entries.remove(&UtxoId::Asset(id)) {
            Some(Utxo::Asset(utxo)) => Some(utxo),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UtxoRollbackJournal {
    pub(crate) consumed_coins: Vec<CoinUtxo>,
    pub(crate) created_coin_ids: Vec<CoinHash>,
    pub(crate) registered_account_public_keys: Vec<Address>,
    pub(crate) burned: crate::coin::Zeno,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountKeyRegistry {
    account_keys: BTreeMap<Address, PublicKey>,
}

impl AccountKeyRegistry {
    pub fn get_account(&self, address: &Address) -> Option<&PublicKey> {
        self.account_keys.get(address)
    }

    pub fn register_account(
        &mut self,
        address: Address,
        public_key: PublicKey,
    ) -> Result<bool, UtxoError> {
        if let Some(existing) = self.account_keys.get(&address) {
            return if existing == &public_key {
                Ok(false)
            } else {
                Err(UtxoError::PublicKeyConflict)
            };
        }
        self.account_keys.insert(address, public_key);
        Ok(true)
    }

    pub fn remove_account(&mut self, address: &Address) -> Result<PublicKey, UtxoError> {
        self.account_keys
            .remove(address)
            .ok_or(UtxoError::PublicKeyNotFound)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtxoError {
    UtxoNotFound,
    CoinHashCollision,
    PublicKeyNotFound,
    PublicKeyConflict,
}

impl fmt::Display for UtxoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UtxoNotFound => formatter.write_str("UTXO was not found"),
            Self::CoinHashCollision => formatter.write_str("UTXO coin ID already exists"),
            Self::PublicKeyNotFound => formatter.write_str("account public key was not found"),
            Self::PublicKeyConflict => {
                formatter.write_str("account address is registered to another public key")
            }
        }
    }
}

impl Error for UtxoError {}

const ASSET_STATE_CONTEXT: &[u8] = b"xparq:native-asset-state";

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetState {
    pub(crate) metadata: BTreeMap<AssetHash, AssetMetadata>,
    pub(crate) supplies: BTreeMap<AssetHash, Unit>,
    pub(crate) nonces: BTreeMap<Address, u64>,
}

impl AssetState {
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty() && self.supplies.is_empty() && self.nonces.is_empty()
    }

    pub fn state_root(&self) -> Result<[u8; 32], AssetError> {
        let bytes = canonical_bytes(self).map_err(|_| AssetError::Encoding)?;

        Ok(asset_domain_hash(ASSET_STATE_CONTEXT, &[&bytes]))
    }

    pub fn metadata(&self, id: AssetHash) -> Option<&AssetMetadata> {
        self.metadata.get(&id)
    }

    pub fn metadata_entries(&self) -> impl Iterator<Item = (AssetHash, &AssetMetadata)> + '_ {
        self.metadata.iter().map(|(&id, metadata)| (id, metadata))
    }

    pub fn balance(&self, utxos: &UtxoSet, asset_id: AssetHash, owner: Address) -> Unit {
        self.account_balance(utxos, asset_id, owner)
    }

    pub fn supply(&self, id: AssetHash) -> Unit {
        self.supplies.get(&id).copied().unwrap_or(Unit::ZERO)
    }

    pub fn utxo<'a>(&self, utxos: &'a UtxoSet, id: AssetShareHash) -> Option<&'a AssetShare> {
        utxos.asset(id)
    }

    pub fn utxos<'a>(
        &self,
        utxos: &'a UtxoSet,
    ) -> impl Iterator<Item = (AssetShareHash, &'a AssetShare)> + 'a {
        utxos.assets()
    }

    pub fn account_balance(&self, utxos: &UtxoSet, asset_id: AssetHash, owner: Address) -> Unit {
        utxos
            .assets()
            .map(|(_, utxo)| utxo)
            .filter(|utxo| utxo.parent == asset_id && utxo.owner == owner)
            .fold(Unit::ZERO, |total, utxo| total.saturating_add(utxo.amount))
    }

    pub fn nonce(&self, owner: Address) -> u64 {
        self.nonces.get(&owner).copied().unwrap_or(0)
    }

    pub fn apply(
        &mut self,
        utxos: &mut UtxoSet,
        call: &AssetIntent,
        genesis_hash: [u8; 32],
    ) -> Result<AssetRollbackJournal, AssetError> {
        call.validate_structure()?;
        self.validate_transition(utxos, call, genesis_hash)?;

        let commitment = call.commitment(genesis_hash)?;

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
                let asset_id = AssetHash::derive(call.signer, symbol);

                let object_id = AssetShareHash::derive(asset_id, commitment, 0);

                let owner = call.signer;

                journal
                    .metadata
                    .push((asset_id, self.metadata.get(&asset_id).cloned()));

                journal
                    .supplies
                    .push((asset_id, self.supplies.get(&asset_id).copied()));

                journal
                    .utxos
                    .push((object_id, utxos.asset(object_id).copied()));

                self.metadata.insert(
                    asset_id,
                    AssetMetadata {
                        name: name.clone(),
                        symbol: symbol.clone(),
                        decimals: *decimals,
                        max_supply: *max_supply,
                        creator: call.signer,
                        mint_authority: *mint_authority,
                    },
                );

                self.supplies.insert(asset_id, *initial_mint);

                utxos.insert_asset(
                    object_id,
                    AssetShare {
                        parent: asset_id,
                        owner,
                        amount: *initial_mint,
                    },
                );
            }

            AssetInstruction::Mint {
                asset_id,
                recipient,
                amount,
            } => {
                let object_id = AssetShareHash::derive(*asset_id, commitment, 0);

                let supply = self
                    .supply(*asset_id)
                    .checked_add(*amount)
                    .ok_or(AssetError::SupplyOverflow)?;

                journal
                    .supplies
                    .push((*asset_id, self.supplies.get(asset_id).copied()));

                journal
                    .utxos
                    .push((object_id, utxos.asset(object_id).copied()));

                self.supplies.insert(*asset_id, supply);

                utxos.insert_asset(
                    object_id,
                    AssetShare {
                        parent: *asset_id,
                        owner: *recipient,
                        amount: *amount,
                    },
                );
            }

            AssetInstruction::Burn { asset_id, inputs } => {
                let total = self.validate_inputs(
                    utxos,
                    *asset_id,
                    inputs,
                    call.signer,
                )?;

                let supply = self
                    .supply(*asset_id)
                    .checked_sub(total)
                    .ok_or(AssetError::SupplyOverflow)?;

                journal
                    .supplies
                    .push((*asset_id, self.supplies.get(asset_id).copied()));

                for input in inputs {
                    journal.utxos.push((*input, utxos.asset(*input).copied()));

                    utxos.remove_asset(*input);
                }

                self.supplies.insert(*asset_id, supply);
            }
        }

        let next_nonce = call.nonce.checked_add(1).ok_or(AssetError::InvalidNonce)?;

        self.nonces.insert(call.signer, next_nonce);

        Ok(journal)
    }

    pub fn apply_user_transfer(
        &mut self,
        utxos: &mut UtxoSet,
        signer: Address,
        asset_id: AssetHash,
        inputs: &[AssetShareHash],
        outputs: &[AssetShareOutput],
        commitment: [u8; 32],
    ) -> Result<AssetRollbackJournal, AssetError> {
        self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;
        let input_total =
            self.validate_inputs(utxos, asset_id, inputs, signer)?;
        if input_total != outputs_total(outputs)? {
            return Err(AssetError::InvalidAmount);
        }
        for index in 0..outputs.len() {
            let index = u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?;
            if utxos
                .asset(AssetShareHash::derive(asset_id, commitment, index))
                .is_some()
            {
                return Err(AssetError::ShareAlreadyExists);
            }
        }
        let mut journal = AssetRollbackJournal::default();
        for input in inputs {
            journal.utxos.push((*input, utxos.asset(*input).copied()));
            utxos.remove_asset(*input);
        }
        for (index, output) in outputs.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| AssetError::InvalidProgram)?;
            let id = AssetShareHash::derive(asset_id, commitment, index);
            journal.utxos.push((id, utxos.asset(id).copied()));
            utxos.insert_asset(
                id,
                AssetShare {
                    parent: asset_id,
                    owner: output.recipient,
                    amount: output.amount,
                },
            );
        }
        Ok(journal)
    }

    pub fn user_transfer_created_state_weight(
        &self,
        utxos: &UtxoSet,
        signer: Address,
        asset_id: AssetHash,
        inputs: &[AssetShareHash],
        outputs: &[AssetShareOutput],
    ) -> Result<u64, AssetError> {
        self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;
        let input_total =
            self.validate_inputs(utxos, asset_id, inputs, signer)?;
        if input_total != outputs_total(outputs)? {
            return Err(AssetError::InvalidAmount);
        }
        outputs.iter().try_fold(0_u64, |weight, output| {
            checked_asset_entry_weight(
                weight,
                32,
                &AssetShare {
                    parent: asset_id,
                    owner: output.recipient,
                    amount: output.amount,
                },
            )
        })
    }

    pub fn rollback(&mut self, utxos: &mut UtxoSet, journal: AssetRollbackJournal) {
        restore_map(&mut self.metadata, journal.metadata);

        restore_map(&mut self.supplies, journal.supplies);

        for (id, previous) in journal.utxos.into_iter().rev() {
            match previous {
                Some(utxo) => {
                    utxos.insert_asset(id, utxo);
                }
                None => {
                    utxos.remove_asset(id);
                }
            }
        }

        restore_map(&mut self.nonces, journal.nonces);
    }

    pub(crate) fn validate_transition(
        &self,
        utxos: &UtxoSet,
        call: &AssetIntent,
        _genesis_hash: [u8; 32],
    ) -> Result<(), AssetError> {
        if call.nonce != self.nonce(call.signer) {
            return Err(AssetError::InvalidNonce);
        }

        match &call.instruction {
            AssetInstruction::Register { symbol, .. } => {
                let id = AssetHash::derive(call.signer, symbol);

                if self.metadata(id).is_some() {
                    return Err(AssetError::AssetAlreadyExists);
                }
            }

            AssetInstruction::Mint {
                asset_id, amount, ..
            } => {
                let metadata = self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;

                if metadata.mint_authority != Some(call.signer) {
                    return Err(AssetError::Unauthorized);
                }

                self.supply(*asset_id)
                    .checked_add(*amount)
                    .filter(|supply| *supply <= metadata.max_supply)
                    .ok_or(AssetError::SupplyOverflow)?;
            }

            AssetInstruction::Burn { asset_id, inputs } => {
                self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;

                self.validate_inputs(utxos, *asset_id, inputs, call.signer)?;
            }
        }

        Ok(())
    }

    fn validate_inputs(
        &self,
        utxos: &UtxoSet,
        asset_id: AssetHash,
        inputs: &[AssetShareHash],
        expected_owner: AssetShareOwner,
    ) -> Result<Unit, AssetError> {
        if inputs.is_empty() {
            return Err(AssetError::InvalidProgram);
        }

        ensure_unique_asset_inputs(inputs)?;

        let mut total = Unit::ZERO;

        for input in inputs {
            let utxo = self.utxo(utxos, *input).ok_or(AssetError::UnknownObject)?;

            if utxo.parent != asset_id {
                return Err(AssetError::AssetMismatch);
            }

            if utxo.owner != expected_owner {
                return Err(AssetError::Unauthorized);
            }

            total = total
                .checked_add(utxo.amount)
                .ok_or(AssetError::BalanceOverflow)?;
        }

        Ok(total)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetRollbackJournal {
    metadata: Vec<(AssetHash, Option<AssetMetadata>)>,

    supplies: Vec<(AssetHash, Option<Unit>)>,

    utxos: Vec<(AssetShareHash, Option<AssetShare>)>,

    nonces: Vec<(Address, Option<u64>)>,
}

fn outputs_total(outputs: &[AssetShareOutput]) -> Result<Unit, AssetError> {
    if outputs.is_empty() {
        return Err(AssetError::InvalidProgram);
    }

    let mut total = Unit::ZERO;

    for output in outputs {
        ensure_nonzero_asset_amount(output.amount)?;

        total = total
            .checked_add(output.amount)
            .ok_or(AssetError::BalanceOverflow)?;
    }

    Ok(total)
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