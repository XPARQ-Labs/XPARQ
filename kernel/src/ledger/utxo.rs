use std::{collections::BTreeMap, error::Error, fmt};

use crate::asset::{
    AssetError, AssetHash, AssetMetadata, AssetShare, AssetShareHash, AssetShareOutput,
    AssetShareOwner, Unit, asset_domain_hash, checked_asset_entry_weight,
    ensure_nonzero_asset_amount, ensure_unique_asset_inputs,
};
use crate::coin::{Coin, CoinHash};
use crate::common::{Authority, ExtensionHash, Input, Output, canonical_bytes};
use crate::transaction::{AssetInstruction, AssetIntent};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, PublicKey};

/// Owner of a native coin UTXO.
///
/// Coin can be controlled by either an account address or an extension hash.
pub type CoinOwner = Authority<Address>;

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

impl UtxoRollbackJournal {
    /// Cancel outputs created and then spent inside this same transition.
    /// Only inputs that existed before the transition need restoring.
    pub(crate) fn record_consumed(&mut self, coin: CoinUtxo) {
        if let Some(index) = self
            .created_coin_ids
            .iter()
            .position(|id| *id == coin.coin.utxo)
        {
            self.created_coin_ids.remove(index);
        } else {
            self.consumed_coins.push(coin);
        }
    }
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

const ASSET_PROGRAM_COMMITMENT_CONTEXT: &[u8] = b"XPARQ Native Asset Program";
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

    pub fn extension_balance(
        &self,
        utxos: &UtxoSet,
        asset_id: AssetHash,
        program: ExtensionHash,
    ) -> Unit {
        utxos
            .assets()
            .map(|(_, utxo)| utxo)
            .filter(|utxo| utxo.parent == asset_id && utxo.owner == Authority::Extension(program))
            .fold(Unit::ZERO, |total, utxo| total.saturating_add(utxo.amount))
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
            .filter(|utxo| utxo.parent == asset_id && utxo.owner == Authority::Address(owner))
            .fold(Unit::ZERO, |total, utxo| total.saturating_add(utxo.amount))
    }

    pub fn program_transfer_plan(
        &self,
        utxos: &UtxoSet,
        program: ExtensionHash,
        asset_id: AssetHash,
        recipient: Address,
        amount: Unit,
    ) -> Result<(Vec<AssetShareHash>, Vec<AssetShareOutput>), AssetError> {
        ensure_nonzero_asset_amount(amount)?;
        let program_owner = Authority::Extension(program);
        let mut inputs = Vec::new();
        let mut total = Unit::ZERO;
        for (id, utxo) in utxos.assets() {
            if utxo.parent == asset_id && utxo.owner == program_owner {
                inputs.push(id);
                total = total
                    .checked_add(utxo.amount)
                    .ok_or(AssetError::BalanceOverflow)?;
                if total >= amount {
                    break;
                }
            }
        }
        if total < amount {
            return Err(AssetError::InsufficientBalance);
        }
        let mut outputs = vec![AssetShareOutput {
            recipient: Authority::Address(recipient),
            amount,
        }];
        if total > amount {
            outputs.push(AssetShareOutput {
                recipient: program_owner,
                amount: total
                    .checked_sub(amount)
                    .ok_or(AssetError::BalanceOverflow)?,
            });
        }
        Ok((inputs, outputs))
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

                let owner = Authority::Address(call.signer);

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
                    Authority::Address(call.signer),
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
            self.validate_inputs(utxos, asset_id, inputs, Authority::Address(signer))?;
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
            self.validate_inputs(utxos, asset_id, inputs, Authority::Address(signer))?;
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

    /// Mint under a trusted extension execution context.
    /// `execution_origin` must identify the invoking fee spend, chain and program;
    /// `execution_nonce` is the effect index within that invocation.
    pub fn apply_program_mint(
        &mut self,
        utxos: &mut UtxoSet,
        program: ExtensionHash,
        asset_id: AssetHash,
        recipient: AssetShareOwner,
        amount: Unit,
        execution_origin: [u8; 32],
        execution_nonce: u64,
    ) -> Result<AssetRollbackJournal, AssetError> {
        ensure_nonzero_asset_amount(amount)?;

        let metadata = self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;

        if metadata.mint_authority != Some(Authority::Extension(program)) {
            return Err(AssetError::Unauthorized);
        }

        let supply = self
            .supply(asset_id)
            .checked_add(amount)
            .filter(|supply| *supply <= metadata.max_supply)
            .ok_or(AssetError::SupplyOverflow)?;

        let commitment = program_commitment(
            execution_origin,
            program,
            asset_id,
            recipient,
            amount,
            execution_nonce,
        )?;

        let object_id = AssetShareHash::derive(asset_id, commitment, 0);
        if utxos.asset(object_id).is_some() {
            return Err(AssetError::ShareAlreadyExists);
        }

        let mut journal = AssetRollbackJournal::default();

        journal
            .supplies
            .push((asset_id, self.supplies.get(&asset_id).copied()));

        journal
            .utxos
            .push((object_id, utxos.asset(object_id).copied()));

        self.supplies.insert(asset_id, supply);

        utxos.insert_asset(
            object_id,
            AssetShare {
                parent: asset_id,
                owner: recipient,
                amount,
            },
        );

        Ok(journal)
    }

    pub fn program_mint_created_state_weight(
        &self,
        _utxos: &UtxoSet,
        program: ExtensionHash,
        asset_id: AssetHash,
        recipient: AssetShareOwner,
        amount: Unit,
    ) -> Result<u64, AssetError> {
        ensure_nonzero_asset_amount(amount)?;

        let metadata = self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;

        if metadata.mint_authority != Some(Authority::Extension(program)) {
            return Err(AssetError::Unauthorized);
        }

        self.supply(asset_id)
            .checked_add(amount)
            .filter(|supply| *supply <= metadata.max_supply)
            .ok_or(AssetError::SupplyOverflow)?;

        let object = AssetShare {
            parent: asset_id,
            owner: recipient,
            amount,
        };

        checked_asset_entry_weight(0, 32, &object)
    }

    /// Transfers UTXOs held by an extension.
    pub fn apply_program_transfer(
        &mut self,
        utxos: &mut UtxoSet,
        program: ExtensionHash,
        asset_id: AssetHash,
        inputs: &[AssetShareHash],
        outputs: &[AssetShareOutput],
        execution_origin: [u8; 32],
        execution_nonce: u64,
    ) -> Result<AssetRollbackJournal, AssetError> {
        ensure_nonempty_inputs(inputs)?;
        ensure_nonempty_outputs(outputs)?;
        ensure_unique_asset_inputs(inputs)?;

        let source = Authority::Extension(program);

        let input_total = self.validate_inputs(utxos, asset_id, inputs, source)?;

        let output_total = outputs_total(outputs)?;

        if input_total != output_total {
            return Err(AssetError::InvalidAmount);
        }

        let commitment = program_transfer_commitment(
            execution_origin,
            program,
            asset_id,
            inputs,
            outputs,
            execution_nonce,
        )?;

        // Reject collisions before consuming inputs or changing any state.
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

            let object_id = AssetShareHash::derive(asset_id, commitment, index);

            journal
                .utxos
                .push((object_id, utxos.asset(object_id).copied()));

            utxos.insert_asset(
                object_id,
                AssetShare {
                    parent: asset_id,
                    owner: output.recipient,
                    amount: output.amount,
                },
            );
        }

        Ok(journal)
    }

    pub fn program_transfer_created_state_weight(
        &self,
        utxos: &UtxoSet,
        program: ExtensionHash,
        asset_id: AssetHash,
        inputs: &[AssetShareHash],
        outputs: &[AssetShareOutput],
    ) -> Result<u64, AssetError> {
        let source = Authority::Extension(program);

        let input_total = self.validate_inputs(utxos, asset_id, inputs, source)?;

        let output_total = outputs_total(outputs)?;

        if input_total != output_total {
            return Err(AssetError::InvalidAmount);
        }

        let mut weight = 0;

        for output in outputs {
            let object = AssetShare {
                parent: asset_id,
                owner: output.recipient,
                amount: output.amount,
            };

            weight = checked_asset_entry_weight(weight, 32, &object)?;
        }

        Ok(weight)
    }

    /// Burns asset shares controlled by the trusted executing extension.
    pub fn apply_program_burn(
        &mut self,
        utxos: &mut UtxoSet,
        program: ExtensionHash,
        asset_id: AssetHash,
        amount: Unit,
        execution_origin: [u8; 32],
        execution_nonce: u64,
    ) -> Result<AssetRollbackJournal, AssetError> {
        ensure_nonzero_asset_amount(amount)?;
        self.metadata(asset_id).ok_or(AssetError::UnknownAsset)?;

        let owner = Authority::Extension(program);
        let mut inputs = Vec::new();
        let mut total = Unit::ZERO;
        for (id, share) in utxos.assets() {
            if share.parent == asset_id && share.owner == owner {
                inputs.push(id);
                total = total
                    .checked_add(share.amount)
                    .ok_or(AssetError::BalanceOverflow)?;
                if total >= amount {
                    break;
                }
            }
        }
        if total < amount {
            return Err(AssetError::InsufficientBalance);
        }
        let supply = self
            .supply(asset_id)
            .checked_sub(amount)
            .ok_or(AssetError::SupplyOverflow)?;

        let change = total.checked_sub(amount).ok_or(AssetError::InvalidAmount)?;
        let commitment = asset_domain_hash(
            b"XPARQ Native Asset Burn",
            &[&canonical_bytes(&(
                execution_origin,
                program,
                asset_id,
                &inputs,
                amount,
                execution_nonce,
            ))
            .map_err(|_| AssetError::Encoding)?],
        );
        let change_id = AssetShareHash::derive(asset_id, commitment, 0);
        if !change.is_zero() && utxos.asset(change_id).is_some() {
            return Err(AssetError::ShareAlreadyExists);
        }

        let mut journal = AssetRollbackJournal::default();
        journal
            .supplies
            .push((asset_id, self.supplies.get(&asset_id).copied()));
        for input in inputs {
            journal.utxos.push((input, utxos.asset(input).copied()));
            utxos.remove_asset(input);
        }
        if !change.is_zero() {
            journal.utxos.push((change_id, None));
            utxos.insert_asset(
                change_id,
                AssetShare {
                    parent: asset_id,
                    owner,
                    amount: change,
                },
            );
        }
        self.supplies.insert(asset_id, supply);
        Ok(journal)
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

                if metadata.mint_authority != Some(Authority::Address(call.signer)) {
                    return Err(AssetError::Unauthorized);
                }

                self.supply(*asset_id)
                    .checked_add(*amount)
                    .filter(|supply| *supply <= metadata.max_supply)
                    .ok_or(AssetError::SupplyOverflow)?;
            }

            AssetInstruction::Burn { asset_id, inputs } => {
                self.metadata(*asset_id).ok_or(AssetError::UnknownAsset)?;

                self.validate_inputs(utxos, *asset_id, inputs, Authority::Address(call.signer))?;
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

fn program_commitment(
    execution_origin: [u8; 32],
    program: ExtensionHash,
    asset_id: AssetHash,
    recipient: AssetShareOwner,
    amount: Unit,
    execution_nonce: u64,
) -> Result<[u8; 32], AssetError> {
    let bytes = canonical_bytes(&(
        execution_origin,
        program,
        asset_id,
        recipient,
        amount,
        execution_nonce,
    ))
    .map_err(|_| AssetError::Encoding)?;

    Ok(asset_domain_hash(
        ASSET_PROGRAM_COMMITMENT_CONTEXT,
        &[&bytes],
    ))
}

fn program_transfer_commitment(
    execution_origin: [u8; 32],
    program: ExtensionHash,
    asset_id: AssetHash,
    inputs: &[AssetShareHash],
    outputs: &[AssetShareOutput],
    execution_nonce: u64,
) -> Result<[u8; 32], AssetError> {
    let bytes = canonical_bytes(&(
        execution_origin,
        program,
        asset_id,
        inputs,
        outputs,
        execution_nonce,
    ))
    .map_err(|_| AssetError::Encoding)?;

    Ok(asset_domain_hash(
        ASSET_PROGRAM_COMMITMENT_CONTEXT,
        &[&bytes],
    ))
}

fn ensure_nonempty_inputs(inputs: &[AssetShareHash]) -> Result<(), AssetError> {
    if inputs.is_empty() {
        Err(AssetError::InvalidProgram)
    } else {
        Ok(())
    }
}

fn ensure_nonempty_outputs(outputs: &[AssetShareOutput]) -> Result<(), AssetError> {
    if outputs.is_empty() {
        Err(AssetError::InvalidProgram)
    } else {
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_asset_spend_consumes_shares_creates_change_and_rolls_back() {
        let signer = Address([3; crypto::ADDRESS_SIZE]);
        let recipient = Address([4; crypto::ADDRESS_SIZE]);
        let asset = AssetHash::derive(signer, "TST");
        let input = AssetShareHash::from_bytes([5; 32]);
        let mut assets = AssetState::default();
        assets.metadata.insert(
            asset,
            AssetMetadata {
                name: "Test".into(),
                symbol: "TST".into(),
                decimals: 0,
                max_supply: Unit::from_units(10),
                creator: signer,
                mint_authority: Some(Authority::Address(signer)),
            },
        );
        let mut utxos = UtxoSet::default();
        utxos.insert_asset(
            input,
            AssetShare {
                parent: asset,
                owner: Authority::Address(signer),
                amount: Unit::from_units(10),
            },
        );
        let outputs = [
            AssetShareOutput {
                recipient: Authority::Address(recipient),
                amount: Unit::from_units(6),
            },
            AssetShareOutput {
                recipient: Authority::Address(signer),
                amount: Unit::from_units(4),
            },
        ];
        let journal = assets
            .apply_user_transfer(&mut utxos, signer, asset, &[input], &outputs, [6; 32])
            .unwrap();
        assert!(utxos.asset(input).is_none());
        assert_eq!(
            assets.account_balance(&utxos, asset, recipient),
            Unit::from_units(6)
        );
        assert_eq!(
            assets.account_balance(&utxos, asset, signer),
            Unit::from_units(4)
        );
        assets.rollback(&mut utxos, journal);
        assert_eq!(utxos.asset(input).unwrap().amount, Unit::from_units(10));
        assert_eq!(assets.account_balance(&utxos, asset, recipient), Unit::ZERO);
    }

    #[test]
    fn canonical_utxo_storage_does_not_duplicate_coin_id() {
        let id = CoinHash::from_bytes([1; CoinHash::SIZE]);
        let mut coins = UtxoSet::default();
        coins
            .insert(CoinUtxo {
                coin: Coin::new(id, crate::coin::Zeno::from_zeno(2)),
                owner: Authority::Address(Address([3; crypto::ADDRESS_SIZE])),
            })
            .unwrap();
        let coin_bytes = crate::common::canonical_bytes(&coins).unwrap();
        assert_eq!(coin_bytes.len(), 4 + 1 + 32 + 1 + 8 + 1 + 20);
        assert_eq!(
            coins.get(&id).unwrap().coin,
            Coin::new(id, crate::coin::Zeno::from_zeno(2))
        );
    }

    #[test]
    fn one_utxo_map_indexes_coin_and_asset_outputs() {
        let coin_id = CoinHash::from_bytes([1; CoinHash::SIZE]);
        let asset_id = AssetHash::from_bytes([2; 32]);
        let share_id = AssetShareHash::from_bytes([3; 32]);
        let owner = Authority::Address(Address([4; crypto::ADDRESS_SIZE]));
        let mut utxos = UtxoSet::default();

        utxos
            .insert(CoinUtxo {
                coin: Coin::new(coin_id, crate::coin::Zeno::from_zeno(5)),
                owner,
            })
            .unwrap();
        utxos.insert_asset(
            share_id,
            AssetShare {
                parent: asset_id,
                owner,
                amount: Unit::from_units(7),
            },
        );

        assert_eq!(utxos.len(), 2);
        assert_eq!(utxos.get(&coin_id).unwrap().coin.amount.as_zeno(), 5);
        assert_eq!(utxos.asset(share_id).unwrap().amount, Unit::from_units(7));
    }

    #[test]
    fn extension_asset_burn_reduces_supply_and_rolls_back() {
        let program = ExtensionHash::derive("test.asset.burner");
        let asset_id = AssetHash::from_bytes([0x51; 32]);
        let share_id = AssetShareHash::from_bytes([0x52; 32]);
        let mut assets = AssetState::default();
        assets.metadata.insert(
            asset_id,
            AssetMetadata::new(
                "Burnable".into(),
                "BRN".into(),
                0,
                Unit::from_units(10),
                Address::ZERO,
                Some(Authority::Extension(program)),
            )
            .unwrap(),
        );
        assets.supplies.insert(asset_id, Unit::from_units(10));
        let mut utxos = UtxoSet::default();
        utxos.insert_asset(
            share_id,
            AssetShare::new(
                asset_id,
                Unit::from_units(10),
                Authority::Extension(program),
            ),
        );

        let journal = assets
            .apply_program_burn(
                &mut utxos,
                program,
                asset_id,
                Unit::from_units(4),
                [0x53; 32],
                0,
            )
            .unwrap();
        assert_eq!(assets.supply(asset_id), Unit::from_units(6));
        assert_eq!(
            utxos
                .assets()
                .filter(|(_, share)| share.parent == asset_id)
                .map(|(_, share)| share.amount)
                .fold(Unit::ZERO, |total, amount| total
                    .checked_add(amount)
                    .unwrap()),
            Unit::from_units(6)
        );

        assets.rollback(&mut utxos, journal);
        assert_eq!(assets.supply(asset_id), Unit::from_units(10));
        assert_eq!(utxos.asset(share_id).unwrap().amount, Unit::from_units(10));
    }

    #[test]
    fn account_registry_stores_account_keys() {
        let signing = crypto::SigningSeed::new(crypto::Signature::Falcon512, [21; 32]);
        let public_key = signing.public_key();
        let address = crypto::address_from_public_key(&public_key);
        let mut registry = AccountKeyRegistry::default();

        assert!(
            registry
                .register_account(address, public_key.clone())
                .unwrap()
        );
        assert_eq!(registry.get_account(&address), Some(&public_key));
        assert_eq!(registry.remove_account(&address).unwrap(), public_key);
    }
}
