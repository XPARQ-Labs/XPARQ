use std::collections::BTreeSet;

use crate::asset::{
    AssetError, AssetHash, AssetMetadata, AssetShare, AssetShareHash, AssetTransferOutput, Unit,
    asset_domain_hash, checked_asset_entry_weight, ensure_nonzero_asset_amount,
    ensure_unique_asset_inputs,
};
use crate::coin::{COIN_HASH_SIZE, CoinHash, Zeno};
use crate::common::{Authority, ExtensionHash, canonical_bytes, domain_hash};
use borsh::{BorshDeserialize, BorshSerialize};
use xparq_crypto::{ADDRESS_SIZE, Address, HASH_SIZE};

use crate::transaction::IntentError;

const COIN_INTENT_COMMITMENT_CONTEXT: &[u8] = b"XPARQ OnChain SpendIntent";

/// Genesis identity supplied by consensus, not serialized inside transactions.
///
/// The genesis hash commits the transaction signature to one chain. Individual
/// chain parameters must not be repeated or independently validated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct ChainContext {
    pub genesis_hash: [u8; HASH_SIZE],
}

impl ChainContext {
    pub const fn new(genesis_hash: [u8; HASH_SIZE]) -> Self {
        Self { genesis_hash }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum Recipient {
    Address(Address),
    BlockMiner,
    Burn,
    Extension(ExtensionHash),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct SpendOutput {
    pub output: Recipient,
    pub amount: Zeno,
}

impl SpendOutput {
    pub const fn new(recipient: Address, amount: Zeno) -> Self {
        Self {
            output: Recipient::Address(recipient),
            amount,
        }
    }

    pub const fn block_miner(amount: Zeno) -> Self {
        Self {
            output: Recipient::BlockMiner,
            amount,
        }
    }

    pub const fn burn(amount: Zeno) -> Self {
        Self {
            output: Recipient::Burn,
            amount,
        }
    }

    pub const fn extension(extension: ExtensionHash, amount: Zeno) -> Self {
        Self {
            output: Recipient::Extension(extension),
            amount,
        }
    }
}

/// XPQ UTXO spend intent. Input amounts and ownership come from ledger state.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinIntent {
    pub sender: Address,
    pub inputs: Vec<CoinHash>,
    pub outputs: Vec<SpendOutput>,
}

impl CoinIntent {
    pub fn new(
        sender: Address,
        inputs: Vec<CoinHash>,
        outputs: Vec<SpendOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            sender,
            inputs,
            outputs,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        validate_input_ids(&self.inputs)?;
        validate_public_outputs(&self.outputs, false)
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        chain_bound_bytes(chain, self)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        Ok(SpendCommitment(domain_hash(
            COIN_INTENT_COMMITMENT_CONTEXT,
            &[&self.signing_bytes(chain)?],
        )))
    }
}

fn validate_input_ids(inputs: &[CoinHash]) -> Result<(), IntentError> {
    if inputs.is_empty() {
        return Err(IntentError::EmptyInputs);
    }
    let mut unique = BTreeSet::new();
    if inputs.iter().any(|id| !unique.insert(*id)) {
        return Err(IntentError::DuplicateInput);
    }
    Ok(())
}

fn chain_bound_bytes<T: BorshSerialize>(
    chain: ChainContext,
    intent: &T,
) -> Result<Vec<u8>, IntentError> {
    canonical_bytes(&(chain, intent)).map_err(IntentError::Encoding)
}

fn validate_public_outputs(outputs: &[SpendOutput], allow_empty: bool) -> Result<(), IntentError> {
    if outputs.is_empty() && !allow_empty {
        return Err(IntentError::EmptyOutputs);
    }
    if outputs.iter().any(|output| output.amount.as_zeno() == 0) {
        return Err(IntentError::ZeroZeno);
    }
    if outputs
        .iter()
        .filter(|output| output.output == Recipient::BlockMiner)
        .count()
        > 1
    {
        return Err(IntentError::InvalidMinerOutput);
    }
    if outputs
        .iter()
        .filter(|output| output.output == Recipient::Burn)
        .count()
        > 1
    {
        return Err(IntentError::InvalidBurnOutput);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct SpendCommitment([u8; 32]);

impl SpendCommitment {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

const _: () = assert!(COIN_HASH_SIZE == 32);
const _: () = assert!(ADDRESS_SIZE > 0);
const ASSET_PROGRAM_COMMITMENT_CONTEXT: &[u8] = b"XPARQ Native Asset Program";

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum AssetInstruction {
    Register {
        name: String,
        symbol: String,
        decimals: u8,
        max_supply: Unit,
        initial_mint: Unit,
        mint_authority: Option<Authority<Address>>,
    },

    Mint {
        asset_id: AssetHash,
        recipient: Authority<Address>,
        amount: Unit,
    },

    Burn {
        asset_id: AssetHash,
        inputs: Vec<AssetShareHash>,
    },

    Transfer {
        asset_id: AssetHash,
        inputs: Vec<AssetShareHash>,
        outputs: Vec<AssetTransferOutput>,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AssetIntent {
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

impl AssetIntent {
    pub fn asset_id(&self) -> AssetHash {
        match &self.instruction {
            AssetInstruction::Register { symbol, .. } => AssetHash::derive(self.signer, symbol),

            AssetInstruction::Mint { asset_id, .. }
            | AssetInstruction::Burn { asset_id, .. }
            | AssetInstruction::Transfer { asset_id, .. } => *asset_id,
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

    pub fn validate_structure(&self) -> Result<(), AssetError> {
        match &self.instruction {
            AssetInstruction::Register {
                name,
                symbol,
                decimals,
                max_supply,
                initial_mint,
                mint_authority,
            } => {
                AssetMetadata {
                    name: name.clone(),
                    symbol: symbol.clone(),
                    decimals: *decimals,
                    max_supply: *max_supply,
                    creator: self.signer,
                    mint_authority: *mint_authority,
                }
                .validate()?;

                if *initial_mint == Unit::ZERO || *initial_mint > *max_supply {
                    return Err(AssetError::InvalidProgram);
                }
            }

            AssetInstruction::Mint { amount, .. } => {
                ensure_nonzero_asset_amount(*amount)?;
            }

            AssetInstruction::Burn { inputs, .. } => {
                if inputs.is_empty() {
                    return Err(AssetError::InvalidProgram);
                }

                ensure_unique_asset_inputs(inputs)?;
            }

            AssetInstruction::Transfer {
                inputs, outputs, ..
            } => {
                if inputs.is_empty() || outputs.is_empty() {
                    return Err(AssetError::InvalidProgram);
                }

                ensure_unique_asset_inputs(inputs)?;

                for output in outputs {
                    ensure_nonzero_asset_amount(output.amount)?;
                }
            }
        }

        self.nonce.checked_add(1).ok_or(AssetError::InvalidNonce)?;

        Ok(())
    }

    /// Calculates newly-created state weight.
    ///
    /// Consumed UTXOs do not count as newly-created state.
    pub fn created_state_weight_from_presence(
        &self,
        nonce_exists: bool,
    ) -> Result<u64, AssetError> {
        let mut weight = 0;

        if !nonce_exists {
            weight = checked_asset_entry_weight(weight, xparq_crypto::ADDRESS_SIZE, &0_u64)?;
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

                weight = checked_asset_entry_weight(weight, 32, &metadata)?;

                let object = AssetShare {
                    parent: AssetHash::derive(self.signer, symbol),
                    owner: Authority::Address(self.signer),
                    amount: *initial_mint,
                };

                weight = checked_asset_entry_weight(weight, 32, &object)?;
            }

            AssetInstruction::Mint {
                amount, recipient, ..
            } => {
                let object = AssetShare {
                    parent: self.asset_id(),
                    owner: *recipient,
                    amount: *amount,
                };

                weight = checked_asset_entry_weight(weight, 32, &object)?;
            }

            AssetInstruction::Burn { .. } => {}

            AssetInstruction::Transfer { outputs, .. } => {
                for output in outputs {
                    let object = AssetShare {
                        parent: self.asset_id(),
                        owner: output.recipient,
                        amount: output.amount,
                    };

                    weight = checked_asset_entry_weight(weight, 32, &object)?;
                }
            }
        }

        Ok(weight)
    }
}

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

    Ok(asset_domain_hash(
        ASSET_PROGRAM_COMMITMENT_CONTEXT,
        &[&bytes],
    ))
}
