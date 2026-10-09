use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

use borsh::{BorshDeserialize, BorshSerialize};
use kernel::{
    common::{ChainContext, Height},
    monetary::coin::CoinShare,
    program::{AuthorizedProgramEnvelope, ProgramInvocationId, program_invocation_commitment},
};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

const DATABASE_FILE: &str = "xparq.redb";

// Reset-chain schema stores coin-only UTXOs and Program extension state/journals.
// Tagged CoinOutput recipients require a fresh database; old bytes are incompatible.
const SCHEMA_VERSION: u32 = 1;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("canonical_blocks");
const MEMPOOL: TableDefinition<u64, &[u8]> = TableDefinition::new("mempool");
const SNAPSHOTS: TableDefinition<u64, &[u8]> = TableDefinition::new("ledger_snapshots");
const SNAPSHOT_CHECKPOINTS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("snapshot_validation_checkpoints");
// Bump when admission rules change without a chain-spec hash change.
pub(crate) const SNAPSHOT_VALIDATION_VERSION: u32 = 1;

#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) struct SnapshotValidationCheckpoint {
    pub version: u32,
    pub genesis_hash: [u8; 32],
    pub chain_spec_hash: [u8; 32],
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub snapshot_hash: [u8; 32],
    pub history_digest: [u8; 32],
}

/// Non-consensus integrity fingerprint over every encoded body in a prefix.
pub(crate) fn advance_history_digest(previous: [u8; 32], height: u64, body: &[u8]) -> [u8; 32] {
    let mut frame = Vec::with_capacity(96);
    frame.extend_from_slice(b"xparq:validated-history:v1");
    frame.extend_from_slice(&previous);
    frame.extend_from_slice(&height.to_le_bytes());
    frame.extend_from_slice(&kernel::crypto::hash_bytes(body).0);
    kernel::crypto::hash_bytes(&frame).0
}
const AUXILIARY: TableDefinition<&str, &[u8]> = TableDefinition::new("auxiliary");

// Rebuildable, non-consensus runtime indexes.
const BLOCK_HASH_INDEX: TableDefinition<&[u8], u64> = TableDefinition::new("block_hash_index");

const TX_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("transaction_index");

const INDEX_TIP_HEIGHT_KEY: &str = "canonical_index_tip_height";
const INDEX_TIP_HASH_KEY: &str = "canonical_index_tip_hash";

const PROGRAM_ACTIVITY_INDEX: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("program_activity_index");
const COIN_ORIGIN_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("coin_origin_index");
const PROGRAM_PROGRAM_INDEX_VERSION_KEY: &str = "program_id_program_index_version";
const COIN_ORIGIN_INDEX_VERSION_KEY: &str = "coin_origin_index_version";

/// Rebuildable canonical-chain metadata, separate from consensus UTXO state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinOrigin {
    pub created_at: Option<ProgramInvocationId>,
    pub deploy_operation_id: Option<[u8; 32]>,
    pub created_in: Height,
}

pub const PROGRAM_ACTIVITY_CURSOR_SIZE: usize = 8 + 1 + 8;

#[derive(Debug)]
pub struct ProgramActivityPage {
    pub entries: Vec<(u64, Option<u64>)>,
    pub next_cursor: Option<[u8; PROGRAM_ACTIVITY_CURSOR_SIZE]>,
}

const EMPTY_INDEX_VALUE: &[u8] = &[];

#[derive(Debug, Clone, Copy)]
pub struct StoredProgramActivity {
    pub program_id: [u8; kernel::crypto::PROGRAM_ID_SIZE],
    pub transaction_index: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct StoredCanonicalBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
    pub transactions: Vec<[u8; 32]>,
    pub activities: Vec<StoredProgramActivity>,
}

#[derive(Debug, Clone)]
pub struct CanonicalIndexBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub bytes: Vec<u8>,
    pub transactions: Vec<[u8; 32]>,
    pub activities: Vec<StoredProgramActivity>,
}

pub fn read_program_activities_page(
    directory: &Path,
    program_id: [u8; kernel::crypto::PROGRAM_ID_SIZE],
    before: Option<[u8; PROGRAM_ACTIVITY_CURSOR_SIZE]>,
    limit: usize,
) -> Result<ProgramActivityPage, String> {
    if limit == 0 {
        return Err("program_id activity page limit must be greater than zero".into());
    }

    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin program_id activity page read: {error}"))?;

    let table = transaction
        .open_table(PROGRAM_ACTIVITY_INDEX)
        .map_err(|error| format!("open program_id activity index table: {error}"))?;

    let key_size = kernel::crypto::PROGRAM_ID_SIZE + PROGRAM_ACTIVITY_CURSOR_SIZE;

    let mut start = Vec::with_capacity(key_size);
    start.extend_from_slice(&program_id);
    start.resize(key_size, 0x00);

    let mut end = Vec::with_capacity(key_size);
    end.extend_from_slice(&program_id);

    match before {
        Some(cursor) => {
            end.extend_from_slice(&cursor);
        }

        None => {
            end.resize(key_size, 0xff);
        }
    }

    let height_start = kernel::crypto::PROGRAM_ID_SIZE;
    let height_end = height_start + 8;
    let kind_index = height_end;
    let transaction_start = kind_index + 1;
    let transaction_end = transaction_start + 8;

    let mut selected = Vec::with_capacity(limit.saturating_add(1));

    let entries = table
        .range(start.as_slice()..=end.as_slice())
        .map_err(|error| format!("range program_id activity page: {error}"))?;

    for entry in entries.rev() {
        let (key, _) =
            entry.map_err(|error| format!("read program_id activity page entry: {error}"))?;

        let key = key.value();

        if key.len() != key_size {
            return Err("stored program_id activity key has invalid length".into());
        }

        if key[..kernel::crypto::PROGRAM_ID_SIZE] != program_id {
            return Err("stored program_id activity key has invalid program_id prefix".into());
        }

        let cursor: [u8; PROGRAM_ACTIVITY_CURSOR_SIZE] = key[kernel::crypto::PROGRAM_ID_SIZE..]
            .try_into()
            .map_err(|_| "stored program_id activity cursor is invalid")?;

        // `before` is exclusive. The previous page's final entry
        // must not appear again.
        if before.is_some_and(|before| before == cursor) {
            continue;
        }

        let height = u64::from_be_bytes(
            key[height_start..height_end]
                .try_into()
                .map_err(|_| "stored program_id activity height is invalid")?,
        );

        let transaction_index = match key[kind_index] {
            0 => None,

            1 => Some(u64::from_be_bytes(
                key[transaction_start..transaction_end]
                    .try_into()
                    .map_err(|_| "stored program_id activity transaction index is invalid")?,
            )),

            _ => {
                return Err("stored program_id activity kind is invalid".into());
            }
        };

        selected.push(((height, transaction_index), cursor));

        if selected.len() > limit {
            break;
        }
    }

    let has_more = selected.len() > limit;

    if has_more {
        selected.pop();
    }

    let next_cursor = if has_more {
        selected.last().map(|(_, cursor)| *cursor)
    } else {
        None
    };

    let entries = selected.into_iter().map(|(entry, _)| entry).collect();

    Ok(ProgramActivityPage {
        entries,
        next_cursor,
    })
}

fn encode_program_activity_key(
    program_id: [u8; kernel::crypto::PROGRAM_ID_SIZE],
    height: u64,
    transaction_index: Option<u64>,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(kernel::crypto::PROGRAM_ID_SIZE + 8 + 1 + 8);

    key.extend_from_slice(&program_id);
    key.extend_from_slice(&height.to_be_bytes());

    match transaction_index {
        None => {
            key.push(0);
            key.extend_from_slice(&0_u64.to_be_bytes());
        }

        Some(transaction_index) => {
            key.push(1);
            key.extend_from_slice(&transaction_index.to_be_bytes());
        }
    }

    key
}

fn encode_transaction_location(height: u64, transaction_index: u64) -> [u8; 16] {
    let mut bytes = [0_u8; 16];

    bytes[..8].copy_from_slice(&height.to_le_bytes());
    bytes[8..].copy_from_slice(&transaction_index.to_le_bytes());

    bytes
}

type CachedDatabase = Option<(PathBuf, Arc<Database>)>;

static DATABASE: OnceLock<Mutex<CachedDatabase>> = OnceLock::new();
// Readers may outlive a change of the most-recently used directory. Weak handles
// let open() reuse those databases without retaining every historical directory.
static LIVE_DATABASES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Database>>>> = OnceLock::new();

pub fn canonical_index_tip(directory: &Path) -> Result<Option<(u64, [u8; 32])>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin canonical index metadata read: {error}"))?;

    let metadata = transaction
        .open_table(META)
        .map_err(|error| format!("open metadata table: {error}"))?;

    let height = metadata
        .get(INDEX_TIP_HEIGHT_KEY)
        .map_err(|error| format!("read canonical index tip height: {error}"))?
        .map(|value| value.value().to_vec());

    let hash = metadata
        .get(INDEX_TIP_HASH_KEY)
        .map_err(|error| format!("read canonical index tip hash: {error}"))?
        .map(|value| value.value().to_vec());

    let origin_version = metadata
        .get(COIN_ORIGIN_INDEX_VERSION_KEY)
        .map_err(|error| format!("read coin origin index version: {error}"))?
        .map(|value| value.value().to_vec());

    let program_version = metadata
        .get(PROGRAM_PROGRAM_INDEX_VERSION_KEY)
        .map_err(|e| format!("read program program_id index version: {e}"))?
        .map(|v| v.value().to_vec());
    if program_version.as_deref() != Some(&[1_u8][..])
        || origin_version.as_deref() != Some(&[1_u8][..])
    {
        return Ok(None);
    }

    let (Some(height), Some(hash)) = (height, hash) else {
        return Ok(None);
    };

    let Ok(height): Result<[u8; 8], _> = height.try_into() else {
        return Ok(None);
    };

    let Ok(hash): Result<[u8; 32], _> = hash.try_into() else {
        return Ok(None);
    };

    Ok(Some((u64::from_le_bytes(height), hash)))
}

pub fn read_block_height_by_hash(directory: &Path, hash: [u8; 32]) -> Result<Option<u64>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin block hash index read: {error}"))?;

    let table = transaction
        .open_table(BLOCK_HASH_INDEX)
        .map_err(|error| format!("open block hash index table: {error}"))?;

    Ok(table
        .get(hash.as_slice())
        .map_err(|error| format!("read block hash index: {error}"))?
        .map(|height| height.value()))
}

pub fn read_transaction_location(
    directory: &Path,
    hash: [u8; 32],
) -> Result<Option<(u64, u64)>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin transaction index read: {error}"))?;

    let table = transaction
        .open_table(TX_INDEX)
        .map_err(|error| format!("open transaction index table: {error}"))?;

    let Some(value) = table
        .get(hash.as_slice())
        .map_err(|error| format!("read transaction index: {error}"))?
    else {
        return Ok(None);
    };

    let bytes: [u8; 16] = value
        .value()
        .try_into()
        .map_err(|_| "stored transaction index location is invalid")?;

    let height = u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| "stored transaction height is invalid")?,
    );

    let transaction_index = u64::from_le_bytes(
        bytes[8..]
            .try_into()
            .map_err(|_| "stored transaction position is invalid")?,
    );

    Ok(Some((height, transaction_index)))
}

pub fn read_coin_origin(directory: &Path, share: CoinShare) -> Result<Option<CoinOrigin>, String> {
    let database = open(directory)?;
    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin coin origin read: {error}"))?;
    let table = transaction
        .open_table(COIN_ORIGIN_INDEX)
        .map_err(|error| format!("open coin origin index: {error}"))?;
    let Some(value) = table
        .get(share.as_bytes().as_slice())
        .map_err(|error| format!("read coin origin: {error}"))?
    else {
        return Ok(None);
    };
    CoinOrigin::try_from_slice(value.value())
        .map(Some)
        .map_err(|error| format!("decode coin origin: {error}"))
}

fn decode_canonical_block(bytes: &[u8]) -> Result<kernel::blockchain::Block, String> {
    kernel::crypto::canonical_decode(bytes)
        .map_err(|error| format!("decode canonical block for coin origins: {error}"))
}

fn genesis_context(bytes: &[u8]) -> Result<ChainContext, String> {
    let genesis = decode_canonical_block(bytes)?;
    if !genesis.is_genesis() {
        return Err("first canonical block is not genesis".into());
    }
    Ok(ChainContext::new(
        genesis
            .hash()
            .map_err(|error| error.to_string())?
            .into_bytes(),
    ))
}

fn block_coin_origins(
    block: &kernel::blockchain::Block,
    chain: ChainContext,
) -> Result<Vec<(CoinShare, CoinOrigin)>, String> {
    let mut origins = Vec::new();
    let height = block.height();
    if !block.is_genesis() {
        let origin = kernel::consensus::emission_origin(block)
            .map_err(|error| format!("derive emission coin origin: {error}"))?;
        origins.push((
            CoinShare::from_emission(&origin.into_bytes()),
            CoinOrigin {
                created_at: None,
                deploy_operation_id: None,
                created_in: height,
            },
        ));
    }
    for operation in block.operations() {
        let (spend, commitment, created_at, deploy_operation_id) = match operation {
            kernel::operation::BlockOperation::ProgramCall(transaction) => {
                let commitment = program_invocation_commitment(
                    transaction.signer,
                    &transaction.call,
                    &transaction.payment,
                    chain,
                )
                .map_err(|error| format!("derive program call coin origin: {error}"))?;
                let id = AuthorizedProgramEnvelope::Program(transaction.clone())
                    .program_invocation_id()
                    .map_err(|error| format!("derive transaction origin: {error}"))?;
                (&transaction.payment, commitment, Some(id), None)
            }
            kernel::operation::BlockOperation::DeployProgram(deploy) => {
                let commitment = deploy
                    .commitment(chain)
                    .map_err(|error| format!("derive deploy coin origin: {error}"))?;
                let id = operation
                    .id()
                    .map_err(|error| format!("derive deploy operation id: {error}"))?
                    .into_bytes();
                (&deploy.payment, commitment, None, Some(id))
            }
        };
        let (_, outputs) = spend
            .coin_parts()
            .ok_or("transaction has no coin outputs")?;
        let output_count = outputs.len() + usize::from(!spend.charges.miner_fee.is_zero());
        for index in 0..output_count {
            let index = u32::try_from(index).map_err(|_| "coin output index exceeds u32")?;
            origins.push((
                CoinShare::from_output(commitment.as_bytes(), index),
                CoinOrigin {
                    created_at,
                    deploy_operation_id,
                    created_in: height,
                },
            ));
        }
    }
    Ok(origins)
}

fn insert_coin_origins(
    table: &mut redb::Table<'_, &[u8], &[u8]>,
    block: &kernel::blockchain::Block,
    chain: ChainContext,
) -> Result<(), String> {
    for (share, origin) in block_coin_origins(block, chain)? {
        if table
            .get(share.as_bytes().as_slice())
            .map_err(|error| format!("inspect coin origin: {error}"))?
            .is_some()
        {
            return Err(format!("duplicate coin origin {share}"));
        }
        let bytes =
            borsh::to_vec(&origin).map_err(|error| format!("encode coin origin: {error}"))?;
        table
            .insert(share.as_bytes().as_slice(), bytes.as_slice())
            .map_err(|error| format!("insert coin origin: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod coin_origin_tests {
    use super::*;
    use kernel::{
        blockchain::{Block, Emission, GENESIS_TARGET_BITS},
        common::Nonce,
        crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key},
        monetary::coin::{CoinOutput, Zeno},
        program::{
            AccountAuthorization, AuthorizedProgramInvocation, CoinTransition,
            program_invocation_commitment,
        },
    };

    #[test]
    fn transaction_outputs_and_miner_fee_point_to_program_invocation_id() {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([5; 32]));
        let signer = program_id_from_public_key(&seed.public_key()).unwrap();
        let chain = ChainContext::new([7; kernel::crypto::HASH_SIZE]);
        let mut spend = CoinTransition::coin(
            signer,
            vec![CoinShare::from_bytes([1; kernel::crypto::HASH_SIZE])],
            vec![CoinOutput::new(signer, Zeno::from_zeno(10))],
        )
        .unwrap();
        spend.charges.miner_fee = Zeno::from_zeno(1);
        let call = extension::coin_program::transfer_call();
        let commitment = program_invocation_commitment(signer, &call, &spend, chain).unwrap();
        let tx = AuthorizedProgramEnvelope::Program(Box::new(AuthorizedProgramInvocation {
            signer,
            call,
            payment: spend.clone(),
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(commitment.as_bytes()),
            },
        }));
        let tx_id = tx.program_invocation_id().unwrap();
        let block = Block::from_protocol_operations(
            Height(1),
            kernel::crypto::PreviousHash([2; kernel::crypto::HASH_SIZE]),
            GENESIS_TARGET_BITS,
            Nonce(0),
            Some(Emission::new(
                signer,
                kernel::consensus::expected_emission_for_height(Height(1)),
            )),
            vec![tx.into()],
        )
        .unwrap();
        let origins = block_coin_origins(&block, chain).unwrap();
        let stored_call = &block.operations()[0].as_program_call().unwrap().call;
        let spend_commitment =
            program_invocation_commitment(signer, stored_call, &spend, chain).unwrap();
        for index in 0..2 {
            let share = CoinShare::from_output(spend_commitment.as_bytes(), index);
            assert_eq!(
                origins
                    .iter()
                    .find(|(id, _)| *id == share)
                    .map(|(_, origin)| *origin),
                Some(CoinOrigin {
                    created_at: Some(tx_id),
                    deploy_operation_id: None,
                    created_in: Height(1)
                }),
            );
        }
    }

    #[test]
    fn deploy_payment_outputs_point_to_deploy_operation() {
        use kernel::{
            operation::{AuthorizedDeployProgram, BlockOperation},
            program::DeployProgram,
        };
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([6; 32]));
        let owner = program_id_from_public_key(&seed.public_key()).unwrap();
        let chain = ChainContext::new([8; kernel::crypto::HASH_SIZE]);
        let mut payment = CoinTransition::coin(
            owner,
            vec![CoinShare::from_bytes([2; kernel::crypto::HASH_SIZE])],
            vec![CoinOutput::new(owner, Zeno::from_zeno(10))],
        )
        .unwrap();
        payment.charges.miner_fee = Zeno::ONE;
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend_from_slice(&7i64.to_le_bytes());
        code.push(3);
        let mut deploy = AuthorizedDeployProgram {
            deploy: DeployProgram {
                owner,
                nonce: 1,
                code: code.into(),
            },
            payment,
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(&[0; kernel::crypto::HASH_SIZE]),
            },
        };
        let commitment = deploy.commitment(chain).unwrap();
        deploy.authorization.signature = seed.sign(commitment.as_bytes());
        let operation = BlockOperation::DeployProgram(Box::new(deploy));
        let operation_id = operation.id().unwrap().into_bytes();
        let block = Block::from_protocol_operations(
            Height(1),
            kernel::crypto::PreviousHash([2; kernel::crypto::HASH_SIZE]),
            GENESIS_TARGET_BITS,
            Nonce(0),
            Some(Emission::new(
                owner,
                kernel::consensus::expected_emission_for_height(Height(1)),
            )),
            vec![operation],
        )
        .unwrap();
        let deploy = match &block.operations()[0] {
            BlockOperation::DeployProgram(deploy) => deploy,
            _ => unreachable!(),
        };
        let commitment = deploy.commitment(chain).unwrap();
        let origins = block_coin_origins(&block, chain).unwrap();
        for index in 0..2 {
            let share = CoinShare::from_output(commitment.as_bytes(), index);
            assert_eq!(
                origins
                    .iter()
                    .find(|(id, _)| *id == share)
                    .map(|(_, origin)| *origin),
                Some(CoinOrigin {
                    created_at: None,
                    deploy_operation_id: Some(operation_id),
                    created_in: Height(1),
                })
            );
        }
    }
}

#[cfg(test)]
pub fn read_program_activities(
    directory: &Path,
    program_id: [u8; kernel::crypto::PROGRAM_ID_SIZE],
) -> Result<Vec<(u64, Option<u64>)>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin program_id activity index read: {error}"))?;

    let table = transaction
        .open_table(PROGRAM_ACTIVITY_INDEX)
        .map_err(|error| format!("open program_id activity index table: {error}"))?;

    const ACTIVITY_SUFFIX_SIZE: usize = 8 + 1 + 8;

    let key_size = kernel::crypto::PROGRAM_ID_SIZE + ACTIVITY_SUFFIX_SIZE;

    let mut start = Vec::with_capacity(key_size);
    start.extend_from_slice(&program_id);
    start.resize(key_size, 0x00);

    let mut end = Vec::with_capacity(key_size);
    end.extend_from_slice(&program_id);
    end.resize(key_size, 0xff);

    let height_start = kernel::crypto::PROGRAM_ID_SIZE;
    let height_end = height_start + 8;
    let kind_index = height_end;
    let transaction_start = kind_index + 1;
    let transaction_end = transaction_start + 8;

    let mut activities = Vec::new();

    for entry in table
        .range(start.as_slice()..=end.as_slice())
        .map_err(|error| format!("range program_id activity index: {error}"))?
    {
        let (key, _) =
            entry.map_err(|error| format!("read program_id activity index entry: {error}"))?;

        let key = key.value();

        if key.len() != key_size {
            return Err("stored program_id activity key has invalid length".into());
        }

        if key[..kernel::crypto::PROGRAM_ID_SIZE] != program_id {
            return Err("stored program_id activity key has invalid program_id prefix".into());
        }

        let height = u64::from_be_bytes(
            key[height_start..height_end]
                .try_into()
                .map_err(|_| "stored program_id activity height is invalid")?,
        );

        let transaction_index = match key[kind_index] {
            0 => None,

            1 => Some(u64::from_be_bytes(
                key[transaction_start..transaction_end]
                    .try_into()
                    .map_err(|_| "stored program_id activity transaction index is invalid")?,
            )),

            _ => {
                return Err("stored program_id activity kind is invalid".into());
            }
        };

        activities.push((height, transaction_index));
    }

    Ok(activities)
}

pub fn rebuild_canonical_indexes_stream<F, I>(directory: &Path, blocks: F) -> Result<(), String>
where
    F: Fn() -> I,
    I: Iterator<Item = Result<CanonicalIndexBlock, String>>,
{
    let first = blocks()
        .next()
        .ok_or("cannot rebuild indexes from an empty chain")??;
    let chain = genesis_context(&first.bytes)?;
    drop(first);
    let database = open(directory)?;

    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin canonical index rebuild: {error}"))?;

    {
        let mut block_index = transaction
            .open_table(BLOCK_HASH_INDEX)
            .map_err(|error| format!("open block hash index table: {error}"))?;

        block_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear block hash index: {error}"))?;

        let mut tx_index = transaction
            .open_table(TX_INDEX)
            .map_err(|error| format!("open transaction index table: {error}"))?;

        tx_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear transaction index: {error}"))?;

        let mut activity_index = transaction
            .open_table(PROGRAM_ACTIVITY_INDEX)
            .map_err(|error| format!("open program_id activity index table: {error}"))?;

        activity_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear program_id activity index: {error}"))?;

        let mut origin_index = transaction
            .open_table(COIN_ORIGIN_INDEX)
            .map_err(|error| format!("open coin origin index: {error}"))?;
        origin_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear coin origin index: {error}"))?;

        let mut tip = None;
        for block in blocks() {
            let block = block?;
            let canonical = decode_canonical_block(&block.bytes)?;
            if canonical.height().0 != block.height
                || canonical.hash().map_err(|error| error.to_string())?.0 != block.hash
            {
                return Err("canonical blocks changed before index rebuild".into());
            }
            tip = Some((block.height, block.hash));
            insert_coin_origins(&mut origin_index, &canonical, chain)?;
            if block_index
                .get(block.hash.as_slice())
                .map_err(|error| format!("inspect block hash index: {error}"))?
                .is_some()
            {
                return Err(format!(
                    "duplicate canonical block hash at height {}",
                    block.height,
                ));
            }

            block_index
                .insert(block.hash.as_slice(), block.height)
                .map_err(|error| format!("insert block hash index: {error}"))?;

            for (position, hash) in block.transactions.iter().enumerate() {
                if tx_index
                    .get(hash.as_slice())
                    .map_err(|error| format!("inspect transaction index: {error}"))?
                    .is_some()
                {
                    return Err(format!(
                        "duplicate canonical transaction hash at height {}",
                        block.height,
                    ));
                }

                let position =
                    u64::try_from(position).map_err(|_| "transaction index exceeds u64")?;

                let location = encode_transaction_location(block.height, position);

                tx_index
                    .insert(hash.as_slice(), location.as_slice())
                    .map_err(|error| format!("insert transaction index: {error}"))?;
            }

            for activity in &block.activities {
                let key = encode_program_activity_key(
                    activity.program_id,
                    block.height,
                    activity.transaction_index,
                );

                activity_index
                    .insert(key.as_slice(), EMPTY_INDEX_VALUE)
                    .map_err(|error| format!("insert program_id activity index: {error}"))?;
            }
        }

        let (tip_height, tip_hash) = tip.ok_or("cannot rebuild indexes from an empty chain")?;
        let mut metadata = transaction
            .open_table(META)
            .map_err(|error| format!("open metadata table: {error}"))?;

        metadata
            .insert(INDEX_TIP_HEIGHT_KEY, tip_height.to_le_bytes().as_slice())
            .map_err(|error| format!("write canonical index tip height: {error}"))?;

        metadata
            .insert(INDEX_TIP_HASH_KEY, tip_hash.as_slice())
            .map_err(|error| format!("write canonical index tip hash: {error}"))?;
        metadata
            .insert(PROGRAM_PROGRAM_INDEX_VERSION_KEY, &[1_u8][..])
            .map_err(|e| format!("write program program_id index version: {e}"))?;
        metadata
            .insert(COIN_ORIGIN_INDEX_VERSION_KEY, &[1_u8][..])
            .map_err(|error| format!("write coin origin index version: {error}"))?;
    }

    transaction
        .commit()
        .map_err(|error| format!("commit canonical index rebuild: {error}"))
}

fn open(directory: &Path) -> Result<Arc<Database>, String> {
    let slot = DATABASE.get_or_init(|| Mutex::new(None));

    let mut slot = slot.lock().map_err(|_| "redb database cache is poisoned")?;

    if let Some((cached, database)) = slot.as_ref()
        && cached == directory
    {
        return Ok(Arc::clone(database));
    }

    let mut live = LIVE_DATABASES
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| "redb live handle registry is poisoned")?;
    live.retain(|_, handle| handle.strong_count() != 0);
    if let Some(database) = live.get(directory).and_then(Weak::upgrade) {
        *slot = Some((directory.to_path_buf(), Arc::clone(&database)));
        return Ok(database);
    }

    fs::create_dir_all(directory).map_err(|error| format!("create database directory: {error}"))?;

    let database = Arc::new(
        Database::create(directory.join(DATABASE_FILE))
            .map_err(|error| format!("open redb database: {error}"))?,
    );

    initialize(&database)?;
    live.insert(directory.to_path_buf(), Arc::downgrade(&database));

    *slot = Some((directory.to_path_buf(), Arc::clone(&database)));

    Ok(database)
}

fn initialize(database: &Database) -> Result<(), String> {
    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin redb schema transaction: {error}"))?;

    {
        let mut metadata = transaction
            .open_table(META)
            .map_err(|error| format!("open metadata table: {error}"))?;

        let stored_version = metadata
            .get("schema_version")
            .map_err(|error| format!("read schema version: {error}"))?
            .map(|version| version.value().to_vec());

        match stored_version {
            Some(version) => {
                let bytes: [u8; 4] = version
                    .try_into()
                    .map_err(|_| "stored redb schema version is invalid")?;

                if u32::from_le_bytes(bytes) != SCHEMA_VERSION {
                    return Err("redb schema version does not match this node".into());
                }
            }

            None => {
                metadata
                    .insert("schema_version", SCHEMA_VERSION.to_le_bytes().as_slice())
                    .map_err(|error| format!("write schema version: {error}"))?;
            }
        }

        let expected_genesis = kernel::genesis::EXPECTED_GENESIS_HASH.0;

        let stored_genesis = metadata
            .get("genesis_hash")
            .map_err(|error| format!("read stored genesis hash: {error}"))?
            .map(|hash| hash.value().to_vec());

        match stored_genesis {
            Some(hash) if hash.as_slice() != expected_genesis => {
                return Err("redb genesis hash does not match this node".into());
            }

            Some(_) => {}

            None => {
                metadata
                    .insert("genesis_hash", expected_genesis.as_slice())
                    .map_err(|error| format!("write genesis hash: {error}"))?;
            }
        }

        let expected_chain_spec = kernel::genesis::chain_spec_hash()
            .map_err(|error| format!("calculate chain specification: {error}"))?
            .0;

        let stored_chain_spec = metadata
            .get("chain_spec_hash")
            .map_err(|error| format!("read stored chain specification: {error}"))?
            .map(|hash| hash.value().to_vec());

        match stored_chain_spec {
            Some(hash) if hash.as_slice() != expected_chain_spec => {
                return Err("redb chain specification does not match this node".into());
            }

            Some(_) => {}

            None => {
                metadata
                    .insert("chain_spec_hash", expected_chain_spec.as_slice())
                    .map_err(|error| format!("write chain specification: {error}"))?;
            }
        }

        transaction
            .open_table(BLOCKS)
            .map_err(|error| format!("open blocks table: {error}"))?;

        transaction
            .open_table(MEMPOOL)
            .map_err(|error| format!("open mempool table: {error}"))?;

        transaction
            .open_table(SNAPSHOTS)
            .map_err(|error| format!("open snapshots table: {error}"))?;
        transaction
            .open_table(SNAPSHOT_CHECKPOINTS)
            .map_err(|error| format!("open snapshot checkpoints: {error}"))?;

        transaction
            .open_table(AUXILIARY)
            .map_err(|error| format!("open auxiliary table: {error}"))?;

        transaction
            .open_table(BLOCK_HASH_INDEX)
            .map_err(|error| format!("open block hash index table: {error}"))?;

        transaction
            .open_table(TX_INDEX)
            .map_err(|error| format!("open transaction index table: {error}"))?;

        transaction
            .open_table(PROGRAM_ACTIVITY_INDEX)
            .map_err(|error| format!("open program_id activity index table: {error}"))?;

        transaction
            .open_table(COIN_ORIGIN_INDEX)
            .map_err(|error| format!("open coin origin index table: {error}"))?;
    }

    transaction
        .commit()
        .map_err(|error| format!("commit redb schema: {error}"))
}

pub fn has_blocks(directory: &Path) -> Result<bool, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin block read: {error}"))?;

    let table = transaction
        .open_table(BLOCKS)
        .map_err(|error| format!("open blocks table: {error}"))?;

    Ok(table
        .len()
        .map_err(|error| format!("count blocks: {error}"))?
        > 0)
}

/// Read one canonical body without materializing the historical block log.
pub fn read_block_at_height(directory: &Path, height: u64) -> Result<Option<Vec<u8>>, String> {
    let database = open(directory)?;
    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin block read: {error}"))?;
    let table = transaction
        .open_table(BLOCKS)
        .map_err(|error| format!("open blocks table: {error}"))?;
    let value = table
        .get(height)
        .map_err(|error| format!("read block at height {height}: {error}"))?;
    value
        .map(|value| {
            let bytes = value.value();
            if bytes.is_empty() || bytes.len() > kernel::block::MAX_BLOCK_SIZE {
                return Err("stored block size is outside allowed range".to_string());
            }
            Ok(bytes.to_vec())
        })
        .transpose()
}

/// A pinned read transaction streams one body at a time from a stable DB generation.
pub struct CanonicalBodyReader {
    transaction: redb::ReadTransaction,
    _database: Arc<Database>,
    next: u64,
    last: Option<u64>,
}

impl CanonicalBodyReader {
    /// Read checkpoint metadata from the same pinned generation as the bodies.
    pub(crate) fn snapshot_checkpoint(
        &self,
        height: u64,
    ) -> Result<Option<SnapshotValidationCheckpoint>, String> {
        let table = self
            .transaction
            .open_table(SNAPSHOT_CHECKPOINTS)
            .map_err(|error| format!("open snapshot checkpoint read: {error}"))?;
        table
            .get(height)
            .map_err(|error| format!("read snapshot checkpoint: {error}"))?
            .map(|bytes| {
                borsh::from_slice(bytes.value())
                    .map_err(|error| format!("decode snapshot checkpoint: {error}"))
            })
            .transpose()
    }

    pub fn new(directory: &Path) -> Result<Self, String> {
        let database = open(directory)?;
        let transaction = database
            .begin_read()
            .map_err(|error| format!("begin body stream: {error}"))?;
        let last = {
            let table = transaction
                .open_table(BLOCKS)
                .map_err(|error| format!("open body stream: {error}"))?;
            table
                .last()
                .map_err(|error| format!("read body stream tip: {error}"))?
                .map(|(height, _)| height.value())
        };
        Ok(Self {
            transaction,
            _database: database,
            next: 0,
            last,
        })
    }
}

impl Iterator for CanonicalBodyReader {
    type Item = Result<Vec<u8>, String>;
    fn next(&mut self) -> Option<Self::Item> {
        let last = self.last?;
        if self.next > last {
            self.last = None;
            return None;
        }
        let height = self.next;
        if height == last {
            self.last = None;
        } else {
            self.next += 1;
        }
        let result = (|| {
            let table = self
                .transaction
                .open_table(BLOCKS)
                .map_err(|error| format!("open body stream: {error}"))?;
            let value = table
                .get(height)
                .map_err(|error| format!("read streamed body: {error}"))?
                .ok_or_else(|| format!("local block body missing at height {height}"))?;
            let bytes = value.value();
            if bytes.is_empty() || bytes.len() > kernel::block::MAX_BLOCK_SIZE {
                return Err(format!("local block size outside range at height {height}"));
            }
            Ok(bytes.to_vec())
        })();
        if result.is_err() {
            self.last = None;
        }
        Some(result)
    }
}

#[cfg(test)]
pub fn read_blocks(directory: &Path) -> Result<Vec<Vec<u8>>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin block read: {error}"))?;

    let table = transaction
        .open_table(BLOCKS)
        .map_err(|error| format!("open blocks table: {error}"))?;

    table
        .iter()
        .map_err(|error| format!("iterate blocks: {error}"))?
        .map(|entry| {
            entry
                .map(|(_, value)| value.value().to_vec())
                .map_err(|error| format!("read block: {error}"))
        })
        .collect()
}

pub fn append_block_and_replace_mempool(
    directory: &Path,
    block: &StoredCanonicalBlock,
    mempool: &[Vec<u8>],
) -> Result<(), String> {
    let database = open(directory)?;

    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin canonical commit: {error}"))?;

    {
        let mut blocks = transaction
            .open_table(BLOCKS)
            .map_err(|error| format!("open blocks table: {error}"))?;

        if blocks
            .get(block.height)
            .map_err(|error| format!("inspect block height: {error}"))?
            .is_some()
        {
            return Err(format!(
                "canonical block height {} already exists",
                block.height,
            ));
        }

        blocks
            .insert(block.height, block.bytes.as_slice())
            .map_err(|error| format!("insert block: {error}"))?;

        let genesis_bytes = blocks
            .get(0)
            .map_err(|error| format!("read genesis for coin origin: {error}"))?
            .ok_or("genesis block missing while indexing coin origin")?
            .value()
            .to_vec();
        let chain = genesis_context(&genesis_bytes)?;
        let canonical = decode_canonical_block(&block.bytes)?;
        if canonical.height().0 != block.height
            || canonical.hash().map_err(|error| error.to_string())?.0 != block.hash
        {
            return Err("stored block identity does not match coin origin source".into());
        }
        let mut origin_index = transaction
            .open_table(COIN_ORIGIN_INDEX)
            .map_err(|error| format!("open coin origin index: {error}"))?;
        insert_coin_origins(&mut origin_index, &canonical, chain)?;

        let mut block_index = transaction
            .open_table(BLOCK_HASH_INDEX)
            .map_err(|error| format!("open block hash index table: {error}"))?;

        block_index
            .insert(block.hash.as_slice(), block.height)
            .map_err(|error| format!("insert block hash index: {error}"))?;

        let mut tx_index = transaction
            .open_table(TX_INDEX)
            .map_err(|error| format!("open transaction index table: {error}"))?;

        let mut metadata = transaction
            .open_table(META)
            .map_err(|error| format!("open metadata table: {error}"))?;

        let previous_index_height = metadata
            .get(INDEX_TIP_HEIGHT_KEY)
            .map_err(|error| format!("read canonical index tip height: {error}"))?
            .map(|value| value.value().to_vec());

        let has_previous_hash = metadata
            .get(INDEX_TIP_HASH_KEY)
            .map_err(|error| format!("read canonical index tip hash: {error}"))?
            .is_some();

        let has_origin_version = metadata
            .get(COIN_ORIGIN_INDEX_VERSION_KEY)
            .map_err(|error| format!("read coin origin index version: {error}"))?
            .is_some_and(|value| value.value() == [1_u8]);

        let previous_index_height = previous_index_height
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map(u64::from_le_bytes);

        let indexes_were_complete = block.height == 0
            || (has_previous_hash
                && has_origin_version
                && previous_index_height.and_then(|height| height.checked_add(1))
                    == Some(block.height));

        if indexes_were_complete {
            metadata
                .insert(INDEX_TIP_HEIGHT_KEY, block.height.to_le_bytes().as_slice())
                .map_err(|error| format!("write canonical index tip height: {error}"))?;

            metadata
                .insert(INDEX_TIP_HASH_KEY, block.hash.as_slice())
                .map_err(|error| format!("write canonical index tip hash: {error}"))?;
            metadata
                .insert(COIN_ORIGIN_INDEX_VERSION_KEY, &[1_u8][..])
                .map_err(|error| format!("write coin origin index version: {error}"))?;
        }

        for (position, hash) in block.transactions.iter().enumerate() {
            let position = u64::try_from(position).map_err(|_| "transaction index exceeds u64")?;

            let location = encode_transaction_location(block.height, position);

            tx_index
                .insert(hash.as_slice(), location.as_slice())
                .map_err(|error| format!("insert transaction index: {error}"))?;
        }

        let mut activity_index = transaction
            .open_table(PROGRAM_ACTIVITY_INDEX)
            .map_err(|error| format!("open program_id activity index table: {error}"))?;

        for activity in &block.activities {
            let key = encode_program_activity_key(
                activity.program_id,
                block.height,
                activity.transaction_index,
            );

            activity_index
                .insert(key.as_slice(), EMPTY_INDEX_VALUE)
                .map_err(|error| format!("insert program_id activity index: {error}"))?;
        }

        let mut transactions = transaction
            .open_table(MEMPOOL)
            .map_err(|error| format!("open mempool table: {error}"))?;

        replace_ordered_values(&mut transactions, mempool, "mempool")?;
    }

    transaction
        .commit()
        .map_err(|error| format!("commit canonical block, indexes and mempool: {error}"))
}

/// Atomically persist canonical blocks from a repeatable streaming source.
/// Only one encoded block and its indexes are materialized at a time.
pub fn replace_blocks_and_mempool_stream<F, I>(
    directory: &Path,
    blocks: F,
    mempool: &[Vec<u8>],
) -> Result<(), String>
where
    F: Fn() -> I,
    I: Iterator<Item = Result<StoredCanonicalBlock, String>>,
{
    replace_blocks_mempool_and_snapshot_stream(directory, blocks, mempool, None)
}

pub(crate) fn replace_blocks_mempool_and_snapshot_stream<F, I>(
    directory: &Path,
    blocks: F,
    mempool: &[Vec<u8>],
    snapshot: Option<(u64, &[u8])>,
) -> Result<(), String>
where
    F: Fn() -> I,
    I: Iterator<Item = Result<StoredCanonicalBlock, String>>,
{
    let first = blocks()
        .next()
        .ok_or("canonical reorg cannot persist an empty chain")??;
    let chain = genesis_context(&first.bytes)?;
    drop(first);
    let database = open(directory)?;

    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin canonical reorg: {error}"))?;

    {
        let mut canonical = transaction
            .open_table(BLOCKS)
            .map_err(|error| format!("open blocks table: {error}"))?;

        let mut common_height = None;
        for block in blocks() {
            let block = block?;
            let matches = canonical
                .get(block.height)
                .map_err(|error| format!("compare canonical block: {error}"))?
                .is_some_and(|stored| stored.value() == block.bytes.as_slice());
            if !matches {
                break;
            }
            common_height = Some(block.height);
        }

        canonical
            .retain(|_, _| false)
            .map_err(|error| format!("clear canonical blocks: {error}"))?;

        let mut block_index = transaction
            .open_table(BLOCK_HASH_INDEX)
            .map_err(|error| format!("open block hash index table: {error}"))?;

        block_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear block hash index: {error}"))?;

        let mut tx_index = transaction
            .open_table(TX_INDEX)
            .map_err(|error| format!("open transaction index table: {error}"))?;

        tx_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear transaction index: {error}"))?;

        let mut activity_index = transaction
            .open_table(PROGRAM_ACTIVITY_INDEX)
            .map_err(|error| format!("open program_id activity index table: {error}"))?;

        activity_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear program_id activity index: {error}"))?;

        let mut origin_index = transaction
            .open_table(COIN_ORIGIN_INDEX)
            .map_err(|error| format!("open coin origin index: {error}"))?;
        origin_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear coin origin index: {error}"))?;

        let mut tip = None;
        for block in blocks() {
            let block = block?;
            let canonical_block = decode_canonical_block(&block.bytes)?;
            if canonical_block.height().0 != block.height
                || canonical_block.hash().map_err(|error| error.to_string())?.0 != block.hash
            {
                return Err("stored block identity does not match coin origin source".into());
            }
            insert_coin_origins(&mut origin_index, &canonical_block, chain)?;
            canonical
                .insert(block.height, block.bytes.as_slice())
                .map_err(|error| format!("insert canonical block: {error}"))?;

            block_index
                .insert(block.hash.as_slice(), block.height)
                .map_err(|error| format!("insert block hash index: {error}"))?;

            for (position, hash) in block.transactions.iter().enumerate() {
                let position =
                    u64::try_from(position).map_err(|_| "transaction index exceeds u64")?;

                let location = encode_transaction_location(block.height, position);

                tx_index
                    .insert(hash.as_slice(), location.as_slice())
                    .map_err(|error| format!("insert transaction index: {error}"))?;
            }

            tip = Some((block.height, block.hash));
            for activity in &block.activities {
                let key = encode_program_activity_key(
                    activity.program_id,
                    block.height,
                    activity.transaction_index,
                );

                activity_index
                    .insert(key.as_slice(), EMPTY_INDEX_VALUE)
                    .map_err(|error| format!("insert program_id activity index: {error}"))?;
            }
        }

        let (tip_height, tip_hash) = tip.ok_or("canonical reorg cannot persist an empty chain")?;

        let mut metadata = transaction
            .open_table(META)
            .map_err(|error| format!("open metadata table: {error}"))?;

        metadata
            .insert(INDEX_TIP_HEIGHT_KEY, tip_height.to_le_bytes().as_slice())
            .map_err(|error| format!("write canonical index tip height: {error}"))?;

        metadata
            .insert(INDEX_TIP_HASH_KEY, tip_hash.as_slice())
            .map_err(|error| format!("write canonical index tip hash: {error}"))?;
        metadata
            .insert(COIN_ORIGIN_INDEX_VERSION_KEY, &[1_u8][..])
            .map_err(|error| format!("write coin origin index version: {error}"))?;

        metadata
            .insert(PROGRAM_PROGRAM_INDEX_VERSION_KEY, &[1_u8][..])
            .map_err(|error| format!("write program program_id index version: {error}"))?;

        let mut transactions = transaction
            .open_table(MEMPOOL)
            .map_err(|error| format!("open mempool table: {error}"))?;

        replace_ordered_values(&mut transactions, mempool, "mempool")?;

        let mut snapshots = transaction
            .open_table(SNAPSHOTS)
            .map_err(|error| format!("open snapshots during reorg: {error}"))?;
        snapshots
            .retain(|height, _| common_height.is_some_and(|last| height <= last))
            .map_err(|error| format!("discard snapshots from replaced branch: {error}"))?;
        let mut checkpoints = transaction
            .open_table(SNAPSHOT_CHECKPOINTS)
            .map_err(|error| format!("open reorg snapshot checkpoints: {error}"))?;
        checkpoints
            .retain(|height, _| common_height.is_some_and(|last| height <= last))
            .map_err(|error| format!("discard replaced snapshot checkpoints: {error}"))?;
        if let Some((height, bytes)) = snapshot {
            checkpoints
                .remove(height)
                .map_err(|error| format!("invalidate recovery snapshot checkpoint: {error}"))?;
            if height != tip_height {
                return Err("recovery snapshot height does not match canonical tip".into());
            }
            snapshots
                .insert(height, bytes)
                .map_err(|error| format!("publish recovery snapshot: {error}"))?;
        }
    }

    transaction
        .commit()
        .map_err(|error| format!("commit canonical reorg, indexes and mempool: {error}"))
}

pub fn read_mempool(directory: &Path) -> Result<Vec<Vec<u8>>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin mempool read: {error}"))?;

    let table = transaction
        .open_table(MEMPOOL)
        .map_err(|error| format!("open mempool table: {error}"))?;

    table
        .iter()
        .map_err(|error| format!("iterate mempool: {error}"))?
        .map(|entry| {
            entry
                .map(|(_, value)| value.value().to_vec())
                .map_err(|error| format!("read mempool transaction: {error}"))
        })
        .collect()
}

/// Commit borrowed canonical mempool buffers without copying their payloads.
pub fn replace_mempool_slices(directory: &Path, values: &[&[u8]]) -> Result<(), String> {
    let database = open(directory)?;
    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin mempool write: {error}"))?;
    {
        let mut table = transaction
            .open_table(MEMPOOL)
            .map_err(|error| format!("open mempool table: {error}"))?;
        table
            .retain(|_, _| false)
            .map_err(|error| format!("clear mempool: {error}"))?;
        for (index, bytes) in values.iter().enumerate() {
            table
                .insert(index as u64, *bytes)
                .map_err(|error| format!("insert mempool value: {error}"))?;
        }
    }
    transaction
        .commit()
        .map_err(|error| format!("commit mempool: {error}"))
}

pub fn replace_mempool(directory: &Path, transactions: &[Vec<u8>]) -> Result<(), String> {
    let database = open(directory)?;

    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin mempool write: {error}"))?;

    {
        let mut table = transaction
            .open_table(MEMPOOL)
            .map_err(|error| format!("open mempool table: {error}"))?;

        replace_ordered_values(&mut table, transactions, "mempool")?;
    }

    transaction
        .commit()
        .map_err(|error| format!("commit mempool: {error}"))
}

fn replace_ordered_values(
    table: &mut redb::Table<'_, u64, &[u8]>,
    values: &[Vec<u8>],
    label: &str,
) -> Result<(), String> {
    table
        .retain(|_, _| false)
        .map_err(|error| format!("clear {label}: {error}"))?;

    for (index, bytes) in values.iter().enumerate() {
        table
            .insert(index as u64, bytes.as_slice())
            .map_err(|error| format!("insert {label} value: {error}"))?;
    }

    Ok(())
}

#[cfg(test)]
pub fn put_snapshot(directory: &Path, height: u64, bytes: &[u8]) -> Result<(), String> {
    put_snapshot_inner(directory, height, bytes, None)
}

/// Called only for a locally admitted ledger. Header comparison ties the write
/// transaction's exact body prefix to that ledger before checkpoint publication.
pub(crate) fn put_validated_snapshot(
    directory: &Path,
    height: u64,
    bytes: &[u8],
    headers: &[(Height, kernel::blockchain::Header)],
) -> Result<(), String> {
    put_snapshot_inner(directory, height, bytes, Some(headers))
}

fn put_snapshot_inner(
    directory: &Path,
    height: u64,
    bytes: &[u8],
    headers: Option<&[(Height, kernel::blockchain::Header)]>,
) -> Result<(), String> {
    let database = open(directory)?;

    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin snapshot write: {error}"))?;

    let checkpoint = if let Some(headers) = headers {
        if u64::try_from(headers.len()).ok() != height.checked_add(1) {
            return Err("snapshot validation header prefix is incomplete".into());
        }
        let bodies = transaction
            .open_table(BLOCKS)
            .map_err(|error| format!("open snapshot body prefix: {error}"))?;
        let mut digest = [0; 32];
        for (index, (expected_height, header)) in headers.iter().enumerate() {
            let index = index as u64;
            if expected_height.0 != index {
                return Err("snapshot validation header heights are not contiguous".into());
            }
            let body = bodies
                .get(index)
                .map_err(|error| format!("read snapshot body prefix: {error}"))?
                .ok_or_else(|| format!("snapshot body prefix missing at height {index}"))?;
            let decoded = kernel::codec::decode_block(body.value())
                .map_err(|error| format!("decode snapshot body prefix: {error}"))?;
            if decoded.height() != *expected_height || &decoded.header != header {
                return Err(format!("snapshot body prefix changed at height {index}"));
            }
            digest = advance_history_digest(digest, index, body.value());
        }
        let tip_hash = headers
            .last()
            .ok_or("empty snapshot body prefix")?
            .1
            .hash()
            .map_err(|error| error.to_string())?
            .0;
        let checkpoint = SnapshotValidationCheckpoint {
            version: SNAPSHOT_VALIDATION_VERSION,
            genesis_hash: kernel::genesis::EXPECTED_GENESIS_HASH.0,
            chain_spec_hash: kernel::genesis::chain_spec_hash()
                .map_err(|error| error.to_string())?
                .0,
            height,
            tip_hash,
            snapshot_hash: kernel::crypto::hash_bytes(bytes).0,
            history_digest: digest,
        };
        Some(borsh::to_vec(&checkpoint).map_err(|error| error.to_string())?)
    } else {
        None
    };

    {
        let mut table = transaction
            .open_table(SNAPSHOTS)
            .map_err(|error| format!("open snapshots table: {error}"))?;

        let mut checkpoints = transaction
            .open_table(SNAPSHOT_CHECKPOINTS)
            .map_err(|error| format!("open snapshot checkpoints write: {error}"))?;
        checkpoints
            .remove(height)
            .map_err(|error| format!("invalidate snapshot checkpoint: {error}"))?;
        if let Some(checkpoint) = &checkpoint {
            checkpoints
                .insert(height, checkpoint.as_slice())
                .map_err(|error| format!("publish snapshot checkpoint: {error}"))?;
        }

        table
            .insert(height, bytes)
            .map_err(|error| format!("insert snapshot: {error}"))?;

        while table
            .len()
            .map_err(|error| format!("count snapshots: {error}"))?
            > 2
        {
            let oldest = table
                .first()
                .map_err(|error| format!("read oldest snapshot: {error}"))?
                .map(|(key, _)| key.value());

            if let Some(oldest) = oldest {
                table
                    .remove(oldest)
                    .map_err(|error| format!("remove old snapshot: {error}"))?;
                checkpoints
                    .remove(oldest)
                    .map_err(|error| format!("remove old snapshot checkpoint: {error}"))?;
            }
        }
    }

    transaction
        .commit()
        .map_err(|error| format!("commit snapshot: {error}"))
}

pub fn snapshots_descending(directory: &Path) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin snapshot read: {error}"))?;

    let table = transaction
        .open_table(SNAPSHOTS)
        .map_err(|error| format!("open snapshots table: {error}"))?;

    let mut snapshots = table
        .iter()
        .map_err(|error| format!("iterate snapshots: {error}"))?
        .map(|entry| {
            entry
                .map(|(key, value)| (key.value(), value.value().to_vec()))
                .map_err(|error| format!("read snapshot: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    snapshots.reverse();

    Ok(snapshots)
}

pub fn auxiliary_get(directory: &Path, key: &str) -> Result<Option<Vec<u8>>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_read()
        .map_err(|error| format!("begin auxiliary read: {error}"))?;

    let table = transaction
        .open_table(AUXILIARY)
        .map_err(|error| format!("open auxiliary table: {error}"))?;

    Ok(table
        .get(key)
        .map_err(|error| format!("read auxiliary value: {error}"))?
        .map(|value| value.value().to_vec()))
}

pub fn auxiliary_put(directory: &Path, key: &str, value: &[u8]) -> Result<(), String> {
    let database = open(directory)?;

    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin auxiliary write: {error}"))?;

    {
        let mut table = transaction
            .open_table(AUXILIARY)
            .map_err(|error| format!("open auxiliary table: {error}"))?;

        table
            .insert(key, value)
            .map_err(|error| format!("write auxiliary value: {error}"))?;
    }

    transaction
        .commit()
        .map_err(|error| format!("commit auxiliary value: {error}"))
}

pub fn auxiliary_get_or_insert(
    directory: &Path,
    key: &str,
    value: &[u8],
) -> Result<Vec<u8>, String> {
    let database = open(directory)?;

    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin auxiliary initialization: {error}"))?;

    let result;

    {
        let mut table = transaction
            .open_table(AUXILIARY)
            .map_err(|error| format!("open auxiliary table: {error}"))?;

        let existing = table
            .get(key)
            .map_err(|error| format!("read auxiliary value: {error}"))?
            .map(|stored| stored.value().to_vec());

        result = match existing {
            Some(existing) => existing,

            None => {
                table
                    .insert(key, value)
                    .map_err(|error| format!("initialize auxiliary value: {error}"))?;

                value.to_vec()
            }
        };
    }

    transaction
        .commit()
        .map_err(|error| format!("commit auxiliary initialization: {error}"))?;

    Ok(result)
}

#[cfg(test)]
pub fn clear_canonical_indexes_for_test(directory: &Path) -> Result<(), String> {
    let database = open(directory)?;

    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin canonical index test clear: {error}"))?;

    {
        let mut block_index = transaction
            .open_table(BLOCK_HASH_INDEX)
            .map_err(|error| format!("open block hash index table: {error}"))?;

        block_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear block hash index: {error}"))?;

        let mut tx_index = transaction
            .open_table(TX_INDEX)
            .map_err(|error| format!("open transaction index table: {error}"))?;

        tx_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear transaction index: {error}"))?;

        let mut activity_index = transaction
            .open_table(PROGRAM_ACTIVITY_INDEX)
            .map_err(|error| format!("open program_id activity index table: {error}"))?;

        activity_index
            .retain(|_, _| false)
            .map_err(|error| format!("clear program_id activity index: {error}"))?;

        let mut metadata = transaction
            .open_table(META)
            .map_err(|error| format!("open metadata table: {error}"))?;

        metadata
            .remove(INDEX_TIP_HEIGHT_KEY)
            .map_err(|error| format!("remove canonical index tip height: {error}"))?;

        metadata
            .remove(INDEX_TIP_HASH_KEY)
            .map_err(|error| format!("remove canonical index tip hash: {error}"))?;
    }

    transaction
        .commit()
        .map_err(|error| format!("commit canonical index test clear: {error}"))
}

#[cfg(test)]
mod body_stream_tests {
    use super::*;

    #[test]
    fn missing_or_oversized_local_bodies_fail_without_returning_a_partial_log() {
        let directory = std::env::temp_dir().join(format!(
            "xparq-body-stream-errors-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let database = open(&directory).unwrap();
        let bytes = kernel::block::block_bytes(&kernel::genesis::genesis_block().unwrap()).unwrap();
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(BLOCKS).unwrap();
            table.insert(0, bytes.as_slice()).unwrap();
            table.insert(2, bytes.as_slice()).unwrap();
        }
        transaction.commit().unwrap();
        let mut reader = CanonicalBodyReader::new(&directory).unwrap();
        assert_eq!(reader.next().unwrap().unwrap(), bytes);
        assert!(reader.next().unwrap().unwrap_err().contains("missing"));
        assert!(reader.next().is_none());
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(BLOCKS).unwrap();
            table
                .insert(1, vec![0; kernel::block::MAX_BLOCK_SIZE + 1].as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
        assert!(
            read_block_at_height(&directory, 1)
                .unwrap_err()
                .contains("range")
        );
        let mut reader = CanonicalBodyReader::new(&directory).unwrap();
        assert!(reader.next().unwrap().is_ok());
        assert!(reader.next().unwrap().unwrap_err().contains("range"));
        assert!(reader.next().is_none());
    }
}

/// Release the singleton's handle before deleting an owned recovery database.
pub(crate) fn release_cached_database(directory: &Path) {
    if let Some(cache) = DATABASE.get() {
        if let Ok(mut cache) = cache.lock() {
            if cache.as_ref().is_some_and(|(path, _)| path == directory) {
                *cache = None;
            }
        }
    }
}

#[cfg(test)]
mod snapshot_checkpoint_tests {
    use super::*;

    fn fixture(
        label: &str,
    ) -> (
        PathBuf,
        StoredCanonicalBlock,
        Vec<(Height, kernel::blockchain::Header)>,
    ) {
        let directory = std::env::temp_dir().join(format!(
            "xparq-checkpoint-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let genesis = kernel::genesis::genesis_block().unwrap();
        let stored = StoredCanonicalBlock {
            height: 0,
            hash: genesis.hash().unwrap().0,
            bytes: kernel::codec::block_bytes(&genesis).unwrap(),
            transactions: vec![],
            activities: vec![],
        };
        append_block_and_replace_mempool(&directory, &stored, &[]).unwrap();
        (directory, stored, vec![(Height(0), genesis.header)])
    }

    #[test]
    fn checkpoint_and_snapshot_publish_atomically_and_reject_changed_prefix() {
        let (directory, stored, headers) = fixture("atomic");
        put_validated_snapshot(&directory, 0, b"first", &headers).unwrap();
        let pinned = CanonicalBodyReader::new(&directory).unwrap();
        let checkpoint = pinned.snapshot_checkpoint(0).unwrap().unwrap();
        assert_eq!(
            checkpoint.snapshot_hash,
            kernel::crypto::hash_bytes(b"first").0
        );
        assert_eq!(
            checkpoint.history_digest,
            advance_history_digest([0; 32], 0, &stored.bytes)
        );
        let mut wrong = headers.clone();
        wrong[0].1.nonce.0 += 1;
        assert!(put_validated_snapshot(&directory, 0, b"second", &wrong).is_err());
        assert_eq!(
            snapshots_descending(&directory).unwrap(),
            vec![(0, b"first".to_vec())]
        );
        assert_eq!(
            CanonicalBodyReader::new(&directory)
                .unwrap()
                .snapshot_checkpoint(0)
                .unwrap()
                .unwrap()
                .snapshot_hash,
            checkpoint.snapshot_hash
        );
        // A plain snapshot overwrite cannot keep an earlier validation record.
        put_snapshot(&directory, 0, b"unvalidated").unwrap();
        assert!(
            CanonicalBodyReader::new(&directory)
                .unwrap()
                .snapshot_checkpoint(0)
                .unwrap()
                .is_none()
        );
        // A pinned reader still sees the exact old checkpoint/body generation.
        assert_eq!(
            pinned
                .snapshot_checkpoint(0)
                .unwrap()
                .unwrap()
                .snapshot_hash,
            checkpoint.snapshot_hash
        );
        drop(pinned);
        release_cached_database(&directory);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovery_snapshot_publication_invalidates_earlier_checkpoint() {
        let (directory, stored, headers) = fixture("recovery");
        put_validated_snapshot(&directory, 0, b"first", &headers).unwrap();
        assert!(
            replace_blocks_mempool_and_snapshot_stream(
                &directory,
                || std::iter::once(Ok(stored.clone())),
                &[],
                Some((1, b"wrong height")),
            )
            .is_err()
        );
        assert!(
            CanonicalBodyReader::new(&directory)
                .unwrap()
                .snapshot_checkpoint(0)
                .unwrap()
                .is_some()
        );
        replace_blocks_mempool_and_snapshot_stream(
            &directory,
            || std::iter::once(Ok(stored.clone())),
            &[],
            Some((0, b"recovered")),
        )
        .unwrap();
        assert!(
            CanonicalBodyReader::new(&directory)
                .unwrap()
                .snapshot_checkpoint(0)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            snapshots_descending(&directory).unwrap(),
            vec![(0, b"recovered".to_vec())]
        );
        release_cached_database(&directory);
        fs::remove_dir_all(directory).unwrap();
    }
}
