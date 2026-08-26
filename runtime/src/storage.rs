use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

const DATABASE_FILE: &str = "xparq.redb";
// Version 4 replaces scheme-specific account registries with one profile registry.
const SCHEMA_VERSION: u32 = 4;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("canonical_blocks");
const MEMPOOL: TableDefinition<u64, &[u8]> = TableDefinition::new("mempool");
const SNAPSHOTS: TableDefinition<u64, &[u8]> = TableDefinition::new("ledger_snapshots");
const AUXILIARY: TableDefinition<&str, &[u8]> = TableDefinition::new("auxiliary");

type CachedDatabase = Option<(PathBuf, Arc<Database>)>;

static DATABASE: OnceLock<Mutex<CachedDatabase>> = OnceLock::new();

fn open(directory: &Path) -> Result<Arc<Database>, String> {
    let slot = DATABASE.get_or_init(|| Mutex::new(None));
    let mut slot = slot.lock().map_err(|_| "redb database cache is poisoned")?;
    if let Some((cached, database)) = slot.as_ref()
        && cached == directory
    {
        return Ok(Arc::clone(database));
    }
    fs::create_dir_all(directory).map_err(|error| format!("create database directory: {error}"))?;
    let database = Arc::new(
        Database::create(directory.join(DATABASE_FILE))
            .map_err(|error| format!("open redb database: {error}"))?,
    );
    initialize(&database)?;
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
        let expected_genesis = xparq::genesis::EXPECTED_GENESIS_HASH.0;
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
        let expected_chain_spec = xparq::genesis::chain_spec_hash()
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
            .open_table(AUXILIARY)
            .map_err(|error| format!("open auxiliary table: {error}"))?;
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

pub fn append_block(directory: &Path, height: u64, bytes: &[u8]) -> Result<(), String> {
    let database = open(directory)?;
    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin block write: {error}"))?;
    {
        let mut table = transaction
            .open_table(BLOCKS)
            .map_err(|error| format!("open blocks table: {error}"))?;
        if table
            .get(height)
            .map_err(|error| format!("inspect block height: {error}"))?
            .is_some()
        {
            return Err(format!("canonical block height {height} already exists"));
        }
        table
            .insert(height, bytes)
            .map_err(|error| format!("insert block: {error}"))?;
    }
    transaction
        .commit()
        .map_err(|error| format!("commit block: {error}"))
}

pub fn append_block_and_replace_mempool(
    directory: &Path,
    height: u64,
    block: &[u8],
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
            .get(height)
            .map_err(|error| format!("inspect block height: {error}"))?
            .is_some()
        {
            return Err(format!("canonical block height {height} already exists"));
        }
        blocks
            .insert(height, block)
            .map_err(|error| format!("insert block: {error}"))?;
        let mut transactions = transaction
            .open_table(MEMPOOL)
            .map_err(|error| format!("open mempool table: {error}"))?;
        replace_ordered_values(&mut transactions, mempool, "mempool")?;
    }
    transaction
        .commit()
        .map_err(|error| format!("commit canonical block and mempool: {error}"))
}

pub fn replace_blocks_and_mempool(
    directory: &Path,
    blocks: &[(u64, Vec<u8>)],
    mempool: &[Vec<u8>],
) -> Result<(), String> {
    let database = open(directory)?;
    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin canonical reorg: {error}"))?;
    {
        let mut canonical = transaction
            .open_table(BLOCKS)
            .map_err(|error| format!("open blocks table: {error}"))?;
        canonical
            .retain(|_, _| false)
            .map_err(|error| format!("clear canonical blocks: {error}"))?;
        for (height, bytes) in blocks {
            canonical
                .insert(*height, bytes.as_slice())
                .map_err(|error| format!("insert canonical block: {error}"))?;
        }
        let mut transactions = transaction
            .open_table(MEMPOOL)
            .map_err(|error| format!("open mempool table: {error}"))?;
        replace_ordered_values(&mut transactions, mempool, "mempool")?;
    }
    transaction
        .commit()
        .map_err(|error| format!("commit canonical reorg and mempool: {error}"))
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

pub fn put_snapshot(directory: &Path, height: u64, bytes: &[u8]) -> Result<(), String> {
    let database = open(directory)?;
    let transaction = database
        .begin_write()
        .map_err(|error| format!("begin snapshot write: {error}"))?;
    {
        let mut table = transaction
            .open_table(SNAPSHOTS)
            .map_err(|error| format!("open snapshots table: {error}"))?;
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
