use crate::runtime::params::{ADDRESS_SIZE, HASH_SIZE, STORAGE_VERSION};
use crate::runtime::recovery::{
    RollbackIssue, RollbackIssueId, RollbackProofContext, RollbackProofContextId,
};
use crate::runtime::storage::error::StorageError;
use borsh::{BorshDeserialize, BorshSerialize};
use lmdb::{Cursor, Database, DatabaseFlags, Environment, Transaction, WriteFlags};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::{fs, time};
use xparq::block::{Block, BlockHeader, BlockHeight, Height};
use xparq::codec::{block_bytes, decode_block};
use xparq::crypto::{Address, BlockHash, Hash, TransactionHash};
use xparq::event::{EventId, ProtocolEvent, ProtocolEventKind};
use xparq::ledger::Ledger;
use xparq::qcash::recovery::ChainHeader;
use xparq::state::{
    Account, QCashCoinId, QCashJournalState, QCashUtxo, QCashUtxoSet, XpqCoinId, XpqUtxo,
    XpqUtxoSet,
};
use xparq::transaction::{SignedProtocolTransaction, SignedTransfer, TransactionFamily};

const BLOCKS_BY_HEIGHT: &str = "blocks_by_height";
const BLOCKS_BY_HASH: &str = "blocks_by_hash";
const HEADERS_BY_HEIGHT: &str = "headers_by_height";
const ACCOUNTS: &str = "accounts";
const GENESIS_ACCOUNTS: &str = "genesis_accounts";
const TX_INDEX: &str = "tx_index";
const WTX_INDEX: &str = "wtx_index";
const ADDRESS_TX_INDEX: &str = "address_tx_index";
const MINER_BLOCK_INDEX: &str = "miner_block_index";
const META: &str = "meta";
const PROTOCOL_STATE: &str = "protocol_state";
const STATE_DIFFS: &str = "state_diffs";
const EVENTS_BY_ID: &str = "events_by_id";
const BLOCK_EVENT_INDEX: &str = "block_event_index";
const TRANSACTION_EVENT_INDEX: &str = "transaction_event_index";
const ADDRESS_EVENT_INDEX: &str = "address_event_index";
const ROLLBACK_ISSUES: &str = "rollback_issues";
const ROLLBACK_PROOF_CONTEXTS: &str = "rollback_proof_contexts";
const PROTOCOL_STATE_KEY: &[u8] = b"current";
const TIP_HEIGHT_KEY: &[u8] = b"tip_height";
const TIP_HASH_KEY: &[u8] = b"tip_hash";
const STORAGE_VERSION_KEY: &[u8] = b"storage_version";
const CHECKPOINT_HEIGHT_KEY: &[u8] = b"checkpoint_height";
#[cfg(target_pointer_width = "64")]
const DEFAULT_LMDB_MAP_SIZE: usize = 4 * 1024 * 1024 * 1024;
#[cfg(not(target_pointer_width = "64"))]
const DEFAULT_LMDB_MAP_SIZE: usize = 1024 * 1024 * 1024;
const STATE_SNAPSHOT_INTERVAL: u64 = 2_048;

fn lmdb_map_size() -> usize {
    std::env::var("XPARQ_LMDB_MAP_SIZE_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 64 * 1024 * 1024)
        .unwrap_or(DEFAULT_LMDB_MAP_SIZE)
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionLocation {
    pub block_height: BlockHeight,
    pub block_hash: BlockHash,
    pub tx_index: u32,
    pub family: TransactionFamily,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressTransactionLocation {
    pub tx_hash: TransactionHash,
    pub block_height: BlockHeight,
    pub block_hash: BlockHash,
    pub tx_index: u32,
    pub sent: bool,
    pub family: TransactionFamily,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinerBlockLocation {
    pub block_height: BlockHeight,
    pub block_hash: BlockHash,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
struct StoredProtocolState {
    xpq_utxos: XpqUtxoSet,
    qcash_utxos: QCashUtxoSet,
    events_by_block: BTreeMap<BlockHash, Vec<ProtocolEvent>>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
struct StoredStateDiff {
    block_hash: BlockHash,
    removed_xpq: Vec<XpqCoinId>,
    upserted_xpq: Vec<XpqUtxo>,
    removed_qcash: Vec<QCashCoinId>,
    upserted_qcash: Vec<QCashUtxo>,
    qcash_journal_state: QCashJournalState,
    events: Vec<ProtocolEvent>,
}

impl StoredProtocolState {
    fn from_ledger(ledger: &Ledger) -> Self {
        Self {
            xpq_utxos: ledger.xpq_utxos.clone(),
            qcash_utxos: ledger.qcash_utxos.clone(),
            events_by_block: ledger.events_by_block.clone(),
        }
    }

    fn restore(self, ledger: &mut Ledger) {
        ledger.xpq_utxos = self.xpq_utxos;
        ledger.qcash_utxos = self.qcash_utxos;
        ledger.events_by_block = self.events_by_block;
    }
}

fn protocol_state_diff(
    previous: &Ledger,
    current: &Ledger,
    block_hash: BlockHash,
) -> StoredStateDiff {
    let previous_xpq = previous.xpq_utxos.coins();
    let current_xpq = current.xpq_utxos.coins();
    let removed_xpq = previous_xpq
        .keys()
        .filter(|id| !current_xpq.contains_key(id))
        .copied()
        .collect();
    let upserted_xpq = current_xpq
        .iter()
        .filter(|(id, coin)| previous_xpq.get(id) != Some(*coin))
        .map(|(_, coin)| coin.clone())
        .collect();

    let previous_qcash = previous
        .qcash_utxos
        .coins()
        .map(|coin| (coin.id, coin))
        .collect::<BTreeMap<_, _>>();
    let current_qcash = current
        .qcash_utxos
        .coins()
        .map(|coin| (coin.id, coin))
        .collect::<BTreeMap<_, _>>();
    let removed_qcash = previous_qcash
        .keys()
        .filter(|id| !current_qcash.contains_key(id))
        .copied()
        .collect();
    let upserted_qcash = current_qcash
        .iter()
        .filter(|(id, coin)| previous_qcash.get(id) != Some(*coin))
        .map(|(_, coin)| (*coin).clone())
        .collect();

    StoredStateDiff {
        block_hash,
        removed_xpq,
        upserted_xpq,
        removed_qcash,
        upserted_qcash,
        qcash_journal_state: current.qcash_utxos.persistence_journal_state(),
        events: current.events_for_block(&block_hash).to_vec(),
    }
}

#[derive(Clone, Debug)]
pub struct Storage {
    env: Arc<Environment>,
    blocks_by_height: Database,
    blocks_by_hash: Database,
    headers_by_height: Database,
    accounts: Database,
    genesis_accounts: Database,
    tx_index: Database,
    wtx_index: Database,
    address_tx_index: Database,
    miner_block_index: Database,
    protocol_state: Database,
    state_diffs: Database,
    events_by_id: Database,
    block_event_index: Database,
    transaction_event_index: Database,
    address_event_index: Database,
    rollback_issues: Database,
    rollback_proof_contexts: Database,
    meta: Database,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        fs::create_dir_all(path.as_ref()).map_err(StorageError::from_std_io)?;
        let env = Arc::new(
            Environment::new()
                .set_max_dbs(20)
                .set_map_size(lmdb_map_size())
                .open(path.as_ref())?,
        );
        let storage = Self::from_env(env)?;
        storage.ensure_storage_version()?;
        Ok(storage)
    }

    pub fn temporary() -> Result<Self, StorageError> {
        let nanos = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "xparq-fullnode-lmdb-{}-{nanos}",
            std::process::id()
        ));
        Self::open(path)
    }

    fn from_env(env: Arc<Environment>) -> Result<Self, StorageError> {
        Ok(Self {
            blocks_by_height: env.create_db(Some(BLOCKS_BY_HEIGHT), DatabaseFlags::empty())?,
            blocks_by_hash: env.create_db(Some(BLOCKS_BY_HASH), DatabaseFlags::empty())?,
            headers_by_height: env.create_db(Some(HEADERS_BY_HEIGHT), DatabaseFlags::empty())?,
            accounts: env.create_db(Some(ACCOUNTS), DatabaseFlags::empty())?,
            genesis_accounts: env.create_db(Some(GENESIS_ACCOUNTS), DatabaseFlags::empty())?,
            tx_index: env.create_db(Some(TX_INDEX), DatabaseFlags::empty())?,
            wtx_index: env.create_db(Some(WTX_INDEX), DatabaseFlags::empty())?,
            address_tx_index: env.create_db(Some(ADDRESS_TX_INDEX), DatabaseFlags::empty())?,
            miner_block_index: env.create_db(Some(MINER_BLOCK_INDEX), DatabaseFlags::empty())?,
            protocol_state: env.create_db(Some(PROTOCOL_STATE), DatabaseFlags::empty())?,
            state_diffs: env.create_db(Some(STATE_DIFFS), DatabaseFlags::empty())?,
            events_by_id: env.create_db(Some(EVENTS_BY_ID), DatabaseFlags::empty())?,
            block_event_index: env.create_db(Some(BLOCK_EVENT_INDEX), DatabaseFlags::empty())?,
            transaction_event_index: env
                .create_db(Some(TRANSACTION_EVENT_INDEX), DatabaseFlags::empty())?,
            address_event_index: env
                .create_db(Some(ADDRESS_EVENT_INDEX), DatabaseFlags::empty())?,
            rollback_issues: env.create_db(Some(ROLLBACK_ISSUES), DatabaseFlags::empty())?,
            rollback_proof_contexts: env
                .create_db(Some(ROLLBACK_PROOF_CONTEXTS), DatabaseFlags::empty())?,
            meta: env.create_db(Some(META), DatabaseFlags::empty())?,
            env,
        })
    }

    pub fn load_storage_version(&self) -> Result<Option<u8>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        read_value(&txn, self.meta, STORAGE_VERSION_KEY)
    }

    fn save_storage_version(&self, version: u8) -> Result<(), StorageError> {
        let mut txn = self.env.begin_rw_txn()?;
        put_value(&mut txn, self.meta, STORAGE_VERSION_KEY, &version)?;
        txn.commit()?;
        Ok(())
    }

    fn ensure_storage_version(&self) -> Result<(), StorageError> {
        match self.load_storage_version()? {
            Some(STORAGE_VERSION) => Ok(()),
            Some(found) => Err(StorageError::UnsupportedStorageVersion {
                expected: STORAGE_VERSION,
                found,
            }),
            None if self.is_empty_database()? => {
                self.save_storage_version(STORAGE_VERSION)?;
                self.flush()
            }
            None => Err(StorageError::MissingStorageVersion),
        }
    }

    fn is_empty_database(&self) -> Result<bool, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        Ok(is_db_empty(&txn, self.blocks_by_height)?
            && is_db_empty(&txn, self.blocks_by_hash)?
            && is_db_empty(&txn, self.headers_by_height)?
            && is_db_empty(&txn, self.accounts)?
            && is_db_empty(&txn, self.genesis_accounts)?
            && is_db_empty(&txn, self.tx_index)?
            && is_db_empty(&txn, self.wtx_index)?
            && is_db_empty(&txn, self.address_tx_index)?
            && is_db_empty(&txn, self.miner_block_index)?
            && is_db_empty(&txn, self.events_by_id)?
            && is_db_empty(&txn, self.block_event_index)?
            && is_db_empty(&txn, self.transaction_event_index)?
            && is_db_empty(&txn, self.address_event_index)?
            && is_db_empty(&txn, self.rollback_issues)?
            && is_db_empty(&txn, self.rollback_proof_contexts)?)
    }

    pub fn save_block(&self, block: &Block) -> Result<(), StorageError> {
        validate_block_for_storage(block)?;
        let bytes = block_bytes(block)?;
        let block_hash = block.hash()?;
        let mut txn = self.env.begin_rw_txn()?;
        txn.put(
            self.blocks_by_height,
            &height_key(block.height()),
            &block_hash.0,
            WriteFlags::empty(),
        )?;
        txn.put(
            self.blocks_by_hash,
            &block_hash.0,
            &bytes,
            WriteFlags::empty(),
        )?;
        put_value(
            &mut txn,
            self.headers_by_height,
            &height_key(block.height()),
            &block.header,
        )?;
        self.index_block_transactions(&mut txn, block)?;
        self.index_miner_block(&mut txn, block)?;
        txn.commit()?;
        Ok(())
    }

    pub fn save_side_block(&self, block: &Block) -> Result<(), StorageError> {
        validate_block_for_storage(block)?;
        let bytes = block_bytes(block)?;
        let block_hash = block.hash()?;
        let mut txn = self.env.begin_rw_txn()?;
        txn.put(
            self.blocks_by_hash,
            &block_hash.0,
            &bytes,
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    fn index_miner_block(
        &self,
        txn: &mut lmdb::RwTransaction<'_>,
        block: &Block,
    ) -> Result<(), StorageError> {
        if block.coinbase().is_none() {
            return Ok(());
        }

        let location = MinerBlockLocation {
            block_height: block.height(),
            block_hash: block.hash()?,
        };
        put_value(
            txn,
            self.miner_block_index,
            &miner_block_key(&block.miner_address(), block.height()),
            &location,
        )
    }

    fn index_block_transactions(
        &self,
        txn: &mut lmdb::RwTransaction<'_>,
        block: &Block,
    ) -> Result<(), StorageError> {
        let block_hash = block.hash()?;

        for (index, transaction) in protocol_transactions(block).into_iter().enumerate() {
            let tx_index_u32 = u32::try_from(index)
                .map_err(|_| StorageError::Integrity("transaction index exceeds u32"))?;
            let tx_hash = transaction.hash()?;
            let location = TransactionLocation {
                block_height: block.height(),
                block_hash,
                tx_index: tx_index_u32,
                family: transaction.family(),
            };
            put_value(txn, self.tx_index, &tx_hash.0, &location)?;
            put_value(txn, self.wtx_index, &tx_hash.0, &location)?;

            for (address, sent) in transaction_addresses(&transaction) {
                let address_location = AddressTransactionLocation {
                    tx_hash,
                    block_height: block.height(),
                    block_hash,
                    tx_index: tx_index_u32,
                    sent,
                    family: transaction.family(),
                };
                put_value(
                    txn,
                    self.address_tx_index,
                    &address_tx_key(&address, block.height(), tx_index_u32, sent),
                    &address_location,
                )?;
            }
        }

        Ok(())
    }

    fn index_protocol_events(
        &self,
        txn: &mut lmdb::RwTransaction<'_>,
        events: &[ProtocolEvent],
    ) -> Result<(), StorageError> {
        for event in events {
            if !event.validate() {
                return Err(StorageError::Integrity("invalid protocol event"));
            }
            let id = event.id()?;
            put_value(txn, self.events_by_id, &id.0, event)?;
            put_value(
                txn,
                self.block_event_index,
                &block_event_key(&event.block_hash, event.event_index),
                &id,
            )?;
            if let Some(transaction_hash) = event.transaction_hash {
                put_value(
                    txn,
                    self.transaction_event_index,
                    &transaction_event_key(&transaction_hash, event.event_index),
                    &id,
                )?;
            }
            for address in event_addresses(&event.kind) {
                put_value(
                    txn,
                    self.address_event_index,
                    &address_event_key(&address, event.block_height, event.event_index),
                    &id,
                )?;
            }
        }
        Ok(())
    }

    pub fn load_protocol_event(&self, id: &EventId) -> Result<Option<ProtocolEvent>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let event: Option<ProtocolEvent> = read_value(&txn, self.events_by_id, &id.0)?;
        if event
            .as_ref()
            .is_some_and(|event| !event.validate() || event.id() != Ok(*id))
        {
            return Err(StorageError::Integrity("stored protocol event is invalid"));
        }
        Ok(event)
    }

    pub fn load_block_events(
        &self,
        block_hash: &BlockHash,
    ) -> Result<Vec<ProtocolEvent>, StorageError> {
        self.load_indexed_events(self.block_event_index, &block_hash.0)
    }

    pub fn load_transaction_events(
        &self,
        transaction_hash: &TransactionHash,
    ) -> Result<Vec<ProtocolEvent>, StorageError> {
        self.load_indexed_events(self.transaction_event_index, &transaction_hash.0)
    }

    pub fn load_address_events(
        &self,
        address: &Address,
    ) -> Result<Vec<ProtocolEvent>, StorageError> {
        self.load_indexed_events(self.address_event_index, &address.0)
    }

    fn load_indexed_events(
        &self,
        database: Database,
        prefix: &[u8],
    ) -> Result<Vec<ProtocolEvent>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(database)?;
        let mut events = Vec::new();
        for item in cursor.iter() {
            let (key, bytes) = item;
            if key < prefix {
                continue;
            }
            if !key.starts_with(prefix) {
                break;
            }
            let id: EventId = decode(bytes)?;
            let event: ProtocolEvent = read_value(&txn, self.events_by_id, &id.0)?
                .ok_or(StorageError::Integrity("indexed protocol event is missing"))?;
            if !event.validate() || event.id()? != id {
                return Err(StorageError::Integrity("indexed protocol event is invalid"));
            }
            events.push(event);
        }
        events.sort_by_key(|event| (event.block_height, event.event_index));
        Ok(events)
    }

    pub fn load_block_by_height(&self, height: BlockHeight) -> Result<Option<Block>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let Some(hash_bytes) = read_bytes(&txn, self.blocks_by_height, &height_key(height))? else {
            return Ok(None);
        };
        let block_hash = BlockHash(
            hash_bytes
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Integrity("stored block height index is invalid"))?,
        );
        let block_bytes = read_bytes(&txn, self.blocks_by_hash, &block_hash.0)?.ok_or(
            StorageError::Integrity("height-indexed block is missing from hash index"),
        )?;
        let block = decode_stored_block(&block_bytes)?;
        if block.height() != height {
            return Err(StorageError::Integrity(
                "stored block height does not match height key",
            ));
        }
        if block.hash()? != block_hash {
            return Err(StorageError::Integrity(
                "height-indexed block hash does not match hash index key",
            ));
        }
        Ok(Some(block))
    }

    pub fn load_header_by_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>, StorageError> {
        Ok(self
            .load_header_proof_by_height(height)?
            .map(|header| header.header))
    }

    pub fn load_header_proof_by_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ChainHeader>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let mut header: Option<ChainHeader> =
            read_value(&txn, self.headers_by_height, &height_key(height))?;
        drop(txn);
        if header.is_none() {
            header = self
                .load_block_by_height(height)?
                .map(|block| ChainHeader::new(block.height(), block.header));
        }
        if header
            .as_ref()
            .is_some_and(|header| header.height != height)
        {
            return Err(StorageError::Integrity(
                "stored header height does not match height key",
            ));
        }
        Ok(header)
    }

    pub fn load_block_by_hash(&self, hash: &BlockHash) -> Result<Option<Block>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        read_bytes(&txn, self.blocks_by_hash, &hash.0)?
            .map(|bytes| {
                let block = decode_stored_block(&bytes)?;
                if block.hash()? != *hash {
                    return Err(StorageError::Integrity(
                        "stored block hash does not match hash key",
                    ));
                }
                Ok(block)
            })
            .transpose()
    }

    pub fn load_blocks_by_hash(&self) -> Result<Vec<Block>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(self.blocks_by_hash)?;
        let mut blocks = Vec::new();
        for item in cursor.iter() {
            let (_key, bytes) = item;
            let block = decode_stored_block(bytes)?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    pub fn load_transaction_location(
        &self,
        hash: &TransactionHash,
    ) -> Result<Option<TransactionLocation>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        read_value(&txn, self.tx_index, &hash.0)
    }

    pub fn load_auth_transaction_location(
        &self,
        hash: &TransactionHash,
    ) -> Result<Option<TransactionLocation>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        read_value(&txn, self.wtx_index, &hash.0)
    }

    pub fn load_transaction(
        &self,
        hash: &TransactionHash,
    ) -> Result<Option<(TransactionLocation, SignedTransfer)>, StorageError> {
        let Some((location, transaction)) = self.load_protocol_transaction(hash)? else {
            return Ok(None);
        };
        if let SignedProtocolTransaction::Transfer(transaction) = transaction {
            Ok(Some((location, *transaction)))
        } else {
            Ok(None)
        }
    }

    pub fn load_protocol_transaction(
        &self,
        hash: &TransactionHash,
    ) -> Result<Option<(TransactionLocation, SignedProtocolTransaction)>, StorageError> {
        let Some(location) = self.load_transaction_location(hash)? else {
            return Ok(None);
        };
        let Some(block) = self.load_block_by_height(location.block_height)? else {
            return Err(StorageError::Integrity(
                "indexed transaction block is missing",
            ));
        };
        if block.hash()? != location.block_hash {
            return Err(StorageError::Integrity(
                "indexed transaction block hash mismatch",
            ));
        }
        let transaction = protocol_transactions(&block)
            .get(location.tx_index as usize)
            .ok_or(StorageError::Integrity(
                "indexed transaction position is missing",
            ))?
            .clone();
        if transaction.hash()? != *hash || transaction.family() != location.family {
            return Err(StorageError::Integrity(
                "indexed transaction does not match its location",
            ));
        }
        Ok(Some((location, transaction)))
    }

    pub fn load_protocol_transaction_by_auth_hash(
        &self,
        hash: &TransactionHash,
    ) -> Result<Option<(TransactionLocation, SignedProtocolTransaction)>, StorageError> {
        let Some(location) = self.load_auth_transaction_location(hash)? else {
            return Ok(None);
        };
        let Some(block) = self.load_block_by_height(location.block_height)? else {
            return Err(StorageError::Integrity(
                "indexed authorization transaction block is missing",
            ));
        };
        if block.hash()? != location.block_hash {
            return Err(StorageError::Integrity(
                "indexed authorization transaction block hash mismatch",
            ));
        }
        let transaction = protocol_transactions(&block)
            .get(location.tx_index as usize)
            .ok_or(StorageError::Integrity(
                "indexed authorization transaction position is missing",
            ))?
            .clone();
        if transaction.hash()? != *hash || transaction.family() != location.family {
            return Err(StorageError::Integrity(
                "indexed authorization transaction does not match its location",
            ));
        }
        Ok(Some((location, transaction)))
    }

    pub fn load_address_transaction_locations(
        &self,
        address: &Address,
    ) -> Result<Vec<AddressTransactionLocation>, StorageError> {
        let prefix = address.0;
        let mut locations = Vec::new();
        let txn = self.env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(self.address_tx_index)?;
        for item in cursor.iter() {
            let (key, bytes) = item;
            if key < prefix.as_slice() {
                continue;
            }
            if !key.starts_with(&prefix) {
                break;
            }
            locations.push(decode(bytes)?);
        }
        locations.sort_by_key(|location: &AddressTransactionLocation| {
            (location.block_height, location.tx_index, location.sent)
        });
        Ok(locations)
    }

    pub fn load_miner_block_locations(
        &self,
        address: &Address,
    ) -> Result<Vec<MinerBlockLocation>, StorageError> {
        let prefix = address.0;
        let mut locations = Vec::new();
        let txn = self.env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(self.miner_block_index)?;
        for item in cursor.iter() {
            let (key, bytes) = item;
            if key < prefix.as_slice() {
                continue;
            }
            if !key.starts_with(&prefix) {
                break;
            }
            locations.push(decode(bytes)?);
        }
        locations.sort_by_key(|location: &MinerBlockLocation| location.block_height);
        Ok(locations)
    }

    pub fn save_account(&self, account: &Account) -> Result<(), StorageError> {
        let mut txn = self.env.begin_rw_txn()?;
        put_value(&mut txn, self.accounts, &account.address.0, account)?;
        txn.commit()?;
        Ok(())
    }

    pub fn load_account(&self, address: &Address) -> Result<Option<Account>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        read_value(&txn, self.accounts, &address.0)
    }

    pub fn save_rollback_issue(&self, issue: &RollbackIssue) -> Result<(), StorageError> {
        validate_rollback_issue(issue, None)?;
        let mut txn = self.env.begin_rw_txn()?;
        put_value(&mut txn, self.rollback_issues, &issue.id.0, issue)?;
        txn.commit()?;
        Ok(())
    }

    pub fn load_rollback_issue(
        &self,
        id: &RollbackIssueId,
    ) -> Result<Option<RollbackIssue>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let issue: Option<RollbackIssue> = read_value(&txn, self.rollback_issues, &id.0)?;
        if let Some(issue) = &issue {
            validate_rollback_issue(issue, Some(id))?;
        }
        Ok(issue)
    }

    pub fn load_rollback_issues(&self) -> Result<Vec<RollbackIssue>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let mut cursor = txn.open_ro_cursor(self.rollback_issues)?;
        let mut issues = Vec::new();
        for item in cursor.iter() {
            let (key, bytes) = item;
            let issue: RollbackIssue = decode(bytes)?;
            validate_rollback_issue(&issue, None)?;
            if key != issue.id.0 {
                return Err(StorageError::Integrity(
                    "stored rollback issue key is invalid",
                ));
            }
            issues.push(issue);
        }
        issues.sort_by_key(|issue| {
            (
                issue.disconnected_block_height,
                issue.transaction_index,
                issue.id,
            )
        });
        Ok(issues)
    }

    pub fn save_rollback_proof_context(
        &self,
        context: &RollbackProofContext,
    ) -> Result<(), StorageError> {
        let expected = RollbackProofContext::new(
            context.losing_headers.clone(),
            context.canonical_headers.clone(),
            context.common_ancestor,
        )?;
        if expected.id != context.id {
            return Err(StorageError::Integrity(
                "rollback proof context id is invalid",
            ));
        }
        let mut txn = self.env.begin_rw_txn()?;
        put_value(
            &mut txn,
            self.rollback_proof_contexts,
            &context.id.0,
            context,
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn load_rollback_proof_context(
        &self,
        id: &RollbackProofContextId,
    ) -> Result<Option<RollbackProofContext>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let context: Option<RollbackProofContext> =
            read_value(&txn, self.rollback_proof_contexts, &id.0)?;
        if let Some(context) = &context {
            let expected = RollbackProofContext::new(
                context.losing_headers.clone(),
                context.canonical_headers.clone(),
                context.common_ancestor,
            )?;
            if expected.id != *id || context.id != *id {
                return Err(StorageError::Integrity(
                    "stored rollback proof context id is invalid",
                ));
            }
        }
        Ok(context)
    }

    pub fn save_genesis_accounts(
        &self,
        accounts: &BTreeMap<Address, Account>,
    ) -> Result<(), StorageError> {
        let mut txn = self.env.begin_rw_txn()?;
        put_value(&mut txn, self.genesis_accounts, b"accounts", accounts)?;
        txn.commit()?;
        Ok(())
    }

    pub fn load_genesis_accounts(
        &self,
    ) -> Result<Option<BTreeMap<Address, Account>>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        read_value(&txn, self.genesis_accounts, b"accounts")
    }

    pub fn save_tip(&self, height: BlockHeight, hash: &BlockHash) -> Result<(), StorageError> {
        let mut txn = self.env.begin_rw_txn()?;
        put_value(&mut txn, self.meta, TIP_HEIGHT_KEY, &height)?;
        txn.put(self.meta, &TIP_HASH_KEY, &hash.0, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    pub fn load_tip(&self) -> Result<Option<(BlockHeight, BlockHash)>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        let Some(height_bytes) = read_bytes(&txn, self.meta, TIP_HEIGHT_KEY)? else {
            return Ok(None);
        };
        let Some(hash_bytes) = read_bytes(&txn, self.meta, TIP_HASH_KEY)? else {
            return Ok(None);
        };

        let height = decode(&height_bytes)?;
        let hash = Hash(
            hash_bytes
                .as_slice()
                .try_into()
                .map_err(|_| invalid_data("stored tip hash has invalid length"))?,
        );
        Ok(Some((height, hash.into())))
    }

    pub fn save_ledger(&self, ledger: &Ledger) -> Result<(), StorageError> {
        let genesis_accounts = ledger
            .chain
            .block(&Height(0))
            .map(|block| genesis_accounts_from_ledger(ledger, block))
            .transpose()?;
        let mut txn = self.env.begin_rw_txn()?;
        txn.clear_db(self.blocks_by_height)?;
        txn.clear_db(self.headers_by_height)?;
        txn.clear_db(self.accounts)?;
        txn.clear_db(self.tx_index)?;
        txn.clear_db(self.wtx_index)?;
        txn.clear_db(self.address_tx_index)?;
        txn.clear_db(self.miner_block_index)?;
        txn.clear_db(self.events_by_id)?;
        txn.clear_db(self.block_event_index)?;
        txn.clear_db(self.transaction_event_index)?;
        txn.clear_db(self.address_event_index)?;
        txn.clear_db(self.state_diffs)?;

        for account in ledger.accounts().values() {
            put_value(&mut txn, self.accounts, &account.address.0, account)?;
        }

        for (height, header) in &ledger.chain.headers {
            put_value(
                &mut txn,
                self.headers_by_height,
                &height_key(*height),
                &ChainHeader::new(*height, header.clone()),
            )?;
        }

        for block in ledger.chain.blocks.values() {
            validate_block_for_storage(block)?;
            let bytes = block_bytes(block)?;
            let block_hash = block.hash()?;
            txn.put(
                self.blocks_by_height,
                &height_key(block.height()),
                &block_hash.0,
                WriteFlags::empty(),
            )?;
            txn.put(
                self.blocks_by_hash,
                &block_hash.0,
                &bytes,
                WriteFlags::empty(),
            )?;
            self.index_block_transactions(&mut txn, block)?;
            self.index_miner_block(&mut txn, block)?;
            self.index_protocol_events(&mut txn, ledger.events_for_block(&block_hash))?;
        }

        if let (Some(height), Some(hash)) = (ledger.tip_height(), ledger.tip_hash()) {
            put_value(&mut txn, self.meta, TIP_HEIGHT_KEY, &height)?;
            txn.put(self.meta, &TIP_HASH_KEY, &hash.0, WriteFlags::empty())?;
        }
        match ledger.chain.checkpoint_height {
            Some(height) => put_value(&mut txn, self.meta, CHECKPOINT_HEIGHT_KEY, &height)?,
            None => {
                let _ = txn.del(self.meta, &CHECKPOINT_HEIGHT_KEY, None);
            }
        }

        put_value(
            &mut txn,
            self.protocol_state,
            PROTOCOL_STATE_KEY,
            &StoredProtocolState::from_ledger(ledger),
        )?;
        if let Some(accounts) = genesis_accounts {
            put_value(&mut txn, self.genesis_accounts, b"accounts", &accounts)?;
        }

        txn.commit()?;
        self.flush()?;
        Ok(())
    }

    /// Atomically persists a block that directly extends the active tip without rebuilding all
    /// historical indexes. Reorganizations still use `save_ledger` because they must remove
    /// entries belonging to the disconnected branch.
    pub fn save_active_extension(
        &self,
        previous: &Ledger,
        ledger: &Ledger,
        block: &Block,
    ) -> Result<(), StorageError> {
        validate_block_for_storage(block)?;
        let block_hash = block.hash()?;
        let bytes = block_bytes(block)?;
        let mut txn = self.env.begin_rw_txn()?;

        for (address, previous_account) in previous.accounts() {
            match ledger.accounts().get(address) {
                Some(account) if account == previous_account => {}
                Some(account) => put_value(&mut txn, self.accounts, &address.0, account)?,
                None => {
                    let _ = txn.del(self.accounts, &address.0, None);
                }
            }
        }
        for (address, account) in ledger.accounts() {
            if !previous.accounts().contains_key(address) {
                put_value(&mut txn, self.accounts, &address.0, account)?;
            }
        }

        txn.put(
            self.blocks_by_height,
            &height_key(block.height()),
            &block_hash.0,
            WriteFlags::empty(),
        )?;
        txn.put(
            self.blocks_by_hash,
            &block_hash.0,
            &bytes,
            WriteFlags::empty(),
        )?;
        put_value(
            &mut txn,
            self.headers_by_height,
            &height_key(block.height()),
            &ChainHeader::new(block.height(), block.header.clone()),
        )?;
        self.index_block_transactions(&mut txn, block)?;
        self.index_miner_block(&mut txn, block)?;
        self.index_protocol_events(&mut txn, ledger.events_for_block(&block_hash))?;

        put_value(&mut txn, self.meta, TIP_HEIGHT_KEY, &block.height())?;
        txn.put(self.meta, &TIP_HASH_KEY, &block_hash.0, WriteFlags::empty())?;
        match ledger.chain.checkpoint_height {
            Some(height) => put_value(&mut txn, self.meta, CHECKPOINT_HEIGHT_KEY, &height)?,
            None => {
                let _ = txn.del(self.meta, &CHECKPOINT_HEIGHT_KEY, None);
            }
        }
        if block.is_genesis() || block.height().0.is_multiple_of(STATE_SNAPSHOT_INTERVAL) {
            put_value(
                &mut txn,
                self.protocol_state,
                PROTOCOL_STATE_KEY,
                &StoredProtocolState::from_ledger(ledger),
            )?;
            txn.clear_db(self.state_diffs)?;
        } else {
            let diff = protocol_state_diff(previous, ledger, block_hash);
            put_value(
                &mut txn,
                self.state_diffs,
                &height_key(block.height()),
                &diff,
            )?;
        }
        if block.is_genesis() {
            let accounts = genesis_accounts_from_ledger(ledger, block)?;
            put_value(&mut txn, self.genesis_accounts, b"accounts", &accounts)?;
        }

        txn.commit()?;
        self.flush()?;
        Ok(())
    }

    pub fn load_ledger(&self) -> Result<Ledger, StorageError> {
        self.ensure_storage_version()?;
        self.validate_chain_integrity()?;

        let mut ledger = Ledger::new();
        let mut accounts = BTreeMap::new();
        {
            let txn = self.env.begin_ro_txn()?;
            let mut cursor = txn.open_ro_cursor(self.accounts)?;
            for item in cursor.iter() {
                let (_key, bytes) = item;
                let account: Account = decode(bytes)?;
                if account.address.0.as_slice() != _key {
                    return Err(StorageError::Integrity(
                        "stored account address does not match account key",
                    ));
                }
                accounts.insert(account.address, account);
            }
        }
        ledger
            .replace_accounts(accounts)
            .map_err(|_| StorageError::Integrity("failed to rebuild account state tree"))?;

        {
            let txn = self.env.begin_ro_txn()?;
            if let Some(state) =
                read_value::<StoredProtocolState>(&txn, self.protocol_state, PROTOCOL_STATE_KEY)?
            {
                state.restore(&mut ledger);
            }
            let mut cursor = txn.open_ro_cursor(self.state_diffs)?;
            for item in cursor.iter() {
                let (_key, bytes) = item;
                let diff: StoredStateDiff = decode(bytes)?;
                ledger
                    .xpq_utxos
                    .apply_persistence_diff(&diff.removed_xpq, diff.upserted_xpq);
                ledger.qcash_utxos.apply_persistence_diff(
                    &diff.removed_qcash,
                    diff.upserted_qcash,
                    diff.qcash_journal_state,
                );
                ledger.events_by_block.insert(diff.block_hash, diff.events);
            }
        }

        if let Some((tip_height, _tip_hash)) = self.load_tip()? {
            let checkpoint_height = {
                let txn = self.env.begin_ro_txn()?;
                read_value::<Height>(&txn, self.meta, CHECKPOINT_HEIGHT_KEY)?
            };
            if let Some(checkpoint_height) = checkpoint_height {
                let mut headers = Vec::with_capacity(
                    usize::try_from(tip_height.0.saturating_add(1)).unwrap_or_default(),
                );
                for height in 0..=tip_height.0 {
                    headers.push(
                        self.load_header_proof_by_height(Height(height))?
                            .ok_or(StorageError::Integrity("stored chain proof is missing"))?,
                    );
                }
                ledger
                    .restore_authenticated_headers(&headers, checkpoint_height)
                    .map_err(|_| {
                        StorageError::Integrity("stored authenticated header chain is invalid")
                    })?;
                for height in 0..=tip_height.0 {
                    if let Some(block) = self.load_block_by_height(Height(height))? {
                        ledger.attach_stored_block_body(block).map_err(|_| {
                            StorageError::Integrity("stored block body does not match its header")
                        })?;
                    }
                }
            } else {
                for height in 0..=tip_height.0 {
                    let block = self
                        .load_block_by_height(Height(height))?
                        .ok_or(StorageError::Integrity("stored chain block is missing"))?;
                    ledger
                        .chain
                        .insert_block(block)
                        .map_err(|_| StorageError::Integrity("stored chain block is invalid"))?;
                }
            }
        }

        ledger
            .validate_supply()
            .map_err(|_| StorageError::Integrity("stored ledger supply is invalid"))?;

        if let Some(tip_height) = ledger.tip_height() {
            let tip = ledger
                .chain
                .header(&tip_height)
                .ok_or(StorageError::Integrity("stored canonical tip is missing"))?;
            let expected_state_root = if tip_height == Height(0) {
                ledger.state_root()
            } else {
                ledger.protocol_state_root().map_err(|_| {
                    StorageError::Integrity("failed to rebuild stored protocol state root")
                })?
            };
            if tip.state_root != expected_state_root {
                return Err(StorageError::Integrity(
                    "stored ledger state root does not match canonical tip",
                ));
            }
        }

        xparq::ledger::validate_ledger_invariants(&ledger)
            .map_err(|_| StorageError::Integrity("stored ledger invariants are invalid"))?;

        Ok(ledger)
    }

    pub fn difficulty_window(
        &self,
        tip_height: BlockHeight,
        window: u64,
    ) -> Result<Option<(u64, u64, u64, u32)>, StorageError> {
        if window == 0 || tip_height.0 < window {
            return Ok(None);
        }

        let Some(tip) = self.load_header_by_height(tip_height)? else {
            return Ok(None);
        };
        let first_height = Height(tip_height.0 - window);
        let Some(_first) = self.load_header_by_height(first_height)? else {
            return Ok(None);
        };
        let block_count = tip_height.0.saturating_sub(first_height.0);

        Ok(Some((
            first_height.0,
            tip_height.0,
            block_count,
            tip.difficulty,
        )))
    }

    pub fn validate_chain_integrity(&self) -> Result<(), StorageError> {
        let Some((tip_height, tip_hash)) = self.load_tip()? else {
            return Ok(());
        };
        let checkpoint_height = {
            let txn = self.env.begin_ro_txn()?;
            read_value::<Height>(&txn, self.meta, CHECKPOINT_HEIGHT_KEY)?
        };
        if checkpoint_height.is_none() {
            let tip_block =
                self.load_block_by_height(tip_height)?
                    .ok_or(StorageError::Integrity(
                        "stored tip height block is missing",
                    ))?;
            if tip_block.hash()? != tip_hash {
                return Err(StorageError::Integrity(
                    "stored tip hash does not match tip height block",
                ));
            }
            let mut expected_hash = tip_hash;
            for height in (0..=tip_height.0).rev() {
                let block = self
                    .load_block_by_height(Height(height))?
                    .ok_or(StorageError::Integrity("stored chain block is missing"))?;
                if block.hash()? != expected_hash {
                    return Err(StorageError::Integrity(
                        "stored chain block hash does not match expected hash",
                    ));
                }
                if height == 0 {
                    if block.previous_hash() != Hash([0; HASH_SIZE]) {
                        return Err(StorageError::Integrity(
                            "stored genesis block previous hash is not zero",
                        ));
                    }
                } else {
                    let previous = self.load_block_by_height(Height(height - 1))?.ok_or(
                        StorageError::Integrity("stored previous chain block is missing"),
                    )?;
                    let previous_hash = previous.hash()?;
                    if block.previous_hash() != previous_hash {
                        return Err(StorageError::Integrity(
                            "stored chain block previous hash is broken",
                        ));
                    }
                    expected_hash = previous_hash;
                }
            }
            return Ok(());
        }

        let tip_header = self
            .load_header_by_height(tip_height)?
            .ok_or(StorageError::Integrity(
                "stored tip height header is missing",
            ))?;
        if tip_header.hash()? != tip_hash {
            return Err(StorageError::Integrity(
                "stored tip hash does not match tip height header",
            ));
        }

        let mut expected_hash = tip_hash;
        for height in (0..=tip_height.0).rev() {
            let block_height = Height(height);
            let header = self
                .load_header_by_height(block_height)?
                .ok_or(StorageError::Integrity("stored chain header is missing"))?;

            if header.hash()? != expected_hash {
                return Err(StorageError::Integrity(
                    "stored chain header hash does not match expected hash",
                ));
            }

            if height == 0 {
                if header.previous_hash != Hash([0; HASH_SIZE]) {
                    return Err(StorageError::Integrity(
                        "stored genesis block previous hash is not zero",
                    ));
                }
            } else {
                let previous = self.load_header_by_height(Height(height - 1))?.ok_or(
                    StorageError::Integrity("stored previous chain header is missing"),
                )?;
                let previous_hash = previous.hash()?;
                if header.previous_hash != previous_hash {
                    return Err(StorageError::Integrity(
                        "stored chain block previous hash is broken",
                    ));
                }
                expected_hash = previous_hash;
            }
        }

        Ok(())
    }

    pub fn flush(&self) -> Result<(), StorageError> {
        self.env.sync(true)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_put_blocks_by_height<T: BorshSerialize>(
        &self,
        key: &[u8],
        value: &T,
    ) -> Result<(), StorageError> {
        self.test_put(self.blocks_by_height, key, value)
    }

    #[cfg(test)]
    pub(crate) fn test_blocks_by_height_value_len(
        &self,
        height: BlockHeight,
    ) -> Result<Option<usize>, StorageError> {
        let txn = self.env.begin_ro_txn()?;
        Ok(read_bytes(&txn, self.blocks_by_height, &height_key(height))?.map(|value| value.len()))
    }

    #[cfg(test)]
    pub(crate) fn test_put_blocks_by_hash<T: BorshSerialize>(
        &self,
        key: &[u8],
        value: &T,
    ) -> Result<(), StorageError> {
        self.test_put(self.blocks_by_hash, key, value)
    }

    #[cfg(test)]
    pub(crate) fn test_put_meta<T: BorshSerialize>(
        &self,
        key: &[u8],
        value: &T,
    ) -> Result<(), StorageError> {
        self.test_put(self.meta, key, value)
    }

    #[cfg(test)]
    pub(crate) fn test_put_account(&self, account: &Account) -> Result<(), StorageError> {
        self.test_put(self.accounts, &account.address.0, account)
    }

    #[cfg(test)]
    pub(crate) fn test_remove_meta(&self, key: &[u8]) -> Result<(), StorageError> {
        let mut txn = self.env.begin_rw_txn()?;
        match txn.del(self.meta, &key, None) {
            Ok(()) | Err(lmdb::Error::NotFound) => {}
            Err(error) => return Err(error.into()),
        }
        txn.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_abort_tip_write(
        &self,
        height: BlockHeight,
        hash: BlockHash,
    ) -> Result<(), StorageError> {
        let mut txn = self.env.begin_rw_txn()?;
        put_value(&mut txn, self.meta, TIP_HEIGHT_KEY, &height)?;
        put_value(&mut txn, self.meta, TIP_HASH_KEY, &hash)?;
        txn.abort();
        Ok(())
    }

    #[cfg(test)]
    fn test_put<T: BorshSerialize>(
        &self,
        db: Database,
        key: &[u8],
        value: &T,
    ) -> Result<(), StorageError> {
        let mut txn = self.env.begin_rw_txn()?;
        put_value(&mut txn, db, key, value)?;
        txn.commit()?;
        Ok(())
    }
}

fn height_key(height: BlockHeight) -> [u8; 8] {
    height.0.to_be_bytes()
}

fn validate_rollback_issue(
    issue: &RollbackIssue,
    expected_id: Option<&RollbackIssueId>,
) -> Result<(), StorageError> {
    let transaction_hash = issue.transaction.hash()?;
    let id = RollbackIssueId::for_transaction(issue.disconnected_block_hash, transaction_hash)?;
    if issue.transaction_hash != transaction_hash
        || issue.id != id
        || expected_id.is_some_and(|expected| *expected != id)
    {
        return Err(StorageError::Integrity(
            "stored rollback issue transaction identity is invalid",
        ));
    }
    Ok(())
}

fn protocol_transactions(block: &Block) -> Vec<SignedProtocolTransaction> {
    block.transactions().to_vec()
}

fn transaction_addresses(transaction: &SignedProtocolTransaction) -> Vec<(Address, bool)> {
    let signer = transaction.signer();
    let mut addresses = vec![(signer, true)];
    let recipients = match transaction {
        SignedProtocolTransaction::Transfer(tx) => tx
            .transaction
            .outputs
            .iter()
            .filter_map(|output| output.to.address())
            .collect(),
        SignedProtocolTransaction::QCash(tx) => match &tx.transaction.kind {
            xparq::transaction::QCashTransactionKind::Redeem { outputs, .. } => outputs
                .iter()
                .filter_map(|output| output.to.address())
                .collect(),
            _ => Vec::new(),
        },
    };
    for recipient in recipients {
        if recipient != signer {
            addresses.push((recipient, false));
        }
    }
    addresses
}

fn event_addresses(kind: &ProtocolEventKind) -> Vec<Address> {
    let addresses = match kind {
        ProtocolEventKind::Transfer { from, to, .. } => vec![*from, *to],
        ProtocolEventKind::QCashWithdrawn { signer, .. } => vec![*signer],
        ProtocolEventKind::QCashRedeemed {
            signer, recipient, ..
        } => vec![*signer, *recipient],
        ProtocolEventKind::QCashRecoverRedeemed {
            signer, claimant, ..
        } => vec![*signer, *claimant],
        ProtocolEventKind::EmissionDistributed { miner, .. } => vec![*miner],
    };
    let mut unique = std::collections::BTreeSet::new();
    unique.extend(addresses);
    unique.into_iter().collect()
}

fn genesis_accounts_from_ledger(
    ledger: &Ledger,
    block: &Block,
) -> Result<BTreeMap<Address, Account>, StorageError> {
    if block.height() != Height(0) {
        return Err(StorageError::Integrity(
            "genesis account source block is not height 0",
        ));
    }
    let mut genesis_ledger = Ledger::new();
    if genesis_ledger.apply_block(block.clone()).is_err() {
        if ledger.tip_height() == Some(Height(0)) {
            return Ok(ledger.accounts().clone());
        }
        return Err(StorageError::Integrity("stored genesis block is invalid"));
    }
    Ok(genesis_ledger.accounts().clone())
}

fn address_tx_key(address: &Address, height: BlockHeight, tx_index: u32, sent: bool) -> Vec<u8> {
    let mut key = Vec::with_capacity(ADDRESS_SIZE + 8 + 4 + 1);
    key.extend_from_slice(&address.0);
    key.extend_from_slice(&height.0.to_be_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
    key.push(u8::from(sent));
    key
}

fn block_event_key(block_hash: &BlockHash, event_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(HASH_SIZE + 4);
    key.extend_from_slice(&block_hash.0);
    key.extend_from_slice(&event_index.to_be_bytes());
    key
}

fn transaction_event_key(transaction_hash: &TransactionHash, event_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(HASH_SIZE + 4);
    key.extend_from_slice(&transaction_hash.0);
    key.extend_from_slice(&event_index.to_be_bytes());
    key
}

fn address_event_key(address: &Address, height: BlockHeight, event_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(ADDRESS_SIZE + 8 + 4);
    key.extend_from_slice(&address.0);
    key.extend_from_slice(&height.0.to_be_bytes());
    key.extend_from_slice(&event_index.to_be_bytes());
    key
}

fn miner_block_key(address: &Address, height: BlockHeight) -> Vec<u8> {
    let mut key = Vec::with_capacity(ADDRESS_SIZE + 8);
    key.extend_from_slice(&address.0);
    key.extend_from_slice(&height.0.to_be_bytes());
    key
}

fn read_bytes(
    txn: &impl Transaction,
    db: Database,
    key: &[u8],
) -> Result<Option<Vec<u8>>, StorageError> {
    match txn.get(db, &key) {
        Ok(bytes) => Ok(Some(bytes.to_vec())),
        Err(lmdb::Error::NotFound) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_value<T: BorshDeserialize>(
    txn: &impl Transaction,
    db: Database,
    key: &[u8],
) -> Result<Option<T>, StorageError> {
    read_bytes(txn, db, key)?
        .map(|bytes| decode(&bytes))
        .transpose()
}

fn put_value<T: BorshSerialize>(
    txn: &mut lmdb::RwTransaction<'_>,
    db: Database,
    key: &[u8],
    value: &T,
) -> Result<(), StorageError> {
    let bytes = encode(value)?;
    txn.put(db, &key, &bytes, WriteFlags::empty())?;
    Ok(())
}

fn is_db_empty(txn: &lmdb::RoTransaction<'_>, db: Database) -> Result<bool, StorageError> {
    let mut cursor = txn.open_ro_cursor(db)?;
    Ok(cursor.iter().next().is_none())
}

fn encode<T: BorshSerialize>(value: &T) -> Result<Vec<u8>, StorageError> {
    Ok(borsh::to_vec(value)?)
}

fn decode<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, StorageError> {
    Ok(T::try_from_slice(bytes)?)
}

fn validate_block_for_storage(block: &Block) -> Result<(), StorageError> {
    block
        .validate_structure()
        .map_err(|_| StorageError::Integrity("refusing to store an invalid block"))
}

fn decode_stored_block(bytes: &[u8]) -> Result<Block, StorageError> {
    decode_block(bytes).map_err(|_| StorageError::Integrity("stored block failed validation"))
}

fn invalid_data(message: &'static str) -> StorageError {
    StorageError::Serialization(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

#[cfg(test)]
mod incremental_tests {
    use super::*;

    #[test]
    fn active_extension_persists_tip_and_block_atomically() {
        let ledger = xparq::genesis::genesis_ledger().unwrap();
        let block = ledger.chain.block(&Height(0)).unwrap().clone();
        let storage = Storage::temporary().unwrap();

        storage
            .save_active_extension(&Ledger::new(), &ledger, &block)
            .unwrap();

        assert_eq!(
            storage.load_tip().unwrap(),
            Some((Height(0), block.hash().unwrap()))
        );
        assert_eq!(
            storage.load_block_by_height(Height(0)).unwrap(),
            Some(block)
        );
        let loaded = storage.load_ledger().unwrap();
        assert_eq!(loaded.state_root(), ledger.state_root());
        assert_eq!(loaded.xpq_utxos, ledger.xpq_utxos);
        assert_eq!(loaded.qcash_utxos, ledger.qcash_utxos);
    }
}
