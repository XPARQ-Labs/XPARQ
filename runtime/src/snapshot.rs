use std::{path::Path, time::Instant};

use borsh::{BorshDeserialize, BorshSerialize};
use kernel::{
    block::Block,
    common::Height,
    crypto::{BlockHash, canonical_bytes, canonical_decode, hash_bytes},
    genesis::{EXPECTED_GENESIS_HASH, chain_spec_hash},
    ledger::{Ledger, LedgerSnapshot},
};

pub const SNAPSHOT_INTERVAL: u64 = 1_000;

const SNAPSHOT_MAGIC: [u8; 8] = *b"XPQSNAP1";
const SNAPSHOT_VERSION: u32 = 3;
const CHECKSUM_SIZE: usize = 32;

#[derive(BorshSerialize, BorshDeserialize)]
struct SnapshotPayload {
    magic: [u8; 8],
    version: u32,
    genesis_hash: BlockHash,
    chain_spec_hash: [u8; 32],
    height: Height,
    tip_hash: BlockHash,
    ledger: LedgerSnapshot,
}

#[cfg(test)]
#[derive(BorshSerialize, BorshDeserialize)]
struct LegacySnapshotPayload {
    magic: [u8; 8],
    version: u32,
    genesis_hash: BlockHash,
    chain_spec_hash: [u8; 32],
    height: Height,
    tip_hash: BlockHash,
    ledger: LegacyLedgerData,
}

// Legacy wire data is untrusted; decode it separately from the live Ledger API.
#[cfg(test)]
#[derive(BorshSerialize, BorshDeserialize)]
struct LegacyLedgerData {
    chain: kernel::blockchain::Chain,
    state: kernel::ledger::LedgerState,
    journals: std::collections::BTreeMap<Height, Vec<kernel::ledger::StateRollbackJournal>>,
    chain_context: Option<kernel::common::ChainContext>,
}

#[cfg(test)]
impl LegacyLedgerData {
    fn from_ledger(ledger: &Ledger) -> Self {
        canonical_decode(&canonical_bytes(ledger).unwrap()).unwrap()
    }
}

pub fn write_if_due(database: &Path, ledger: &Ledger) -> Result<bool, String> {
    let height = ledger
        .tip_height()
        .ok_or("cannot snapshot an empty ledger")?;
    if height.0 == 0 || height.0 % SNAPSHOT_INTERVAL != 0 {
        return Ok(false);
    }
    write(database, ledger)?;
    Ok(true)
}

pub fn write_after_large_sync(
    database: &Path,
    ledger: &Ledger,
    applied_blocks: usize,
) -> Result<bool, String> {
    if applied_blocks < SNAPSHOT_INTERVAL as usize {
        return Ok(false);
    }
    write(database, ledger)?;
    Ok(true)
}

pub(crate) fn write(database: &Path, ledger: &Ledger) -> Result<(), String> {
    let height = ledger
        .tip_height()
        .ok_or("cannot snapshot an empty ledger")?;
    let tip_hash = ledger
        .tip_hash()
        .ok_or("cannot snapshot a ledger without a tip")?;
    let payload = SnapshotPayload {
        magic: SNAPSHOT_MAGIC,
        version: SNAPSHOT_VERSION,
        genesis_hash: EXPECTED_GENESIS_HASH,
        chain_spec_hash: chain_spec_hash().map_err(|error| error.to_string())?.0,
        height,
        tip_hash,
        ledger: ledger.snapshot(),
    };
    let payload = canonical_bytes(&payload).map_err(|error| format!("encode snapshot: {error}"))?;
    let checksum = hash_bytes(&payload);
    let mut bytes = Vec::with_capacity(payload.len() + CHECKSUM_SIZE);
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&checksum.0);

    if ledger.state_root().map_err(|error| error.to_string())?
        != ledger
            .chain
            .header(&height)
            .ok_or("snapshot tip header is missing")?
            .state_root
    {
        return Err("snapshot state root does not match its canonical tip".into());
    }
    crate::storage::put_validated_snapshot(
        database,
        height.0,
        &bytes,
        &ledger.chain.chain_headers(),
    )?;
    println!(
        "snapshot: saved height={} tip={}",
        height.0,
        hex::encode(tip_hash.0)
    );
    Ok(())
}

#[cfg(test)]
pub fn load(database: &Path, blocks: &[Block]) -> Result<Option<(Ledger, usize)>, String> {
    let mut errors = Vec::new();
    for (height, bytes) in crate::storage::snapshots_descending(database)? {
        match load_bytes(height, &bytes, blocks) {
            Ok(Some(snapshot)) => return Ok(Some(snapshot)),
            Ok(None) => {}
            Err(error) => errors.push(format!("height {height}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(None)
    } else {
        Err(errors.join("; "))
    }
}

/// Load only locally persisted compact snapshots using a pinned streaming body log.
/// Legacy snapshots fall back to full replay; no database or snapshot is deleted.
pub fn load_streamed(
    database: &Path,
    max_body_bytes: usize,
    max_body_blocks: usize,
) -> Result<Option<(Ledger, u64)>, String> {
    load_streamed_mode(database, max_body_bytes, max_body_blocks, u64::MAX, true)
}

/// Recovery may use only local snapshots at or before the common ancestor.
pub(crate) fn load_streamed_through(
    database: &Path,
    max_body_bytes: usize,
    max_body_blocks: usize,
    maximum_height: u64,
) -> Result<Option<(Ledger, u64)>, String> {
    load_streamed_mode(
        database,
        max_body_bytes,
        max_body_blocks,
        maximum_height,
        false,
    )
}

fn load_streamed_mode(
    database: &Path,
    max_body_bytes: usize,
    max_body_blocks: usize,
    maximum_height: u64,
    allow_checkpoint: bool,
) -> Result<Option<(Ledger, u64)>, String> {
    let mut errors = Vec::new();
    for (stored_height, bytes) in crate::storage::snapshots_descending(database)? {
        if stored_height > maximum_height {
            continue;
        }
        let attempt = (|| {
            let total_start = Instant::now();
            let decode_start = Instant::now();
            if bytes.len() <= CHECKSUM_SIZE {
                return Err("snapshot is truncated".to_string());
            }
            let (payload, checksum) = bytes.split_at(bytes.len() - CHECKSUM_SIZE);
            if hash_bytes(payload).0.as_slice() != checksum {
                return Err("snapshot checksum does not match".into());
            }
            let snapshot = match canonical_decode::<SnapshotPayload>(payload) {
                Ok(snapshot) => snapshot,
                Err(_) => return Ok(None),
            };
            if snapshot.magic != SNAPSHOT_MAGIC
                || snapshot.version != SNAPSHOT_VERSION
                || snapshot.genesis_hash != EXPECTED_GENESIS_HASH
                || snapshot.chain_spec_hash
                    != chain_spec_hash().map_err(|error| error.to_string())?.0
                || snapshot.height.0 != stored_height
            {
                return Err("snapshot identity does not match this node or table key".into());
            }
            let decode_elapsed = decode_start.elapsed();
            let mut reader = crate::storage::CanonicalBodyReader::new(database)?;
            // The record is read from the same pinned generation as its history.
            // A malformed/missing/old record simply uses the full PoW path.
            let checkpoint = if allow_checkpoint {
                reader
                    .snapshot_checkpoint(stored_height)
                    .ok()
                    .flatten()
                    .filter(|record| {
                        record.version == crate::storage::SNAPSHOT_VALIDATION_VERSION
                            && record.genesis_hash == snapshot.genesis_hash.0
                            && record.chain_spec_hash == snapshot.chain_spec_hash
                            && record.height == snapshot.height.0
                            && record.tip_hash == snapshot.tip_hash.0
                            && record.snapshot_hash == hash_bytes(&bytes).0
                    })
            } else {
                None
            };
            if allow_checkpoint && checkpoint.is_none() {
                println!("snapshot: validation checkpoint unavailable; full replay required");
                return Ok(None);
            }
            let trusted = checkpoint.is_some();
            let mut history_digest = [0; 32];
            let mut local_error = None;
            let mut next_height = 0_u64;
            let blocks = std::iter::from_fn(|| {
                if next_height > stored_height {
                    return None;
                }
                let result = reader
                    .next()
                    .ok_or_else(|| "snapshot extends beyond local body log".to_string())
                    .and_then(|bytes| bytes)
                    .and_then(|bytes| {
                        if trusted {
                            history_digest = crate::storage::advance_history_digest(
                                history_digest,
                                next_height,
                                &bytes,
                            );
                        }
                        decode_snapshot_block(&bytes)
                    });
                match result {
                    Ok(block) => {
                        next_height += 1;
                        Some(block)
                    }
                    Err(error) => {
                        local_error = Some(error);
                        None
                    }
                }
            });
            let restored = if trusted {
                Ledger::from_trusted_snapshot_with_body_cache_measured(
                    snapshot.ledger,
                    blocks,
                    max_body_bytes,
                    max_body_blocks,
                )
            } else {
                Ledger::from_snapshot_with_body_cache_measured(
                    snapshot.ledger,
                    blocks,
                    max_body_bytes,
                    max_body_blocks,
                )
            };
            if let Some(error) = local_error {
                return Err(error);
            }
            if checkpoint.is_some_and(|record| record.history_digest != history_digest) {
                return Err("snapshot validated history digest does not match local bodies".into());
            }
            let (ledger, metrics) =
                restored.map_err(|error| format!("restore local snapshot: {error}"))?;
            let ledger = ledger.with_applications(extension::SystemApplications);
            if ledger.tip_height() != Some(snapshot.height)
                || ledger.tip_hash() != Some(snapshot.tip_hash)
                || ledger
                    .chain
                    .header(&Height(0))
                    .and_then(|header| header.hash().ok())
                    != Some(EXPECTED_GENESIS_HASH)
            {
                return Err("snapshot does not match canonical body history".into());
            }
            println!(
                "snapshot: restore mode={} blocks={} pow_checks={} decode_ms={:.3} history_ms={:.3} pow_ms={:.3} supply_ms={:.3} registry_ms={:.3} root_ms={:.3} total_ms={:.3}",
                if trusted {
                    "trusted-local"
                } else {
                    "verify-pow"
                },
                metrics.blocks,
                metrics.pow_checks,
                decode_elapsed.as_secs_f64() * 1000.0,
                metrics.history.as_secs_f64() * 1000.0,
                metrics.proof_of_work.as_secs_f64() * 1000.0,
                metrics.supply_audit.as_secs_f64() * 1000.0,
                metrics.registry.as_secs_f64() * 1000.0,
                metrics.state_root.as_secs_f64() * 1000.0,
                total_start.elapsed().as_secs_f64() * 1000.0,
            );
            Ok(Some((ledger, next_height)))
        })();
        match attempt {
            Ok(Some((ledger, next))) => {
                println!(
                    "snapshot: loaded height={} tip={}",
                    ledger.tip_height().unwrap().0,
                    hex::encode(ledger.tip_hash().unwrap().0)
                );
                return Ok(Some((ledger, next)));
            }
            Ok(None) => {}
            Err(error) => errors.push(format!("height {stored_height}: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(None)
    } else {
        Err(errors.join("; "))
    }
}

fn decode_snapshot_block(bytes: &[u8]) -> Result<Block, String> {
    kernel::codec::decode_block(bytes)
        .map_err(|error| format!("decode local snapshot history: {error}"))
}

#[cfg(test)]
fn load_bytes(
    stored_height: u64,
    bytes: &[u8],
    blocks: &[Block],
) -> Result<Option<(Ledger, usize)>, String> {
    if bytes.len() <= CHECKSUM_SIZE {
        return Err("snapshot is truncated".into());
    }
    let payload_length = bytes.len() - CHECKSUM_SIZE;
    let (payload, stored_checksum) = bytes.split_at(payload_length);
    if hash_bytes(payload).0.as_slice() != stored_checksum {
        return Err("snapshot checksum does not match".into());
    }
    let snapshot = canonical_decode::<SnapshotPayload>(payload);
    let (magic, version, genesis_hash, spec_hash, height, tip_hash, compact, legacy) =
        match snapshot {
            Ok(snapshot) => (
                snapshot.magic,
                snapshot.version,
                snapshot.genesis_hash,
                snapshot.chain_spec_hash,
                snapshot.height,
                snapshot.tip_hash,
                Some(snapshot.ledger),
                None,
            ),
            Err(_) => {
                let snapshot: LegacySnapshotPayload = canonical_decode(payload)
                    .map_err(|error| format!("decode snapshot: {error}"))?;
                (
                    snapshot.magic,
                    snapshot.version,
                    snapshot.genesis_hash,
                    snapshot.chain_spec_hash,
                    snapshot.height,
                    snapshot.tip_hash,
                    None,
                    Some(snapshot.ledger),
                )
            }
        };
    if magic != SNAPSHOT_MAGIC
        || !(version == SNAPSHOT_VERSION || version == 1 && legacy.is_some())
        || genesis_hash != EXPECTED_GENESIS_HASH
        || spec_hash != chain_spec_hash().map_err(|error| error.to_string())?.0
    {
        return Err("snapshot format or genesis does not match this node".into());
    }
    if height.0 != stored_height {
        return Err("snapshot table key does not match payload height".into());
    }
    let index = usize::try_from(height.0).map_err(|_| "snapshot height is too large")?;
    let canonical = blocks
        .get(index)
        .ok_or("snapshot height is beyond the block log")?;
    if canonical.height() != height
        || canonical.hash().map_err(|error| error.to_string())? != tip_hash
    {
        return Err("snapshot tip does not match the canonical block log".into());
    }
    let ledger = match (compact, legacy) {
        (Some(snapshot), None) => Ledger::from_snapshot(snapshot, &blocks[..=index])
            .map_err(|error| format!("restore snapshot: {error}"))?,
        (None, Some(data)) => {
            if data.chain.blocks().count() != index + 1
                || !data
                    .chain
                    .blocks()
                    .zip(&blocks[..=index])
                    .all(|(saved, stored)| saved == stored)
                || data.chain_context
                    != Some(kernel::common::ChainContext::new(
                        EXPECTED_GENESIS_HASH.into_bytes(),
                    ))
            {
                return Err("legacy snapshot block log does not match the canonical chain".into());
            }
            let snapshot: LedgerSnapshot = canonical_decode(
                &canonical_bytes(&(data.state, data.journals))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            Ledger::from_snapshot(snapshot, &blocks[..=index])
                .map_err(|error| format!("restore legacy snapshot: {error}"))?
        }
        _ => return Err("snapshot format is invalid".into()),
    };
    let ledger = ledger.with_applications(extension::SystemApplications);
    if ledger.tip_height() != Some(height) || ledger.tip_hash() != Some(tip_hash) {
        return Err("snapshot metadata does not match its ledger".into());
    }
    if ledger.state_root().map_err(|error| error.to_string())? != canonical.state_root() {
        return Err("snapshot state root does not match the canonical block".into());
    }
    if version == 1
        && (ledger.chain.blocks().count() != index + 1
            || !ledger
                .chain
                .blocks()
                .zip(&blocks[..=index])
                .all(|(saved, stored)| saved == stored))
    {
        return Err("legacy snapshot block log does not match the canonical chain".into());
    }
    println!(
        "snapshot: loaded height={} tip={}",
        height.0,
        hex::encode(tip_hash.0)
    );
    Ok(Some((ledger, index + 1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::{
        blockchain::Emission,
        common::Nonce,
        consensus::{
            apply_block, apply_genesis, expected_emission_for_height, expected_next_difficulty,
            new_pow_memory,
        },
        crypto::ProgramId,
        genesis::genesis_block,
    };
    use std::fs;

    fn write(database: &Path, ledger: &Ledger) -> Result<(), String> {
        for block in ledger.chain.blocks() {
            if crate::storage::read_block_at_height(database, block.height().0)?.is_none() {
                crate::storage::append_block_and_replace_mempool(
                    database,
                    &crate::storage::StoredCanonicalBlock {
                        height: block.height().0,
                        hash: block.hash().map_err(|error| error.to_string())?.0,
                        bytes: kernel::codec::block_bytes(block)
                            .map_err(|error| error.to_string())?,
                        transactions: vec![],
                        activities: vec![],
                    },
                    &[],
                )?;
            }
        }
        super::write(database, ledger)
    }

    #[test]
    fn uncertified_snapshot_requires_replay_but_recovery_keeps_full_restore() {
        let directory = test_directory("uncertified");
        let ledger = kernel::genesis::genesis_ledger()
            .unwrap()
            .with_applications(extension::SystemApplications);
        write(&directory, &ledger).unwrap();
        let (restored, next) = load_streamed(&directory, usize::MAX, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(restored, ledger);
        assert_eq!(next, 1);
        let bytes = crate::storage::snapshots_descending(&directory)
            .unwrap()
            .remove(0)
            .1;
        // Overwriting snapshot data clears the validation checkpoint atomically.
        crate::storage::put_snapshot(&directory, 0, &bytes).unwrap();
        assert!(
            load_streamed(&directory, usize::MAX, usize::MAX)
                .unwrap()
                .is_none()
        );
        let (recovery, next) = load_streamed_through(&directory, usize::MAX, usize::MAX, 0)
            .unwrap()
            .unwrap();
        assert_eq!(recovery, ledger);
        assert_eq!(next, 1);
        crate::storage::release_cached_database(&directory);
        fs::remove_dir_all(directory).unwrap();
    }

    fn test_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kernel-snapshot-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn snapshot_roundtrip_is_bound_to_canonical_tip() {
        let directory = test_directory("roundtrip");
        fs::create_dir_all(&directory).unwrap();
        let genesis = genesis_block().unwrap();
        let mut ledger = Ledger::new().with_applications(extension::SystemApplications);
        apply_genesis(&mut ledger, genesis.clone(), EXPECTED_GENESIS_HASH).unwrap();

        write(&directory, &ledger).unwrap();
        let (loaded, next) = load(&directory, &[genesis]).unwrap().unwrap();
        assert_eq!(loaded, ledger);
        assert_eq!(next, 1);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn corrupted_snapshot_is_rejected() {
        let directory = test_directory("corrupt");
        fs::create_dir_all(&directory).unwrap();
        crate::storage::put_snapshot(&directory, 0, &[0_u8; CHECKSUM_SIZE + 1]).unwrap();
        assert!(load(&directory, &[]).unwrap_err().contains("checksum"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compact_snapshot_omits_duplicate_chain_and_accepts_legacy_snapshot() {
        let directory = test_directory("legacy");
        fs::create_dir_all(&directory).unwrap();
        let genesis = genesis_block().unwrap();
        let mut ledger = Ledger::new().with_applications(extension::SystemApplications);
        apply_genesis(&mut ledger, genesis.clone(), EXPECTED_GENESIS_HASH).unwrap();

        write(&directory, &ledger).unwrap();
        let (_, compact) = crate::storage::snapshots_descending(&directory)
            .unwrap()
            .remove(0);
        let legacy = LegacySnapshotPayload {
            magic: SNAPSHOT_MAGIC,
            version: 1,
            genesis_hash: EXPECTED_GENESIS_HASH,
            chain_spec_hash: chain_spec_hash().unwrap().0,
            height: Height(0),
            tip_hash: EXPECTED_GENESIS_HASH,
            ledger: LegacyLedgerData::from_ledger(&ledger),
        };
        let legacy_bytes = canonical_bytes(&legacy).unwrap();
        assert!(compact.len() < legacy_bytes.len() + CHECKSUM_SIZE);

        let mut stored = legacy_bytes.clone();
        stored.extend_from_slice(&hash_bytes(&legacy_bytes).0);
        crate::storage::put_snapshot(&directory, 0, &stored).unwrap();
        let (loaded, next) = load(&directory, &[genesis]).unwrap().unwrap();
        assert_eq!(loaded, ledger);
        assert_eq!(next, 1);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn compact_snapshot_rejects_state_that_disagrees_with_block() {
        let directory = test_directory("state-root");
        fs::create_dir_all(&directory).unwrap();
        let genesis = genesis_block().unwrap();
        let mut canonical = Ledger::new().with_applications(extension::SystemApplications);
        apply_genesis(&mut canonical, genesis.clone(), EXPECTED_GENESIS_HASH).unwrap();
        let canonical_bytes = borsh::to_vec(&canonical).unwrap();
        let (_, journals): (
            kernel::ledger::LedgerState,
            std::collections::BTreeMap<Height, Vec<kernel::ledger::StateRollbackJournal>>,
        ) = borsh::from_slice(&borsh::to_vec(&canonical.snapshot()).unwrap()).unwrap();
        let state = canonical.state();
        let forged_state: kernel::ledger::LedgerState = borsh::from_slice(
            &borsh::to_vec(&(
                state.utxos(),
                kernel::ledger::CoinRecord {
                    total_mined: kernel::monetary::coin::Zeno::from_zeno(1),
                    total_burned: kernel::monetary::coin::Zeno::from_zeno(1),
                },
                state.programs(),
                state.extensions(),
            ))
            .unwrap(),
        )
        .unwrap();
        let payload = SnapshotPayload {
            magic: SNAPSHOT_MAGIC,
            version: SNAPSHOT_VERSION,
            genesis_hash: EXPECTED_GENESIS_HASH,
            chain_spec_hash: chain_spec_hash().unwrap().0,
            height: Height(0),
            tip_hash: EXPECTED_GENESIS_HASH,
            ledger: borsh::from_slice(&borsh::to_vec(&(forged_state, journals)).unwrap()).unwrap(),
        };
        let mut stored = borsh::to_vec(&payload).unwrap();
        let checksum = hash_bytes(&stored);
        stored.extend_from_slice(&checksum.0);
        crate::storage::put_snapshot(&directory, 0, &stored).unwrap();
        assert!(
            load(&directory, &[genesis])
                .unwrap_err()
                .contains("state root")
        );
        assert_eq!(borsh::to_vec(&canonical).unwrap(), canonical_bytes);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn restored_snapshot_can_rollback_a_mined_block() {
        let directory = test_directory("rollback");
        fs::create_dir_all(&directory).unwrap();
        let genesis = genesis_block().unwrap();
        let mut ledger = Ledger::new().with_applications(extension::SystemApplications);
        apply_genesis(&mut ledger, genesis.clone(), EXPECTED_GENESIS_HASH).unwrap();
        let genesis_ledger = ledger.clone();
        write(&directory, &genesis_ledger).unwrap();
        let mut blocks = vec![genesis];
        let mut memory = new_pow_memory();

        for height in 1..=2 {
            let height = Height(height);
            let mut block = Block::from_protocol_operations(
                height,
                ledger.tip_hash().unwrap(),
                expected_next_difficulty(&ledger.chain).unwrap(),
                Nonce(0),
                Some(Emission::new(
                    ProgramId::ZERO,
                    expected_emission_for_height(height),
                )),
                vec![],
            )
            .unwrap();
            let (state_root, weight) = ledger.preview_block_commitments(&block).unwrap();
            block.set_state_root(state_root);
            block.set_block_weight(weight);
            assert!(
                crate::miner::mine_range(
                    &mut block,
                    crate::miner::MiningRange {
                        start_nonce: 0,
                        attempts: 100,
                    },
                    &mut memory,
                )
                .unwrap()
                .is_some()
            );
            apply_block(&mut ledger, block.clone()).unwrap();
            blocks.push(block);
        }

        write(&directory, &ledger).unwrap();
        let (_, compact) = crate::storage::snapshots_descending(&directory)
            .unwrap()
            .remove(0);
        let legacy = LegacySnapshotPayload {
            magic: SNAPSHOT_MAGIC,
            version: 1,
            genesis_hash: EXPECTED_GENESIS_HASH,
            chain_spec_hash: chain_spec_hash().unwrap().0,
            height: Height(2),
            tip_hash: ledger.tip_hash().unwrap(),
            ledger: LegacyLedgerData::from_ledger(&ledger),
        };
        let legacy_size = canonical_bytes(&legacy).unwrap().len() + CHECKSUM_SIZE;
        println!(
            "snapshot sizes: compact={} legacy={legacy_size}",
            compact.len()
        );
        assert!(compact.len() < legacy_size);
        let (mut restored, next) = load(&directory, &blocks).unwrap().unwrap();
        assert_eq!(next, 3);
        assert_eq!(restored, ledger);
        assert_eq!(restored.rollback_tip().unwrap(), blocks[2]);
        assert_eq!(restored.tip_hash(), Some(blocks[1].hash().unwrap()));

        let mut changed_body = blocks.clone();
        changed_body[1].body_mut().emission.as_mut().unwrap().to =
            ProgramId::from_bytes([1; kernel::crypto::PROGRAM_ID_SIZE]);
        assert!(
            load_bytes(2, &compact, &changed_body)
                .unwrap_err()
                .contains("invalid block")
        );

        let legacy_bytes = canonical_bytes(&legacy).unwrap();
        let mut stored_legacy = legacy_bytes.clone();
        stored_legacy.extend_from_slice(&hash_bytes(&legacy_bytes).0);
        assert!(
            load_bytes(2, &stored_legacy, &changed_body)
                .unwrap_err()
                .contains("legacy snapshot block log")
        );

        let mut different_tip = blocks.clone();
        different_tip[2].header.nonce = Nonce(99);
        let (fallback, next) = load(&directory, &different_tip).unwrap().unwrap();
        assert_eq!(fallback, genesis_ledger);
        assert_eq!(next, 1);

        fs::remove_dir_all(directory).unwrap();
    }
}
