use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use xparq::{
    block::{Block, Height},
    common::{canonical_bytes, canonical_decode},
    crypto::{BlockHash, hash_bytes},
    genesis::{EXPECTED_GENESIS_HASH, chain_spec_hash},
    ledger::Ledger,
};

pub const SNAPSHOT_INTERVAL: u64 = 1_000;

const SNAPSHOT_MAGIC: [u8; 8] = *b"XPQSNAP1";
const SNAPSHOT_VERSION: u32 = 1;
const CHECKSUM_SIZE: usize = 32;

#[derive(BorshSerialize, BorshDeserialize)]
struct SnapshotPayload {
    magic: [u8; 8],
    version: u32,
    genesis_hash: BlockHash,
    chain_spec_hash: [u8; 32],
    height: Height,
    tip_hash: BlockHash,
    ledger: Ledger,
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

fn write(database: &Path, ledger: &Ledger) -> Result<(), String> {
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
        ledger: ledger.clone(),
    };
    let payload = canonical_bytes(&payload).map_err(|error| format!("encode snapshot: {error}"))?;
    let checksum = hash_bytes(&payload);
    let mut bytes = Vec::with_capacity(payload.len() + CHECKSUM_SIZE);
    bytes.extend_from_slice(&payload);
    bytes.extend_from_slice(&checksum.0);

    crate::storage::put_snapshot(database, height.0, &bytes)?;
    println!(
        "snapshot: saved height={} tip={}",
        height.0,
        hex::encode(tip_hash.0)
    );
    Ok(())
}

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
    let snapshot: SnapshotPayload =
        canonical_decode(payload).map_err(|error| format!("decode snapshot: {error}"))?;
    if snapshot.magic != SNAPSHOT_MAGIC
        || snapshot.version != SNAPSHOT_VERSION
        || snapshot.genesis_hash != EXPECTED_GENESIS_HASH
        || snapshot.chain_spec_hash != chain_spec_hash().map_err(|error| error.to_string())?.0
    {
        return Err("snapshot format or genesis does not match this node".into());
    }
    if snapshot.height.0 != stored_height {
        return Err("snapshot table key does not match payload height".into());
    }
    if snapshot.ledger.tip_height() != Some(snapshot.height)
        || snapshot.ledger.tip_hash() != Some(snapshot.tip_hash)
    {
        return Err("snapshot metadata does not match its ledger".into());
    }
    let index = usize::try_from(snapshot.height.0).map_err(|_| "snapshot height is too large")?;
    let canonical = blocks
        .get(index)
        .ok_or("snapshot height is beyond the block log")?;
    if canonical.height() != snapshot.height
        || canonical.hash().map_err(|error| error.to_string())? != snapshot.tip_hash
    {
        return Err("snapshot tip does not match the canonical block log".into());
    }
    println!(
        "snapshot: loaded height={} tip={}",
        snapshot.height.0,
        hex::encode(snapshot.tip_hash.0)
    );
    Ok(Some((snapshot.ledger, index + 1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use xparq::{consensus::apply_genesis, genesis::genesis_block};

    fn test_directory(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "xparq-snapshot-{label}-{}-{}",
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
        let mut ledger = Ledger::new();
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
}
