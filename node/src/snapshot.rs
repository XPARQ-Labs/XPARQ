use crate::runtime::storage::Storage;
use borsh::{BorshDeserialize, BorshSerialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use xparq::genesis::artifact::{ledger_from_authenticated_snapshot, snapshot_xparq_bytes};
use xparq::genesis::genesis_ledger;
use xparq::ledger::{Ledger, Work};
use xparq::qcash::recovery::ChainHeader;

pub const FAST_SYNC_BUNDLE_VERSION: u8 = 1;
pub const MAX_FAST_SYNC_BUNDLE_SIZE: u64 = 300 * 1024 * 1024;

pub fn compress_chunk(bytes: &[u8]) -> (crate::runtime::network::SnapshotCompression, Vec<u8>) {
    let mut encoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let value = bytes[index];
        let mut count = 1usize;
        while index + count < bytes.len() && bytes[index + count] == value && count < 255 {
            count += 1;
        }
        encoded.push(count as u8);
        encoded.push(value);
        index += count;
    }
    if encoded.len() < bytes.len() {
        (crate::runtime::network::SnapshotCompression::Rle, encoded)
    } else {
        (
            crate::runtime::network::SnapshotCompression::None,
            bytes.to_vec(),
        )
    }
}

pub fn decompress_chunk(
    compression: crate::runtime::network::SnapshotCompression,
    bytes: &[u8],
    expected_length: usize,
) -> Result<Vec<u8>, String> {
    if expected_length > crate::runtime::network::handler::SNAPSHOT_CHUNK_SIZE as usize {
        return Err("snapshot chunk decompressed size exceeds limit".to_string());
    }
    match compression {
        crate::runtime::network::SnapshotCompression::None => {
            if bytes.len() != expected_length {
                return Err("snapshot chunk length mismatch".to_string());
            }
            Ok(bytes.to_vec())
        }
        crate::runtime::network::SnapshotCompression::Rle => {
            if !bytes.len().is_multiple_of(2) {
                return Err("invalid RLE snapshot chunk".to_string());
            }
            let mut decoded = Vec::with_capacity(expected_length);
            for pair in bytes.chunks_exact(2) {
                let count = pair[0] as usize;
                if count == 0 || decoded.len().saturating_add(count) > expected_length {
                    return Err("invalid RLE snapshot expansion".to_string());
                }
                decoded.extend(std::iter::repeat_n(pair[1], count));
            }
            if decoded.len() != expected_length {
                return Err("snapshot chunk decompressed length mismatch".to_string());
            }
            Ok(decoded)
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct FastSyncBundle {
    pub version: u8,
    pub headers: Vec<ChainHeader>,
    pub snapshot: Vec<u8>,
}

impl FastSyncBundle {
    pub fn from_ledger(ledger: &Ledger) -> Result<Self, String> {
        let headers = ledger
            .chain
            .chain_headers()
            .map_err(|error| format!("failed to collect canonical headers: {error}"))?;
        if headers.is_empty() {
            return Err("cannot export a snapshot without a canonical header chain".to_string());
        }
        let snapshot = snapshot_xparq_bytes(ledger)
            .map_err(|error| format!("failed to create snapshot: {error}"))?;
        Ok(Self {
            version: FAST_SYNC_BUNDLE_VERSION,
            headers,
            snapshot,
        })
    }

    pub fn validate(self) -> Result<(Ledger, Work), String> {
        if self.version != FAST_SYNC_BUNDLE_VERSION {
            return Err(format!(
                "unsupported fast-sync bundle version {}",
                self.version
            ));
        }
        ledger_from_authenticated_snapshot(&self.snapshot, &self.headers)
            .map_err(|error| format!("authenticated snapshot rejected: {error}"))
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes =
            borsh::to_vec(self).map_err(|error| format!("failed to encode snapshot: {error}"))?;
        if bytes.len() as u64 > MAX_FAST_SYNC_BUNDLE_SIZE {
            return Err("fast-sync bundle exceeds the local size limit".to_string());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() as u64 > MAX_FAST_SYNC_BUNDLE_SIZE {
            return Err("fast-sync bundle exceeds the local size limit".to_string());
        }
        Self::try_from_slice(bytes)
            .map_err(|error| format!("failed to decode fast-sync bundle: {error}"))
    }
}

pub fn export_to_file(ledger: &Ledger, output: impl AsRef<Path>) -> Result<(), String> {
    let bytes = FastSyncBundle::from_ledger(ledger)?.encode()?;
    fs::write(output.as_ref(), bytes).map_err(|error| {
        format!(
            "failed to write fast-sync bundle {}: {error}",
            output.as_ref().display()
        )
    })
}

pub fn import_file_atomic(
    database_path: impl AsRef<Path>,
    bundle_path: impl AsRef<Path>,
) -> Result<(xparq::block::Height, xparq::crypto::BlockHash, Work), String> {
    let database_path = database_path.as_ref();
    if database_path.exists() {
        return Err(format!(
            "fast-sync target {} already exists; use a new database path",
            database_path.display()
        ));
    }
    let metadata = fs::metadata(bundle_path.as_ref()).map_err(|error| {
        format!(
            "failed to inspect fast-sync bundle {}: {error}",
            bundle_path.as_ref().display()
        )
    })?;
    if metadata.len() > MAX_FAST_SYNC_BUNDLE_SIZE {
        return Err("fast-sync bundle exceeds the local size limit".to_string());
    }
    let bytes = fs::read(bundle_path.as_ref()).map_err(|error| {
        format!(
            "failed to read fast-sync bundle {}: {error}",
            bundle_path.as_ref().display()
        )
    })?;
    import_bytes_atomic(database_path, &bytes)
}

pub fn import_bytes_atomic(
    database_path: impl AsRef<Path>,
    bytes: &[u8],
) -> Result<(xparq::block::Height, xparq::crypto::BlockHash, Work), String> {
    let database_path = database_path.as_ref();
    if database_path.exists() {
        return Err(format!(
            "fast-sync target {} already exists; use a new database path",
            database_path.display()
        ));
    }
    let bundle = FastSyncBundle::decode(bytes)?;
    let (ledger, work) = bundle.validate()?;
    let height = ledger
        .tip_height()
        .ok_or_else(|| "authenticated snapshot has no tip height".to_string())?;
    let hash = ledger
        .tip_hash()
        .ok_or_else(|| "authenticated snapshot has no tip hash".to_string())?;

    let staging = staging_path(database_path)?;
    fs::create_dir_all(&staging)
        .map_err(|error| format!("failed to create snapshot staging directory: {error}"))?;
    let result = (|| {
        let storage = Storage::open(&staging)
            .map_err(|error| format!("failed to open snapshot staging database: {error}"))?;
        storage
            .save_ledger(&ledger)
            .map_err(|error| format!("failed to persist authenticated snapshot: {error}"))?;
        storage
            .save_genesis_accounts(
                genesis_ledger()
                    .map_err(|error| error.to_string())?
                    .accounts(),
            )
            .map_err(|error| format!("failed to persist canonical genesis accounts: {error}"))?;
        drop(storage);
        fs::rename(&staging, database_path)
            .map_err(|error| format!("failed to atomically activate snapshot database: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    Ok((height, hash, work))
}

fn staging_path(database_path: &Path) -> Result<PathBuf, String> {
    let parent = database_path.parent().unwrap_or_else(|| Path::new("."));
    let name = database_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "fast-sync database path has no valid final component".to_string())?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    Ok(parent.join(format!(".{name}.fastsync-{}-{nonce}", std::process::id())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_target(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "xparq-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn snapshot_chunk_compression_roundtrips_and_is_bounded() {
        let bytes = vec![7_u8; 16_384];
        let (compression, encoded) = compress_chunk(&bytes);
        assert_eq!(
            compression,
            crate::runtime::network::SnapshotCompression::Rle
        );
        assert!(encoded.len() < bytes.len());
        assert_eq!(
            decompress_chunk(compression, &encoded, bytes.len()).unwrap(),
            bytes
        );
        assert!(
            decompress_chunk(
                compression,
                &encoded,
                crate::runtime::network::handler::SNAPSHOT_CHUNK_SIZE as usize + 1
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(feature = "mainnet")]
    fn authenticated_genesis_snapshot_imports_and_reopens() {
        let ledger = genesis_ledger().unwrap();
        let bytes = FastSyncBundle::from_ledger(&ledger)
            .unwrap()
            .encode()
            .unwrap();
        let target = unique_target("fastsync-ok");

        let (height, hash, _) = import_bytes_atomic(&target, &bytes).unwrap();
        assert_eq!(height, xparq::block::Height(0));
        assert_eq!(hash, ledger.tip_hash().unwrap());

        let restored = Storage::open(&target).unwrap().load_ledger().unwrap();
        assert_eq!(restored.tip_hash(), ledger.tip_hash());
        assert_eq!(restored.accounts(), ledger.accounts());
        fs::remove_dir_all(target).unwrap();
    }

    #[test]
    #[cfg(feature = "mainnet")]
    fn tampered_snapshot_never_activates_target_database() {
        let ledger = genesis_ledger().unwrap();
        let mut bundle = FastSyncBundle::from_ledger(&ledger).unwrap();
        let last = bundle.snapshot.len() - 1;
        bundle.snapshot[last] ^= 1;
        let bytes = bundle.encode().unwrap();
        let target = unique_target("fastsync-reject");

        assert!(import_bytes_atomic(&target, &bytes).is_err());
        assert!(!target.exists());
    }

    #[test]
    #[cfg(feature = "mainnet")]
    fn forged_header_chain_never_activates_target_database() {
        let ledger = genesis_ledger().unwrap();
        let mut bundle = FastSyncBundle::from_ledger(&ledger).unwrap();
        bundle.headers[0].header.block_weight ^= 1;
        let bytes = bundle.encode().unwrap();
        let target = unique_target("fastsync-forged-header");

        assert!(import_bytes_atomic(&target, &bytes).is_err());
        assert!(!target.exists());
    }
}
