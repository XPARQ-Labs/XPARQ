//! Durable, bounded block download cache. Stored data is never trusted as consensus state.
use std::path::Path;

use super::{Block, MAX_STORED_BLOCK_SIZE, decode_block};
use kernel::consensus::HeaderAtHeight;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
const META: TableDefinition<u8, &[u8]> = TableDefinition::new("metadata");
pub(super) const DEFAULT_STAGING_BYTES: u64 = 8 * 1024 * 1024 * 1024;

pub(super) struct DiskStage {
    database: Database,
    pub(super) count: usize,
    pub(super) bytes: u64,
    maximum: u64,
}

fn matches(block: &Block, expected: &HeaderAtHeight) -> bool {
    block.height() == expected.height && block.header == expected.header
}

impl DiskStage {
    /// Resume only a matching branch and revalidate every retained body against
    /// freshly verified headers. A corrupt/incomplete suffix is discarded.
    pub(super) fn open(
        directory: &Path,
        branch: &[u8],
        headers: &[HeaderAtHeight],
        maximum: u64,
    ) -> Result<Self, String> {
        std::fs::create_dir_all(directory)
            .map_err(|error| format!("create sync staging directory: {error}"))?;
        let database = Database::builder()
            .set_cache_size(16 * 1024 * 1024)
            .create(directory.join("litep2p-sync.redb"))
            .map_err(|error| format!("open sync staging database: {error}"))?;
        let transaction = database.begin_write().map_err(|error| error.to_string())?;
        {
            let mut metadata = transaction
                .open_table(META)
                .map_err(|error| error.to_string())?;
            let same = metadata
                .get(0)
                .map_err(|error| error.to_string())?
                .is_some_and(|value| value.value() == branch);
            let mut blocks = transaction
                .open_table(BLOCKS)
                .map_err(|error| error.to_string())?;
            if !same {
                blocks
                    .retain(|_, _| false)
                    .map_err(|error| error.to_string())?;
                metadata
                    .insert(0, branch)
                    .map_err(|error| error.to_string())?;
            }
        }
        transaction.commit().map_err(|error| error.to_string())?;
        let mut stage = Self {
            database,
            count: 0,
            bytes: 0,
            maximum,
        };
        let transaction = stage
            .database
            .begin_read()
            .map_err(|error| error.to_string())?;
        let table = transaction
            .open_table(BLOCKS)
            .map_err(|error| error.to_string())?;
        for (index, expected) in headers.iter().enumerate() {
            let Some(value) = table.get(index as u64).map_err(|error| error.to_string())? else {
                break;
            };
            let bytes = value.value();
            if bytes.len() > MAX_STORED_BLOCK_SIZE {
                break;
            }
            let Ok(block) = decode_block(bytes) else {
                break;
            };
            if !matches(&block, expected) {
                break;
            }
            let next_bytes = stage
                .bytes
                .checked_add(bytes.len() as u64)
                .filter(|bytes| *bytes <= maximum)
                .ok_or("sync staging disk budget exceeded; increase --sync-staging-mib")?;
            stage.bytes = next_bytes;
            stage.count += 1;
        }
        drop(table);
        drop(transaction);
        stage.truncate(stage.count)?;
        Ok(stage)
    }

    fn truncate(&self, count: usize) -> Result<(), String> {
        let transaction = self
            .database
            .begin_write()
            .map_err(|error| error.to_string())?;
        transaction
            .open_table(BLOCKS)
            .map_err(|error| error.to_string())?
            .retain(|index, _| index < count as u64)
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())
    }

    pub(super) fn append(&mut self, bytes: &[u8], expected: &HeaderAtHeight) -> Result<(), String> {
        if bytes.len() > MAX_STORED_BLOCK_SIZE {
            return Err("staged block exceeds size limit".into());
        }
        let next_bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|bytes| *bytes <= self.maximum)
            .ok_or("sync staging disk budget exceeded; increase --sync-staging-mib")?;
        let block = decode_block(bytes).map_err(|error| format!("decode staged block: {error}"))?;
        if !matches(&block, expected) {
            return Err("staged block does not match verified header".into());
        }
        let transaction = self
            .database
            .begin_write()
            .map_err(|error| error.to_string())?;
        transaction
            .open_table(BLOCKS)
            .map_err(|error| error.to_string())?
            .insert(self.count as u64, bytes)
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        self.count += 1;
        self.bytes = next_bytes;
        Ok(())
    }

    pub(super) fn read(&self, index: usize) -> Result<Block, String> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| error.to_string())?;
        let table = transaction
            .open_table(BLOCKS)
            .map_err(|error| error.to_string())?;
        let value = table
            .get(index as u64)
            .map_err(|error| error.to_string())?
            .ok_or("staged block is missing")?;
        if value.value().len() > MAX_STORED_BLOCK_SIZE {
            return Err("staged block exceeds size limit".into());
        }
        decode_block(value.value()).map_err(|error| format!("decode staged block: {error}"))
    }

    pub(super) fn clear(&mut self) -> Result<(), String> {
        self.truncate(0)?;
        self.count = 0;
        self.bytes = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::{
        common::{Height, Nonce},
        crypto::{AccountSignatureScheme, ProgramId, SigningSeed, program_id_from_public_key},
        monetary::coin::Zeno,
        operation::{AuthorizedDeployProgram, BlockOperation},
        program::{AccountAuthorization, CoinTransition, DeployProgram},
    };

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("xparq-sync-stage-{}-{}",
                std::process::id(), std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn genesis_fixture() -> (Vec<u8>, HeaderAtHeight) {
        let block = kernel::genesis::genesis_block().unwrap();
        (
            super::super::block_bytes(&block).unwrap(),
            HeaderAtHeight::new(block.height(), block.header),
        )
    }

    #[test]
    fn resumes_valid_prefix_and_repairs_corrupt_suffix_without_trusting_metadata() {
        let directory = Directory::new();
        let (bytes, header) = genesis_fixture();
        let headers = vec![header; 3];
        let mut stage = DiskStage::open(&directory.0, b"branch", &headers, 8192).unwrap();
        stage.append(&bytes, &headers[0]).unwrap();
        stage.append(&bytes, &headers[1]).unwrap();
        let transaction = stage.database.begin_write().unwrap();
        transaction
            .open_table(BLOCKS)
            .unwrap()
            .insert(1, &[0_u8][..])
            .unwrap();
        transaction.commit().unwrap();
        drop(stage);
        let mut stage = DiskStage::open(&directory.0, b"branch", &headers, 8192).unwrap();
        assert_eq!(stage.count, 1);
        assert_eq!(stage.bytes, bytes.len() as u64);
        assert!(stage.read(1).is_err());
        stage.append(&bytes, &headers[1]).unwrap();
        drop(stage);
        // Extending the target reuses already verified bodies under the same ancestor.
        let stage = DiskStage::open(&directory.0, b"branch", &headers, 8192).unwrap();
        assert_eq!(stage.count, 2);
        drop(stage);
        let stage = DiskStage::open(&directory.0, b"different-ancestor", &headers, 8192).unwrap();
        assert_eq!((stage.count, stage.bytes), (0, 0));
    }

    #[test]
    fn quota_checks_are_atomic_and_corrupted_staged_bytes_are_rejected() {
        let directory = Directory::new();
        let (bytes, header) = genesis_fixture();
        let mut stage = DiskStage::open(
            &directory.0,
            b"branch",
            std::slice::from_ref(&header),
            bytes.len() as u64,
        )
        .unwrap();
        assert!(stage.append(&[0], &header).is_err());
        assert_eq!((stage.count, stage.bytes), (0, 0));
        stage.append(&bytes, &header).unwrap();
        assert!(
            stage
                .append(&[0], &header)
                .unwrap_err()
                .contains("disk budget")
        );
        assert_eq!(stage.count, 1);
        stage.clear().unwrap();
        assert_eq!((stage.count, stage.bytes), (0, 0));
        drop(stage);
        assert_eq!(
            DiskStage::open(&directory.0, b"branch", &[header], 8192)
                .unwrap()
                .count,
            0
        );
    }

    #[test]
    fn staging_supports_more_than_4096_entries_without_a_body_vector() {
        let directory = Directory::new();
        let (bytes, header) = genesis_fixture();
        let headers = vec![header; 5000];
        let stage = DiskStage::open(
            &directory.0,
            b"large-prefix",
            &headers,
            DEFAULT_STAGING_BYTES,
        )
        .unwrap();
        // Storage stress fixture; these repeated genesis entries are not a mined chain.
        let transaction = stage.database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(BLOCKS).unwrap();
            for index in 0..headers.len() {
                table.insert(index as u64, bytes.as_slice()).unwrap();
            }
        }
        transaction.commit().unwrap();
        drop(stage);
        let stage = DiskStage::open(
            &directory.0,
            b"large-prefix",
            &headers,
            DEFAULT_STAGING_BYTES,
        )
        .unwrap();
        assert_eq!(stage.count, 5000);
        assert_eq!(stage.bytes, 5000 * bytes.len() as u64);
        assert_eq!(stage.read(4999).unwrap().height(), Height(0));
    }

    #[test]
    fn staging_and_resume_cross_the_former_64_mib_budget() {
        let directory = Directory::new();
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([57; 32]));
        let owner = program_id_from_public_key(&seed.public_key()).unwrap();
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.resize(kernel::program::MAX_PROGRAM_CODE_SIZE - 10, 0); // NOP padding.
        code.push(1);
        code.extend_from_slice(&7_i64.to_le_bytes());
        code.push(3);
        let operation = BlockOperation::DeployProgram(Box::new(AuthorizedDeployProgram {
            deploy: DeployProgram {
                owner,
                nonce: 1,
                code: code.into(),
            },
            payment: CoinTransition::coin(
                owner,
                vec![kernel::monetary::coin::CoinShare::from_bytes([1; 32])],
                vec![kernel::monetary::coin::CoinOutput::new(owner, Zeno::ONE)],
            )
            .unwrap(),
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(b"storage-stress"),
            },
        }));
        let block = Block::from_protocol_operations(
            Height(1),
            kernel::crypto::PreviousHash::ZERO,
            0x207f_ffff,
            Nonce(1),
            Some(super::super::Emission::new(ProgramId::ZERO, Zeno::ONE)),
            vec![operation],
        )
        .unwrap();
        let bytes = super::super::block_bytes(&block).unwrap();
        assert!(decode_block(&bytes).is_ok());
        let header = HeaderAtHeight::new(block.height(), block.header);
        let headers = vec![header; 65];
        let mut stage =
            DiskStage::open(&directory.0, b"large-bodies", &headers, 128 * 1024 * 1024).unwrap();
        // These blocks exercise the storage/codec boundary, not consensus authorization.
        for expected in &headers {
            stage.append(&bytes, expected).unwrap();
        }
        assert!(stage.bytes > 64 * 1024 * 1024);
        drop(stage);
        let stage =
            DiskStage::open(&directory.0, b"large-bodies", &headers, 128 * 1024 * 1024).unwrap();
        assert_eq!(stage.count, 65);
        assert!(stage.bytes > 64 * 1024 * 1024);
        assert_eq!(stage.read(64).unwrap().height(), Height(1));
    }
}
