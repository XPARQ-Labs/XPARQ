use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind, Read};
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{HASH_SIZE, HashDomain, canonical_bytes, domain};

use crate::{common::Height, state_map::StateMap};

pub use crypto::ProgramId;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct ProgramHash([u8; HASH_SIZE]);

impl ProgramHash {
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    pub fn derive(code: &[u8]) -> Result<Self, RegistryError> {
        let bytes = canonical_bytes(&(b"xparq:program-code:v1", code))
            .map_err(|_| RegistryError::Encoding)?;

        Ok(Self(domain(HashDomain::XPARQArtifact, &bytes).into_bytes()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRecord {
    pub code_hash: ProgramHash,
    /// Shared code bytes; canonical encoding remains the historical Vec encoding.
    pub code: Arc<Vec<u8>>,
    /// Deployment key identity, not authority to spend this program's balances.
    pub owner: ProgramId,
    pub nonce: u64,
    pub deployed_at: Height,
    pub state_value: i64,
    /// Shared between staged states; writes detach only this program's storage.
    /// Canonical encoding remains the historical BTreeMap encoding.
    pub storage: Arc<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl BorshSerialize for ProgramRecord {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.code_hash, writer)?;
        BorshSerialize::serialize(&self.code, writer)?;
        BorshSerialize::serialize(&self.owner, writer)?;
        BorshSerialize::serialize(&self.nonce, writer)?;
        BorshSerialize::serialize(&self.deployed_at, writer)?;
        BorshSerialize::serialize(&self.state_value, writer)?;
        if self.code.get(4) == Some(&super::vm::APPLICATION_VERSION) {
            BorshSerialize::serialize(&self.storage, writer)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for ProgramRecord {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let code_hash = ProgramHash::deserialize_reader(reader)?;
        let code: Arc<Vec<u8>> = super::deserialize_program_code(reader)?.into();
        let version = code.get(4).copied();
        Ok(Self {
            code_hash,
            code,
            owner: ProgramId::deserialize_reader(reader)?,
            nonce: u64::deserialize_reader(reader)?,
            deployed_at: Height::deserialize_reader(reader)?,
            state_value: i64::deserialize_reader(reader)?,
            storage: if version == Some(super::vm::APPLICATION_VERSION) {
                super::vm_app::read_storage(reader)?.into()
            } else {
                Arc::default()
            },
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize)]
pub struct ProgramRegistry {
    programs: StateMap<ProgramId, ProgramRecord>,
    // Derived lookup data must never affect canonical state bytes.
    #[borsh(skip)]
    deployments: StateMap<(ProgramId, u64), ()>,
}

impl BorshDeserialize for ProgramRegistry {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let count = u32::deserialize_reader(reader)?;
        let mut registry = Self::default();
        let mut previous = None;
        for _ in 0..count {
            let id = ProgramId::deserialize_reader(reader)?;
            if previous.is_some_and(|previous| previous >= id) {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "noncanonical program registry keys",
                ));
            }
            previous = Some(id);
            let record = ProgramRecord::deserialize_reader(reader)?;
            registry.validate_record(id, &record).map_err(|_| {
                Error::new(ErrorKind::InvalidData, "invalid program registry record")
            })?;
            registry
                .insert(id, record)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "duplicate program deployment"))?;
        }
        Ok(registry)
    }
}

impl ProgramRegistry {
    pub(crate) fn same_canonical_view(&self, other: &Self) -> bool {
        let Self {
            programs,
            deployments: _,
        } = self;
        programs.shares_root(&other.programs)
    }

    pub fn program(&self, id: &ProgramId) -> Option<&ProgramRecord> {
        self.programs.get(id)
    }

    pub fn contains(&self, id: &ProgramId) -> bool {
        self.programs.contains_key(id)
    }

    pub(crate) fn insert(
        &mut self,
        id: ProgramId,
        record: ProgramRecord,
    ) -> Result<(), RegistryError> {
        self.check_available(id, record.owner, record.nonce)?;
        self.deployments.insert((record.owner, record.nonce), ());
        self.programs.insert(id, record);
        Ok(())
    }

    pub(crate) fn remove(&mut self, id: &ProgramId) -> Option<ProgramRecord> {
        let record = self.programs.remove(id)?;
        self.deployments.remove(&(record.owner, record.nonce));
        Some(record)
    }

    pub(crate) fn check_available(
        &self,
        id: ProgramId,
        owner: ProgramId,
        nonce: u64,
    ) -> Result<(), RegistryError> {
        if self.contains(&id) || self.deployments.contains_key(&(owner, nonce)) {
            return Err(RegistryError::AlreadyExists);
        }
        Ok(())
    }

    fn validate_record(&self, id: ProgramId, record: &ProgramRecord) -> Result<(), RegistryError> {
        super::deploy::DeployProgram {
            owner: record.owner,
            nonce: record.nonce,
            code: record.code.clone(),
        }
        .validate_structure()
        .map_err(|_| RegistryError::InvalidRecord)?;
        if !super::vm_app::valid_storage(&record.storage)
            || (record.code.get(4) != Some(&super::vm::APPLICATION_VERSION)
                && !record.storage.is_empty())
        {
            return Err(RegistryError::InvalidRecord);
        }
        let hash = ProgramHash::derive(&record.code)?;
        if hash != record.code_hash || ProgramId::derive(record.owner, record.nonce, hash)? != id {
            return Err(RegistryError::InvalidRecord);
        }
        Ok(())
    }

    /// Audit restored state, including the derived owner/nonce lookup.
    pub fn validate(&self, tip: Height) -> Result<(), RegistryError> {
        let mut deployments = BTreeSet::new();
        for (&id, record) in &self.programs {
            self.validate_record(id, record)?;
            if record.deployed_at > tip || !deployments.insert((record.owner, record.nonce)) {
                return Err(RegistryError::InvalidRecord);
            }
        }
        if !deployments.iter().eq(self.deployments.keys()) {
            return Err(RegistryError::InvalidRecord);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.programs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    pub(crate) fn set_storage(
        &mut self,
        id: ProgramId,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Result<(), RegistryError> {
        let record = self.programs.get(&id).ok_or(RegistryError::InvalidRecord)?;
        if record.storage.get(&key) == value.as_ref() {
            return Ok(());
        }
        let record = self.programs.get_mut(&id).unwrap();
        match value {
            Some(value) => {
                Arc::make_mut(&mut record.storage).insert(key, value);
            }
            None => {
                Arc::make_mut(&mut record.storage).remove(&key);
            }
        }
        Ok(())
    }

    pub(crate) fn set_state(&mut self, id: ProgramId, value: i64) -> Option<i64> {
        let previous = self.programs.get(&id)?.state_value;
        if previous != value {
            self.programs.get_mut(&id).unwrap().state_value = value;
        }
        Some(previous)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    AlreadyExists,
    Encoding,
    InvalidRecord,
}

impl AsRef<[u8; HASH_SIZE]> for ProgramHash {
    fn as_ref(&self) -> &[u8; HASH_SIZE] {
        self.as_bytes()
    }
}
impl From<crypto::CodecError> for RegistryError {
    fn from(_: crypto::CodecError) -> Self {
        Self::Encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{DeployProgram, deploy_program, rollback_program};

    #[test]
    fn staged_storage_detaches_only_changed_program_and_preserves_encoding() {
        let mut original = ProgramRegistry::default();
        let mut application = deployment(201);
        let mut code = b"XPVM".to_vec();
        code.extend([4, 16, 0, 1, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend(0u128.to_le_bytes());
        code.push(3);
        application.code = code.into();
        let (first, _) = deploy_program(&mut original, application.clone(), Height(3)).unwrap();
        application.nonce += 1;
        let (second, _) = deploy_program(&mut original, application, Height(3)).unwrap();
        original
            .set_storage(first, b"key".to_vec(), Some(vec![7; 4096]))
            .unwrap();
        original
            .set_storage(second, b"other".to_vec(), Some(vec![8; 4096]))
            .unwrap();
        let bytes = canonical_bytes(&original).unwrap();
        let record = original.program(&first).unwrap();
        let historical = canonical_bytes(&(
            record.code_hash,
            record.code.as_ref(),
            record.owner,
            record.nonce,
            record.deployed_at,
            record.state_value,
            record.storage.as_ref(),
        ))
        .unwrap();
        assert_eq!(canonical_bytes(record).unwrap(), historical);
        assert_eq!(ProgramRegistry::try_from_slice(&bytes).unwrap(), original);

        let mut staged = original.clone();
        assert!(Arc::ptr_eq(
            &original.program(&first).unwrap().storage,
            &staged.program(&first).unwrap().storage
        ));
        staged
            .set_storage(first, b"key".to_vec(), Some(vec![7; 4096]))
            .unwrap();
        staged
            .set_storage(first, b"missing".to_vec(), None)
            .unwrap();
        assert!(Arc::ptr_eq(
            &original.program(&first).unwrap().storage,
            &staged.program(&first).unwrap().storage
        ));
        staged
            .set_storage(first, b"key".to_vec(), Some(vec![9; 4096]))
            .unwrap();
        assert!(!Arc::ptr_eq(
            &original.program(&first).unwrap().storage,
            &staged.program(&first).unwrap().storage
        ));
        assert!(Arc::ptr_eq(
            &original.program(&second).unwrap().storage,
            &staged.program(&second).unwrap().storage
        ));
        staged.set_storage(first, b"key".to_vec(), None).unwrap();
        assert!(staged.program(&first).unwrap().storage.is_empty());
        assert_eq!(canonical_bytes(&original).unwrap(), bytes);
    }

    fn deployment(nonce: u64) -> DeployProgram {
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend_from_slice(&nonce.to_le_bytes());
        code.push(3);
        DeployProgram {
            owner: ProgramId::ZERO,
            nonce,
            code: code.into(),
        }
    }

    #[test]
    fn record_growth_matches_legacy_serialization_and_index_survives_restore() {
        let mut registry = ProgramRegistry::default();
        for nonce in 0..128 {
            let before = canonical_bytes(&registry).unwrap().len();
            let (id, record) =
                crate::program::prepare_deployment(deployment(nonce), Height(3)).unwrap();
            let expected_growth = canonical_bytes(&(id, &record)).unwrap().len();
            registry.insert(id, record).unwrap();
            let encoded = canonical_bytes(&registry).unwrap();
            assert_eq!(encoded.len() - before, expected_growth);
            // The auxiliary index must not change any historical state bytes.
            assert_eq!(encoded, canonical_bytes(&registry.programs).unwrap());
            registry = ProgramRegistry::try_from_slice(&encoded).unwrap();
            registry.validate(Height(3)).unwrap();
            let mut different_code = deployment(nonce);
            Arc::make_mut(&mut different_code.code)[14] ^= 1;
            assert!(matches!(
                deploy_program(&mut registry, different_code, Height(3)),
                Err(crate::program::DeployError::Registry(
                    RegistryError::AlreadyExists
                ))
            ));
        }
        let (id, journal) = deploy_program(&mut registry, deployment(128), Height(3)).unwrap();
        rollback_program(&mut registry, journal).unwrap();
        assert!(!registry.contains(&id));
        assert!(deploy_program(&mut registry, deployment(128), Height(3)).is_ok());
    }

    #[test]
    fn restored_registry_rejects_corrupted_records_and_duplicate_owner_nonce() {
        let mut registry = ProgramRegistry::default();
        let (id, _) = deploy_program(&mut registry, deployment(1), Height(3)).unwrap();
        for case in 0..6 {
            let mut records = registry.programs.clone();
            let record = records.get_mut(&id).unwrap();
            match case {
                0 => record.code_hash = ProgramHash::from_bytes([0; HASH_SIZE]),
                1 => record.owner = ProgramId::from_bytes([1; crypto::PROGRAM_ID_SIZE]),
                2 => record.nonce += 1,
                3 => Arc::make_mut(&mut record.code)[0] = 0,
                4 => {
                    let record = records.remove(&id).unwrap();
                    records.insert(ProgramId::from_bytes([0; HASH_SIZE]), record);
                }
                _ => {
                    let mut record = record.clone();
                    Arc::make_mut(&mut record.code)[14] ^= 1;
                    record.code_hash = ProgramHash::derive(&record.code).unwrap();
                    let second =
                        ProgramId::derive(record.owner, record.nonce, record.code_hash).unwrap();
                    records.insert(second, record);
                }
            }
            assert!(
                ProgramRegistry::try_from_slice(&canonical_bytes(&records).unwrap()).is_err(),
                "case {case}"
            );
        }
        assert_eq!(
            registry.validate(Height(2)),
            Err(RegistryError::InvalidRecord)
        );
        registry.deployments.clear();
        assert_eq!(
            registry.validate(Height(3)),
            Err(RegistryError::InvalidRecord)
        );
    }
}
