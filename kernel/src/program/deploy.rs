use borsh::{BorshDeserialize, BorshSerialize};
use crypto::ProgramId;
use std::io::Read;
use std::sync::Arc;

use crate::common::Height;

use super::registry::{ProgramHash, ProgramRecord, ProgramRegistry, RegistryError};

pub const MAX_PROGRAM_CODE_SIZE: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct DeployProgram {
    pub owner: ProgramId,
    pub nonce: u64,
    /// Shared code bytes; canonical encoding remains the historical Vec encoding.
    pub code: Arc<Vec<u8>>,
}

impl BorshDeserialize for DeployProgram {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(Self {
            owner: ProgramId::deserialize_reader(reader)?,
            nonce: u64::deserialize_reader(reader)?,
            code: super::deserialize_program_code(reader)?.into(),
        })
    }
}

impl DeployProgram {
    pub fn validate_structure(&self) -> Result<(), DeployError> {
        if self.code.is_empty() {
            return Err(DeployError::EmptyProgram);
        }

        if self.code.len() > MAX_PROGRAM_CODE_SIZE {
            return Err(DeployError::ProgramTooLarge);
        }

        super::vm::validate_code(&self.code).map_err(|_| DeployError::InvalidCode)?;

        Ok(())
    }
}

#[derive(BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub enum ProgramJournal {
    Deploy {
        program_id: ProgramId,
    },
    State {
        program_id: ProgramId,
        previous: i64,
    },
    // Appended after historical variants to preserve their wire tags.
    Calls {
        states: Vec<(ProgramId, i64)>,
        storage: Vec<(ProgramId, Vec<u8>, Option<Vec<u8>>)>,
    },
}

impl BorshDeserialize for ProgramJournal {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        use std::io::{Error, ErrorKind};
        fn invalid() -> Error {
            Error::new(ErrorKind::InvalidData, "invalid VM rollback journal")
        }
        fn bytes<R: Read>(reader: &mut R, max: usize) -> std::io::Result<Vec<u8>> {
            let n = u32::deserialize_reader(reader)? as usize;
            if n == 0 || n > max {
                return Err(invalid());
            }
            let mut v = vec![0; n];
            reader.read_exact(&mut v)?;
            Ok(v)
        }
        match u8::deserialize_reader(reader)? {
            0 => Ok(Self::Deploy {
                program_id: ProgramId::deserialize_reader(reader)?,
            }),
            1 => Ok(Self::State {
                program_id: ProgramId::deserialize_reader(reader)?,
                previous: i64::deserialize_reader(reader)?,
            }),
            2 => {
                let states = super::deserialize_bounded_vec::<(ProgramId, i64), _>(
                    reader,
                    super::vm_app::MAX_CALLS,
                )?;
                if states.windows(2).any(|v| v[0].0 >= v[1].0) {
                    return Err(invalid());
                }
                let n = u32::deserialize_reader(reader)? as usize;
                if n > super::vm_app::MAX_ACTIONS {
                    return Err(invalid());
                }
                let mut storage = Vec::new();
                for _ in 0..n {
                    let id = ProgramId::deserialize_reader(reader)?;
                    let key = bytes(reader, super::vm_app::MAX_KEY_BYTES)?;
                    if storage
                        .last()
                        .is_some_and(|(last_id, last_key, _)| (*last_id, last_key) >= (id, &key))
                    {
                        return Err(invalid());
                    }
                    let value = match u8::deserialize_reader(reader)? {
                        0 => None,
                        1 => Some(bytes(reader, super::vm_app::MAX_DATA_BYTES)?),
                        _ => return Err(invalid()),
                    };
                    storage.push((id, key, value));
                }
                Ok(Self::Calls { states, storage })
            }
            _ => Err(invalid()),
        }
    }
}

pub fn deploy_program(
    registry: &mut ProgramRegistry,
    deploy: DeployProgram,
    height: Height,
) -> Result<(ProgramId, ProgramJournal), DeployError> {
    let (program_id, record) = prepare_deployment(deploy, height)?;

    registry
        .insert(program_id, record)
        .map_err(DeployError::Registry)?;

    Ok((program_id, ProgramJournal::Deploy { program_id }))
}

/// Prepare one record without cloning or serializing the existing registry.
pub(crate) fn prepare_deployment(
    deploy: DeployProgram,
    height: Height,
) -> Result<(ProgramId, ProgramRecord), DeployError> {
    deploy.validate_structure()?;

    let code_hash = ProgramHash::derive(&deploy.code).map_err(DeployError::Registry)?;

    let program_id = ProgramId::derive(deploy.owner, deploy.nonce, code_hash)
        .map_err(|_| DeployError::Registry(RegistryError::Encoding))?;

    let record = ProgramRecord {
        code_hash,
        code: deploy.code,
        owner: deploy.owner,
        nonce: deploy.nonce,
        deployed_at: height,
        state_value: 0,
        storage: Default::default(),
    };

    Ok((program_id, record))
}

pub fn rollback_program(
    registry: &mut ProgramRegistry,
    journal: ProgramJournal,
) -> Result<(), DeployError> {
    match journal {
        ProgramJournal::Calls { states, storage } => {
            for (id, previous) in states {
                registry
                    .set_state(id, previous)
                    .ok_or(DeployError::MissingProgram)?;
            }
            for (id, key, previous) in storage {
                registry
                    .set_storage(id, key, previous)
                    .map_err(DeployError::Registry)?;
            }
        }
        ProgramJournal::Deploy { program_id } => {
            registry
                .remove(&program_id)
                .ok_or(DeployError::MissingProgram)?;
        }
        ProgramJournal::State {
            program_id,
            previous,
        } => {
            registry
                .set_state(program_id, previous)
                .ok_or(DeployError::MissingProgram)?;
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployError {
    EmptyProgram,
    ProgramTooLarge,
    InvalidCode,
    InvalidPayment,
    InvalidAuthorization,
    Encoding,
    MissingProgram,
    Registry(RegistryError),
}

#[cfg(test)]
fn valid_code(value: u64) -> Vec<u8> {
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend_from_slice(&value.to_le_bytes());
    code.push(3);
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{LedgerState, StateRollbackJournal};
    use crypto::ProgramId;

    #[test]
    fn deploy_and_rollback_restore_registry() {
        let mut state = LedgerState::default();
        let before = state.clone();

        let (program_id, journal) = deploy_program(
            &mut state.programs,
            DeployProgram {
                owner: ProgramId::ZERO,
                nonce: 1,
                code: valid_code(1).into(),
            },
            Height(1),
        )
        .unwrap();

        assert!(state.programs.contains(&program_id));

        state
            .rollback_state(StateRollbackJournal {
                coin: None,
                program: Some(journal),
                extension: None,
            })
            .unwrap();

        assert_eq!(state, before);
    }
}
#[test]
fn duplicate_program_deployment_is_rejected() {
    let mut registry = ProgramRegistry::default();

    let deploy = DeployProgram {
        owner: ProgramId::ZERO,
        nonce: 1,
        code: valid_code(1).into(),
    };

    let (first_id, _) = deploy_program(&mut registry, deploy.clone(), Height(1)).unwrap();

    let result = deploy_program(&mut registry, deploy, Height(2));

    assert!(matches!(
        result,
        Err(DeployError::Registry(RegistryError::AlreadyExists))
    ));

    assert!(registry.contains(&first_id));
    assert_eq!(registry.len(), 1);
}

#[test]
fn empty_program_is_rejected() {
    let mut registry = ProgramRegistry::default();

    let result = deploy_program(
        &mut registry,
        DeployProgram {
            owner: ProgramId::ZERO,
            nonce: 1,
            code: vec![].into(),
        },
        Height(1),
    );

    assert!(matches!(result, Err(DeployError::EmptyProgram)));
    assert!(registry.is_empty());
}

#[test]
fn oversized_program_is_rejected() {
    let mut registry = ProgramRegistry::default();

    let result = deploy_program(
        &mut registry,
        DeployProgram {
            owner: ProgramId::ZERO,
            nonce: 1,
            code: vec![0; MAX_PROGRAM_CODE_SIZE + 1].into(),
        },
        Height(1),
    );

    assert!(matches!(result, Err(DeployError::ProgramTooLarge)));
    assert!(registry.is_empty());
}

#[test]
fn different_deploys_produce_different_program_ids() {
    let mut registry = ProgramRegistry::default();

    let (first, _) = deploy_program(
        &mut registry,
        DeployProgram {
            owner: ProgramId::ZERO,
            nonce: 1,
            code: valid_code(1).into(),
        },
        Height(1),
    )
    .unwrap();

    let (second, _) = deploy_program(
        &mut registry,
        DeployProgram {
            owner: ProgramId::ZERO,
            nonce: 2,
            code: valid_code(2).into(),
        },
        Height(2),
    )
    .unwrap();

    assert_ne!(first, second);
    assert_eq!(registry.len(), 2);
}
