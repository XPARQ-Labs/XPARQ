//! Deterministic namespaced state lifecycle for consensus extensions.

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::extension::{
    EXTENSION_STATE_KEY_MAX_SIZE, EXTENSION_STATE_MAX_ENTRIES, EXTENSION_STATE_VALUE_MAX_SIZE,
    ExtensionCall, ExtensionCommitment, ExtensionContext, ExtensionFailure, ExtensionId,
    ExtensionJournalEntry, ExtensionStateRead, ExtensionStateRoot, ExtensionStateWrite,
    extension_set_root,
};

const EXTENSION_NAMESPACE_ROOT_CONTEXT: &str = "XPARQ Extension Namespace Root";

type Namespace = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtensionStateSet {
    namespaces: BTreeMap<ExtensionId, Namespace>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ExtensionRollbackJournal {
    pub extension_id: ExtensionId,
    pub namespace_existed: bool,
    pub previous_root: ExtensionStateRoot,
    pub applied_root: ExtensionStateRoot,
    pub entries: Vec<ExtensionJournalEntry>,
}

impl ExtensionStateSet {
    pub fn namespace(&self, extension_id: ExtensionId) -> ExtensionNamespace<'_> {
        ExtensionNamespace {
            extension_id,
            namespace: self.namespaces.get(&extension_id),
            namespaces: &self.namespaces,
        }
    }
    pub fn namespace_root(&self, extension_id: ExtensionId) -> ExtensionStateRoot {
        self.namespaces
            .get(&extension_id)
            .map_or_else(|| namespace_root(&Namespace::new()), namespace_root)
    }

    pub fn state_root(&self) -> Result<ExtensionStateRoot, ExtensionFailure> {
        if self.namespaces.is_empty() {
            return Ok(ExtensionStateRoot::ZERO);
        }
        let commitments = self
            .namespaces
            .iter()
            .map(|(extension_id, namespace)| ExtensionCommitment {
                extension_id: *extension_id,
                state_root: namespace_root(namespace),
            })
            .collect::<Vec<_>>();
        extension_set_root(&commitments)
    }

    pub fn get(
        &self,
        extension_id: ExtensionId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ExtensionFailure> {
        validate_key(key)?;
        Ok(self
            .namespaces
            .get(&extension_id)
            .and_then(|namespace| namespace.get(key))
            .cloned())
    }

    pub fn validate(
        &self,
        registry: &xparq_extension::ExtensionRegistry,
        context: ExtensionContext,
        call: &ExtensionCall,
    ) -> Result<(), ExtensionFailure> {
        let empty = Namespace::new();
        let namespace = self.namespaces.get(&call.extension_id()).unwrap_or(&empty);
        registry.validate(
            context,
            call,
            &NamespaceRead {
                extension_id: call.extension_id(),
                namespace,
                namespaces: &self.namespaces,
            },
        )
    }

    pub fn apply(
        &mut self,
        registry: &xparq_extension::ExtensionRegistry,
        context: ExtensionContext,
        call: &ExtensionCall,
    ) -> Result<ExtensionRollbackJournal, ExtensionFailure> {
        self.validate(registry, context, call)?;

        let extension_id = call.extension_id();
        let namespace_existed = self.namespaces.contains_key(&extension_id);
        let previous = self
            .namespaces
            .get(&extension_id)
            .cloned()
            .unwrap_or_default();
        let previous_root = namespace_root(&previous);
        let mut staged = previous.clone();
        registry.apply(
            context,
            call,
            &mut NamespaceWrite {
                extension_id,
                namespace: &mut staged,
                namespaces: &self.namespaces,
            },
        )?;
        let applied_root = namespace_root(&staged);

        let entries = journal_diff(&previous, &staged);
        self.namespaces.insert(extension_id, staged);
        Ok(ExtensionRollbackJournal {
            extension_id,
            namespace_existed,
            previous_root,
            applied_root,
            entries,
        })
    }

    pub fn rollback(&mut self, journal: ExtensionRollbackJournal) -> Result<(), ExtensionFailure> {
        if self.namespace_root(journal.extension_id) != journal.applied_root {
            return Err(ExtensionFailure::InvalidState);
        }

        let mut staged = self
            .namespaces
            .get(&journal.extension_id)
            .cloned()
            .unwrap_or_default();
        for entry in journal.entries.into_iter().rev() {
            match entry.previous_value {
                Some(value) => {
                    staged.insert(entry.key, value);
                }
                None => {
                    staged.remove(&entry.key);
                }
            }
        }
        if namespace_root(&staged) != journal.previous_root {
            return Err(ExtensionFailure::InvalidState);
        }
        if journal.namespace_existed {
            self.namespaces.insert(journal.extension_id, staged);
        } else {
            self.namespaces.remove(&journal.extension_id);
        }
        Ok(())
    }
}

pub struct ExtensionNamespace<'a> {
    extension_id: ExtensionId,
    namespace: Option<&'a Namespace>,
    namespaces: &'a BTreeMap<ExtensionId, Namespace>,
}

impl ExtensionStateRead for ExtensionNamespace<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure> {
        validate_key(key)?;
        Ok(self.namespace.and_then(|state| state.get(key)).cloned())
    }

    fn entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ExtensionFailure> {
        Ok(self
            .namespace
            .into_iter()
            .flat_map(|namespace| namespace.iter())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    fn get_extension(
        &self,
        extension_id: ExtensionId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ExtensionFailure> {
        validate_key(key)?;
        if extension_id == self.extension_id {
            return self.get(key);
        }
        Ok(self
            .namespaces
            .get(&extension_id)
            .and_then(|namespace| namespace.get(key))
            .cloned())
    }
}

impl ExtensionNamespace<'_> {
    pub fn entries(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.namespace
            .into_iter()
            .flat_map(|namespace| namespace.iter())
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
    }
}

struct NamespaceRead<'a> {
    extension_id: ExtensionId,
    namespace: &'a Namespace,
    namespaces: &'a BTreeMap<ExtensionId, Namespace>,
}

impl ExtensionStateRead for NamespaceRead<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure> {
        validate_key(key)?;
        Ok(self.namespace.get(key).cloned())
    }

    fn entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ExtensionFailure> {
        Ok(self
            .namespace
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    fn get_extension(
        &self,
        extension_id: ExtensionId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ExtensionFailure> {
        validate_key(key)?;
        if extension_id == self.extension_id {
            return self.get(key);
        }
        Ok(self
            .namespaces
            .get(&extension_id)
            .and_then(|namespace| namespace.get(key))
            .cloned())
    }
}

struct NamespaceWrite<'a> {
    extension_id: ExtensionId,
    namespace: &'a mut Namespace,
    namespaces: &'a BTreeMap<ExtensionId, Namespace>,
}

impl ExtensionStateRead for NamespaceWrite<'_> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure> {
        validate_key(key)?;
        Ok(self.namespace.get(key).cloned())
    }

    fn entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ExtensionFailure> {
        Ok(self
            .namespace
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    fn get_extension(
        &self,
        extension_id: ExtensionId,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, ExtensionFailure> {
        validate_key(key)?;
        if extension_id == self.extension_id {
            return self.get(key);
        }
        Ok(self
            .namespaces
            .get(&extension_id)
            .and_then(|namespace| namespace.get(key))
            .cloned())
    }
}

impl ExtensionStateWrite for NamespaceWrite<'_> {
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ExtensionFailure> {
        validate_key(&key)?;
        if value.len() > EXTENSION_STATE_VALUE_MAX_SIZE {
            return Err(ExtensionFailure::StateValueTooLarge);
        }
        if !self.namespace.contains_key(&key) && self.namespace.len() >= EXTENSION_STATE_MAX_ENTRIES
        {
            return Err(ExtensionFailure::StateEntryLimit);
        }
        self.namespace.insert(key, value);
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), ExtensionFailure> {
        validate_key(key)?;
        self.namespace.remove(key);
        Ok(())
    }
}

fn validate_key(key: &[u8]) -> Result<(), ExtensionFailure> {
    if key.len() > EXTENSION_STATE_KEY_MAX_SIZE {
        return Err(ExtensionFailure::StateKeyTooLarge);
    }
    Ok(())
}

fn namespace_root(namespace: &Namespace) -> ExtensionStateRoot {
    let mut hasher = blake3::Hasher::new_derive_key(EXTENSION_NAMESPACE_ROOT_CONTEXT);
    hasher.update(&(namespace.len() as u64).to_le_bytes());
    for (key, value) in namespace {
        hasher.update(&(key.len() as u64).to_le_bytes());
        hasher.update(key);
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    ExtensionStateRoot::from_bytes(*hasher.finalize().as_bytes())
}

fn journal_diff(previous: &Namespace, applied: &Namespace) -> Vec<ExtensionJournalEntry> {
    let keys = previous
        .keys()
        .chain(applied.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter(|key| previous.get(key) != applied.get(key))
        .map(|key| ExtensionJournalEntry {
            previous_value: previous.get(&key).cloned(),
            key,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xparq_common::{Extension, Height};

    struct CounterExtension {
        id: ExtensionId,
        fail_apply: bool,
    }

    impl Extension for CounterExtension {
        fn id(&self) -> ExtensionId {
            self.id
        }

        fn activation_height(&self) -> Height {
            Height(5)
        }

        fn validate(
            &self,
            _context: ExtensionContext,
            call: &ExtensionCall,
            _state: &dyn ExtensionStateRead,
        ) -> Result<(), ExtensionFailure> {
            if call.payload().len() == 8 {
                Ok(())
            } else {
                Err(ExtensionFailure::InvalidPayload)
            }
        }

        fn apply(
            &self,
            _context: ExtensionContext,
            call: &ExtensionCall,
            state: &mut dyn ExtensionStateWrite,
        ) -> Result<(), ExtensionFailure> {
            state.put(b"counter".to_vec(), call.payload().to_vec())?;
            if self.fail_apply {
                return Err(ExtensionFailure::InvalidState);
            }
            Ok(())
        }
    }

    #[test]
    fn validate_apply_store_and_rollback_are_deterministic() {
        let id = ExtensionId::derive("counter");
        let extension = CounterExtension {
            id,
            fail_apply: false,
        };
        let context = ExtensionContext { height: Height(5) };
        let call = ExtensionCall::new(id, 7_u64.to_le_bytes().to_vec()).unwrap();
        let mut state = ExtensionStateSet::default();
        let mut registry = xparq_extension::ExtensionRegistry::new();
        registry.register(extension).unwrap();
        let initial_root = state.state_root().unwrap();

        state.validate(&registry, context, &call).unwrap();
        let journal = state.apply(&registry, context, &call).unwrap();
        assert_eq!(
            state.get(id, b"counter").unwrap(),
            Some(call.payload().to_vec())
        );
        assert_ne!(state.state_root().unwrap(), initial_root);

        state.rollback(journal).unwrap();
        assert_eq!(state.get(id, b"counter").unwrap(), None);
        assert_eq!(state.state_root().unwrap(), initial_root);
    }

    #[test]
    fn failed_apply_does_not_commit_staged_extension_state() {
        let id = ExtensionId::derive("counter");
        let extension = CounterExtension {
            id,
            fail_apply: true,
        };
        let call = ExtensionCall::new(id, 9_u64.to_le_bytes().to_vec()).unwrap();
        let mut state = ExtensionStateSet::default();
        let mut registry = xparq_extension::ExtensionRegistry::new();
        registry.register(extension).unwrap();
        let initial_root = state.state_root().unwrap();

        assert_eq!(
            state.apply(&registry, ExtensionContext { height: Height(5) }, &call),
            Err(ExtensionFailure::InvalidState)
        );
        assert_eq!(state.get(id, b"counter").unwrap(), None);
        assert_eq!(state.state_root().unwrap(), initial_root);
    }
}
