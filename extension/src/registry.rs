use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use xparq_common::extension::{
    Extension, ExtensionCall, ExtensionContext, ExtensionFailure, ExtensionId, ExtensionStateRead,
    ExtensionStateWrite,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    DuplicateExtension,
    AlreadyInitialized,
}

#[derive(Default)]
pub struct ExtensionRegistry {
    extensions: BTreeMap<ExtensionId, Box<dyn Extension>>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, extension: impl Extension + 'static) -> Result<(), RegistryError> {
        let id = extension.id();
        match self.extensions.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(Box::new(extension));
                Ok(())
            }
            Entry::Occupied(_) => Err(RegistryError::DuplicateExtension),
        }
    }

    pub fn get(&self, id: ExtensionId) -> Result<&dyn Extension, ExtensionFailure> {
        self.extensions
            .get(&id)
            .map(Box::as_ref)
            .ok_or(ExtensionFailure::UnknownExtension)
    }

    pub fn validate(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &dyn ExtensionStateRead,
    ) -> Result<(), ExtensionFailure> {
        let extension = self.get(call.extension_id())?;
        if context.height < extension.activation_height() {
            return Err(ExtensionFailure::InactiveExtension);
        }
        extension.validate(context, call, state)
    }

    pub fn apply(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &mut dyn ExtensionStateWrite,
    ) -> Result<(), ExtensionFailure> {
        let extension = self.get(call.extension_id())?;
        if context.height < extension.activation_height() {
            return Err(ExtensionFailure::InactiveExtension);
        }
        extension.apply(context, call, state)
    }

    pub fn commitments(&self) -> impl Iterator<Item = ExtensionId> + '_ {
        self.extensions.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use xparq_common::Height;

    struct TestExtension {
        id: ExtensionId,
    }

    impl Extension for TestExtension {
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
            if call.payload() == b"valid" {
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
            state.put(b"last-call".to_vec(), call.payload().to_vec())?;
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestStore(BTreeMap<Vec<u8>, Vec<u8>>);

    impl ExtensionStateRead for TestStore {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure> {
            Ok(self.0.get(key).cloned())
        }
    }

    impl ExtensionStateWrite for TestStore {
        fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ExtensionFailure> {
            self.0.insert(key, value);
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), ExtensionFailure> {
            self.0.remove(key);
            Ok(())
        }
    }

    #[test]
    fn registry_enforces_identity_activation_and_validate_before_apply() {
        let id = ExtensionId::derive("test");
        let mut registry = ExtensionRegistry::new();
        registry.register(TestExtension { id }).unwrap();
        assert_eq!(
            registry.register(TestExtension { id }),
            Err(RegistryError::DuplicateExtension)
        );

        let call = ExtensionCall::new(id, b"valid".to_vec()).unwrap();
        let mut store = TestStore::default();
        assert_eq!(
            registry.validate(ExtensionContext { height: Height(4) }, &call, &store),
            Err(ExtensionFailure::InactiveExtension)
        );
        registry
            .validate(ExtensionContext { height: Height(5) }, &call, &store)
            .unwrap();
        registry
            .apply(ExtensionContext { height: Height(5) }, &call, &mut store)
            .unwrap();
        assert_eq!(store.get(b"last-call").unwrap(), Some(b"valid".to_vec()));

        let unknown = ExtensionCall::new(ExtensionId::derive("unknown"), vec![]).unwrap();
        assert_eq!(
            registry.validate(ExtensionContext { height: Height(5) }, &unknown, &store),
            Err(ExtensionFailure::UnknownExtension)
        );
    }
}
