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
    chain_id: [u8; 32],
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_chain_id(chain_id: [u8; 32]) -> Self {
        Self {
            extensions: BTreeMap::new(),
            chain_id,
        }
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
        if let Some(extension) = self.extensions.get(&call.extension_id()) {
            if context.height < extension.activation_height() {
                return Err(ExtensionFailure::InactiveExtension);
            }
            return extension.validate(context, call, state);
        }
        let package = crate::deploy::wasm_deployed_package(state, call.extension_id())?
            .ok_or(ExtensionFailure::UnknownExtension)?;
        let dynamic = package
            .compile()
            .map_err(|_| ExtensionFailure::InvalidState)?;
        let app = crate::WasmAppCall::from_extension_call(call)?;
        app.verify(self.chain_id, call.extension_id(), state)?;
        let guest_call = ExtensionCall::new(call.extension_id(), app.payload)?;
        let extension = &dynamic;
        if context.height < extension.activation_height() {
            return Err(ExtensionFailure::InactiveExtension);
        }
        extension.validate(context, &guest_call, state)
    }

    pub fn apply(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &mut dyn ExtensionStateWrite,
    ) -> Result<(), ExtensionFailure> {
        if let Some(extension) = self.extensions.get(&call.extension_id()) {
            if context.height < extension.activation_height() {
                return Err(ExtensionFailure::InactiveExtension);
            }
            return extension.apply(context, call, state);
        }
        let package = crate::deploy::wasm_deployed_package(state, call.extension_id())?
            .ok_or(ExtensionFailure::UnknownExtension)?;
        let dynamic = package
            .compile()
            .map_err(|_| ExtensionFailure::InvalidState)?;
        let app = crate::WasmAppCall::from_extension_call(call)?;
        app.verify(self.chain_id, call.extension_id(), state)?;
        let guest_call = ExtensionCall::new(call.extension_id(), app.payload.clone())?;
        let extension = &dynamic;
        if context.height < extension.activation_height() {
            return Err(ExtensionFailure::InactiveExtension);
        }
        extension.apply(context, &guest_call, state)?;
        state.put(
            crate::wasm::wasm_app_nonce_key(app.signer),
            app.nonce
                .checked_add(1)
                .ok_or(ExtensionFailure::InvalidState)?
                .to_le_bytes()
                .to_vec(),
        )?;
        Ok(())
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

        fn entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ExtensionFailure> {
            Ok(self
                .0
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect())
        }

        fn get_extension(
            &self,
            _extension_id: ExtensionId,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>, ExtensionFailure> {
            self.get(key)
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
