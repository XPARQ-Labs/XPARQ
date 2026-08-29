//! Permissionless immutable WASM deployment protocol.

use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::{
    Extension, ExtensionCall, ExtensionContext, ExtensionFailure, ExtensionId, ExtensionStateRead,
    ExtensionStateWrite, Height, canonical_bytes,
};
use xparq_crypto::{
    Address, ProfilePublicKey, ProfileSignature, ProfileSigningSeed,
    address_from_profile_public_key, profile_verify,
};

use crate::{WasmExtensionPackage, wasm_code_hash, wasm_extension_id};

pub const WASM_DEPLOY_EXTENSION_NAME: &str = "xparq.wasm.deploy.v1";
pub const WASM_DEPLOY_ACTIVATION_DELAY: u64 = 100;
const DEPLOY_COMMITMENT_CONTEXT: &str = "XPARQ WASM Deploy Call v1";
const PACKAGE_PREFIX: u8 = b'p';
const NONCE_PREFIX: u8 = b'n';

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct WasmDeployCall {
    pub name: String,
    pub module: Vec<u8>,
    pub signer: Address,
    pub nonce: u64,
    pub public_key: ProfilePublicKey,
    pub signature: ProfileSignature,
}

#[derive(BorshSerialize)]
struct UnsignedDeployCall<'a> {
    chain_id: [u8; 32],
    name: &'a str,
    code_hash: [u8; 32],
    signer: Address,
    nonce: u64,
}

impl WasmDeployCall {
    pub fn from_extension_call(call: &ExtensionCall) -> Result<Self, ExtensionFailure> {
        decode_call(call)
    }

    pub fn sign(
        chain_id: [u8; 32],
        name: String,
        module: Vec<u8>,
        nonce: u64,
        signing_seed: &ProfileSigningSeed,
    ) -> Result<Self, ExtensionFailure> {
        let public_key = signing_seed.public_key();
        let signer = address_from_profile_public_key(&public_key);
        let commitment =
            deploy_commitment(chain_id, &name, wasm_code_hash(&module), signer, nonce)?;
        let signature = signing_seed.sign(&commitment);
        Ok(Self {
            name,
            module,
            signer,
            nonce,
            public_key,
            signature,
        })
    }

    pub fn extension_id(&self) -> ExtensionId {
        wasm_extension_id(&self.name, wasm_code_hash(&self.module))
    }

    pub fn into_extension_call(self) -> Result<ExtensionCall, ExtensionFailure> {
        let payload = canonical_bytes(&self).map_err(|_| ExtensionFailure::InvalidPayload)?;
        ExtensionCall::new(wasm_deploy_extension_id(), payload)
    }
}

pub struct WasmDeployExtension {
    chain_id: [u8; 32],
}

impl WasmDeployExtension {
    pub const fn new(chain_id: [u8; 32]) -> Self {
        Self { chain_id }
    }
}

pub fn wasm_deploy_extension_id() -> ExtensionId {
    ExtensionId::derive(WASM_DEPLOY_EXTENSION_NAME)
}

pub(crate) fn package_key(extension_id: ExtensionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(PACKAGE_PREFIX);
    key.extend_from_slice(extension_id.as_bytes());
    key
}

pub fn wasm_deployed_package(
    state: &dyn ExtensionStateRead,
    extension_id: ExtensionId,
) -> Result<Option<WasmExtensionPackage>, ExtensionFailure> {
    let Some(bytes) =
        state.get_extension(wasm_deploy_extension_id(), &package_key(extension_id))?
    else {
        return Ok(None);
    };
    WasmExtensionPackage::try_from_slice(&bytes)
        .map(Some)
        .map_err(|_| ExtensionFailure::InvalidState)
}

impl Extension for WasmDeployExtension {
    fn id(&self) -> ExtensionId {
        wasm_deploy_extension_id()
    }
    fn activation_height(&self) -> Height {
        Height(0)
    }

    fn validate(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &dyn ExtensionStateRead,
    ) -> Result<(), ExtensionFailure> {
        let deploy = decode_call(call)?;
        let expected_signer = address_from_profile_public_key(&deploy.public_key);
        if expected_signer != deploy.signer {
            return Err(ExtensionFailure::InvalidPayload);
        }
        let commitment = deploy_commitment(
            self.chain_id,
            &deploy.name,
            wasm_code_hash(&deploy.module),
            deploy.signer,
            deploy.nonce,
        )?;
        if !profile_verify(&deploy.public_key, &commitment, &deploy.signature) {
            return Err(ExtensionFailure::InvalidPayload);
        }
        if deploy.nonce != wasm_deploy_nonce(state, deploy.signer)? {
            return Err(ExtensionFailure::InvalidState);
        }
        let activation = context
            .height
            .0
            .checked_add(WASM_DEPLOY_ACTIVATION_DELAY)
            .ok_or(ExtensionFailure::InvalidState)?;
        let package = WasmExtensionPackage::new(deploy.name, Height(activation), deploy.module)
            .map_err(|_| ExtensionFailure::InvalidPayload)?;
        if state
            .get(&package_key(package.manifest.extension_id))?
            .is_some()
        {
            return Err(ExtensionFailure::InvalidState);
        }
        Ok(())
    }

    fn apply(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &mut dyn ExtensionStateWrite,
    ) -> Result<(), ExtensionFailure> {
        let deploy = decode_call(call)?;
        let activation = context
            .height
            .0
            .checked_add(WASM_DEPLOY_ACTIVATION_DELAY)
            .ok_or(ExtensionFailure::InvalidState)?;
        let package = WasmExtensionPackage::new(deploy.name, Height(activation), deploy.module)
            .map_err(|_| ExtensionFailure::InvalidPayload)?;
        let package_bytes =
            canonical_bytes(&package).map_err(|_| ExtensionFailure::InvalidPayload)?;
        state.put(package_key(package.manifest.extension_id), package_bytes)?;
        state.put(
            nonce_key(deploy.signer),
            deploy
                .nonce
                .checked_add(1)
                .ok_or(ExtensionFailure::InvalidState)?
                .to_le_bytes()
                .to_vec(),
        )
    }
}

fn decode_call(call: &ExtensionCall) -> Result<WasmDeployCall, ExtensionFailure> {
    if call.extension_id() != wasm_deploy_extension_id() {
        return Err(ExtensionFailure::InvalidPayload);
    }
    WasmDeployCall::try_from_slice(call.payload()).map_err(|_| ExtensionFailure::InvalidPayload)
}

fn nonce_key(address: Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + address.0.len());
    key.push(NONCE_PREFIX);
    key.extend_from_slice(&address.0);
    key
}

pub fn wasm_deploy_nonce(
    state: &dyn ExtensionStateRead,
    address: Address,
) -> Result<u64, ExtensionFailure> {
    match state.get(&nonce_key(address))? {
        None => Ok(0),
        Some(bytes) => u64::try_from_slice(&bytes).map_err(|_| ExtensionFailure::InvalidState),
    }
}

fn deploy_commitment(
    chain_id: [u8; 32],
    name: &str,
    code_hash: [u8; 32],
    signer: Address,
    nonce: u64,
) -> Result<[u8; 32], ExtensionFailure> {
    let unsigned = UnsignedDeployCall {
        chain_id,
        name,
        code_hash,
        signer,
        nonce,
    };
    let bytes = canonical_bytes(&unsigned).map_err(|_| ExtensionFailure::InvalidPayload)?;
    Ok(blake3::derive_key(DEPLOY_COMMITMENT_CONTEXT, &bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::ExtensionRegistry;
    use xparq_crypto::SignatureProfile;

    struct MultiState {
        current: ExtensionId,
        namespaces: BTreeMap<ExtensionId, BTreeMap<Vec<u8>, Vec<u8>>>,
    }

    impl Default for MultiState {
        fn default() -> Self {
            Self {
                current: ExtensionId::from_bytes([0; 32]),
                namespaces: BTreeMap::new(),
            }
        }
    }

    impl ExtensionStateRead for MultiState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure> {
            Ok(self
                .namespaces
                .get(&self.current)
                .and_then(|state| state.get(key))
                .cloned())
        }

        fn entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ExtensionFailure> {
            Ok(self
                .namespaces
                .get(&self.current)
                .into_iter()
                .flat_map(|state| state.iter())
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect())
        }

        fn get_extension(
            &self,
            id: ExtensionId,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>, ExtensionFailure> {
            Ok(self
                .namespaces
                .get(&id)
                .and_then(|state| state.get(key))
                .cloned())
        }
    }

    impl ExtensionStateWrite for MultiState {
        fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ExtensionFailure> {
            self.namespaces
                .entry(self.current)
                .or_default()
                .insert(key, value);
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), ExtensionFailure> {
            if let Some(state) = self.namespaces.get_mut(&self.current) {
                state.remove(key);
            }
            Ok(())
        }
    }

    #[test]
    fn permissionless_deploy_is_immutable_and_activates_after_the_delay() {
        let chain_id = [7; 32];
        let module = wat::parse_str(
            r#"(module
            (memory (export "memory") 16 16)
            (func (export "xparq_alloc") (param i32) (result i32) (i32.const 1024))
            (func (export "xparq_validate") (param i32 i32 i64) (result i32) (i32.const 0))
            (func (export "xparq_apply") (param i32 i32 i64) (result i32) (i32.const 0)))"#,
        )
        .unwrap();
        let seed = ProfileSigningSeed::new(SignatureProfile::MlDsa44, [9; 32]);
        let deploy =
            WasmDeployCall::sign(chain_id, "permissionless.test".into(), module, 0, &seed).unwrap();
        let dynamic_id = deploy.extension_id();
        let deploy_call = deploy.into_extension_call().unwrap();
        let mut registry = ExtensionRegistry::new();
        registry
            .register(WasmDeployExtension::new(chain_id))
            .unwrap();
        let mut state = MultiState {
            current: wasm_deploy_extension_id(),
            ..Default::default()
        };
        let deployed_at = Height(10);
        registry
            .validate(
                ExtensionContext {
                    height: deployed_at,
                },
                &deploy_call,
                &state,
            )
            .unwrap();
        registry
            .apply(
                ExtensionContext {
                    height: deployed_at,
                },
                &deploy_call,
                &mut state,
            )
            .unwrap();
        assert_eq!(
            registry.validate(
                ExtensionContext {
                    height: deployed_at
                },
                &deploy_call,
                &state
            ),
            Err(ExtensionFailure::InvalidState)
        );

        state.current = dynamic_id;
        let call = ExtensionCall::new(dynamic_id, b"hello".to_vec()).unwrap();
        assert_eq!(
            registry.validate(
                ExtensionContext {
                    height: Height(109)
                },
                &call,
                &state
            ),
            Err(ExtensionFailure::InactiveExtension)
        );
        registry
            .validate(
                ExtensionContext {
                    height: Height(110),
                },
                &call,
                &state,
            )
            .unwrap();
        registry
            .apply(
                ExtensionContext {
                    height: Height(110),
                },
                &call,
                &mut state,
            )
            .unwrap();
    }
}
