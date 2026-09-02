//! Deterministic WebAssembly extension ABI.
//!
//! The guest receives no WASI, filesystem, clock, randomness, sockets, or
//! floating-point instructions. The only imports are bounded extension-state
//! operations under the `xparq` module.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use wasmi::{Caller, CompilationMode, Config, Engine, ExternType, Linker, Memory, Module, Store};
use xparq_common::extension::{
    EXTENSION_STATE_KEY_MAX_SIZE, EXTENSION_STATE_VALUE_MAX_SIZE, Extension, ExtensionCall,
    ExtensionContext, ExtensionEffect, ExtensionFailure, ExtensionHash, ExtensionStateRead,
    ExtensionStateWrite,
};
use xparq_common::{Height, canonical_bytes};
use xparq_crypto::{
    Address, ProfilePublicKey, ProfileSignature, ProfileSigningSeed,
    address_from_profile_public_key, profile_verify,
};

pub const WASM_ABI_VERSION: u32 = 1;
pub const WASM_CODE_MAX_SIZE: usize = 2 * 1024 * 1024;
pub const WASM_PACKAGE_MAX_SIZE: usize = WASM_CODE_MAX_SIZE + 4096;
pub const WASM_MEMORY_MAX_PAGES: u32 = 16;
pub const WASM_DEFAULT_FUEL: u64 = 1_000_000;
pub const WASM_MAX_FUEL: u64 = 10_000_000;
pub const WASM_STATE_MAX_SIZE: usize = 16 * 1024 * 1024;
pub const WASM_EFFECT_MAX_COUNT: usize = 1_024;
pub const WASM_APP_CALL_ACTIVATION_HEIGHT: Height = Height(0);

const WASM_CODE_HASH_CONTEXT: &str = "XPARQ WASM Extension Code";
const WASM_EXTENSION_HASH_CONTEXT: &str = "XPARQ WASM Extension Id";
const WASM_NAME_MAX_SIZE: usize = 64;
const WASM_APP_COMMITMENT_CONTEXT: &str = "XPARQ WASM Application Call";
const WASM_APP_NONCE_PREFIX: &[u8] = b"\xffxparq:wasm-app-nonce:";
const HOST_MISSING: i32 = -1;
const HOST_FAILURE: i32 = -2;
const HOST_BUFFER_TOO_SMALL: i32 = -3;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct WasmAppCall {
    pub payload: Vec<u8>,
    pub signer: Address,
    pub nonce: u64,
    pub public_key: ProfilePublicKey,
    pub signature: ProfileSignature,
}

#[derive(BorshSerialize)]
struct UnsignedWasmAppCall<'a> {
    chain_id: [u8; 32],
    extension_id: ExtensionHash,
    payload: &'a [u8],
    signer: Address,
    nonce: u64,
}

impl WasmAppCall {
    pub fn from_extension_call(call: &ExtensionCall) -> Result<Self, ExtensionFailure> {
        Self::try_from_slice(call.payload()).map_err(|_| ExtensionFailure::InvalidPayload)
    }

    pub fn sign(
        chain_id: [u8; 32],
        extension_id: ExtensionHash,
        payload: Vec<u8>,
        nonce: u64,
        signing_seed: &ProfileSigningSeed,
    ) -> Result<Self, ExtensionFailure> {
        let public_key = signing_seed.public_key();
        let signer = address_from_profile_public_key(&public_key);
        let commitment = wasm_app_commitment(chain_id, extension_id, &payload, signer, nonce)?;
        let signature = signing_seed.sign(&commitment);
        Ok(Self {
            payload,
            signer,
            nonce,
            public_key,
            signature,
        })
    }

    pub fn into_extension_call(
        self,
        extension_id: ExtensionHash,
    ) -> Result<ExtensionCall, ExtensionFailure> {
        let payload = canonical_bytes(&self).map_err(|_| ExtensionFailure::InvalidPayload)?;
        ExtensionCall::new(extension_id, payload)
    }

    pub(crate) fn verify(
        &self,
        chain_id: [u8; 32],
        extension_id: ExtensionHash,
        state: &dyn ExtensionStateRead,
    ) -> Result<(), ExtensionFailure> {
        if address_from_profile_public_key(&self.public_key) != self.signer
            || self.public_key.profile != self.signature.profile
        {
            return Err(ExtensionFailure::InvalidPayload);
        }
        if self.nonce != wasm_app_nonce(state, self.signer)? {
            return Err(ExtensionFailure::InvalidState);
        }
        let commitment = wasm_app_commitment(
            chain_id,
            extension_id,
            &self.payload,
            self.signer,
            self.nonce,
        )?;
        if !profile_verify(&self.public_key, &commitment, &self.signature) {
            return Err(ExtensionFailure::InvalidPayload);
        }
        self.nonce
            .checked_add(1)
            .ok_or(ExtensionFailure::InvalidState)?;
        Ok(())
    }
}

pub fn wasm_app_nonce(
    state: &dyn ExtensionStateRead,
    signer: Address,
) -> Result<u64, ExtensionFailure> {
    match state.get(&wasm_app_nonce_key(signer))? {
        None => Ok(0),
        Some(value) => u64::try_from_slice(&value).map_err(|_| ExtensionFailure::InvalidState),
    }
}

pub(crate) fn wasm_app_nonce_key(signer: Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(WASM_APP_NONCE_PREFIX.len() + signer.0.len());
    key.extend_from_slice(WASM_APP_NONCE_PREFIX);
    key.extend_from_slice(&signer.0);
    key
}

fn wasm_app_commitment(
    chain_id: [u8; 32],
    extension_id: ExtensionHash,
    payload: &[u8],
    signer: Address,
    nonce: u64,
) -> Result<[u8; 32], ExtensionFailure> {
    let bytes = canonical_bytes(&UnsignedWasmAppCall {
        chain_id,
        extension_id,
        payload,
        signer,
        nonce,
    })
    .map_err(|_| ExtensionFailure::InvalidPayload)?;
    Ok(blake3::derive_key(WASM_APP_COMMITMENT_CONTEXT, &bytes))
}

fn is_wasm_system_key(key: &[u8]) -> bool {
    key.starts_with(WASM_APP_NONCE_PREFIX)
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct WasmExtensionManifest {
    pub abi_version: u32,
    pub name: String,
    pub extension_id: ExtensionHash,
    pub activation_height: Height,
    pub code_hash: [u8; 32],
    pub fuel_limit: u64,
    pub memory_pages: u32,
}

impl WasmExtensionManifest {
    pub fn new(name: String, activation_height: Height, module: &[u8]) -> Self {
        let code_hash = wasm_code_hash(module);
        Self {
            abi_version: WASM_ABI_VERSION,
            extension_id: wasm_extension_id(&name, code_hash),
            name,
            activation_height,
            code_hash,
            fuel_limit: WASM_DEFAULT_FUEL,
            memory_pages: WASM_MEMORY_MAX_PAGES,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct WasmExtensionPackage {
    pub manifest: WasmExtensionManifest,
    pub module: Vec<u8>,
}

impl WasmExtensionPackage {
    pub fn new(
        name: String,
        activation_height: Height,
        module: Vec<u8>,
    ) -> Result<Self, WasmExtensionError> {
        let manifest = WasmExtensionManifest::new(name, activation_height, &module);
        WasmExtension::new(manifest.clone(), module.clone())?;
        Ok(Self { manifest, module })
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Self, WasmExtensionError> {
        let metadata = fs::metadata(path.as_ref()).map_err(WasmExtensionError::Io)?;
        if metadata.len() > WASM_PACKAGE_MAX_SIZE as u64 {
            return Err(WasmExtensionError::PackageTooLarge);
        }
        let bytes = fs::read(path.as_ref()).map_err(WasmExtensionError::Io)?;
        Self::try_from_slice(&bytes).map_err(|_| WasmExtensionError::InvalidPackage)
    }

    pub fn compile(self) -> Result<WasmExtension, WasmExtensionError> {
        WasmExtension::new(self.manifest, self.module)
    }

    pub fn write_new(&self, path: impl AsRef<Path>) -> Result<(), WasmExtensionError> {
        let bytes = borsh::to_vec(self).map_err(|_| WasmExtensionError::InvalidPackage)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.as_ref())
            .map_err(WasmExtensionError::Io)?;
        file.write_all(&bytes).map_err(WasmExtensionError::Io)
    }
}

#[derive(Debug)]
pub enum WasmExtensionError {
    Io(std::io::Error),
    PackageTooLarge,
    InvalidPackage,
    InvalidManifest,
    CodeTooLarge,
    CodeHashMismatch,
    ExtensionHashMismatch,
    InvalidModule,
    InvalidMemory,
    InvalidAbi,
}

impl fmt::Display for WasmExtensionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io(error) => return write!(formatter, "WASM package I/O error: {error}"),
            Self::PackageTooLarge => "WASM package exceeds the size limit",
            Self::InvalidPackage => "invalid canonical WASM package",
            Self::InvalidManifest => "invalid WASM extension manifest",
            Self::CodeTooLarge => "WASM module exceeds the size limit",
            Self::CodeHashMismatch => "WASM module hash does not match its manifest",
            Self::ExtensionHashMismatch => "WASM extension id does not match name and code hash",
            Self::InvalidModule => "invalid or unsupported deterministic WASM module",
            Self::InvalidMemory => "WASM memory must have equal bounded minimum and maximum",
            Self::InvalidAbi => "WASM module does not export the XPARQ ABI functions",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WasmExtensionError {}

pub fn wasm_code_hash(module: &[u8]) -> [u8; 32] {
    blake3::derive_key(WASM_CODE_HASH_CONTEXT, module)
}

pub fn wasm_extension_id(name: &str, code_hash: [u8; 32]) -> ExtensionHash {
    let mut hasher = blake3::Hasher::new_derive_key(WASM_EXTENSION_HASH_CONTEXT);
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(name.as_bytes());
    hasher.update(&code_hash);
    ExtensionHash::from_bytes(*hasher.finalize().as_bytes())
}

pub struct WasmExtension {
    manifest: WasmExtensionManifest,
    engine: Engine,
    module: Module,
}

impl WasmExtension {
    pub fn new(
        manifest: WasmExtensionManifest,
        module_bytes: Vec<u8>,
    ) -> Result<Self, WasmExtensionError> {
        validate_manifest(&manifest, &module_bytes)?;
        let engine = deterministic_engine();
        let module =
            Module::new(&engine, &module_bytes).map_err(|_| WasmExtensionError::InvalidModule)?;
        validate_module_memory(&module, manifest.memory_pages)?;
        Ok(Self {
            manifest,
            engine,
            module,
        })
    }

    pub fn manifest(&self) -> &WasmExtensionManifest {
        &self.manifest
    }

    fn execute(
        &self,
        export: &str,
        context: ExtensionContext,
        payload: &[u8],
        state: &dyn ExtensionStateRead,
        writable: bool,
    ) -> Result<HostExecutionResult, ExtensionFailure> {
        let entries = state.entries()?;
        let state_bytes = entries
            .iter()
            .try_fold(0_usize, |total, (key, value)| {
                total.checked_add(key.len())?.checked_add(value.len())
            })
            .ok_or(ExtensionFailure::InvalidState)?;
        if state_bytes > WASM_STATE_MAX_SIZE {
            return Err(ExtensionFailure::InvalidState);
        }
        let original: BTreeMap<_, _> = entries.into_iter().collect();
        let mut linker = Linker::<HostState>::new(&self.engine);
        define_host_functions(&mut linker).map_err(|_| ExtensionFailure::InvalidState)?;
        let mut store = Store::new(
            &self.engine,
            HostState {
                state: original.clone(),
                state_bytes,
                failure: None,
                writable,
                protect_system_keys: true,
                effects: Vec::new(),
            },
        );
        store
            .set_fuel(self.manifest.fuel_limit)
            .map_err(|_| ExtensionFailure::InvalidState)?;
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|_| ExtensionFailure::InvalidPayload)?;
        let memory = instance
            .get_memory(&store, "memory")
            .ok_or(ExtensionFailure::InvalidPayload)?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, "xparq_alloc")
            .map_err(|_| ExtensionFailure::InvalidPayload)?;
        let entry = instance
            .get_typed_func::<(i32, i32, i64), i32>(&store, export)
            .map_err(|_| ExtensionFailure::InvalidPayload)?;
        let payload_len =
            i32::try_from(payload.len()).map_err(|_| ExtensionFailure::PayloadTooLarge)?;
        let pointer = alloc
            .call(&mut store, payload_len)
            .map_err(|_| ExtensionFailure::InvalidPayload)?;
        let offset = usize::try_from(pointer).map_err(|_| ExtensionFailure::InvalidPayload)?;
        memory
            .write(&mut store, offset, payload)
            .map_err(|_| ExtensionFailure::InvalidPayload)?;
        let result = entry
            .call(&mut store, (pointer, payload_len, context.height.0 as i64))
            .map_err(|_| ExtensionFailure::InvalidPayload)?;
        if let Some(failure) = store.data().failure {
            return Err(failure);
        }
        if result != 0 {
            return Err(ExtensionFailure::InvalidState);
        }
        let host = store.into_data();
        Ok(HostExecutionResult {
            state: host.state,
            effects: host.effects,
        })
    }
}

impl Extension for WasmExtension {
    fn id(&self) -> ExtensionHash {
        self.manifest.extension_id
    }

    fn activation_height(&self) -> Height {
        self.manifest.activation_height
    }

    fn validate(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &dyn ExtensionStateRead,
    ) -> Result<(), ExtensionFailure> {
        self.execute("xparq_validate", context, call.payload(), state, false)
            .map(|_| ())
    }

    fn apply(
        &self,
        context: ExtensionContext,
        call: &ExtensionCall,
        state: &mut dyn ExtensionStateWrite,
    ) -> Result<(), ExtensionFailure> {
        let original: BTreeMap<_, _> = state.entries()?.into_iter().collect();
        let resulting = self.execute("xparq_apply", context, call.payload(), state, true)?;
        let keys: BTreeSet<_> = original
            .keys()
            .chain(resulting.state.keys())
            .cloned()
            .collect();
        for key in keys {
            match (original.get(&key), resulting.state.get(&key)) {
                (Some(before), Some(after)) if before == after => {}
                (_, Some(after)) => state.put(key, after.clone())?,
                (Some(_), None) => state.delete(&key)?,
                (None, None) => {}
            }
        }
        for effect in resulting.effects {
            state.emit(effect)?;
        }
        Ok(())
    }
}

fn deterministic_engine() -> Engine {
    let mut config = Config::default();
    config
        .floats(false)
        .wasm_memory64(false)
        .wasm_multi_memory(false)
        .wasm_tail_call(false)
        .wasm_custom_page_sizes(false)
        .consume_fuel(true)
        .compilation_mode(CompilationMode::Eager);
    Engine::new(&config)
}

fn validate_manifest(
    manifest: &WasmExtensionManifest,
    module: &[u8],
) -> Result<(), WasmExtensionError> {
    if manifest.abi_version != WASM_ABI_VERSION
        || manifest.name.is_empty()
        || manifest.name.len() > WASM_NAME_MAX_SIZE
        || !manifest.name.is_ascii()
        || manifest.fuel_limit == 0
        || manifest.fuel_limit > WASM_MAX_FUEL
        || manifest.memory_pages == 0
        || manifest.memory_pages > WASM_MEMORY_MAX_PAGES
    {
        return Err(WasmExtensionError::InvalidManifest);
    }
    if module.len() > WASM_CODE_MAX_SIZE {
        return Err(WasmExtensionError::CodeTooLarge);
    }
    if wasm_code_hash(module) != manifest.code_hash {
        return Err(WasmExtensionError::CodeHashMismatch);
    }
    if wasm_extension_id(&manifest.name, manifest.code_hash) != manifest.extension_id {
        return Err(WasmExtensionError::ExtensionHashMismatch);
    }
    Ok(())
}

fn validate_module_memory(module: &Module, pages: u32) -> Result<(), WasmExtensionError> {
    let memory = module
        .exports()
        .find(|export| export.name() == "memory")
        .ok_or(WasmExtensionError::InvalidMemory)?;
    let ExternType::Memory(memory) = memory.ty() else {
        return Err(WasmExtensionError::InvalidMemory);
    };
    if memory.minimum() != u64::from(pages) || memory.maximum() != Some(u64::from(pages)) {
        return Err(WasmExtensionError::InvalidMemory);
    }
    Ok(())
}

struct HostState {
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    state_bytes: usize,
    failure: Option<ExtensionFailure>,
    writable: bool,
    protect_system_keys: bool,
    effects: Vec<ExtensionEffect>,
}

struct HostExecutionResult {
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    effects: Vec<ExtensionEffect>,
}

impl HostState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure> {
        if self.protect_system_keys && is_wasm_system_key(key) {
            return Err(ExtensionFailure::StateAccess);
        }
        Ok(self.state.get(key).cloned())
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ExtensionFailure> {
        if !self.writable {
            return Err(ExtensionFailure::StateAccess);
        }
        if self.protect_system_keys && is_wasm_system_key(&key) {
            return Err(ExtensionFailure::StateAccess);
        }
        let previous_size = self
            .state
            .get(&key)
            .map_or(0, |previous| key.len() + previous.len());
        let next_size = self
            .state_bytes
            .checked_sub(previous_size)
            .and_then(|size| size.checked_add(key.len()))
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(ExtensionFailure::StateEntryLimit)?;
        if next_size > WASM_STATE_MAX_SIZE {
            return Err(ExtensionFailure::StateEntryLimit);
        }
        self.state.insert(key, value);
        self.state_bytes = next_size;
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), ExtensionFailure> {
        if !self.writable {
            return Err(ExtensionFailure::StateAccess);
        }
        if self.protect_system_keys && is_wasm_system_key(key) {
            return Err(ExtensionFailure::StateAccess);
        }
        if let Some(value) = self.state.remove(key) {
            self.state_bytes -= key.len() + value.len();
        }
        Ok(())
    }
}

fn define_host_functions(linker: &mut Linker<HostState>) -> Result<(), wasmi::Error> {
    linker.func_wrap("xparq", "state_get", host_state_get)?;
    linker.func_wrap("xparq", "state_put", host_state_put)?;
    linker.func_wrap("xparq", "state_delete", host_state_delete)?;
    linker.func_wrap("xparq", "asset_mint", host_asset_mint)?;
    linker.func_wrap("xparq", "asset_transfer", host_asset_transfer)?;
    linker.func_wrap("xparq", "coin_transfer", host_coin_transfer)?;
    Ok(())
}

fn guest_memory<T>(caller: &Caller<'_, T>) -> Option<Memory> {
    caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
}

fn read_guest<T>(
    caller: &Caller<'_, T>,
    pointer: i32,
    length: i32,
    maximum: usize,
) -> Option<Vec<u8>> {
    let offset = usize::try_from(pointer).ok()?;
    let length = usize::try_from(length).ok()?;
    if length > maximum {
        return None;
    }
    let mut bytes = vec![0; length];
    guest_memory(caller)?
        .read(caller, offset, &mut bytes)
        .ok()?;
    Some(bytes)
}

fn fail(caller: &mut Caller<'_, HostState>, failure: ExtensionFailure) -> i32 {
    caller.data_mut().failure.get_or_insert(failure);
    HOST_FAILURE
}

fn host_state_get(
    mut caller: Caller<'_, HostState>,
    key_ptr: i32,
    key_len: i32,
    output_ptr: i32,
    output_capacity: i32,
) -> i32 {
    let Some(key) = read_guest(&caller, key_ptr, key_len, EXTENSION_STATE_KEY_MAX_SIZE) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    let value = match caller.data().get(&key) {
        Ok(Some(value)) => value,
        Ok(None) => return HOST_MISSING,
        Err(error) => return fail(&mut caller, error),
    };
    let Ok(value_len) = i32::try_from(value.len()) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    let Ok(capacity) = usize::try_from(output_capacity) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    if value.len() > capacity {
        return HOST_BUFFER_TOO_SMALL;
    }
    let Ok(offset) = usize::try_from(output_ptr) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    let Some(memory) = guest_memory(&caller) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    if memory.write(&mut caller, offset, &value).is_err() {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    }
    value_len
}

fn host_state_put(
    mut caller: Caller<'_, HostState>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) -> i32 {
    let Some(key) = read_guest(&caller, key_ptr, key_len, EXTENSION_STATE_KEY_MAX_SIZE) else {
        return fail(&mut caller, ExtensionFailure::StateKeyTooLarge);
    };
    let Some(value) = read_guest(
        &caller,
        value_ptr,
        value_len,
        EXTENSION_STATE_VALUE_MAX_SIZE,
    ) else {
        return fail(&mut caller, ExtensionFailure::StateValueTooLarge);
    };
    match caller.data_mut().put(key, value) {
        Ok(()) => 0,
        Err(error) => fail(&mut caller, error),
    }
}

fn host_state_delete(mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32) -> i32 {
    let Some(key) = read_guest(&caller, key_ptr, key_len, EXTENSION_STATE_KEY_MAX_SIZE) else {
        return fail(&mut caller, ExtensionFailure::StateKeyTooLarge);
    };
    match caller.data_mut().delete(&key) {
        Ok(()) => 0,
        Err(error) => fail(&mut caller, error),
    }
}

fn host_asset_mint(
    mut caller: Caller<'_, HostState>,
    asset_id_ptr: i32,
    recipient_ptr: i32,
    amount_ptr: i32,
) -> i32 {
    if !caller.data().writable {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    }
    if caller.data().effects.len() >= WASM_EFFECT_MAX_COUNT {
        return fail(&mut caller, ExtensionFailure::StateEntryLimit);
    }
    let Some(asset_id) = read_guest(&caller, asset_id_ptr, 32, 32) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    let Some(recipient) = read_guest(&caller, recipient_ptr, 20, 20) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    let Some(amount) = read_guest(&caller, amount_ptr, 16, 16) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    caller.data_mut().effects.push(ExtensionEffect::MintAsset {
        asset_id: asset_id.try_into().expect("fixed asset ID length"),
        recipient: recipient.try_into().expect("fixed address length"),
        amount: u128::from_le_bytes(amount.try_into().expect("fixed amount length")),
    });
    0
}

fn host_asset_transfer(
    mut caller: Caller<'_, HostState>,
    asset_id_ptr: i32,
    recipient_ptr: i32,
    amount_ptr: i32,
) -> i32 {
    if !caller.data().writable {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    }
    if caller.data().effects.len() >= WASM_EFFECT_MAX_COUNT {
        return fail(&mut caller, ExtensionFailure::StateEntryLimit);
    }
    let Some(asset_id) = read_guest(&caller, asset_id_ptr, 32, 32) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    let Some(recipient) = read_guest(&caller, recipient_ptr, 20, 20) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    let Some(amount) = read_guest(&caller, amount_ptr, 16, 16) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    caller
        .data_mut()
        .effects
        .push(ExtensionEffect::TransferAsset {
            asset_id: asset_id.try_into().expect("fixed asset ID length"),
            recipient: recipient.try_into().expect("fixed address length"),
            amount: u128::from_le_bytes(amount.try_into().expect("fixed amount length")),
        });
    0
}

fn host_coin_transfer(mut caller: Caller<'_, HostState>, recipient_ptr: i32, amount: i64) -> i32 {
    if !caller.data().writable {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    }
    if caller.data().effects.len() >= WASM_EFFECT_MAX_COUNT || amount <= 0 {
        return fail(&mut caller, ExtensionFailure::InvalidState);
    }
    let Some(recipient) = read_guest(&caller, recipient_ptr, 20, 20) else {
        return fail(&mut caller, ExtensionFailure::StateAccess);
    };
    caller
        .data_mut()
        .effects
        .push(ExtensionEffect::TransferCoin {
            recipient: recipient.try_into().expect("fixed address length"),
            amount: amount as u64,
        });
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryState {
        entries: BTreeMap<Vec<u8>, Vec<u8>>,
        effects: Vec<ExtensionEffect>,
    }

    impl ExtensionStateRead for MemoryState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExtensionFailure> {
            Ok(self.entries.get(key).cloned())
        }

        fn entries(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ExtensionFailure> {
            Ok(self
                .entries
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect())
        }

        fn get_extension(
            &self,
            _extension_id: ExtensionHash,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>, ExtensionFailure> {
            self.get(key)
        }
    }

    impl ExtensionStateWrite for MemoryState {
        fn put(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<(), ExtensionFailure> {
            self.entries.insert(key, value);
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), ExtensionFailure> {
            self.entries.remove(key);
            Ok(())
        }

        fn emit(&mut self, effect: ExtensionEffect) -> Result<(), ExtensionFailure> {
            self.effects.push(effect);
            Ok(())
        }
    }

    fn compile(wat_source: &str) -> WasmExtension {
        let module = wat::parse_str(wat_source).unwrap();
        let manifest = WasmExtensionManifest::new("test.extension".into(), Height(5), &module);
        WasmExtension::new(manifest, module).unwrap()
    }

    fn call(extension: &WasmExtension, payload: &[u8]) -> ExtensionCall {
        ExtensionCall::new(extension.id(), payload.to_vec()).unwrap()
    }

    #[test]
    fn guest_validates_and_applies_state_through_the_bounded_host_abi() {
        let extension = compile(
            r#"(module
                (import "xparq" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 16 16)
                (data (i32.const 0) "owner")
                (data (i32.const 16) "alice")
                (func (export "xparq_alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "xparq_validate") (param i32 i32 i64) (result i32)
                    local.get 1 i32.eqz)
                (func (export "xparq_apply") (param i32 i32 i64) (result i32)
                    i32.const 0 i32.const 5 i32.const 16 i32.const 5 call $put)
            )"#,
        );
        let mut state = MemoryState::default();
        let extension_call = call(&extension, b"register");
        extension
            .validate(
                ExtensionContext { height: Height(5) },
                &extension_call,
                &state,
            )
            .unwrap();
        extension
            .apply(
                ExtensionContext { height: Height(5) },
                &extension_call,
                &mut state,
            )
            .unwrap();
        assert_eq!(state.get(b"owner").unwrap(), Some(b"alice".to_vec()));
    }

    #[test]
    fn validation_is_read_only_even_if_the_guest_imports_state_put() {
        let extension = compile(
            r#"(module
                (import "xparq" "state_put" (func $put (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 16 16)
                (data (i32.const 0) "keyvalue")
                (func (export "xparq_alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "xparq_validate") (param i32 i32 i64) (result i32)
                    i32.const 0 i32.const 3 i32.const 3 i32.const 5 call $put)
                (func (export "xparq_apply") (param i32 i32 i64) (result i32) (i32.const 0))
            )"#,
        );
        let state = MemoryState::default();
        assert_eq!(
            extension.validate(
                ExtensionContext { height: Height(5) },
                &call(&extension, b"payload"),
                &state,
            ),
            Err(ExtensionFailure::StateAccess)
        );
    }

    #[test]
    fn guest_can_emit_an_asset_mint_effect_only_during_apply() {
        let extension = compile(
            r#"(module
                (import "xparq" "asset_mint" (func $mint (param i32 i32 i32) (result i32)))
                (memory (export "memory") 16 16)
                (data (i32.const 0) "\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01")
                (data (i32.const 32) "\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02")
                (data (i32.const 64) "\19\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
                (func (export "xparq_alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "xparq_validate") (param i32 i32 i64) (result i32) (i32.const 0))
                (func (export "xparq_apply") (param i32 i32 i64) (result i32)
                    i32.const 0 i32.const 32 i32.const 64 call $mint)
            )"#,
        );
        let mut state = MemoryState::default();
        extension
            .apply(
                ExtensionContext { height: Height(5) },
                &call(&extension, b"mint"),
                &mut state,
            )
            .unwrap();
        assert_eq!(
            state.effects,
            vec![ExtensionEffect::MintAsset {
                asset_id: [1; 32],
                recipient: [2; 20],
                amount: 25,
            }]
        );
    }

    #[test]
    fn guest_can_send_extension_owned_coin_and_asset() {
        let extension = compile(
            r#"(module
                (import "xparq" "asset_transfer" (func $asset (param i32 i32 i32) (result i32)))
                (import "xparq" "coin_transfer" (func $coin (param i32 i64) (result i32)))
                (memory (export "memory") 16 16)
                (data (i32.const 0) "\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01")
                (data (i32.const 32) "\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02\02")
                (data (i32.const 64) "\19\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
                (func (export "xparq_alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "xparq_validate") (param i32 i32 i64) (result i32) (i32.const 0))
                (func (export "xparq_apply") (param i32 i32 i64) (result i32)
                    i32.const 0 i32.const 32 i32.const 64 call $asset drop
                    i32.const 32 i64.const 9 call $coin)
            )"#,
        );
        let mut state = MemoryState::default();
        extension
            .apply(
                ExtensionContext { height: Height(5) },
                &call(&extension, b"send"),
                &mut state,
            )
            .unwrap();
        assert_eq!(
            state.effects,
            vec![
                ExtensionEffect::TransferAsset {
                    asset_id: [1; 32],
                    recipient: [2; 20],
                    amount: 25
                },
                ExtensionEffect::TransferCoin {
                    recipient: [2; 20],
                    amount: 9
                },
            ]
        );
    }

    #[test]
    fn package_rejects_hash_and_memory_limit_mismatches() {
        let module = wat::parse_str(
            r#"(module
                (memory (export "memory") 1 1)
                (func (export "xparq_alloc") (param i32) (result i32) (i32.const 0))
                (func (export "xparq_validate") (param i32 i32 i64) (result i32) (i32.const 0))
                (func (export "xparq_apply") (param i32 i32 i64) (result i32) (i32.const 0)))"#,
        )
        .unwrap();
        let mut manifest = WasmExtensionManifest::new("limits".into(), Height(0), &module);
        assert!(matches!(
            WasmExtension::new(manifest.clone(), module.clone()),
            Err(WasmExtensionError::InvalidMemory)
        ));
        manifest.memory_pages = 1;
        manifest.code_hash[0] ^= 1;
        assert!(matches!(
            WasmExtension::new(manifest, module),
            Err(WasmExtensionError::CodeHashMismatch)
        ));
    }

    #[test]
    fn fuel_stops_a_non_terminating_guest() {
        let extension = compile(
            r#"(module
                (memory (export "memory") 16 16)
                (func (export "xparq_alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "xparq_validate") (param i32 i32 i64) (result i32)
                    (loop $forever (br $forever)) (i32.const 0))
                (func (export "xparq_apply") (param i32 i32 i64) (result i32) (i32.const 0)))"#,
        );
        assert_eq!(
            extension.validate(
                ExtensionContext { height: Height(5) },
                &call(&extension, b"payload"),
                &MemoryState::default(),
            ),
            Err(ExtensionFailure::InvalidPayload)
        );
    }
}
