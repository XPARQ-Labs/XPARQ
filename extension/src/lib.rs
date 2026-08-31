//! Public facade for optional XPARQ extension crates.
//!
//! Extensions remain outside the consensus kernel unless explicitly integrated
//! through a separately reviewed protocol change.

mod deploy;
mod registry;
mod wasm;

use std::sync::OnceLock;

pub use deploy::{
    WASM_DEPLOY_ACTIVATION_DELAY, WasmDeployCall, WasmDeployExtension, wasm_deploy_extension_id,
    wasm_deploy_nonce, wasm_deployed_package,
};
pub use registry::{ExtensionRegistry, RegistryError};
pub use wasm::{
    WASM_ABI_VERSION, WASM_APP_CALL_ACTIVATION_HEIGHT, WASM_CODE_MAX_SIZE, WASM_DEFAULT_FUEL,
    WASM_MEMORY_MAX_PAGES, WASM_STATE_MAX_SIZE, WasmAppCall, WasmExtension, WasmExtensionError,
    WasmExtensionManifest, WasmExtensionPackage, wasm_app_nonce, wasm_code_hash, wasm_extension_id,
};
pub use xparq_bridge as bridge;
pub use xparq_common::extension::*;

static WASM_CHAIN_SPEC_MANIFESTS: OnceLock<Vec<WasmExtensionManifest>> = OnceLock::new();

/// Fixes the ordered WASM allowlist before any chain-spec hash is calculated.
pub fn configure_wasm_chain_spec(
    mut manifests: Vec<WasmExtensionManifest>,
) -> Result<(), RegistryError> {
    manifests.sort_by_key(|manifest| manifest.extension_id);
    if manifests
        .windows(2)
        .any(|pair| pair[0].extension_id == pair[1].extension_id)
    {
        return Err(RegistryError::DuplicateExtension);
    }
    WASM_CHAIN_SPEC_MANIFESTS
        .set(manifests)
        .map_err(|_| RegistryError::AlreadyInitialized)
}

pub fn wasm_chain_spec_manifests() -> &'static [WasmExtensionManifest] {
    WASM_CHAIN_SPEC_MANIFESTS.get_or_init(Vec::new)
}

/// Registry linked into the current node build and initialized once during
/// runtime startup before persisted blocks or mempool entries are decoded.
static PRODUCTION_REGISTRY: OnceLock<ExtensionRegistry> = OnceLock::new();

pub fn initialize_production_registry(registry: ExtensionRegistry) -> Result<(), RegistryError> {
    PRODUCTION_REGISTRY
        .set(registry)
        .map_err(|_| RegistryError::AlreadyInitialized)
}

pub fn production_registry() -> &'static ExtensionRegistry {
    PRODUCTION_REGISTRY.get_or_init(ExtensionRegistry::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_exposes_bridge_crate() {
        assert_eq!(
            bridge::SourceNetwork::Bitcoin,
            bridge::SourceNetwork::Bitcoin
        );
    }
}
