//! Public facade for optional XPARQ extension crates.
//!
//! Extensions remain outside the consensus kernel unless explicitly integrated
//! through a separately reviewed protocol change.

mod registry;

use std::sync::OnceLock;

pub use registry::{ExtensionRegistry, RegistryError};
pub use xparq_asset as asset;
pub use xparq_bridge as bridge;
pub use xparq_common::extension::*;

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
    fn facade_exposes_asset_and_bridge_crates() {
        assert_eq!(asset::bitcoin::ASSET_SYMBOL, "qBTC");
        assert_eq!(
            bridge::SourceNetwork::Bitcoin,
            bridge::SourceNetwork::Bitcoin
        );
    }
}
