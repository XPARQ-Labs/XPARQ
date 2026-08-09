pub mod error;
#[allow(clippy::module_inception)] // Preserve the established public module path.
pub mod storage;

pub use error::StorageError;
pub use storage::Storage;
