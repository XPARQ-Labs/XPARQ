pub mod error;
#[allow(clippy::module_inception)] // Preserve the established public module path.
pub mod node;

pub use error::NodeError;
pub use node::Node;
