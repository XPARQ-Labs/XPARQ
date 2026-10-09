//! Deterministic XPVM bytecode contract, interpreter, and metering.

mod interpreter;
mod requests;
mod types;
mod validation;

pub use interpreter::{execute_code, execute_registered};
pub(crate) use requests::decode_register_request;
pub use requests::{MintAssetRequest, MintAssetTarget, RegisterAssetRequest, TransferRequest};
pub use types::{CodeError, ExecutionError, ExecutionResult, ValidatedCode, VmEffect};
pub use validation::validate_code;

pub const MAGIC: [u8; 4] = *b"XPVM";
pub const VERSION: u8 = 1;
pub const APPLICATION_VERSION: u8 = 4;
pub const ASSET_ISSUANCE_VERSION: u8 = 3;
pub const MAX_STACK_ITEMS: u16 = 256;
pub const MAX_MEMORY_PAGES: u16 = 16;
pub const PAGE_BYTES: usize = 65_536;
pub const MAX_CALL_FUEL: u64 = 65_536;
const HEADER_LEN: usize = 13;

/// State and transfer instructions have explicit deterministic costs.
/// Monetary changes are proposals checked and applied by the kernel.
pub const INSTRUCTION_COST: u64 = 1;
pub const MEMORY_PAGE_COST: u64 = 1;
pub const STATE_READ_COST: u64 = 2;
pub const STATE_WRITE_COST: u64 = 5;

pub const TRANSFER_COST: u64 = 20;
pub const ASSET_REGISTER_COST: u64 = 40;
pub const ASSET_MINT_COST: u64 = 20;

#[cfg(test)]
mod tests;
