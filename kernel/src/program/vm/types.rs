//! Validated code, execution errors, results, and scalar state proposals.

use super::requests::{MintAssetRequest, RegisterAssetRequest, TransferRequest};
use crate::monetary::asset::AssetContract;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedCode {
    pub entry: u32,
    pub max_stack: u16,
    pub memory_pages: u16,
    pub instruction_count: u32,
    pub instruction_fuel: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeError {
    InvalidHeader,
    UnsupportedVersion,
    InvalidLimit,
    InvalidEntry,
    InvalidInstruction,
    MissingReturn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    pub value: i64,
    pub fuel_used: u64,
    pub proposed_effect: Option<VmEffect>,
    pub coin_transfer: Option<TransferRequest>,
    pub asset_transfer: Option<(AssetContract, TransferRequest)>,
    pub asset_register: Option<RegisterAssetRequest>,
    pub asset_mint: Option<MintAssetRequest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionError {
    InvalidCode(CodeError),
    UnknownProgram,
    OutOfFuel,
    ArithmeticOverflow,
    InvalidOperand,
    Reverted,
    ResourceLimit,
    ReentrantCall,
    SettlementFailed,
}

/// The VM proposes a change to its own fixed-size state slot. The kernel applies
/// the proposal only after successful execution and journals the old value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmEffect {
    ProgramState(i64),
}

impl ExecutionResult {
    pub fn has_monetary_effects(&self) -> bool {
        self.coin_transfer.is_some()
            || self.asset_transfer.is_some()
            || self.asset_register.is_some()
            || self.asset_mint.is_some()
    }
}
