//! Unified monetary system-program implementation on restricted kernel hosts.
pub use kernel::program::system::monetary::*;
use kernel::{
    common::Owner,
    monetary::coin::CoinShare,
    program::{
        application::AssetHost,
        system::{
            asset_program::{asset, type_},
            coin_program::{CoinHost, TransferError},
        },
    },
};
/// Execute a validated transfer, including funding for other Program calls.
/// The host must validate authorization and provide atomic commit/rollback.
pub fn execute_transfer<H: CoinHost + ?Sized>(
    host: &mut H,
    inputs: &[CoinShare],
    outputs: &[(Owner, u64)],
    miner: kernel::crypto::ProgramId,
    miner_fee: u64,
) -> Result<(), TransferError<H::Error>> {
    let mut input_total = 0u64;
    for id in inputs {
        input_total = input_total
            .checked_add(host.input_amount(id).map_err(TransferError::Host)?)
            .ok_or(TransferError::AmountOverflow)?;
    }
    let output_total = outputs.iter().try_fold(0u64, |sum, (_, amount)| {
        sum.checked_add(*amount)
            .ok_or(TransferError::AmountOverflow)
    })?;
    let burn = input_total
        .checked_sub(output_total)
        .and_then(|remaining| remaining.checked_sub(miner_fee))
        .ok_or(TransferError::InvalidBalance)?;
    for id in inputs {
        host.consume(*id).map_err(TransferError::Host)?;
    }
    for (index, (owner, amount)) in outputs.iter().enumerate() {
        host.create(
            u32::try_from(index).map_err(|_| TransferError::OutputIndexOverflow)?,
            *owner,
            *amount,
        )
        .map_err(TransferError::Host)?;
    }
    if miner_fee != 0 {
        host.create(
            u32::try_from(outputs.len()).map_err(|_| TransferError::OutputIndexOverflow)?,
            Owner::Program(miner),
            miner_fee,
        )
        .map_err(TransferError::Host)?;
    }
    host.burn(burn).map_err(TransferError::Host)
}

pub fn execute_asset(
    call: &type_::AssetCall,
    host: &mut dyn AssetHost,
) -> Result<(), asset::AssetError> {
    use type_::AssetCall;
    match call {
        AssetCall::Register(call) => host.register(call),
        AssetCall::Mint(call) => host.mint(call),
        AssetCall::Transfer(call) => host.transfer(call),
        AssetCall::Burn(call) => host.burn(call),
    }
}
