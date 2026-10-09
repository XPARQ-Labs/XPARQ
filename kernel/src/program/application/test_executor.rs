use super::*;

pub struct TestApplications;

/// Execute a validated transfer, including funding for other Program calls.
/// The host must validate authorization and provide atomic commit/rollback.
pub fn execute_transfer<H: CoinHost + ?Sized>(
    host: &mut H,
    inputs: &[CoinShare],
    outputs: &[(Owner, u64)],
    miner: crypto::ProgramId,
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
            crate::common::Owner::Program(miner),
            miner_fee,
        )
        .map_err(TransferError::Host)?;
    }
    host.burn(burn).map_err(TransferError::Host)
}

impl ApplicationExecutor for TestApplications {
    fn execute_coin(
        &self,
        host: &mut dyn CoinHost<Error = StateError>,
        inputs: &[CoinShare],
        outputs: &[(crate::common::Owner, u64)],
        miner: ProgramId,
        fee: u64,
    ) -> Result<(), TransferError<StateError>> {
        execute_transfer(host, inputs, outputs, miner, fee)
    }
    fn execute_asset(&self, call: &AssetCall, host: &mut dyn AssetHost) -> Result<(), AssetError> {
        match call {
            AssetCall::Register(c) => host.register(c),
            AssetCall::Mint(c) => host.mint(c),
            AssetCall::Transfer(c) => host.transfer(c),
            AssetCall::Burn(c) => host.burn(c),
        }
    }
}
