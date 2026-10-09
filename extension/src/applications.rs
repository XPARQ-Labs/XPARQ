//! Protocol application set installed by the runtime.

use kernel::{
    common::Owner,
    crypto::ProgramId,
    ledger::StateError,
    monetary::coin::CoinShare,
    program::{
        application::{ApplicationExecutor, AssetHost},
        system::{
            asset_program::{asset::AssetError, type_::AssetCall},
            coin_program::{CoinHost, TransferError},
        },
    },
};

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemApplications;

impl ApplicationExecutor for SystemApplications {
    fn execute_coin(
        &self,
        host: &mut dyn CoinHost<Error = StateError>,
        inputs: &[CoinShare],
        outputs: &[(Owner, u64)],
        miner: ProgramId,
        miner_fee: u64,
    ) -> Result<(), TransferError<StateError>> {
        crate::monetary::execute_transfer(host, inputs, outputs, miner, miner_fee)
    }

    fn execute_asset(&self, call: &AssetCall, host: &mut dyn AssetHost) -> Result<(), AssetError> {
        crate::monetary::execute_asset(call, host)
    }
}
