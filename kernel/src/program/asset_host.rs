//! Bound asset capability: the kernel checks ownership and supply and records
//! rollback, while the application selects the requested monetary operation.

use super::{
    application::{ApplicationExecutor, AssetHost},
    system::asset_program::{
        asset::AssetError,
        type_::{AssetCall, Burn, Mint, Register, Transfer},
    },
};
use crate::ledger::utxo::ExecutionContext;
use crate::ledger::utxo::{AssetJournal, AssetState};

struct BoundAssetHost<'a> {
    state: &'a mut AssetState,
    expected: &'a AssetCall,
    context: ExecutionContext,
    journal: Option<AssetJournal>,
}

impl Drop for BoundAssetHost<'_> {
    fn drop(&mut self) {
        if let Some(journal) = self.journal.take() {
            self.state.rollback(journal);
        }
    }
}

impl BoundAssetHost<'_> {
    fn apply(&mut self, operation: AssetCall) -> Result<(), AssetError> {
        if &operation != self.expected || self.journal.is_some() {
            return Err(AssetError::InvalidProgram);
        }
        self.journal = Some(self.state.apply(&operation, self.context)?);
        Ok(())
    }
}

impl AssetHost for BoundAssetHost<'_> {
    fn register(&mut self, call: &Register) -> Result<(), AssetError> {
        self.apply(AssetCall::Register(call.clone()))
    }
    fn mint(&mut self, call: &Mint) -> Result<(), AssetError> {
        self.apply(AssetCall::Mint(call.clone()))
    }
    fn transfer(&mut self, call: &Transfer) -> Result<(), AssetError> {
        self.apply(AssetCall::Transfer(call.clone()))
    }
    fn burn(&mut self, call: &Burn) -> Result<(), AssetError> {
        self.apply(AssetCall::Burn(call.clone()))
    }
}

pub(crate) fn execute_asset(
    applications: &dyn ApplicationExecutor,
    state: &mut AssetState,
    call: &AssetCall,
    context: ExecutionContext,
) -> Result<AssetJournal, AssetError> {
    let mut host = BoundAssetHost {
        state,
        expected: call,
        context,
        journal: None,
    };
    applications.execute_asset(call, &mut host)?;
    let journal = host.journal.take().ok_or(AssetError::InvalidProgram)?;
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{common::Owner, error::StateError, monetary::coin::CoinShare};
    use crypto::ProgramId;

    #[derive(Clone, Copy)]
    enum Mode {
        Success,
        Error,
        Panic,
        Twice,
        Missing,
    }
    struct Executor(Mode);
    impl ApplicationExecutor for Executor {
        fn execute_coin(
            &self,
            _: &mut dyn super::super::system::coin_program::CoinHost<Error = StateError>,
            _: &[CoinShare],
            _: &[(Owner, u64)],
            _: ProgramId,
            _: u64,
        ) -> Result<(), super::super::system::coin_program::TransferError<StateError>> {
            Err(super::super::system::coin_program::TransferError::Host(
                StateError::InvalidTransition,
            ))
        }
        fn execute_asset(
            &self,
            call: &AssetCall,
            host: &mut dyn AssetHost,
        ) -> Result<(), AssetError> {
            if matches!(self.0, Mode::Missing) {
                return Ok(());
            }
            let apply = |host: &mut dyn AssetHost| match call {
                AssetCall::Register(call) => host.register(call),
                AssetCall::Mint(call) => host.mint(call),
                AssetCall::Transfer(call) => host.transfer(call),
                AssetCall::Burn(call) => host.burn(call),
            };
            apply(host)?;
            match self.0 {
                Mode::Error => Err(AssetError::InvalidProgram),
                Mode::Panic => panic!("injected application panic after asset mutation"),
                Mode::Twice => apply(host),
                _ => Ok(()),
            }
        }
    }

    #[test]
    fn asset_host_restores_state_on_application_errors_and_unwind() {
        use super::super::system::asset_program::asset::Unit;
        let owner = Owner::Program(ProgramId([33; 32]));
        let register = AssetCall::Register(Register {
            name: "Host".into(),
            max_supply: Unit::from_units(100),
            initial_mint: Unit::from_units(10),
            mint_authority: owner,
            nonce: 1,
        });
        let context = ExecutionContext {
            actor: owner,
            commitment: [1; 32],
        };
        let mut state = AssetState::default();
        for mode in [Mode::Error, Mode::Twice, Mode::Missing] {
            assert!(execute_asset(&Executor(mode), &mut state, &register, context).is_err());
            assert_eq!(state, AssetState::default());
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute_asset(
                &Executor(Mode::Panic),
                &mut state,
                &register,
                context
            )))
            .is_err()
        );
        assert_eq!(state, AssetState::default());
        let journal =
            execute_asset(&Executor(Mode::Success), &mut state, &register, context).unwrap();
        let registered = state.clone();
        let asset = *state.records().keys().next().unwrap();
        let mint = AssetCall::Mint(Mint {
            asset,
            recipient: owner,
            amount: Unit::from_units(5),
            nonce: 1,
        });
        assert!(
            execute_asset(
                &Executor(Mode::Error),
                &mut state,
                &mint,
                ExecutionContext {
                    actor: owner,
                    commitment: [2; 32]
                }
            )
            .is_err()
        );
        assert_eq!(state, registered);
        state.rollback(journal);
        assert_eq!(state, AssetState::default());
    }
}
