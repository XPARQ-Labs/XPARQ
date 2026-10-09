mod error;
mod payment;
mod state_view;
mod validation;

pub use error::ProgramConsensusError;
pub(crate) use payment::validate_coin_inputs;
pub use payment::validate_coin_inputs_for_quote;
pub use state_view::{CoinInputState, ProgramStateView};
pub use validation::{validate_program_call, validate_program_call_with_applications};

#[cfg(test)]
mod tests;
