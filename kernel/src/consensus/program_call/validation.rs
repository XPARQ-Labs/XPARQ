use super::{
    ProgramConsensusError, ProgramStateView,
    payment::{count_coin_outputs, validate_coin_inputs, validate_coin_inputs_for_quote},
};
use crate::{
    common::ChainContext,
    consensus::{ProtocolBurn, StateTransitionWeight, validate_exact_burn},
    monetary::coin::Zeno,
    operation::BlockOperationRef,
    program::{
        AuthorizedProgramInvocation, IntentError, MAX_PROGRAM_INVOCATION_SIZE,
        PreparedProgramInvocation,
    },
};
use crypto::canonical_length;
/// Validate one authorized program call against the current ledger state.
pub fn validate_program_call(
    transaction: AuthorizedProgramInvocation,
    chain: ChainContext,
    current_height: u64,
    state: &impl ProgramStateView,
) -> Result<PreparedProgramInvocation, ProgramConsensusError> {
    validate_program_call_with_applications(
        transaction,
        chain,
        current_height,
        state,
        crate::program::application::Applications::default().executor(),
    )
}

pub fn validate_program_call_with_applications(
    transaction: AuthorizedProgramInvocation,
    chain: ChainContext,
    current_height: u64,
    state: &impl ProgramStateView,
    applications: &dyn crate::program::application::ApplicationExecutor,
) -> Result<PreparedProgramInvocation, ProgramConsensusError> {
    transaction
        .validate_structure()
        .map_err(ProgramConsensusError::Intent)?;
    let transaction_size = canonical_length(&BlockOperationRef::ProgramCall(&transaction))
        .map_err(|_| ProgramConsensusError::Encoding)?;
    if transaction_size > MAX_PROGRAM_INVOCATION_SIZE as u64 {
        return Err(ProgramConsensusError::InvocationTooLarge);
    }
    let valid = transaction
        .verify_authorizations(chain, current_height)
        .map_err(ProgramConsensusError::Intent)?;
    if !valid {
        return Err(ProgramConsensusError::InvalidAuthorization);
    }
    let mut vm_quote = crate::program::vm_transfer::TransferQuote::default();
    let vm_fuel = match crate::program::system::script::execute::decode_program(&transaction.call)
        .map_err(|_| ProgramConsensusError::Intent(IntentError::InvalidAssetCall))?
    {
        crate::program::system::script::execute::DecodedProgramCall::Vm(id) => {
            validate_coin_inputs_for_quote(&transaction, state)?;
            if let Some(ledger) = state.ledger_state() {
                let commitment = crate::program::program_invocation_commitment(
                    transaction.signer,
                    &transaction.call,
                    &transaction.payment,
                    chain,
                )
                .map_err(ProgramConsensusError::Intent)?;
                let result = crate::program::vm_app::preview(
                    ledger,
                    &transaction,
                    current_height,
                    commitment,
                    applications,
                )
                .map_err(ProgramConsensusError::Vm)?;
                vm_quote = result.quote;
                result.fuel_used
            } else {
                let registry = state
                    .registry()
                    .ok_or(ProgramConsensusError::UnknownProgram)?;
                let result = crate::program::vm::execute_registered(
                    registry,
                    crate::program::ProgramId::from_bytes(id),
                    crate::program::vm::MAX_CALL_FUEL,
                )
                .map_err(ProgramConsensusError::Vm)?;
                if result.has_monetary_effects() {
                    return Err(ProgramConsensusError::UnknownProgram);
                }
                result.fuel_used
            }
        }
        crate::program::system::script::execute::DecodedProgramCall::Asset(call) => {
            let _ = call;
            0
        }
        _ => 0,
    };
    let created_state_weight = if matches!(
        crate::program::system::script::execute::decode_program(&transaction.call),
        Ok(
            crate::program::system::script::execute::DecodedProgramCall::XpqTransfer
                | crate::program::system::script::execute::DecodedProgramCall::Vm(_)
        )
    ) {
        vm_quote.created_state_weight
    } else {
        let extensions = state
            .extension_state()
            .ok_or(ProgramConsensusError::Intent(IntentError::InvalidAssetCall))?;
        crate::program::program_created_state_weight_with_applications(
            &transaction,
            chain,
            extensions,
            applications,
        )?
    };
    let (inputs, outputs) = transaction
        .payment
        .coin_parts()
        .ok_or(ProgramConsensusError::Intent(IntentError::InvalidAssetCall))?;
    let fee = transaction.payment.charges.miner_fee;
    let actual = validate_coin_inputs(inputs, outputs, fee, transaction.signer, state)?;
    let transition = StateTransitionWeight {
        created_coin_utxos: count_coin_outputs(outputs, fee)? + vm_quote.created_coin_utxos,
        consumed_coin_utxos: inputs.len() as u64 + vm_quote.consumed_coin_utxos,
        created_state_weight,
    };
    let required_burn = ProtocolBurn::for_program_call(transition, transaction_size)?
        .total()?
        .checked_add(Zeno::from_zeno(vm_fuel))
        .ok_or(ProgramConsensusError::ZenoOverflow)?;
    validate_exact_burn(actual, required_burn)?;
    Ok(PreparedProgramInvocation {
        invocation: transaction,
        required_burn,
        created_state_weight,
        height: current_height,
    })
}
