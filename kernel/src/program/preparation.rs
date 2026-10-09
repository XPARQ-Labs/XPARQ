//! Program invocation preparation and read-only state growth quotes.

use crate::ledger::utxo::ExecutionContext;
use crate::{
    common::{ChainContext, Owner},
    program::system::script::{
        execute::{DecodedProgramCall, decode_program},
        state::ExtensionState,
    },
};
use crypto::{HashDomain, canonical_bytes, domain};

/// Validated Program payment and execution context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedProgramInvocation {
    pub invocation: crate::program::AuthorizedProgramInvocation,
    pub required_burn: crate::monetary::coin::Zeno,
    pub created_state_weight: u64,
    pub(crate) height: u64,
}

/// Read-only state growth quote using the same execution preview as consensus.
pub fn program_created_state_weight(
    transaction: &crate::program::AuthorizedProgramInvocation,
    chain: ChainContext,
    extensions: &ExtensionState,
) -> Result<u64, crate::consensus::ProgramConsensusError> {
    program_created_state_weight_with_applications(
        transaction,
        chain,
        extensions,
        crate::program::application::Applications::default().executor(),
    )
}

pub fn program_created_state_weight_with_applications(
    transaction: &crate::program::AuthorizedProgramInvocation,
    chain: ChainContext,
    extensions: &ExtensionState,
    applications: &dyn crate::program::application::ApplicationExecutor,
) -> Result<u64, crate::consensus::ProgramConsensusError> {
    use crate::consensus::{BurnError, ProgramConsensusError as Error};
    transaction.validate_structure().map_err(Error::Intent)?;
    let call = match decode_program(&transaction.call)
        .map_err(|_| Error::Intent(crate::program::IntentError::InvalidAssetCall))?
    {
        DecodedProgramCall::XpqTransfer => return Ok(0),
        DecodedProgramCall::Vm(_) => return Ok(0),
        DecodedProgramCall::Asset(call) => call,
    };
    let commitment = canonical_bytes(&(
        chain.genesis_hash,
        transaction.signer,
        &transaction.call,
        &transaction.payment,
    ))
    .map_err(|_| Error::Encoding)?;
    let context = ExecutionContext {
        actor: Owner::Program(transaction.signer),
        commitment: domain(HashDomain::AssetIntent, &commitment).into_bytes(),
    };
    let mut preview = extensions
        .assets
        .operation_view(&call, context)
        .map_err(|_| Error::Intent(crate::program::IntentError::InvalidAssetCall))?;
    let journal =
        crate::program::asset_host::execute_asset(applications, &mut preview, &call, context)
            .map_err(|_| Error::Intent(crate::program::IntentError::InvalidAssetCall))?;
    let delta = journal
        .canonical_delta(&preview)
        .map_err(|_| Error::Encoding)?;
    let created_state_weight =
        u64::try_from(delta.max(0)).map_err(|_| Error::Burn(BurnError::WeightOverflow))?;
    Ok(created_state_weight)
}

#[cfg(test)]
mod tests;
