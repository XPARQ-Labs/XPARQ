use crate::program::system::asset_program::{self, type_::AssetCall};

use super::{
    call::{ProgramCall, SystemProgramId},
    opcode::ProgramError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedProgramCall {
    XpqTransfer,
    Asset(AssetCall),
    Vm([u8; 32]),
}

/// Decode a call before any state transition. This does not execute it.
pub fn decode_program(call: &ProgramCall) -> Result<DecodedProgramCall, ProgramError> {
    match call.program {
        SystemProgramId::MONETARY => {
            match super::super::monetary::decode(call.opcode, &call.payload)? {
                super::super::monetary::MonetaryCall::TransferCoin => {
                    Ok(DecodedProgramCall::XpqTransfer)
                }
                super::super::monetary::MonetaryCall::Asset(call) => {
                    Ok(DecodedProgramCall::Asset(call))
                }
            }
        }
        SystemProgramId::ASSET => {
            asset_program::decode(call.opcode, &call.payload).map(DecodedProgramCall::Asset)
        }
        SystemProgramId::VM => {
            let (id, _) = crate::program::vm_app::call_input(call)
                .map_err(|_| ProgramError::InvalidPayload)?;
            Ok(DecodedProgramCall::Vm(id.into_bytes()))
        }
        _ => Err(ProgramError::UnknownProgram),
    }
}
