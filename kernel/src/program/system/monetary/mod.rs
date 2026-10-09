//! One monetary route for native coin and asset operations. Hosts still enforce
//! each currency's conservation, authority, supply and protocol burn rules.
use super::{
    asset_program, coin_program,
    script::{
        call::{ProgramCall, SystemProgramId},
        opcode::ProgramError,
    },
};
use asset_program::{opcode::AssetOpcode, type_::AssetCall};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MonetaryOpcode {
    Transfer = 1,
    CreateAsset = 2,
    Mint = 3,
    Burn = 4,
}

/// Currency selector for the shared transfer and burn operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Currency {
    Coin = 0,
    Asset = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonetaryCall {
    TransferCoin,
    Asset(AssetCall),
}

pub fn decode(opcode: u8, payload: &[u8]) -> Result<MonetaryCall, ProgramError> {
    let asset_opcode = match opcode {
        1 | 4 => {
            // Historical native coin transfers used an empty payload.
            let (currency, data) = if opcode == 1 && payload.is_empty() {
                (Currency::Coin as u8, &[][..])
            } else {
                let (&currency, data) =
                    payload.split_first().ok_or(ProgramError::InvalidPayload)?;
                (currency, data)
            };
            match currency {
                0 if opcode == 1 => {
                    if !data.is_empty() {
                        return Err(ProgramError::InvalidPayload);
                    }
                    coin_program::decode(coin_program::TRANSFER, data)?;
                    return Ok(MonetaryCall::TransferCoin);
                }
                // There is no protocol policy for voluntary native-coin burn.
                0 => return Err(ProgramError::ExecutionNotImplemented),
                1 => {
                    return asset_program::decode(
                        if opcode == 1 {
                            AssetOpcode::Transfer
                        } else {
                            AssetOpcode::Burn
                        } as u8,
                        data,
                    )
                    .map(MonetaryCall::Asset);
                }
                _ => return Err(ProgramError::InvalidPayload),
            }
        }
        2 => AssetOpcode::Register,
        3 => AssetOpcode::Mint,
        _ => return Err(ProgramError::UnknownOpcode),
    };
    asset_program::decode(asset_opcode as u8, payload).map(MonetaryCall::Asset)
}

pub fn transfer_coin() -> ProgramCall {
    ProgramCall {
        program: SystemProgramId::MONETARY,
        opcode: MonetaryOpcode::Transfer as u8,
        payload: vec![Currency::Coin as u8],
    }
}

pub fn asset_call<T: borsh::BorshSerialize>(
    opcode: AssetOpcode,
    value: &T,
) -> Result<ProgramCall, ProgramError> {
    let (opcode, currency) = match opcode {
        AssetOpcode::Register => (MonetaryOpcode::CreateAsset, None),
        AssetOpcode::Mint => (MonetaryOpcode::Mint, None),
        AssetOpcode::Transfer => (MonetaryOpcode::Transfer, Some(Currency::Asset)),
        AssetOpcode::Burn => (MonetaryOpcode::Burn, Some(Currency::Asset)),
    };
    let mut payload = Vec::new();
    if let Some(currency) = currency {
        payload.push(currency as u8);
    }
    payload.extend(borsh::to_vec(value).map_err(|_| ProgramError::InvalidPayload)?);
    let call = ProgramCall {
        program: SystemProgramId::MONETARY,
        opcode: opcode as u8,
        payload,
    };
    decode(call.opcode, &call.payload)?;
    Ok(call)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::Owner,
        monetary::asset::{AssetContract, AssetOutput, Share, Unit},
        program::{
            ProgramId,
            system::{
                asset_program::type_::{Burn, Mint, Register, Transfer},
                script::execute::{DecodedProgramCall, decode_program},
            },
        },
    };

    #[test]
    fn one_route_decodes_all_operations_and_rejects_ambiguous_or_unsupported_calls() {
        let owner = Owner::Program(ProgramId::from_bytes([7; 32]));
        let asset = AssetContract::from_bytes([8; 32]);
        let share = Share::from_bytes([9; 32]);
        let calls = [
            asset_call(
                AssetOpcode::Register,
                &Register {
                    name: "UNIFIED".into(),
                    max_supply: Unit::from_units(10),
                    initial_mint: Unit::from_units(1),
                    mint_authority: owner,
                    nonce: 0,
                },
            )
            .unwrap(),
            asset_call(
                AssetOpcode::Mint,
                &Mint {
                    asset,
                    nonce: 1,
                    recipient: owner,
                    amount: Unit::from_units(1),
                },
            )
            .unwrap(),
            asset_call(
                AssetOpcode::Transfer,
                &Transfer {
                    asset,
                    inputs: vec![share],
                    outputs: vec![AssetOutput::new(owner, Unit::from_units(1))],
                },
            )
            .unwrap(),
            asset_call(
                AssetOpcode::Burn,
                &Burn {
                    asset,
                    inputs: vec![share],
                    amount: Unit::from_units(1),
                    output: Unit::ZERO,
                },
            )
            .unwrap(),
        ];
        assert_eq!(
            decode_program(&transfer_coin()),
            Ok(DecodedProgramCall::XpqTransfer)
        );
        for (index, call) in calls.iter().enumerate() {
            assert_eq!(call.program, SystemProgramId::MONETARY);
            assert_eq!(call.opcode, [2, 3, 1, 4][index]);
            assert!(matches!(
                decode_program(call),
                Ok(DecodedProgramCall::Asset(_))
            ));
            let mut extra = call.clone();
            extra.payload.push(0);
            assert!(decode_program(&extra).is_err());
        }
        assert_eq!(
            decode(1, &calls[0].payload),
            Err(ProgramError::InvalidPayload)
        );
        assert_eq!(
            decode(4, &[Currency::Coin as u8]),
            Err(ProgramError::ExecutionNotImplemented)
        );
        assert_eq!(decode(1, &[0, 0]), Err(ProgramError::InvalidPayload));
        assert_eq!(decode(4, &[2]), Err(ProgramError::InvalidPayload));
        assert_eq!(decode(255, &[]), Err(ProgramError::UnknownOpcode));
    }
}
