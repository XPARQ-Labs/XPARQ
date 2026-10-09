//! Ordered asset registration, minting, transfer, and merged rollback journals.

use super::MAX_TRANSFER_INPUTS;
use crate::ledger::utxo::AssetJournal;
use crate::ledger::utxo::ExecutionContext;
use crate::{
    common::Owner,
    ledger::{LedgerState, StateError},
    monetary::asset::{AssetOutput, Metadata, Unit},
    program::{
        AuthorizationCommitment, ProgramId,
        application::ApplicationExecutor,
        system::asset_program::type_::{AssetCall, Mint, Register, Transfer},
        vm::{ExecutionResult, MintAssetTarget},
    },
};

/// Mutates caller-owned staging state; discard that state on any error.
pub(super) fn settle(
    state: &mut LedgerState,
    id: ProgramId,
    result: &ExecutionResult,
    commitment: AuthorizationCommitment,
    applications: &dyn ApplicationExecutor,
    origin: [u8; crypto::HASH_SIZE],
) -> Result<Option<AssetJournal>, StateError> {
    let actor = Owner::Program(id);
    let mut asset_journal: Option<AssetJournal> = None;
    let mut registered_asset = None;
    if let Some(request) = &result.asset_register {
        let metadata = Metadata::new(request.name.clone(), request.max_supply, actor, actor)
            .map_err(|_| StateError::InvalidTransition)?;
        let asset = crate::monetary::asset::AssetContract::derive(&metadata, request.nonce)
            .map_err(|_| StateError::InvalidTransition)?;
        registered_asset = Some(asset);
        match state.extensions.assets.records().get(&asset) {
            Some(record) if request.skip_if_exists && record.metadata == metadata => {}
            Some(_) => return Err(StateError::InvalidTransition),
            None => {
                let journal = crate::program::asset_host::execute_asset(
                    applications,
                    &mut state.extensions.assets,
                    &AssetCall::Register(Register {
                        name: request.name.clone(),
                        max_supply: request.max_supply,
                        initial_mint: request.initial_mint,
                        mint_authority: actor,
                        nonce: request.nonce,
                    }),
                    ExecutionContext {
                        actor,
                        commitment: issuance_origin(id, commitment, 0x08)?,
                    },
                )
                .map_err(|_| StateError::InvalidTransition)?;
                asset_journal = Some(journal);
            }
        }
    }
    if let Some(request) = result.asset_mint {
        let asset = match request.asset {
            MintAssetTarget::Existing(asset) => asset,
            MintAssetTarget::Registered => registered_asset.ok_or(StateError::InvalidTransition)?,
        };
        let record = state
            .extensions
            .assets
            .records()
            .get(&asset)
            .ok_or(StateError::InvalidTransition)?;
        let nonce = record
            .mint_nonce
            .checked_add(1)
            .ok_or(StateError::InvalidTransition)?;
        let journal = crate::program::asset_host::execute_asset(
            applications,
            &mut state.extensions.assets,
            &AssetCall::Mint(Mint {
                asset,
                recipient: request.recipient,
                amount: request.amount,
                nonce,
            }),
            ExecutionContext {
                actor,
                commitment: issuance_origin(id, commitment, 0x09)?,
            },
        )
        .map_err(|_| StateError::InvalidTransition)?;
        asset_journal = Some(match asset_journal {
            Some(previous) => previous.merge(journal),
            None => journal,
        });
    }
    let transfer_journal = if let Some((asset, request)) = result.asset_transfer {
        let mut inputs = Vec::new();
        let mut total = Unit::ZERO;
        for (share, value) in state
            .extensions
            .assets
            .shares_by_owner_asset(actor, asset)
            .take(MAX_TRANSFER_INPUTS)
        {
            inputs.push(share);
            total = total
                .checked_add(value.amount)
                .ok_or(StateError::AmountOverflow)?;
            if total >= Unit::from_units(request.amount as u128) {
                break;
            }
        }
        let amount = Unit::from_units(request.amount as u128);
        let change = total
            .checked_sub(amount)
            .ok_or(StateError::InvalidTransition)?;
        let mut outputs = vec![AssetOutput::new(request.recipient, amount)];
        if !change.is_zero() {
            outputs.push(AssetOutput::new(actor, change));
        }
        Some(
            crate::program::asset_host::execute_asset(
                applications,
                &mut state.extensions.assets,
                &AssetCall::Transfer(Transfer {
                    asset,
                    inputs,
                    outputs,
                }),
                ExecutionContext {
                    actor,
                    commitment: origin,
                },
            )
            .map_err(|_| StateError::InvalidTransition)?,
        )
    } else {
        None
    };
    if let Some(journal) = transfer_journal {
        asset_journal = Some(match asset_journal {
            Some(previous) => previous.merge(journal),
            None => journal,
        });
    }
    Ok(asset_journal)
}

fn issuance_origin(
    id: ProgramId,
    commitment: AuthorizationCommitment,
    opcode: u8,
) -> Result<[u8; crypto::HASH_SIZE], StateError> {
    let bytes = crypto::canonical_bytes(&(b"xparq:vm-asset:v3", id, commitment, opcode))
        .map_err(|_| StateError::InvalidTransition)?;
    Ok(crypto::domain(crypto::HashDomain::AssetIntent, &bytes).into_bytes())
}
