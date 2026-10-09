//! Monetary proposal types and bounded asset registration decoding.

use super::CodeError;
use crate::{
    common::Owner,
    monetary::asset::{ASSET_NAME_MAX_LEN, AssetContract, Unit, validate_asset_name},
};
use borsh::{BorshDeserialize, BorshSerialize};

/// Version 2 permits one coin and one asset transfer per execution. Recipients
/// and positive amounts are embedded in deployed code, never chosen by a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransferRequest {
    pub recipient: Owner,
    pub amount: u64,
}

/// Version 3 registration binds creator and mint authority to the executing program.
/// Initial supply goes to that program. Repeated registration may explicitly be
/// skipped; it never issues the initial supply again.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RegisterAssetRequest {
    pub name: String,
    pub max_supply: Unit,
    pub initial_mint: Unit,
    pub nonce: u64,
    pub skip_if_exists: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum MintAssetTarget {
    Existing(AssetContract),
    /// The asset resolved by the preceding registration instruction. Avoids
    /// embedding an asset ID that depends on this program's own code hash.
    Registered,
}

/// Nonce is selected by the kernel from canonical asset state, never from caller data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MintAssetRequest {
    pub asset: MintAssetTarget,
    pub recipient: Owner,
    pub amount: Unit,
}

pub(crate) fn decode_register_request(
    bytes: &mut &[u8],
) -> Result<RegisterAssetRequest, CodeError> {
    // Bound the string before Borsh allocates it, including when called outside deployment.
    let length = bytes.get(..4).ok_or(CodeError::InvalidInstruction)?;
    let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
    if length == 0 || length > ASSET_NAME_MAX_LEN {
        return Err(CodeError::InvalidInstruction);
    }
    let request =
        RegisterAssetRequest::deserialize(bytes).map_err(|_| CodeError::InvalidInstruction)?;
    validate_asset_name(&request.name).map_err(|_| CodeError::InvalidInstruction)?;
    if request.max_supply.is_zero()
        || request.initial_mint.is_zero()
        || request.initial_mint > request.max_supply
    {
        return Err(CodeError::InvalidInstruction);
    }
    Ok(request)
}
