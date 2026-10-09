use borsh::{BorshDeserialize, BorshSerialize};

use crate::program::system::asset_program::state::AssetState;

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExtensionState {
    pub assets: AssetState,
}

impl ExtensionState {
    pub(crate) fn canonical_encoded_len(&self) -> Result<u64, crypto::CodecError> {
        let Self { assets } = self;
        assets.canonical_encoded_len()
    }

    pub(crate) fn same_canonical_view(&self, other: &Self) -> bool {
        // Exhaustive patterns force any future extension fields to be considered.
        let Self { assets } = self;
        let Self {
            assets: other_assets,
        } = other;
        assets.same_canonical_view(other_assets)
    }
}
