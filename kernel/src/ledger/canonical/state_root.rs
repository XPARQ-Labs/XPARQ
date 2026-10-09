//! Canonical ledger state encoding and cached state roots.

use super::LedgerError;
use crate::ledger::LedgerState;
use crypto::{HashDomain, StateRoot, canonical_length, domain_serialized};

impl LedgerState {
    pub(crate) fn canonical_encoded_len(&self) -> Result<u64, crypto::CodecError> {
        let Self {
            utxos,
            coin,
            programs,
            extensions,
            root_cache: _,
        } = self;
        let lengths = [
            utxos.canonical_encoded_len()?,
            canonical_length(coin)?,
            canonical_length(programs)?,
            extensions.canonical_encoded_len()?,
        ];
        lengths.into_iter().try_fold(0u64, |sum, len| {
            sum.checked_add(len).ok_or(crypto::CodecError::EncodeFailed)
        })
    }

    pub(crate) fn hash_canonical_state(&self) -> Result<StateRoot, LedgerError> {
        Ok(StateRoot(
            domain_serialized(
                HashDomain::ProtocolState,
                self.canonical_encoded_len()?,
                &(&self.utxos, &self.coin, &self.programs, &self.extensions),
            )?
            .into_bytes(),
        ))
    }

    pub(crate) fn application_state_root(&self) -> Result<StateRoot, LedgerError> {
        if let Some(root) = self.cached_state_root() {
            return Ok(root);
        }
        if self.extensions == crate::program::system::script::state::ExtensionState::default()
            && self.utxos.is_empty()
            && self.programs.is_empty()
            && self.coin.total_mined.is_zero()
            && self.coin.total_burned.is_zero()
        {
            return Ok(StateRoot::ZERO);
        }

        let root = self.hash_canonical_state()?;
        self.cache_state_root(root);
        Ok(root)
    }
}
