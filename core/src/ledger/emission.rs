use crate::block::Block;
use crate::block::BlockHeight;
use crate::consensus::supply::Amount;
use crate::consensus::{
    BASE_BLOCK_REWARD, WBDA_WINDOW, is_wbda_epoch_boundary, next_reward_from_window,
};
use crate::crypto::{Address, HashDomain, domain_hash};
use crate::ledger::{BLOCK_REWARD_MATURITY, Ledger, LedgerError};
use crate::state::XpqCoinSource;

impl Ledger {
    pub(crate) fn apply_emission(&mut self, block: &Block) -> Result<(), LedgerError> {
        let emission = block
            .body
            .emission
            .as_ref()
            .ok_or(LedgerError::InvalidEmission)?;
        let expected_subsidy = self.expected_reward_for_height(block.height())?;
        if emission.subsidy != expected_subsidy {
            return Err(LedgerError::InvalidEmission);
        }
        self.mint_miner_subsidy(block, emission.to, emission.subsidy, block.height())?;
        self.accounts
            .entry(emission.to)
            .or_insert_with(|| crate::state::Account::new(emission.to));
        self.refresh_account_state(&emission.to)?;
        Ok(())
    }

    fn mint_miner_subsidy(
        &mut self,
        block: &Block,
        miner_address: Address,
        subsidy: Amount,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        let maturity_height =
            crate::block::Height(height.0.saturating_add(BLOCK_REWARD_MATURITY as u64));
        let origin = domain_hash(
            HashDomain::XpqCoin,
            &crate::codec::canonical_bytes(&(
                b"emission",
                block.previous_hash(),
                block.height(),
                miner_address,
                subsidy,
            ))?,
        );
        self.xpq_utxos.issue(
            origin,
            miner_address,
            subsidy,
            maturity_height,
            XpqCoinSource::MiningReward,
        )?;
        Ok(())
    }

    pub fn mintable_subsidy(&self, height: BlockHeight) -> Result<Amount, LedgerError> {
        self.expected_reward_for_height(height)
    }

    pub(crate) fn expected_reward_for_height(
        &self,
        height: BlockHeight,
    ) -> Result<Amount, LedgerError> {
        if height.0 <= 1 {
            return Ok(Amount(BASE_BLOCK_REWARD));
        }
        let mut reward = Amount(BASE_BLOCK_REWARD);
        let mut boundary = WBDA_WINDOW as u64 + 1;
        while boundary <= height.0 {
            debug_assert!(is_wbda_epoch_boundary(boundary));
            let start = boundary - WBDA_WINDOW as u64;
            let weights = (start..boundary)
                .map(|height| {
                    self.chain
                        .header(&crate::block::Height(height))
                        .ok_or(LedgerError::InvalidParent)?
                        .block_weight
                        .try_into()
                        .map_err(|_| LedgerError::InvalidParent)
                })
                .collect::<Result<Vec<_>, _>>()?;
            reward = next_reward_from_window(reward, &weights).ok_or(LedgerError::InvalidParent)?;
            boundary = boundary.saturating_add(WBDA_WINDOW as u64);
        }
        Ok(reward)
    }
}
