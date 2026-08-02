use crate::block::Block;
use crate::block::BlockHeight;
use crate::consensus::supply::Amount;
use crate::consensus::{
    BASE_BLOCK_REWARD, WBDA_WINDOW, is_wbda_epoch_boundary, next_reward_from_window,
};
use crate::crypto::Address;
use crate::ledger::{BLOCK_REWARD_MATURITY, Ledger, LedgerError};
use crate::state::{Account, CreditSource};

impl Ledger {
    pub(crate) fn apply_coinbase(&mut self, block: &Block) -> Result<(), LedgerError> {
        let coinbase = block
            .body
            .coinbase
            .as_ref()
            .ok_or(LedgerError::InvalidCoinbase)?;
        if coinbase.to != block.miner_address() {
            return Err(LedgerError::InvalidCoinbase);
        }

        let expected_subsidy = self.expected_reward_for_height(block.height())?;
        if coinbase.subsidy != expected_subsidy {
            return Err(LedgerError::InvalidCoinbase);
        }
        self.mint_miner_subsidy(coinbase.to, coinbase.subsidy, block.height())?;
        self.refresh_account_state(&coinbase.to)?;
        Ok(())
    }

    fn mint_miner_subsidy(
        &mut self,
        miner_address: Address,
        subsidy: Amount,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        let maturity_height =
            crate::block::Height(height.0.saturating_add(BLOCK_REWARD_MATURITY as u64));
        self.credit_miner(
            miner_address,
            subsidy,
            maturity_height,
            CreditSource::MiningReward,
        )
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

    fn credit_miner(
        &mut self,
        miner_address: Address,
        amount: Amount,
        maturity_height: BlockHeight,
        source: CreditSource,
    ) -> Result<(), LedgerError> {
        if let Some(miner) = self.accounts.get_mut(&miner_address) {
            miner.credit_at_maturity(amount, maturity_height, source)?;
        } else {
            let mut account = Account::new(miner_address, Amount(0));
            account.credit_at_maturity(amount, maturity_height, source)?;
            self.accounts.insert(miner_address, account);
        }

        Ok(())
    }
}
