use crate::block::Block;
use crate::block::BlockHeight;
use crate::consensus::block_reward;
use crate::consensus::supply::Amount;
use crate::crypto::Address;
use crate::ledger::{BLOCK_REWARD_MATURITY, CONFIRMATION_DEPTH, Ledger, LedgerError};
use crate::state::{Account, CreditSource};

impl Ledger {
    pub(crate) fn apply_coinbase(&mut self, block: &Block) -> Result<(), LedgerError> {
        let coinbase = block
            .coinbase
            .as_ref()
            .ok_or(LedgerError::InvalidCoinbase)?;
        let expected_fees = block.checked_total_fees().map_err(LedgerError::from)?;
        if coinbase.to != block.miner_address() || coinbase.fees != expected_fees {
            return Err(LedgerError::InvalidCoinbase);
        }

        self.credit_miner_fees(coinbase.to, coinbase.fees, block.height())?;
        let expected_subsidy = block_reward(block.height());
        if coinbase.subsidy != expected_subsidy {
            return Err(LedgerError::InvalidCoinbase);
        }
        self.mint_miner_subsidy(coinbase.to, coinbase.subsidy, block.height())?;
        self.refresh_account_state(&coinbase.to)?;
        Ok(())
    }

    fn credit_miner_fees(
        &mut self,
        miner_address: Address,
        fees: Amount,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        let maturity_height =
            crate::block::Height(height.0.saturating_add(CONFIRMATION_DEPTH as u64));
        self.credit_miner(miner_address, fees, maturity_height, CreditSource::Fee)
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

    pub fn mintable_subsidy(&self, height: BlockHeight) -> Amount {
        block_reward(height)
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
