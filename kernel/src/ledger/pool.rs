use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Address, HASH_SIZE, Height};

use crate::native::{
    amm,
    pool::{
        Liquidity, Pair, Pool, PoolAmount, PoolError, PoolHash, PoolShare, PoolShareHash,
        canonical_pair,
    },
};

/// Standalone canonical pool state. It is deliberately not part of `LedgerState` yet.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolState {
    pub(crate) pools: BTreeMap<PoolHash, Pool>,
    pub(crate) pool_shares: BTreeMap<PoolShareHash, PoolShare>,
}

impl PoolState {
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty() && self.pool_shares.is_empty()
    }
}

impl PoolState {
    pub fn pool(&self, id: PoolHash) -> Option<&Pool> {
        self.pools.get(&id)
    }
    pub fn pool_share(&self, id: PoolShareHash) -> Option<&PoolShare> {
        self.pool_shares.get(&id)
    }
    pub fn pools(&self) -> impl Iterator<Item = (PoolHash, &Pool)> + '_ {
        self.pools.iter().map(|(&id, pool)| (id, pool))
    }
    pub fn pool_shares(&self) -> impl Iterator<Item = (PoolShareHash, &PoolShare)> + '_ {
        self.pool_shares.iter().map(|(&id, share)| (id, share))
    }

    pub fn create_pool(
        &mut self,
        asset_x: Pair,
        asset_y: Pair,
        amount_x: PoolAmount,
        amount_y: PoolAmount,
        fee_units: u32,
        owner: Address,
        commitment: [u8; HASH_SIZE],
        height: Height,
    ) -> Result<(PoolHash, PoolShareHash), PoolError> {
        let input_asset_x = asset_x;
        let (asset_x, asset_y) = canonical_pair(asset_x, asset_y)?;
        let (reserve_x, reserve_y) = if input_asset_x == asset_x {
            (amount_x, amount_y)
        } else {
            (amount_y, amount_x)
        };
        let liquidity = amm::initial_liquidity(reserve_x, reserve_y)?;
        let pool = Pool::new(
            asset_x, asset_y, reserve_x, reserve_y, liquidity, fee_units, height,
        )?;
        let pool_id = pool.id()?;
        if self.pools.contains_key(&pool_id) {
            return Err(PoolError::Collision);
        }
        let share_id = PoolShareHash::derive(pool_id, commitment, 0);
        if self.pool_shares.contains_key(&share_id) {
            return Err(PoolError::Collision);
        }
        let share = PoolShare::new(pool_id, owner, liquidity)?;
        self.pools.insert(pool_id, pool);
        self.pool_shares.insert(share_id, share);
        Ok((pool_id, share_id))
    }

    pub fn add_liquidity(
        &mut self,
        pool_id: PoolHash,
        amount_x: PoolAmount,
        amount_y: PoolAmount,
        minimum_liquidity: Liquidity,
        owner: Address,
        commitment: [u8; HASH_SIZE],
        output_index: u32,
        height: Height,
    ) -> Result<(PoolShareHash, Liquidity), PoolError> {
        let pool = self
            .pools
            .get(&pool_id)
            .copied()
            .ok_or(PoolError::UnknownPool)?;
        pool.ensure_transition_height(height)?;
        let minted = amm::liquidity_minted(
            amount_x,
            amount_y,
            pool.reserve_x,
            pool.reserve_y,
            pool.total_liquidity,
        )?;
        if minted < minimum_liquidity {
            return Err(PoolError::InsufficientOutput);
        }
        let updated = Pool::new(
            pool.asset_x,
            pool.asset_y,
            pool.reserve_x
                .checked_add(amount_x)
                .ok_or(PoolError::ArithmeticOverflow)?,
            pool.reserve_y
                .checked_add(amount_y)
                .ok_or(PoolError::ArithmeticOverflow)?,
            pool.total_liquidity
                .checked_add(minted)
                .ok_or(PoolError::ArithmeticOverflow)?,
            pool.fee_units,
            height,
        )?;
        let share_id = PoolShareHash::derive(pool_id, commitment, output_index);
        if self.pool_shares.contains_key(&share_id) {
            return Err(PoolError::Collision);
        }
        let share = PoolShare::new(pool_id, owner, minted)?;
        self.pools.insert(pool_id, updated);
        self.pool_shares.insert(share_id, share);
        Ok((share_id, minted))
    }

    pub fn remove_liquidity(
        &mut self,
        share_id: PoolShareHash,
        signer: Address,
        minimum_x: PoolAmount,
        minimum_y: PoolAmount,
        height: Height,
    ) -> Result<(PoolAmount, PoolAmount), PoolError> {
        let share = self
            .pool_shares
            .get(&share_id)
            .copied()
            .ok_or(PoolError::UnknownShare)?;
        if share.owner != signer {
            return Err(PoolError::Unauthorized);
        }
        let pool = self
            .pools
            .get(&share.pool)
            .copied()
            .ok_or(PoolError::UnknownPool)?;
        pool.ensure_transition_height(height)?;
        let (amount_x, amount_y) = amm::liquidity_removed(
            share.amount,
            pool.reserve_x,
            pool.reserve_y,
            pool.total_liquidity,
        )?;
        if amount_x < minimum_x || amount_y < minimum_y {
            return Err(PoolError::InsufficientOutput);
        }
        let reserve_x = pool
            .reserve_x
            .checked_sub(amount_x)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let reserve_y = pool
            .reserve_y
            .checked_sub(amount_y)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let total = pool
            .total_liquidity
            .checked_sub(share.amount)
            .ok_or(PoolError::InsufficientLiquidity)?;
        if total.is_zero() {
            self.pools.remove(&share.pool);
        } else {
            self.pools.insert(
                share.pool,
                Pool::new(
                    pool.asset_x,
                    pool.asset_y,
                    reserve_x,
                    reserve_y,
                    total,
                    pool.fee_units,
                    height,
                )?,
            );
        }
        self.pool_shares.remove(&share_id);
        Ok((amount_x, amount_y))
    }

    pub fn swap(
        &mut self,
        pool_id: PoolHash,
        input_asset: Pair,
        amount_in: PoolAmount,
        minimum_out: PoolAmount,
        height: Height,
    ) -> Result<PoolAmount, PoolError> {
        let pool = self
            .pools
            .get(&pool_id)
            .copied()
            .ok_or(PoolError::UnknownPool)?;
        pool.ensure_transition_height(height)?;
        let (reserve_in, reserve_out) = if input_asset == pool.asset_x {
            (pool.reserve_x, pool.reserve_y)
        } else if input_asset == pool.asset_y {
            (pool.reserve_y, pool.reserve_x)
        } else {
            return Err(PoolError::InvalidAmount);
        };
        let output = amm::amount_out(amount_in, reserve_in, reserve_out, pool.fee_units)?;
        if output < minimum_out {
            return Err(PoolError::InsufficientOutput);
        }
        let new_in = reserve_in
            .checked_add(amount_in)
            .ok_or(PoolError::ArithmeticOverflow)?;
        let new_out = reserve_out
            .checked_sub(output)
            .ok_or(PoolError::InsufficientLiquidity)?;
        let updated = if input_asset == pool.asset_x {
            Pool::new(
                pool.asset_x,
                pool.asset_y,
                new_in,
                new_out,
                pool.total_liquidity,
                pool.fee_units,
                height,
            )?
        } else {
            Pool::new(
                pool.asset_x,
                pool.asset_y,
                new_out,
                new_in,
                pool.total_liquidity,
                pool.fee_units,
                height,
            )?
        };
        self.pools.insert(pool_id, updated);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn amount(value: u128) -> PoolAmount {
        PoolAmount::from_raw(value)
    }
    fn assets() -> (Pair, Pair) {
        (
            Pair::Asset(crate::native::asset::Asset::from_bytes([1; HASH_SIZE])),
            Pair::Asset(crate::native::asset::Asset::from_bytes([2; HASH_SIZE])),
        )
    }

    #[test]
    fn complete_pool_lifecycle() {
        let (a, b) = assets();
        let owner = Address::from_bytes([7; 20]);
        let mut state = PoolState::default();
        let (pool_id, initial_share) = state
            .create_pool(
                a,
                b,
                amount(10_000),
                amount(20_000),
                300,
                owner,
                [1; HASH_SIZE],
                Height(10),
            )
            .unwrap();
        assert_eq!(
            state.pool(pool_id).unwrap().total_liquidity,
            Liquidity::from_raw(14_142)
        );

        let (_, minted) = state
            .add_liquidity(
                pool_id,
                amount(1_000),
                amount(2_000),
                Liquidity::from_raw(1_400),
                owner,
                [2; HASH_SIZE],
                0,
                Height(11),
            )
            .unwrap();
        assert_eq!(minted, Liquidity::from_raw(1_414));
        assert_eq!(
            state.swap(pool_id, a, amount(1_000), amount(1_500), Height(12)),
            Ok(amount(1_828))
        );

        let before = state.clone();
        assert_eq!(
            state.remove_liquidity(
                initial_share,
                Address::ZERO,
                PoolAmount::ZERO,
                PoolAmount::ZERO,
                Height(12),
            ),
            Err(PoolError::Unauthorized)
        );
        assert_eq!(state, before);
        let removed = state
            .remove_liquidity(
                initial_share,
                owner,
                PoolAmount::ZERO,
                PoolAmount::ZERO,
                Height(12),
            )
            .unwrap();
        assert!(removed.0.as_raw() > 0 && removed.1.as_raw() > 0);
    }

    #[test]
    fn slippage_failure_does_not_mutate_state() {
        let (a, b) = assets();
        let mut state = PoolState::default();
        let (pool_id, _) = state
            .create_pool(
                a,
                b,
                amount(10_000),
                amount(20_000),
                300,
                Address::ZERO,
                [3; HASH_SIZE],
                Height(20),
            )
            .unwrap();
        let before = state.clone();
        assert_eq!(
            state.swap(pool_id, a, amount(100), amount(1_000), Height(21)),
            Err(PoolError::InsufficientOutput)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn coin_asset_pool_swaps_in_both_directions() {
        let coin = Pair::Coin;
        let asset = Pair::Asset(crate::native::asset::Asset::from_bytes([9; HASH_SIZE]));
        let mut state = PoolState::default();
        let (pool_id, _) = state
            .create_pool(
                coin,
                asset,
                amount(10_000),
                amount(20_000),
                300,
                Address::ZERO,
                [8; HASH_SIZE],
                Height(30),
            )
            .unwrap();
        assert_eq!(
            state.swap(pool_id, coin, amount(1_000), amount(1_000), Height(31)),
            Ok(amount(1_813))
        );
        assert!(
            state
                .swap(pool_id, asset, amount(1_000), amount(1), Height(31))
                .is_ok()
        );
        assert_eq!(state.pool(pool_id).unwrap().last_updated_height, Height(31));
    }

    #[test]
    fn create_preserves_amounts_when_pair_is_canonically_reordered() {
        let coin = Pair::Coin;
        let asset = Pair::Asset(crate::native::asset::Asset::from_bytes([6; HASH_SIZE]));
        let mut state = PoolState::default();
        let (pool_id, _) = state
            .create_pool(
                asset,
                coin,
                amount(20_000),
                amount(10_000),
                300,
                Address::ZERO,
                [6; HASH_SIZE],
                Height(35),
            )
            .unwrap();
        let pool = state.pool(pool_id).unwrap();
        assert_eq!((pool.asset_x, pool.reserve_x), (coin, amount(10_000)));
        assert_eq!((pool.asset_y, pool.reserve_y), (asset, amount(20_000)));
    }

    #[test]
    fn stale_height_cannot_change_price() {
        let coin = Pair::Coin;
        let asset = Pair::Asset(crate::native::asset::Asset::from_bytes([5; HASH_SIZE]));
        let mut state = PoolState::default();
        let (pool_id, _) = state
            .create_pool(
                coin,
                asset,
                amount(10_000),
                amount(20_000),
                300,
                Address::ZERO,
                [9; HASH_SIZE],
                Height(40),
            )
            .unwrap();
        state
            .swap(pool_id, coin, amount(1_000), amount(1), Height(41))
            .unwrap();
        let before = state.clone();
        assert_eq!(
            state.swap(pool_id, coin, amount(100), amount(1), Height(40)),
            Err(PoolError::StaleHeight)
        );
        assert_eq!(state, before);
    }
}
