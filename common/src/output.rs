use borsh::{BorshDeserialize, BorshSerialize};

/// A transaction output whose payload is owned by the coin or asset domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Output<CoinOutput, AssetOutput> {
    Coin(CoinOutput),
    Asset(AssetOutput),
}
