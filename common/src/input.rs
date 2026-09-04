use borsh::{BorshDeserialize, BorshSerialize};

/// A transaction input whose concrete identifier is supplied by the domain
/// using it.  Keeping the envelope here makes coin and asset inputs use the
/// same canonical representation without introducing crate dependency cycles.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub enum Input<CoinHash, AssetShareHash> {
    Coin(CoinHash),
    Asset(AssetShareHash),
}
