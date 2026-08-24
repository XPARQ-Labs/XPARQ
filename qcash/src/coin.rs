use borsh::{BorshDeserialize, BorshSerialize};
use xparq_coin::{Amount, Coin, CoinId};

/// Public descriptor of one QCash bearer coin; no signing seed is included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct QCash(pub Coin);

impl QCash {
    pub const fn new(id: CoinId, amount: Amount) -> Self {
        Self(Coin::new(id, amount))
    }

    pub const fn id(self) -> CoinId {
        self.0.id
    }

    pub const fn amount(self) -> Amount {
        self.0.amount
    }

    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }
}
