mod error;
mod graph;
mod ordering;
mod reorg;
mod work;

pub use error::{ForkChoiceError, ReorgError};
pub use graph::{BlockNode, ForkChoice};
pub use ordering::compare_chain_tips;
pub use reorg::{ReorgPlan, common_ancestor, plan_reorg};
pub use work::{Work, block_work};

#[cfg(test)]
mod tests;
