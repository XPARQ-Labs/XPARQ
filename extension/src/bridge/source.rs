/// External networks understood by bridge extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceNetwork {
    Bitcoin,
    Ethereum,
    Solana,
}
