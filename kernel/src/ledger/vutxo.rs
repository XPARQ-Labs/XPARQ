// Vault UTXO (vUTXO)

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
)]
pub struct VaultUTXO {
    pub inputs: Value,
    pub authority: Address,
}