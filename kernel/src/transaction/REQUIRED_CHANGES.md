# Required integration changes

1. Delete the old `transaction/intent.rs`.
2. Add `transaction/asset.rs`.
3. Replace the remaining transaction files with the files in this directory.
4. `crypto::HashDomain` must contain at least:
   - `SpendIntent`
   - `AssetIntent`
   - `Transaction`
   - `TransactionCommit`
5. `crypto` must re-export `canonical_bytes`, `domain`, `HASH_SIZE`, and `ADDRESS_SIZE`.
6. The current asset API is assumed to use:
   - `Asset`
   - `Share`
   - `AssetShare { parent, amount }`
   - `asset::Output { recipient, amount }`
   - `AssetMetadata::new(name, symbol, decimals, max_supply, creator, mint_authority)`
7. `coin::Output` is assumed to be `{ recipient: Address, amount: Zeno }`.
8. Consensus must treat `Transaction::Commit` and `Transaction::Reveal` separately:
   - Commit inserts `TransactionCommitment` into pending commitment state.
   - Reveal derives its commitment, requires a matching pending commit, validates signatures/ownership, consumes the pending commitment, then applies the authorized transaction.
9. There is intentionally no commit nonce. This proves binding but does not provide strong hiding for easily guessed transactions.
10. Because canonical UTXOs no longer store owner/address, consensus must verify the ownership reveal/preimage for each XPQ/Share input before applying it.
