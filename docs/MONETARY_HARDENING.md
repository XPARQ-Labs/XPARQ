# Coin and asset invariant hardening

This change restricts asset mutation to the kernel and strengthens validation
of monetary state. It does not change monetary rates, fees, supply limits, or
the canonical Borsh field layout.

## Mutation boundaries

AssetState accounting maps, ExecutionContext, and the raw apply/rollback
operations are now crate-private. Runtime and application callers read state
through records() and shares(), which return immutable references.
Applications request operations through the bound AssetHost; they cannot supply
their own execution context to the raw asset mutation API.

This is a source API change for callers that previously modified maps or
invoked AssetState::apply directly. Use the authorized LedgerState transaction
path for execution and program_created_state_weight_with_applications for
read-only previews. The network integration test now uses that preview API.

Owned state can still be deserialized for snapshots and synthetic fixtures.
Deserialization is not authorization: canonical admission checks signatures,
ownership, supply, and state roots. The change does not make arbitrary serialized
state trustworthy.

## State validation

- Coin insertion rejects zero-value UTXOs before changing the map or cached total.
- The fast coin supply check also verifies that an empty UTXO map corresponds
  to a zero cached total.
- Recovery's deep coin audit independently sums UTXOs, rejects zero amounts and
  overflow, and compares the sum with both the cache and monetary counters.
- Asset supply validation rejects zero-value shares and invalid metadata in
  addition to unknown assets, aggregate overflow, supply mismatch, and issuance
  above the lifetime mint cap.
- Asset minting checks the existing lifetime issuance cap before inserting a
  share. Burning cannot create room for issuance beyond that cap. This moves an
  existing ledger rule into the monetary primitive; it does not introduce a new
  cap.

Per-operation coin checks continue to use the private cached total. Recomputing
every coin UTXO on each transaction would add work proportional to the entire
UTXO set. Independent cache checks are exercised in tests and during recovery.

## Regression coverage

- Generated coin insertion/consumption sequences: 16 seeds × 256 steps, compared
  with an independent map and independently computed balances.
- Generated asset mint/transfer/burn sequences: 16 seeds × 64 steps, checked
  against independent owner balances and issuance/burn counters. Every journal
  is serialized, decoded, and rolled back, comparing the full prior asset state
  at every step.
- Failed coin insertion, collision, overflow, and missing input preserve both
  the map and cache.
- An asset output collision after input consumption preserves the original state.
- Burn followed by mint cannot bypass the lifetime issuance cap.
- Mint amount overflow at u128::MAX and nonce overflow at u64::MAX are rejected
  without mutation.
- Corrupted serialized fixtures exercise mismatched totals, forged coin caches,
  zero coin/share amounts, invalid asset metadata, unknown assets, overflow,
  and impossible burn counters.
- Signed transaction tests cover changed recipients, duplicate/missing inputs,
  zero outputs, excessive fees, altered calls/signatures, cross-chain replay,
  valid attacker signatures on another owner's input, and replay after commit.
- An application attempting two asset operations through one bound host fails
  without changing the complete ledger state.
- Compile-fail documentation tests enforce immutable asset accessors and prevent
  external access to execution contexts and raw rollback.

These are deterministic generated tests, not exhaustive fuzzing or a proof of
security. The three pre-existing chain identity fixture failures remain a
separate release gate. The RPC availability and synchronization findings in the
[audit](AUDIT-2026-10-04.md) are also separate from this monetary hardening.

## Verification after the change

Workspace compilation, formatting, and Clippy passed; Clippy still reports
existing warnings. The workspace test run passed 201 tests and failed only the
three pre-existing chain identity fixtures. The additional mint amount/nonce
overflow regression passed separately after it was added.

All seven network E2E tests passed (568.54 seconds), including the three-node
Program lifecycle with reorganization and restart. All eight snapshot/storage
tests passed. Both normally ignored wallet lifecycle tests were explicitly run
and passed (201.68 seconds). Four compile-fail API boundary tests also passed.

The snapshot encoding and computed chain-spec identity remain unchanged.
See the [verification output](audit/monetary-verification.txt) for test results.
