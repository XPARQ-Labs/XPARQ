# XPARQ Security Hardening Roadmap

This records implementation and remaining verification, not an independent
security audit. Consensus changes require an explicit reset or migration plan.
See [architecture](ARCHITECTURE.md) and [ProgramCall](PROGRAM_CALL.md).

## Existing controls

Kernel resolves coin inputs from live UTXOs and checks ownership, duplicates,
conservation and protocol burn. Restricted hosts bind extension execution to
signed effects. Checked kernel monetary primitives enforce asset authorization,
mint nonce, supply and unique share IDs. Block execution, rollback and reorg use
staged state. State-root and supply checks run before canonical changes commit.
Raw asset accounting maps, execution contexts, apply and rollback are restricted
to the kernel crate; public accessors expose immutable state. Zero-value monetary
objects and invalid asset metadata are rejected, and mint primitives enforce the
existing lifetime issuance cap. See [monetary hardening](MONETARY_HARDENING.md)
for mutation boundaries and regression coverage.
Authorization binds signed data to the chain; deployed bytecode is validated
before registry insertion. These controls must remain covered when paths change.

## Phase status

| Phase | Status | Acceptance gate |
| --- | --- | --- |
| 1. Bind transitions to expected state | Implemented | Tampered prestate/journal or wrong parent root must fail without canonical mutation. |
| 2. Failure atomicity | Implemented; focused coverage exists | Failed payment, application effect, block or rollback must leave complete canonical state unchanged. Continue reviewing persistence/reorg failure boundaries. |
| 3. Bound consensus/decoding work | Implemented limits; ongoing resource review | Oversized prefixes/payloads must fail before unbounded allocation or expensive validation. Measure RPC, P2P and replay paths rather than assuming byte caps bound CPU. |
| 4. Deterministic vectors | Current fixtures reconciled and tests passed | Preserve chain-spec 9 vectors and state bytes/roots/accounting through replay and rollback when rules change. |
| 5. Audit protections | Pending comprehensive audit | Record findings and focused regressions for arithmetic, canonical encoding, authorization, startup and reorg behavior. |

## Current consensus limits

These limits have different scopes; the ProgramCall cap is not a deploy cap.

| Scope | Limit | Source |
| --- | --- | --- |
| Serialized block | 2 MiB | [block.rs](../kernel/src/blockchain/block.rs) |
| Operations per block | 4,096 | [block.rs](../kernel/src/blockchain/block.rs) |
| Serialized operation envelope | 2 MiB, also constrained by enclosing block | [block.rs](../kernel/src/blockchain/block.rs) |
| Authorized Program invocation | 256 KiB | [program/mod.rs](../kernel/src/program/mod.rs) |
| Coin input list / output list | 4,096 each per invocation | [coin_transition.rs](../kernel/src/program/coin_transition.rs) |
| Call payload | 64 KiB per call | [call.rs](../kernel/src/program/system/script/call.rs) |
| Asset transfer/burn inputs | 256 shares per call | [opcode.rs](../kernel/src/program/system/asset_program/opcode.rs) |
| Asset transfer outputs | 256 per call | [opcode.rs](../kernel/src/program/system/asset_program/opcode.rs) |
| Deployed code | 1 MiB per deploy | [deploy.rs](../kernel/src/program/deploy.rs) |
| VM stack / memory declaration / fuel | 256 items / 16 pages / 65,536 fuel per call | [vm.rs](../kernel/src/program/vm.rs) |

Bounded decoding and direct in-memory validation both matter. Relay policy may
be stricter than consensus. The limits above do not substitute for resource
measurements or a review of validation order.

## Determinism and accounting gates

Keep permanent vectors for authorization, canonical operation/block bytes,
coin and asset supply, program state, roots, replay and rollback. Three existing
chain-spec fixture assertions are reconciled for version 9 and passed on
8 October 2026, including execution, replay and rollback. Keep this gate passing
for every intentional consensus change.

Check block-level accounting alongside individual transitions:

```text
live_coin_supply_after
  = live_coin_supply_before + validated_subsidy - all_protocol_burns
```

Review checked arithmetic, rejection of trailing/noncanonical bytes, cross-chain
replay resistance, all coin creation paths, snapshot/journal consistency and
staged database/reorg boundaries. Preserve zero-value rejection; any economic
minimum or finality rule needs its own protocol decision.

## Delivery gates

Run format, compilation, Clippy, focused regressions and the full workspace
suite. Complete fresh-storage replay, snapshot/restart and reorganization checks,
including the three-node Program lifecycle and explicitly enabled wallet CLI
integration tests. The three-node lifecycle and both wallet CLI lifecycle tests passed on
3 October 2026. On 8 October 2026, the full default workspace suite and
`litep2p-devnet` all-target check passed after the salted-account/share32 reset;
chain-spec fixtures also passed. The ignored wallet CLI lifecycle tests were not
rerun in that default suite. Commands and current limitations are listed in
[ProgramCall verification](PROGRAM_CALL.md#verification-status-and-remaining-gates).
