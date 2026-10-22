# Fee-Offset Tail Emission (FOTE)

## Status

**Implemented** as a consensus rule in the kernel. FOTE activates at block
height `1,100,001`; blocks below that height continue using the existing
emission rule.

At or above activation, nodes derive the fee offset from the block's operation
fees and validate the declared subsidy against the FOTE formula. Mining
candidate construction uses the same calculation. If fees reach or exceed the
net tail target, the gross subsidy remains at `B` to cover the protocol burn,
but miner emission is zero and no zero-value miner UTXO is created. Transaction
fees are still credited to the miner.

## Motivation

The current emission schedule reaches a fixed tail subsidy of 0.781250 XPQ per
block. The block miner also receives transaction miner fees. As a result, fees
add to the miner's tail-phase reward instead of replacing part of the tail
issuance.

Fee-Offset Tail Emission makes eligible transaction fees replace newly issued
tail rewards. When a block collects fees, the protocol issues less XPQ for that
block, while keeping the miner's reward at the existing net tail reward as long
as fees do not exceed that target. This reduces net monetary issuance as fee
revenue grows.

## Consensus rule

Apply FOTE only after the existing emission schedule reaches its tail. Leave the
initial ramp, peak, and halving schedule unchanged.

Under the current emission parameters, the first tail-emission block is height
`1,100,001`. FOTE activates at that height: blocks below it keep the existing
height-only subsidy rule, and blocks at or above it use the FOTE rule. The
activation height is derived from the emission schedule and must be included in
the consensus specification identity.

Define:

- `T`: the current gross tail subsidy per block.
- `B`: the protocol burn already deducted from each block subsidy
  (`MINER_PROTOCOL_BURN`).
- `R`: the current net tail emission, `T - B`.
- `F`: the sum of valid transaction miner fees in the block that are credited to
  its miner.
- `S`: the gross block subsidy under FOTE.

The proposed subsidy is:

```text
S = B + max(0, R - F)
```

The miner receives the net emission plus transaction fees:

```text
miner reward = (S - B) + F
```

When `F <= R`, the miner reward stays at `R`, and each fee unit reduces newly
issued net XPQ by one unit. When `F >= R`, net tail issuance reaches zero: the
subsidy remains at `B` to cover the existing protocol burn, and the miner
receives the fees. Fees above `R` are not burned or capped by this proposal, so
the miner's total reward can exceed `R` when block fees exceed the target.

### Examples

| Fees in block | Gross subsidy | Net tail issuance | Miner reward |
| --- | --- | --- | --- |
| `0` | `B + R` (the current tail subsidy `T`) | `R` | `R` |
| `0 < F < R` | `B + R - F` | `R - F` | `R` |
| `F >= R` | `B` | `0` | `F` |

## Consensus requirements

FOTE requires every node to derive `F` from the miner-fee fields in the block's
operations. Nodes must reject a block whose declared subsidy does not match the
height, tail phase, and included fees. The calculation uses checked integer
arithmetic in the chain's smallest unit; all encoded operation fees are eligible
and no fee rounding is needed.

The fee total is derived with checked arithmetic from the miner-fee fields in
the block's operations before state execution. Every operation must still pass
normal validation; an invalid operation invalidates the whole block. This makes
the fee total deterministic even though execution creates the emission output
before applying operations.

Because the expected subsidy would depend on block contents as well as height,
this is a consensus change. It requires a coordinated protocol upgrade; changing
the miner alone would not activate FOTE.

## Existing-chain compatibility

FOTE can preserve existing chain data. Keep the genesis hash, block encoding,
and all pre-activation rules unchanged. During replay, validate blocks below
height `1,100,001` with the existing emission rule, then apply FOTE from the
activation height onward. Existing block records and ledger state do not need a
format migration if the storage format is unchanged.

This does not make old node software consensus-compatible with the upgrade. The
new chain-spec identity differs from the old one, so current peer handshakes
reject old and upgraded binaries even before activation. Nodes must be upgraded
as a coordinated network before height `1,100,001`; the genesis hash and stored
historical chain data remain unchanged.

## Scope

FOTE changes tail-phase issuance only. It does not change transaction encoding,
salt sizes, transaction archival burn, state-growth burn, or pruning policy.

## Current implementation references

- `kernel/src/consensus/policy/emission.rs` defines the height schedule, FOTE
  activation, fee-offset calculation, and the separation between gross subsidy,
  protocol burn, and miner emission.
- `kernel/src/consensus/policy/burn.rs` defines `MINER_PROTOCOL_BURN`.
- `kernel/src/ledger/canonical/execution.rs` records the protocol burn and
  creates a miner emission UTXO only when its amount is nonzero.
- `runtime/src/node/mining.rs` calculates the candidate subsidy using the
  candidate block's operation fees.
- `runtime/src/node/rpc.rs` reports the next-height subsidy for an empty block.
- `kernel/src/genesis/mod.rs` includes the FOTE activation and rule identifier
  in the chain-spec identity.
