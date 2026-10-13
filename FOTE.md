# Fee-Offset Tail Emission (FOTE)

## Status

FOTE is a consensus-policy proposal. It is not active in the current protocol and
does not change block validation or miner rewards today.

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

## Proposed rule

Apply FOTE only after the existing emission schedule reaches its tail. Leave the
initial ramp, peak, and halving schedule unchanged.

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

FOTE requires every node to derive `F` from the validated transactions in the
block. Nodes must reject a block whose declared subsidy does not match the
height, tail phase, and included fees. The calculation must use checked integer
arithmetic in the chain's smallest unit and must define exactly which fees are
eligible and how fee rounding works.

Because the expected subsidy would depend on block contents as well as height,
this is a consensus change. It requires a coordinated protocol upgrade; changing
the miner alone would not activate FOTE.

## Scope

FOTE changes tail-phase issuance only. It does not change transaction encoding,
salt sizes, transaction archival burn, state-growth burn, or pruning policy.

## Current implementation references

- `kernel/src/consensus/policy/emission.rs` defines the current height-based
  emission schedule and subtracts `MINER_PROTOCOL_BURN` to calculate miner
  emission.
- `kernel/src/consensus/policy/burn.rs` defines `MINER_PROTOCOL_BURN`.
- `README.md` documents that transaction miner fees are credited separately to
  the block miner.
