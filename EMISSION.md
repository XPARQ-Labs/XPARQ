# XPARQ Emission Model

## Status

This document describes the active, height-based XPARQ block-emission schedule.
It does not activate the proposed Fee-Offset Tail Emission (FOTE) described in
[`FOTE.md`](FOTE.md).

## Units and validation

XPQ is represented in integer zeno, with 100,000,000 zeno per XPQ. Emission is
determined by block height, not elapsed time, transaction fees, block weight, or
miner identity. The genesis block has no emission. Every later block must declare
the exact subsidy prescribed for its height or consensus rejects it.

The listed subsidy is the gross per-block subsidy. The protocol subtracts the
fixed `MINER_PROTOCOL_BURN` from it to calculate the miner's emission. The miner
also receives valid transaction miner fees separately; those fees do not reduce
the active block subsidy.

## Schedule

The schedule uses 100,000-block intervals. It starts at 1.562500 XPQ, doubles
for five intervals to a 50 XPQ peak, then halves for six intervals until it
reaches a permanent 0.781250 XPQ tail.

| Block heights | Gross subsidy per block |
| --- | ---: |
| 1–100,000 | 1.562500 XPQ |
| 100,001–200,000 | 3.125000 XPQ |
| 200,001–300,000 | 6.250000 XPQ |
| 300,001–400,000 | 12.500000 XPQ |
| 400,001–500,000 | 25.000000 XPQ |
| 500,001–600,000 | 50.000000 XPQ |
| 600,001–700,000 | 25.000000 XPQ |
| 700,001–800,000 | 12.500000 XPQ |
| 800,001–900,000 | 6.250000 XPQ |
| 900,001–1,000,000 | 3.125000 XPQ |
| 1,000,001–1,100,000 | 1.562500 XPQ |
| 1,100,001 onward | 0.781250 XPQ |

For non-genesis block height `h`, the schedule is equivalent to:

```text
n = floor((h - 1) / 100,000)

if n <= 5:
    gross_subsidy = min(1.562500 XPQ * 2^n, 50 XPQ)
else:
    halvings = n - 5
    gross_subsidy = max(50 XPQ / 2^halvings, 0.781250 XPQ)
```

All values are represented as integer zeno in consensus; the decimal values above
are for display.

## Miner reward and issuance

Let `E(h)` be the gross subsidy for height `h`, and `B` be
`MINER_PROTOCOL_BURN`. The emission component paid to the miner is:

```text
miner_emission(h) = E(h) - B
```

The protocol burn is accounted for separately. Transaction miner fees are
additional transfers to the miner, not new issuance and not an offset against
`E(h)` under the active rules.

The permanent tail means the schedule has no finite maximum supply: after height
1,100,000, each block continues to issue the tail subsidy, less the fixed
protocol burn. Actual net supply change also depends on transaction and state
burns.

## Relation to FOTE

Under the active schedule, fees add to the miner's reward while gross subsidy
continues to depend only on height. FOTE proposes using eligible block fees to
reduce net tail emission. That would make emission depend on block contents and
would require a coordinated consensus upgrade; it is not part of this model yet.

## Current implementation references

- `kernel/src/consensus/policy/emission.rs` defines the schedule and validates
  the block subsidy.
- `kernel/src/consensus/policy/burn.rs` defines `MINER_PROTOCOL_BURN`.
- `README.md` describes the miner address and reporting of gross subsidy and
  protocol burn.
