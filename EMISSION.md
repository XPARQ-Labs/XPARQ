# XPARQ Emission Model

## Status

This document describes the height-based XPARQ block-emission schedule and the
scheduled Fee-Offset Tail Emission (FOTE) described in [`FOTE.md`](FOTE.md).
FOTE activates at block height `1,100,001`.

## Units and validation

XPQ is represented in integer zeno, with 100,000,000 zeno per XPQ. Before
height `1,100,001`, emission is determined by block height. From that height
onward, transaction miner fees reduce net tail issuance. The genesis block has
no emission. Every later block must declare the exact subsidy prescribed by the
active rule or consensus rejects it.

The listed subsidy is the scheduled gross per-block subsidy. Before FOTE
activation, the protocol subtracts the fixed `MINER_PROTOCOL_BURN` from it to
calculate the miner's emission, and valid transaction fees are credited
separately. At and after activation, the fee-offset rule may reduce the gross
subsidy while preserving the protocol burn.

## Schedule

The schedule uses 100,000-block intervals. It starts at 1.562500 XPQ, doubles
for five intervals to a 50 XPQ peak, then halves for six intervals until it
reaches a permanent 0.781250 XPQ tail.

| Block heights | Scheduled gross subsidy per block |
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

Let `E(h)` be the scheduled gross subsidy for height `h`, and `B` be
`MINER_PROTOCOL_BURN`. Before FOTE activation, the emission component paid to
the miner is:

```text
miner_emission(h) = E(h) - B
```

The protocol burn is accounted for separately. At and after FOTE activation,
let `R = E(h) - B` and let `F` be the sum of valid operation miner fees credited
to the block miner. The gross subsidy becomes `B + max(0, R - F)`, so the net
emission is `max(0, R - F)`. Transaction fees remain transfers to the miner and
are not new issuance.

The permanent tail begins at height `1,100,001`. Under FOTE, net tail issuance
falls as eligible miner fees rise and reaches zero for a block when its fees are
at least `R`. Actual net supply change also depends on transaction and state
burns.

## Relation to FOTE

Before activation, fees add to the miner's reward while gross subsidy depends
only on height. Starting at height `1,100,001`, FOTE uses eligible block fees to
reduce net tail emission. This is a scheduled consensus rule; all nodes must
upgrade before activation.

## Current implementation references

- `kernel/src/consensus/policy/emission.rs` defines the schedule and validates
  the block subsidy.
- `kernel/src/consensus/policy/burn.rs` defines `MINER_PROTOCOL_BURN`.
- `README.md` describes the miner address and reporting of gross subsidy and
  protocol burn.
