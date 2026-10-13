# Weight-Based Difficulty Adjustment (WBDA)

## Status

WBDA is the active XPARQ difficulty-adjustment rule. It adjusts the proof-of-work
target from recent block weight, rather than elapsed wall-clock time.

## Parameters

| Parameter | Current value |
| --- | ---: |
| Adjustment window | 2,500 completed blocks |
| Target average block weight | 1 MiB (1,048,576 bytes) |
| Low-utilization threshold | 80% (800,000 ppm) |
| High-utilization threshold | 120% (1,200,000 ppm) |
| Harder-target step | 80% of the previous target |
| Easier-target step | 120% of the previous target |
| Proof-of-work function | Argon2id |

The block header commits to its weight. Mining computes the weight from the
serialized block, and full block execution recomputes it and requires an exact
match.

## Window and utilization

At an adjustment boundary, WBDA reads the 2,500 blocks immediately before the
next block. For next height `H`, that window is heights `H - 2500` through
`H - 1`.

It calculates the integer average block weight and compares it with the 1 MiB
target:

```text
average_weight = sum(window_block_weights) / 2500
utilization_ppm = average_weight * 1,000,000 / 1,048,576
```

Both divisions use integer arithmetic. Utilization below 800,000 ppm is low;
utilization above 1,200,000 ppm is high. Values exactly at either threshold are
within the keep range.

## Target adjustment

| Window utilization | Next target | Effect |
| --- | --- | --- |
| Below 80% | Previous target × 80% | Harder mining target; difficulty increases |
| 80% through 120%, inclusive | Unchanged | Difficulty stays the same |
| Above 120% | Previous target × 120% | Easier mining target; difficulty decreases |

The adjustment is applied only at epoch boundaries. With a 2,500-block window,
the first adjusted target is for height 2,501, using weights from heights 1
through 2,500. The next adjustment is for height 5,001. At all other heights,
the child inherits its parent's target.

The target is bounded by the XPARQ proof-of-work limit, so the easier adjustment
cannot make mining easier than that limit. The initial target is also the
configured PoW limit. Repeated adjustments compound across epochs.

WBDA changes the target checked by Argon2id proof of work. Fork choice remains a
separate rule based on cumulative work; block weight is not itself fork-choice
work.

## Design interpretation

WBDA responds to sustained use of block capacity. It does not measure block
timestamps or promise a fixed time between blocks. A window consistently below
the utilization band makes mining harder by reducing the target. A window
consistently above the band makes mining easier by increasing the target, subject
to the PoW limit.

## Current implementation references

- `kernel/src/consensus/policy/difficulty.rs` defines the window, thresholds,
  utilization calculation, and target steps.
- `kernel/src/consensus/target.rs` bounds consensus target scaling by the PoW
  limit.
- `kernel/src/consensus/header.rs` and `kernel/src/consensus/block.rs` validate
  target transitions using the exact preceding weight window.
- `kernel/src/blockchain/block.rs` computes serialized block weight; canonical
  ledger execution rejects a header weight that does not match it.
