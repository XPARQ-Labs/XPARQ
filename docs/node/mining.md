# Mining

Paqus uses Argon2id proof of work. Each hash uses 64 MiB of memory, one
iteration, and one lane. Difficulty is adjusted by WBDA from block-weight
utilization, not from wall-clock block time.

## Start mining

```bash
cargo run --release --bin paqus-node \
  --no-default-features --features mainnet -- \
  node run data/mainnet \
  --network mainnet \
  --wallet wallets/mainnet.json \
  --mine \
  --mine-attempts 0 \
  --mine-interval-secs 10
```

`--mine-attempts 0` enables continuous mining. The node rebuilds its candidate
at the selected interval so new mempool transactions can be included.

For bounded batches:

```bash
--mine-attempts 5000000 --mine-interval-secs 1
```

## Rewards

| Rule | Value |
| --- | ---: |
| Initial subsidy | 15 XPQ |
| Tail emission begins | Height 400,000 |
| Tail emission | 0.85 XPQ |
| Reward maturity | 50 blocks |
| Genesis premine | 0 XPQ |

Transaction fees are included in the coinbase transaction by node policy.
Miner fee selection is controlled locally in `paqus/byte`; it is not a
consensus-required field inside the core transaction.

## Operational notes

* Mining and validation are memory-intensive.
* Confirm that the wallet belongs to the selected network.
* Back up the mining wallet before accumulating rewards.
* Monitor `/status`, `/stats`, and `/metrics`.
* A node must validate the same frozen genesis as its peers.
