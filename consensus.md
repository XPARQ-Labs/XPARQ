# XPARQ Consensus Overview

This page summarizes the active rules that decide whether a block is valid,
which target miners must meet, how new XPQ is issued, and which valid chain tip
wins. It is an overview; the linked policy documents and implementation define
the detailed rules.

## Block validity

For a non-genesis block, a node checks that:

1. The block has a valid structure and commitments, including its declared
   weight and operation data.
2. Its height follows its parent and its previous-block hash names that parent.
3. Its target is the one required by the active difficulty rule, and its
   Argon2id proof of work meets that target.
4. Its emission declares the exact subsidy for its height.
5. Applying its operations produces valid authorization, ownership, value
   conservation, required protocol burns, and the committed canonical state.

Blocks are limited to 2 MiB. The header commits to block weight; canonical
execution checks the weight against the block. The genesis block is checked
against the chain's configured genesis and has no emission.

## Proof of work and difficulty adjustment

XPARQ uses Argon2id proof of work. Its consensus parameters are 128 MiB of
memory, one iteration, and one lane. A candidate must use the expected target
for its height as well as produce a hash that satisfies that target.

The active difficulty adjustment is [WBDA](WBDA.md). At every 2,500-block
boundary, it measures the average block weight over the preceding
2,500 blocks against a 1 MiB target. If utilization is below 80%, the target
shrinks to 80% of its previous value, making mining harder. Above 120%, the
target grows to 120%, making mining easier, up to the proof-of-work limit. At
utilization from 80% through 120%, the target stays the same. Between boundaries
the parent target carries forward.

WBDA uses block weight, not elapsed time. Its detailed window arithmetic and
boundary examples are in [WBDA.md](WBDA.md).

## Emission and protocol burn

The active [emission model](EMISSION.md) prescribes gross subsidy by block
height. It starts at 1.562500 XPQ, rises to 50 XPQ, then halves to a permanent
0.781250 XPQ tail. Every non-genesis block must declare the exact scheduled
subsidy. The fixed miner protocol burn is deducted from that subsidy. Valid
transaction miner fees are credited separately and do not reduce active
subsidy.

Transactions must also satisfy the protocol's archival and net state-growth
burn rules. See [program-call validation](docs/PROGRAM_CALL.md) and the burn
policy in `kernel/src/consensus/policy/burn.rs` for details.

[FOTE](FOTE.md) proposes using eligible transaction fees to offset tail
emission. It is not active: the current subsidy remains height-based, and FOTE
would require a coordinated consensus upgrade.

## Fork choice

Nodes compare valid chain tips in this order:

1. Greater locally computed cumulative proof-of-work wins.
2. If cumulative work is equal, greater cumulative block weight wins.
3. If both totals are equal, the tip with the numerically smaller block hash
   wins.

Block weight is therefore a tie-breaker; it cannot compensate for lower
cumulative work. The node validates the replacement branch and applies the
corresponding reorganization from its common ancestor. See
[architecture](docs/ARCHITECTURE.md#consensus-validation-and-fork-choice) for
the implementation split.

## Consensus rules and node policy

Consensus validity comes from the chain's expected genesis and the rules above.
Options such as `--minimum-chain-work` and `--minimum-chain-weight` are local
remote-chain admission floors for synchronization. They do not change whether a
block is valid, do not alter fork-choice ordering, and do not prevent a node
from starting with its local chain.

## Policy documents and implementation

- [WBDA](WBDA.md): active weight-based difficulty adjustment.
- [Emission model](EMISSION.md): active subsidy schedule and miner emission.
- [FOTE](FOTE.md): proposed fee-offset tail emission; inactive.
- [Architecture](docs/ARCHITECTURE.md): consensus module responsibilities.
- `kernel/src/consensus/block.rs`: canonical block admission.
- `kernel/src/consensus/pow.rs`: Argon2id proof-of-work construction.
- `kernel/src/consensus/policy/`: difficulty, emission, and burn rules.
- `kernel/src/consensus/fork/`: cumulative-work calculation, fork choice, and
  reorganization planning.
