# XPARQ Node

`node/` builds the `node` full-node binary. It consumes the `xparq` core
library and owns operational concerns: LMDB persistence, libp2p networking,
mempool policy, mining, HTTP RPC, optional gRPC status, snapshots, and database
maintenance.

For the end-to-end mining guide, see [`TUTORIAL.md`](../TUTORIAL.md).

## Current runtime architecture

The current node separates network I/O from CPU-heavy and stateful work:

```text
P2P/RPC ingress
    -> bounded verification/state queues
    -> parallel stateless verification
    -> ordered ledger application
    -> one atomic LMDB commit per accepted block
```

Operational limits are explicit:

| Component | Current limit and behavior |
| --- | --- |
| Crypto verification queue | 256 jobs; saturated work falls back to inline verification |
| Stateless verification cache | 4,096 successful entries, scoped by authorization material and protocol height |
| Blocking state/RPC queue | 128 jobs; saturated RPC work returns service unavailable |
| Parallel sync result queue | At most 8 completed ranges waiting for ordered application |
| Recent-block cache | 32 blocks and 64 MiB, whichever limit is reached first |
| LMDB state snapshots | Genesis and every 2,048 blocks; intervening blocks persist dirty account and UTXO diffs |

The recent-block cache stores one `Arc<Block>` per cached height and a
hash-to-height secondary index. Evicted historical blocks remain available
from the canonical Ledger/LMDB path. All caches are process-local and are not
consensus or persisted state.

`GET /metrics` exposes queue pressure, per-stage sync timing, crypto fallback,
database size, and block-cache occupancy. CPU profiles can be captured with
`perf` and `cargo flamegraph`; benchmark builds retain debug symbols through
the workspace `profile.bench` configuration.

## Build and identify the network

```bash
cargo build --release -p node
./target/release/node version
./target/release/node node info
```

Mainnet is the default. Build testnet or devnet with one explicit workspace
feature:

```bash
cargo build --release -p node --no-default-features --features testnet
cargo build --release -p node --no-default-features --features devnet
```

## Configuration and startup

Generate the complete configuration for the compiled network:

```bash
./target/release/node node config
```

Default paths are:

| Network | Configuration | Database | P2P | HTTP RPC |
| --- | --- | --- | ---: | ---: |
| mainnet | `data/mainnet/config.json` | `data/mainnet` | 5555 | 6666 |
| testnet | `data/testnet/config.json` | `data/testnet` | 15555 | 16666 |
| devnet | `data/devnet/config.json` | `data/devnet` | 25555 | 26666 |

Start a non-mining node with:

```bash
./target/release/node node run
```

For mining, put only the public payout address in the generated JSON and keep
the wallet file off the mining machine:

```json
{
  "wallet": null,
  "miner_address": "YOUR_XPARQ_ADDRESS",
  "miner_secret_key": null,
  "mine": true
}
```

Keep the other generated fields. Then run:

```bash
./target/release/node mine
```

The implementation still accepts `wallet` as a legacy payout-address source,
but mining never needs the wallet's secret keys. `miner_secret_key` is also
optional and should normally remain `null`.

Use `XPARQ_CONFIG` to select a custom shared JSON file, or pass `--config` for
one node invocation. Precedence is network defaults, JSON, environment, then
command-line options.

## Connectivity and public addresses

`listen_addr_ipv4` and `listen_addr_ipv6` select local P2P listeners.
`public_addr_ipv4` and `public_addr_ipv6` advertise externally reachable P2P
addresses; they are not RPC addresses. `peers_ipv4`, `peers_ipv6`,
`peers_file`, and `dns_seeds` provide entry points, but do not determine
canonical chain state.
Fork choice always uses validated cumulative work.

RPC defaults to loopback. A non-loopback HTTP RPC listener requires TLS and
the configured security controls. Only the P2P port normally needs public
exposure.

## HTTP RPC and gRPC

Common read-only HTTP endpoints include:

```text
GET /health
GET /status
GET /metrics
GET /chain
GET /peers
GET /balance/<address>
GET /blocks/latest
GET /blocks/<height>
GET /tx/<transaction-hash>
GET /mempool
```

Transaction submission and draft endpoints are listed by
`node --help`. The wallet uses this HTTP API.

Set `grpc_addr_ipv4` and/or `grpc_addr_ipv6` in `config.json`, or pass
`--grpc-listen`, to enable the
optional `xparq.node.v1.NodeRpc/GetStatus` service defined in
[`proto/xparq_node.proto`](proto/xparq_node.proto). The current gRPC listener
has no TLS or authentication; bind it to loopback or a trusted private network.

## Database and snapshots

Stop the running node before offline maintenance:

```bash
./target/release/node node db check ./data/mainnet
./target/release/node node db backup ./data/mainnet ./backup/mainnet
./target/release/node node db restore ./backup/mainnet ./data/restored-mainnet

./target/release/node node snapshot export ./data/mainnet snapshot.xparq
./target/release/node node snapshot import ./data/new-mainnet snapshot.xparq
```

Backup, restore, and snapshot import refuse to overwrite an existing
destination. Never open a database with a binary compiled for another network.

Use `Ctrl+C` for graceful shutdown and wait for the shutdown-complete log.

## Runtime logs

Runtime logs are written to standard error with UTC RFC 3339 timestamps,
severity, and a stable component label such as `NODE`, `P2P`, `SYNC`, or `RPC`.
The default level is `info`; use `XPARQ_LOG=debug` for handshake, polling, and
sync-batch diagnostics, or `XPARQ_LOG=warn` to show warnings and errors only.
Command output such as `node version`, database maintenance results, and
generated configuration paths remains clean on standard output for scripting.
