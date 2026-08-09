# XPARQ Node

`node/` builds the `xparq-node` full-node binary. It consumes the `xparq` core
library and owns operational concerns: LMDB persistence, libp2p networking,
mempool policy, mining, HTTP RPC, optional gRPC status, snapshots, and database
maintenance.

For the end-to-end mining guide, see [`tutorial.md`](../tutorial.md).

## Build and identify the network

```bash
cargo build --release -p xparq-node
./target/release/xparq-node version
./target/release/xparq-node node info
```

Mainnet is the default. Build testnet or devnet with one explicit workspace
feature:

```bash
cargo build --release -p xparq-node --no-default-features --features testnet
cargo build --release -p xparq-node --no-default-features --features devnet
```

## Configuration and startup

Generate the complete configuration for the compiled network:

```bash
./target/release/xparq-node node config
```

Default paths are:

| Network | Configuration | Database | P2P | HTTP RPC |
| --- | --- | --- | ---: | ---: |
| mainnet | `data/mainnet/config.json` | `data/mainnet` | 5555 | 6666 |
| testnet | `data/testnet/config.json` | `data/testnet` | 15555 | 16666 |
| devnet | `data/devnet/config.json` | `data/devnet` | 25555 | 26666 |

Start a non-mining node with:

```bash
./target/release/xparq-node node run
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
./target/release/xparq-node mine
```

The implementation still accepts `wallet` as a legacy payout-address source,
but mining never needs the wallet's secret keys. `miner_secret_key` is also
optional and should normally remain `null`.

Use `XPARQ_CONFIG` to select a custom shared JSON file, or pass `--config` for
one node invocation. Precedence is network defaults, JSON, environment, then
command-line options.

## Connectivity and public addresses

`listen_addr` selects local P2P listeners. `public_addr` advertises externally
reachable P2P addresses; it is not an RPC address. `peers`, `peers_file`, and
`dns_seeds` provide entry points, but do not determine canonical chain state.
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
`xparq-node --help`. The wallet uses this HTTP API.

Set `grpc_addr` in `config.json`, or pass `--grpc-listen`, to enable the
optional `xparq.node.v1.NodeRpc/GetStatus` service defined in
[`proto/xparq_node.proto`](proto/xparq_node.proto). The current gRPC listener
has no TLS or authentication; bind it to loopback or a trusted private network.

## Database and snapshots

Stop the running node before offline maintenance:

```bash
./target/release/xparq-node node db check ./data/mainnet
./target/release/xparq-node node db backup ./data/mainnet ./backup/mainnet
./target/release/xparq-node node db restore ./backup/mainnet ./data/restored-mainnet

./target/release/xparq-node node snapshot export ./data/mainnet snapshot.xparq
./target/release/xparq-node node snapshot import ./data/new-mainnet snapshot.xparq
```

Backup, restore, and snapshot import refuse to overwrite an existing
destination. Never open a database with a binary compiled for another network.

Use `Ctrl+C` for graceful shutdown and wait for the shutdown-complete log.
