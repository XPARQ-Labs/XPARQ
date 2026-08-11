# XPARQ Mining Tutorial

This guide explains how to build an XPARQ node, synchronize it with the
network, mine blocks, and monitor mining rewards. Run all commands from the
repository root.

## 1. Requirements

- A 64-bit Linux system
- Rust 1.90 or newer
- A C/C++ build toolchain
- Enough free disk space for the node database
- A stable internet connection
- TCP port `5555` reachable from the internet when accepting mainnet peers

XPARQ proof of work uses Argon2id with 64 MiB of memory, one iteration, and
two lanes. Mining performance depends on both CPU and memory performance.

## 2. Build the mainnet binaries

Mainnet is the default build profile:

```bash
cargo build --release -p node -p wallet
```

The resulting binaries are:

```text
target/release/node
target/release/wallet
```

Confirm that the node was built for the expected network:

```bash
./target/release/node version
./target/release/node node info
```

Do not use the same database for different networks.

## 3. Create the reward wallet

Create a wallet on a trusted machine:

```bash
./target/release/wallet new wallet.json --words 24
```

The command asks for an authorization password and prints the wallet address
and recovery mnemonic. Store the following items securely and separately:

- `wallet.json`
- the recovery mnemonic
- the authorization password

The wallet file contains private material in plaintext. Never commit it to
Git, publish it, or copy it to an untrusted mining server.

## 4. Recommended secure mining setup

Mining only needs the public reward address. It does not need the wallet's
secret keys. Copy the lowercase Bech32 address beginning with `x1` from the
wallet creation output, then generate the default mainnet configuration:

```bash
./target/release/node node config
```

Edit `data/mainnet/config.json` and set the mining fields:

```json
{
  "network": "mainnet",
  "db_path": "./data/mainnet",
  "listen_addr_ipv4": [
    "0.0.0.0:5555"
  ],
  "listen_addr_ipv6": [
    "[::]:5555"
  ],
  "rpc_addr_ipv4": "127.0.0.1:6666",
  "rpc_addr_ipv6": "[::1]:6666",
  "rpc_admin_addr_ipv4": null,
  "rpc_admin_addr_ipv6": null,
  "rpc_admin_token": null,
  "rpc_tls_cert": null,
  "rpc_tls_key": null,
  "rpc_cors_origins": [],
  "rpc_max_body_bytes": 2097152,
  "rpc_timeout_secs": 30,
  "rpc_max_concurrent_requests": 256,
  "rpc_max_connections": 128,
  "rpc_rate_limit_per_second": 50,
  "rpc_rate_limit_burst": 100,
  "peers_ipv4": [],
  "peers_ipv6": [],
  "peers_file": "./data/mainnet/peers.json",
  "dns_seeds": [],
  "gateway_url": null,
  "public_addr_ipv4": null,
  "public_addr_ipv6": null,
  "gateway_heartbeat_secs": 60,
  "nat_traversal": false,
  "nat_lease_secs": 3600,
  "grpc_addr_ipv4": null,
  "grpc_addr_ipv6": null,
  "shutdown_file": "./data/mainnet/STOP",
  "max_peers": 128,
  "fast_sync": false,
  "min_relay_fee": 0,
  "market_fee": 0,
  "low_fee_expiry_secs": 0,
  "mempool_expiry_secs": 0,
  "wallet": null,
  "miner_address": "YOUR_XPARQ_ADDRESS",
  "miner_secret_key": null,
  "miner_min_fee_rate": null,
  "mine": true,
  "mine_interval_secs": 1,
  "mine_attempts": 1000000
}
```

Replace `YOUR_XPARQ_ADDRESS` with the actual reward address. Keep both public
address fields as `null` for an outbound-only node, or set
`public_addr_ipv4` and/or `public_addr_ipv6` to externally reachable P2P
addresses. Add operator-selected peers to `peers_ipv4` and `peers_ipv6`; do
not leave every entry-point source empty unless `peers_file`, a DNS seed, or a
gateway already provides a reliable entry point. Then start mining:

```bash
./target/release/node mine
```

The command reads `data/mainnet/config.json` and enables mining. The mining
machine therefore needs only the public reward address; keep `wallet.json`,
the mnemonic, and the authorization password on the trusted wallet machine.
The node refuses to mine when neither `wallet` nor `miner_address` is
configured.

## 5. Synchronize before mining

A miner should follow the current greatest-work chain before spending CPU on
new blocks. Initially set `"mine": false` in `data/mainnet/config.json`, then
start the node without the mining shortcut:

```bash
./target/release/node node run
```

In another terminal, inspect its status:

```bash
curl http://127.0.0.1:6666/health
curl http://127.0.0.1:6666/status
curl http://127.0.0.1:6666/peers
```

Wait until the node has active peers and its height agrees with independent
mainnet peers. Stop it cleanly with `Ctrl+C`, set `"mine": true`, then run:

```bash
./target/release/node mine
```

Authenticated fast sync may be requested only for a database path that does
not exist yet:

```bash
./target/release/node node run --fast-sync
```

Fast sync requires a reachable peer that provides a valid authenticated
snapshot. If none is available, use normal synchronization.

## 6. Shared configuration and custom paths

The node and wallet share the same default configuration path for the compiled
network:

```text
mainnet   data/mainnet/config.json
testnet   data/testnet/config.json
devnet    data/devnet/config.json
```

The node reads the complete file. The wallet reads only `network` and prefers
`rpc_addr_ipv4`, falling back to `rpc_addr_ipv6`; it ignores P2P, mining,
admin, and secret fields.

The file name and location may be changed. For a one-off node invocation,
generate and use an explicit path:

```bash
./target/release/node node config config.json
./target/release/node mine --config config.json
```

To make both node and wallet use the same custom file on Linux or macOS:

```bash
export XPARQ_CONFIG=/opt/xparq/config.json
./target/release/node node config
# Edit miner_address before starting mining.
./target/release/node mine
./target/release/wallet balance
```

PowerShell uses the same JSON format:

```powershell
$env:XPARQ_CONFIG = "C:\XPARQ\config.json"
.\node.exe node config
# Edit miner_address before starting mining.
.\node.exe mine
.\wallet.exe balance
```

Config-path precedence is explicit node `--config`, `XPARQ_CONFIG`, then the
network default path. Value precedence is defaults, the JSON file, environment,
then command-line options. The `mine` command always enables mining, even if
the JSON field is `false`; the field controls ordinary `node node run`.

### Mining controls

- `mine`: enables or disables mining.
- `miner_address`: receives the block subsidy and selected miner outputs.
- `mine_attempts`: nonce attempts made before rebuilding the candidate block.
- `mine_interval_secs`: delay between bounded mining batches. With
  `mine_attempts = 0`, mining is continuous and this value becomes the
  candidate rebuild interval.
- `miner_min_fee_rate`: optional local minimum fee-output rate for transactions
  selected by this miner. When omitted, the node uses its dynamic rate.
- `grpc_addr_ipv4` / `grpc_addr_ipv6`: enable the optional status-only gRPC
  service. Keep them `null` when unused, or bind them to loopback. The current
  gRPC server has no TLS or authentication and must not be exposed publicly.

These are local operational settings and do not change consensus rules.

## 7. P2P connectivity

Mainnet defaults are:

```text
P2P TCP    5555
RPC TCP    6666, loopback only
```

For an inbound public node, forward TCP port `5555` through the router and set
the public P2P address in `config.json`:

```json
{
  "public_addr_ipv4": "PUBLIC_IPV4:5555",
  "public_addr_ipv6": "[PUBLIC_IPV6]:5555"
}
```

If the router supports automatic mapping, use:

```json
{
  "nat_traversal": true
}
```

Keep all other generated configuration fields, then start with
`./target/release/node mine`.

The node uses encrypted Noise sessions, Yamux multiplexing, Identify, ping,
and Kademlia discovery over libp2p. Outbound-only mining works without opening
port `5555`, but accepting inbound peers improves network connectivity.

Keep RPC bound to `127.0.0.1`. A non-loopback RPC listener requires TLS, and a
wallet should never use plain HTTP RPC across an untrusted network.

## 8. Monitor mining

Check node status and measured hashrate:

```bash
curl http://127.0.0.1:6666/status
./target/release/wallet hashrate
```

When the wallet runs beside the node, `--rpc` may be omitted: the wallet reads
`rpc_addr_ipv4`, or `rpc_addr_ipv6` when IPv4 is disabled, from the matching
`data/<network>/config.json`. Explicit `--rpc` and `XPARQ_RPC_ADDR` values take
precedence.

Check the reward address balance and mining history from the wallet machine:

```bash
./target/release/wallet balance YOUR_XPARQ_ADDRESS
```

Use `--rpc HOST:PORT` only when an explicit per-command override is needed.

The node logs a successful block as a timestamped `INFO BLOCK mined ...` event
and announces it to connected peers. Set `XPARQ_LOG=debug` when detailed P2P
handshake or sync-batch diagnostics are needed. A locally found block is only economically useful if it is
accepted into the canonical greatest-work chain.

## 9. Rewards and maturity

- The first WBDA epoch starts with a subsidy of `10 XPQ` per block.
- The protocol may adjust the subsidy by `1 XPQ` per completed 2,048-block
  epoch, within the `1 XPQ` to `20 XPQ` range.
- Block subsidy outputs mature after 50 blocks.
- A newly mined reward appears as immature until its maturity height.
- Miner payments carried by ordinary transactions follow normal transaction
  confirmation maturity.
- XPARQ has no genesis premine.

The wallet balance view separates available and unavailable UTXOs and reports
mined, matured, immature, and next-maturity values.

## 10. Testnet and devnet

Build testnet binaries with:

```bash
cargo build --release \
  --no-default-features \
  --features testnet \
  -p node -p wallet
```

Testnet uses P2P port `15555`, RPC port `16666`, and a separate database such
as `./data/testnet`.

Build devnet binaries with:

```bash
cargo build --release \
  --no-default-features \
  --features devnet \
  -p node -p wallet
```

Devnet uses P2P port `25555`, RPC port `26666`, and a separate database such
as `./data/devnet`. Testnet and devnet do not include built-in peers, so supply
at least one with `--peer HOST:PORT`, `peers_ipv4`, `peers_ipv6`, or a peers
file.

Building a different network profile into the default `target/release`
directory replaces the previous `node` and `wallet` binaries. Always
verify the compiled network with `./target/release/node node info` before
starting it.

## 11. Safe shutdown and recovery

Stop the node with `Ctrl+C` and wait for:

```text
[OK] shutdown complete
```

Do not terminate the process during database writes unless necessary. Useful
maintenance commands include:

```bash
./target/release/node node db check ./data/mainnet
./target/release/node node db backup ./data/mainnet ./backup/mainnet
```

Never restore a testnet or devnet database into the mainnet path. After a
consensus or storage-layout change, use a fresh database or a specifically
supported migration rather than opening incompatible data.

## 12. Troubleshooting

### Mining is off

Start with `./target/release/node mine` and confirm that the startup log
contains `mining=true`. Also verify that `config.json` contains either a valid
`miner_address` or `wallet` path.

### Hashrate is zero

Wait for at least one mining batch to complete, then inspect `/status`. Also
verify that the process has CPU time and was started with the `mine` command.

### No peers

- Confirm outbound internet access.
- Confirm that the binary uses the intended network.
- Check `peers_ipv4`, `peers_ipv6`, `peers_file`, and optional DNS seeds.
- Open or forward the network's P2P TCP port when accepting inbound peers.
- Do not use an RPC port as a P2P peer address.

### Reward is not spendable

Block subsidies require 50 additional blocks before they mature. Check the
wallet's `Next maturity` value and confirm that the mined block remains on the
canonical chain.

### Existing database is rejected

The database may belong to another network or storage layout. Preserve any
needed backup, then synchronize a fresh database for the compiled network.
