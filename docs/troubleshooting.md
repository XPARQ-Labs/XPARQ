# Troubleshooting

## Build uses several gigabytes

Cargo stores compiled dependencies and incremental state in `target`
directories. Remove rebuildable artifacts with:

```bash
cargo clean
cargo clean
```

The next build will take longer.

## Wrong network or genesis

Symptoms include rejected peers, a genesis mismatch, or an incompatible
database. Check:

```bash
cargo run --bin paqus-node \
  --no-default-features --features mainnet -- \
  node info
```

Confirm that the feature, `--network`, database path, wallet, chain ID, and
ports all refer to the same network. Do not repair this by reusing another
network's database.

## RPC connection refused

Check that:

1. the node is running;
2. the wallet uses the correct `PAQUS_RPC_ADDR`;
3. the RPC port matches the network;
4. the listener is bound to the expected interface;
5. a firewall is not blocking the connection.

```bash
curl http://127.0.0.1:6666/health
```

## Remote RPC will not start

The node rejects non-loopback RPC without a TLS certificate and private key.
Either bind to `127.0.0.1` or configure both `--rpc-tls-cert` and
`--rpc-tls-key`.

## No spendable mining balance

The mainnet genesis has no premine, and block subsidy matures after 50 blocks.
Use the wallet balance view to distinguish available, incoming, and locked
funds.

## Peer does not connect

Verify the public P2P port, advertised address, network feature, genesis, and
firewall. IPv6 addresses in socket form require brackets.

## Database validation

Stop the node and run:

```bash
cargo run --release --bin paqus-node -- \
  node db check data/mainnet
```

Restore only from a backup belonging to the same network.

## QCash file appears pending

A withdrawal can be redeemed starting one block after inclusion. Synchronize
the file against your node:

```bash
cargo run --bin wallet-cli -- cash sync cash/
```

Also confirm that the wallet and node are on the same network.
