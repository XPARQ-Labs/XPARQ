# XPARQ Node Runtime

`runtime/` builds the `node` binary. It owns redb persistence, snapshots,
mining, HTTP RPC, peer discovery, gossip, synchronization, and cumulative-work
reorganization. Consensus rules remain in the root core crates.

```bash
cargo build --release --locked -p xparq-runtime
./target/release/node run --data data/node --p2p 0.0.0.0:6677 --rpc 127.0.0.1:6666
```

Add `--miner XPQ_ADDRESS` to mine, and repeat `--peer HOST:PORT` for initial
peers. RPC is plain HTTP and should remain on loopback or a trusted network.

## Compatibility boundary

The runtime rejects incompatible state at four explicit boundaries:

- P2P protocol version 2 and handshake `chain_spec_hash`;
- redb schema version 2 and persisted `chain_spec_hash`;
- snapshot version 2, checksum, genesis, canonical tip, and `chain_spec_hash`;
- chain-spec version 2, committing frozen genesis plus active PoW, difficulty,
  WBDA, emission, size, address, and hash parameters.

There is intentionally no schema-v1 or snapshot-v1 compatibility path. Reset
old node data before starting this build, and upgrade peers together.

```bash
cargo test --locked -p xparq-runtime
cargo test --locked -p xparq-runtime --test network_e2e
./target/release/node check data/node
```

Connection logs alone are not synchronization evidence. Compare `/status`
height, tip hash, and cumulative work, then verify downloaded blocks applied.
