# Running a node

## Local node

From the project root:

```bash
cargo run --release --bin paqus-node \
  --no-default-features --features mainnet -- \
  node run data/mainnet \
  --network mainnet
```

The default mainnet RPC listener is local-only at `127.0.0.1:6666`.

## Connect to a peer

Add one or more bootstrap peers by repeating `--peer`:

```bash
cargo run --release --bin paqus-node \
  --no-default-features --features mainnet -- \
  node run data/mainnet \
  --network mainnet \
  --peer 203.0.113.20:5555 \
  --peer 203.0.113.30:5555
```

Check connectivity:

```bash
curl http://127.0.0.1:6666/peers
```

## Public P2P node

Expose the P2P listener and advertise a reachable address:

```bash
cargo run --release --bin paqus-node \
  --no-default-features --features mainnet -- \
  node run data/mainnet \
  --network mainnet \
  --listen 0.0.0.0:5555 \
  --public-addr node.example.org:5555
```

Open only the P2P port in the firewall unless remote RPC is intentionally
required.

For IPv6 socket addresses, brackets are required:

```text
[2001:db8::10]:5555
```

## Shutdown

Press `Ctrl+C` to request a clean shutdown. The node also watches the local
`STOP` file:

```text
data/mainnet/STOP
```

Do not terminate the process while it is committing database changes unless a
normal shutdown is impossible.
