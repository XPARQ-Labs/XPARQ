# Configuration and ports

## Default paths and ports

| Network | Database | Config | Peers | P2P | RPC |
| --- | --- | --- | --- | ---: | ---: |
| Mainnet | `data/mainnet` | `data/mainnet/node.json` | `data/mainnet/peers.json` | 5555 | 6666 |

Generate or inspect configuration:

```bash
cargo run --bin paqus-node -- node config
cargo run --bin paqus-node -- node info
```

Use a custom file:

```bash
cargo run --bin paqus-node -- \
  node run data/mainnet --config /etc/paqus/node.json
```

Command-line values override file defaults.

## Common options

```text
--listen <host:port>
--public-addr <host:port>
--rpc-listen <host:port>
--peer <host:port>
--peers-file <path>
--gateway <host:port>
--wallet <path>
--mine
```

Fee policy is local node policy, not consensus:

```text
--min-relay-fee <paqus-per-byte>
--market-fee <paqus-per-byte>
--miner-min-fee-rate <paqus-per-byte>
```

## RPC exposure

Keep public RPC bound to loopback when possible:

```text
127.0.0.1:6666
```

A non-loopback RPC listener requires a TLS certificate and key:

```bash
--rpc-listen 0.0.0.0:6666 \
--rpc-tls-cert ./tls/server.crt \
--rpc-tls-key ./tls/server.key \
--rpc-cors-origin https://wallet.example
```

CORS is disabled unless exact allowed origins are provided.

Default resource controls include a 2 MiB request body limit, a 30-second
timeout, 128 connections, 256 concurrent requests, and per-IP rate limiting.
Use the `--rpc-max-*`, `--rpc-timeout-secs`, and `--rpc-rate-*` options to
adjust them.

## Administrative RPC

Administrative routes use a separate listener and a bearer token of at least
32 characters:

```bash
export PAQUS_RPC_ADMIN_TOKEN='replace-with-a-random-token-at-least-32-characters'

cargo run --bin paqus-node -- \
  node run data/mainnet \
  --rpc-listen 127.0.0.1:6666 \
  --rpc-admin-listen 127.0.0.1:6667
```

Prefer the environment variable to placing the token in shell history or the
process command line.
