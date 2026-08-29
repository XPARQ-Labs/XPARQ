# XPARQ developer tools

This directory is the starting point for developers building on XPARQ. The
repository currently exposes two different extension models:

| Model | Current status | Node rebuild required? | Best suited for |
| --- | --- | --- | --- |
| Native asset extension | Usable end-to-end | No | Fungible assets with fixed metadata and an optional mint authority |
| WASM extension ABI v1 | Experimental | No for permissionless deployment | Deterministic application state and custom validation logic |

Start with [ASSETS.md](ASSETS.md) to create, mint, burn, transfer, and query an
asset. No source-code pull request or governance vote is required.

Read [WASM.md](WASM.md) before developing a WASM extension. Deployment and
automatic activation are implemented, but the public developer experience is
not yet a complete smart-contract platform: XPARQ does not currently provide a
guest SDK, a generic `wasm-call` wallet command, events, contract upgrades, or
inter-extension calls.

## Local prerequisites

- A recent stable Rust toolchain.
- An XPARQ node with RPC enabled (the examples use `127.0.0.1:6666`).
- An XPARQ wallet funded with XPQ for transaction fees.
- `wat2wasm` from WABT only when building the included WAT example.

Build the node and wallet from the repository root:

```bash
cargo build -p xparq-runtime -p wallet
```

Run the node and open the interactive wallet in separate terminals:

```bash
cargo run -p xparq-runtime -- run --data ./data/xparq
cargo run -p wallet -- menu
```

## What is ready today?

Developers can create and distribute native assets on a running chain today.
They can also build, inspect, deploy, and query immutable WASM modules. WASM is
suitable for protocol experimentation and testnet development, but third-party
application calls still require a purpose-built transaction builder until a
generic signed call command and SDK are added.

The canonical protocol references remain:

- [`docs/API.md`](../docs/API.md)
- [`docs/WASM_EXTENSIONS.md`](../docs/WASM_EXTENSIONS.md)
- [`docs/openapi.json`](../docs/openapi.json)

