# WASM extensions

XPARQ WASM extension ABI v1 executes deterministic WebAssembly through the
core extension lifecycle. It does not provide WASI, files, sockets, clocks,
randomness, floating point, or direct ledger access.

For a developer-oriented walkthrough, readiness boundaries, and a minimal
guest module, see [`dev-tools/WASM.md`](../dev-tools/WASM.md).

## Guest ABI

The module must export one fixed-size linear memory and these functions:

```text
memory
xparq_alloc(length: i32) -> i32
xparq_validate(payload_ptr: i32, payload_len: i32, height: i64) -> i32
xparq_apply(payload_ptr: i32, payload_len: i32, height: i64) -> i32
```

Return `0` from `xparq_validate` and `xparq_apply` on success. Any other return
value rejects the extension call.

The module may import these functions from module `xparq`:

```text
state_get(key_ptr: i32, key_len: i32, output_ptr: i32, output_capacity: i32) -> i32
state_put(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32
state_delete(key_ptr: i32, key_len: i32) -> i32
```

`state_get` returns the value length, `-1` when absent, `-2` on host failure,
or `-3` when the output buffer is too small. State writes are allowed only from
`xparq_apply`; attempting a write during validation rejects the call.

ABI v1 limits module code to 2 MiB, linear memory to 16 fixed 64-KiB pages,
fuel to 10,000,000, keys to 256 bytes, individual values to 1 MiB, and the
WASM-visible state snapshot to 16 MiB.

## Build and inspect a package

Compile the extension to a raw WebAssembly module whose memory declaration is
exactly `16 16`, then create the canonical package:

```bash
cargo run -p xparq-runtime -- extension-package module.wasm module.xpqext example.dex 1000
cargo run -p xparq-runtime -- extension-check module.xpqext
```

Package creation refuses to overwrite an existing output file. The package
contains its canonical manifest and raw module. Its extension ID is derived
from the extension name and domain-separated code hash.

## Permissionless on-chain deployment

Any wallet can deploy an immutable module and pay its size-based XPQ fee:

```bash
cargo run -p wallet -- wasm-deploy \
  --name example.dex \
  --wasm module.wasm \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

The deployment receives an ID derived from its name and code hash. Core stores
the verified module in extension state and activates it exactly 100 blocks after
the deployment block. Deploying the same ID twice is rejected. There is no
governance approval, owner upgrade, deletion, or emergency pause; a new version
must use new bytecode and therefore a new ID.

Query its activation status with:

```bash
cargo run -p wallet -- wasm-info --extension EXTENSION_ID --rpc 127.0.0.1:6666
```

The RPC endpoints are `GET /wasm/nonce/{address}` and
`GET /wasm/{extension_id}`. Deployment uses the normal binary
`POST /transaction` endpoint.

## Signed application calls

Generic signed calls and their persistent-state burn are active from genesis.
After the deployed module's own 100-block delay has elapsed, invoke it with
either hexadecimal bytes or a file:

```bash
cargo run -p wallet -- wasm-call \
  --extension EXTENSION_ID \
  --payload-file call.bin \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

`--payload-hex HEX` can replace `--payload-file`. The wallet obtains the
per-extension signer nonce from
`GET /wasm-app/nonce/{extension_id}/{address}`, signs an envelope binding the
chain ID, extension ID, raw guest payload, signer, and nonce, then obtains the
exact current-state burn from `POST /extension/preview`. The call and its XPQ
fee/burn spend are submitted atomically through `POST /transaction`.

Raw unsigned payloads to permissionlessly deployed WASM extensions are invalid
at every height. Guest code cannot read, overwrite, or delete the host-reserved
nonce keys. Because created-state weight depends on canonical state, a
conflicting state change between preview and inclusion can require the caller
to rebuild and resubmit the transaction.

## Optional operator-configured activation

Every validating node for that chain must start with the same ordered package
set:

```bash
cargo run -p xparq-runtime -- run \
  --extension-package module.xpqext \
  --data ./data/wasm-chain
```

Multiple `--extension-package` arguments are supported. Argument order does not
affect identity because manifests are sorted by extension ID.

The package manifests, including code hash, activation height, fuel, and memory
limit, are committed into the effective chain-spec hash. Peers with different
packages fail the handshake, and a database created for one package set cannot
be opened with another. With no WASM packages, the existing native-only
chain-spec hash remains unchanged.

Operator-configured packages remain useful for coordinated chain-specific
extensions. Permissionless deployments instead live entirely in ledger state
and do not require every operator to copy a package file.
