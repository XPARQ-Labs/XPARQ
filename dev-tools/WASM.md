# WASM extension development

WASM ABI v1 lets an extension validate an opaque payload and update its own
isolated key-value state deterministically. Permissionless deployment does not
require governance or a node rebuild: after validation, the immutable module
activates automatically 100 blocks after its deployment block.

This interface is experimental. Treat it as a low-level extension ABI, not yet
as an Ethereum-equivalent smart-contract SDK.

## Build the minimal example

[`examples/state-value.wat`](examples/state-value.wat) demonstrates the exact
ABI and fixed 16-page memory required by XPARQ. It accepts a non-empty payload
and stores that payload under the key `value` during apply. It is intentionally
minimal and intended for small test payloads; production allocators must check
that every host copy fits the fixed linear memory and all state limits.

```bash
wat2wasm dev-tools/examples/state-value.wat -o module.wasm
cargo run -p xparq-runtime -- extension-package \
  module.wasm module.xpqext example.state 1000
cargo run -p xparq-runtime -- extension-check module.xpqext
```

The `.xpqext` package is useful for inspection and operator-configured chains.
The activation height passed to `extension-package` belongs to that coordinated
operator path; permissionless deployment uses the protocol's fixed 100-block
delay instead.

## Deploy permissionlessly

```bash
cargo run -p wallet -- wasm-deploy \
  --name example.state \
  --wasm module.wasm \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

The wallet prints the derived extension ID. Query deployment and activation
state with:

```bash
cargo run -p wallet -- wasm-info \
  --extension EXTENSION_ID \
  --rpc 127.0.0.1:6666
```

The module is immutable. Changed bytecode produces a new extension ID and must
be deployed as a new extension.

## ABI summary

The module exports fixed memory plus:

```text
xparq_alloc(length: i32) -> i32
xparq_validate(payload_ptr: i32, payload_len: i32, height: i64) -> i32
xparq_apply(payload_ptr: i32, payload_len: i32, height: i64) -> i32
```

Return zero for success. Guests may import `state_get`, `state_put`, and
`state_delete` from module `xparq`; writes are rejected during validation.
There is no WASI, clock, random source, floating point, filesystem, socket, or
direct ledger access. See [`docs/WASM_EXTENSIONS.md`](../docs/WASM_EXTENSIONS.md)
for the exact limits and host return codes.

## Important current limitation: application calls

The wallet currently implements `wasm-deploy` and `wasm-info`, but it does not
yet expose a generic `wasm-call --extension ID --payload ...` command. Therefore
a third-party extension can be deployed and activated, but ordinary users
cannot invoke arbitrary application payloads through the stock wallet yet.

Completing the public developer path requires these next pieces:

1. a canonical signed WASM application-call envelope with signer and nonce;
2. a wallet/Rust SDK transaction builder and generic `wasm-call` CLI;
3. local execution and integration-test helpers;
4. stable payload conventions, events/indexing, and application-specific RPC;
5. optional upgrade, pause, and migration policies defined at the protocol
   level.

Until those exist, direct invocation requires custom Rust integration against
the core `ExtensionCall` and `AuthorizedExtensionTransaction` types and should
be considered internal/testnet work. Deployment alone is production-shaped;
the complete third-party application workflow is not.
