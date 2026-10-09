# Persistent counter

This deployable XPVM v1 example starts at zero and increments its shared i64
state by one on every confirmed call. It returns the new value. Anyone can call
it using their own funded wallet; the counter has no owner-only access control.
It does not hold deposits or pay rewards.

## Run on devnet

Build node and wallet for the same network and start a node with mining enabled
or a connected miner. The wallet must have spendable XPQ on that network.
Run these commands from the repository root:

```bash
./build.sh --no-default-features --features devnet
export WALLET_FILE="$HOME/.xparq/wallet.json"
export RPC_ADDR=127.0.0.1:26666
./examples/counter/deploy.sh 1
```

Choose a deployment nonce unused by this wallet owner. Copy the `Program ID`
printed by the wallet, then wait for deployment confirmation before calling:

```bash
PROGRAM_ID=PASTE_THE_64_CHARACTER_PROGRAM_ID
./examples/counter/increment.sh "$PROGRAM_ID"
```

Wait for this transaction to be included in a block. Call again to increment
from one to two. Deployment and every call pay protocol burn and miner fees;
submission alone does not confirm a state change. The wallet prints a transaction
hash, not the VM return value. There is currently no dedicated RPC/CLI query for
the counter's numeric state; `wallet history` can show confirmed wallet activity.
Reorganizations may undo increments through the kernel's rollback journal.

## Use without cloning the repository

Download or copy `counter.xpvm` and a compatible wallet binary, then run:

```bash
wallet program-deploy --code counter.xpvm --nonce 1 --wallet /path/to/wallet.json --rpc 127.0.0.1:26666
# Wait for deployment confirmation and replace PROGRAM_ID with the printed ID.
wallet program-call --program-id PROGRAM_ID --wallet /path/to/wallet.json --rpc 127.0.0.1:26666
```

The binary, wallet Program ID, and RPC must use the same network. For mainnet,
the default local RPC port is 6666. Set `WALLET_BIN` when using the scripts with
a wallet binary outside `target/release/wallet`.

To print signed bytes instead of submitting:

```bash
./examples/counter/increment.sh "$PROGRAM_ID" --offline
```

This mode still needs RPC for funding and quotes; it does not increment state.

## Bytecode

`counter.xpvm` is 27 bytes: a 13-byte header with stack limit two, zero memory
pages, and entry zero, followed by:

```text
READ_STATE
PUSH_I64 1
ADD
WRITE_STATE
READ_STATE
RETURN
```

Hex encoding:

```text
5850564d0102000000000000000401010000000000000002050403
```

Each call uses 12 fuel, adding 12 zeno of protocol burn. The node quote reports
`vm_fuel`, and the wallet includes this execution burn automatically. Node and
wallet binaries must include VM fuel quote support. At `i64::MAX`, checked addition fails and the proposed
state is not applied. The kernel stages effects and journals committed state
for rollback. The bytecode is directly included by the kernel VM regression
that checks fuel, successive values, and restoration after rollback.

The wallet integration test deploys this file, calls it twice, mines the
transactions, and verifies confirmed activity and persistence after restart:

```bash
cargo build -p node -p wallet --bins
cargo test -p wallet --test program_e2e counter_deploy_and_call_cli_survive_restart -- --ignored
```

Verification passed: 48 node unit tests, seven wallet unit tests, the kernel
counter regression, and the explicit node/wallet counter lifecycle test
(57.65 seconds). Clippy passed with existing warnings. See the
[verification results](../../docs/audit/counter-verification.txt).
