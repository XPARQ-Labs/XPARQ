# XPVM versions 1, 2, 3 and 4

The implemented contract lives in [vm.rs](../kernel/src/program/vm.rs).
Deployed v1–v3 code is bounded to **1 MiB**. Version 4 is bounded to **64 KiB** and 4,096 instructions. Code is validated before registry insertion.

## Header

The 13-byte header uses little-endian integers.

| Byte offset | Field | Accepted value |
| --- | --- | --- |
| 0–3 | Magic | ASCII `XPVM` |
| 4 | Version | 1, 2, 3 or 4 |
| 5–6 | Maximum stack items (u16) | 1–256 |
| 7–8 | Declared memory pages (u16) | 0–16 for v1–v3; 1–16 for v4; each page is 65,536 bytes |
| 9–12 | Entry (u32) | 0 |

## Instructions

| Opcode | Instruction | Effect |
| --- | --- | --- |
| 0x00 | NOP | No stack change |
| 0x01 | PUSH_I64 | Read the next 8 bytes as a little-endian signed integer |
| 0x02 | ADD | Pop two values and push their checked sum |
| 0x03 | RETURN | Return the sole stack value; must be the final instruction |
| 0x04 | READ_STATE | Push the program's current i64 state |
| 0x05 | WRITE_STATE | Pop a value and propose the new i64 state |

Each instruction costs 1 fuel. Each declared memory page costs 1 fuel.
READ_STATE costs 2 and WRITE_STATE costs 5. The call ceiling is **65,536 fuel**.
The straight-line program is validated and its required fuel checked before
execution. Arithmetic overflow or insufficient fuel fails execution.

Memory declarations are metered, but v1 has no memory load/store instructions,
branches, coin/asset host calls, filesystem, networking, clock or host randomness.
The interpreter returns a value and optional state effect; kernel applies the
effect to staged registry state and journals it for rollback.

## Deploy and call

`program-deploy` in the [wallet](../wallet/README.md#deployed-programs) signs and
submits deployment. The kernel derives ProgramId from owner, nonce and code hash;
an owner/nonce pair must be unused. A VM call uses SystemProgramId::VM (2), opcode
0, and exactly the deployed 32-byte ProgramId as payload, with an authenticated
XPQ payment. Use `wallet program-call --program-id HEX_ID` to sign and submit a VM call.
The wallet selects XPQ inputs and calculates burn and fees automatically.
See the [persistent counter example](../examples/counter/README.md).

This bytecode returns 7, with stack limit 1 and no memory pages:

```text
5850564d01010000000000000001070000000000000003
```

For a lower-level deployment example, see
[deploy_program.rs](../runtime/examples/deploy_program.rs).

## Contract-owned coin and assets (v2)

Version 2 adds `0x06 COIN_TRANSFER` and `0x07 ASSET_TRANSFER`. Each costs 20
fuel and leaves the stack unchanged. A program may contain at most one of each.
Version 1 rejects these opcodes. Existing v1 bytecode remains executable.

`COIN_TRANSFER` is followed by Borsh `Owner` and a positive little-endian u64
amount in zeno. `ASSET_TRANSFER` adds a 32-byte asset contract ID before the same
recipient/amount encoding; its amount is asset base units. `Owner` is a one-byte
tag 0, followed by the 32-byte ProgramId.
These initial instructions support amounts up to u64::MAX, including for assets
whose ledger accounting uses u128.

The VM proposes transfers; kernel settlement selects only `Owner::Program`
shares belonging to the executing ProgramId. It selects up to 256 inputs per
transfer in canonical share-ID order, stopping when funded, and returns change
to that program. Wallet signature policies cannot spend shares owned by deployed contracts.
Receiving does not require deployment; executing bytecode does.

Recipient and amount are embedded in code. Calls are public and can trigger the
fixed payout repeatedly while funded. There are no caller checks, branches,
arbitrary call arguments, cross-contract calls, or dynamic withdrawal policies
in this initial transfer instruction set.

Payment, both transfers, and the scalar state effect commit atomically. Failed
execution, insufficient balance, invalid ownership, or output collision commits
nothing. Rollback journals restore all consumed and created shares and program
state. Quotes and consensus use the same settlement preview, accounting for VM
coin UTXO counts, asset state growth, and fuel. The caller pays these costs.

Send funds with `--to program:HEX_PROGRAM_ID` on `sign-spend`, `program-transfer`,
or `program-mint`. Inspect balances using `program-account --program-id HEX_ID`
or `GET /program/account/HEX_ID`. See the [fixed payout example](../examples/vault/README.md).

CoinOutput's Borsh recipient uses a tagged Program owner,
coin state-weight accounting, and chain-spec 1/schema 1 compatibility.
Old serialized transactions and databases must not be reused with this format.
Use a fresh development data directory; there is no database migration here.
All peers must run the matching protocol version.


## Program-owned asset registration and minting (v3)

Version 3 accepts the v1/v2 instructions and adds `0x08 ASSET_REGISTER` (40 fuel)
and `0x09 ASSET_MINT` (20 fuel). Each leaves the stack unchanged. At most one
register and one mint are allowed, alongside the existing one coin and one asset
transfer. Register must precede mint. Versions 1 and 2 reject issuance opcodes.

`ASSET_REGISTER` carries Borsh `RegisterAssetRequest`:

| Field | Encoding |
| --- | --- |
| name | u32 byte length + 1–64 printable ASCII bytes, no outer whitespace |
| max_supply | positive u128 LE base units |
| initial_mint | positive u128 LE base units, no greater than max_supply |
| nonce | u64 LE asset creation nonce |
| skip_if_exists | Borsh bool: 0 or 1 |

The kernel sets both creator and mint authority to `Owner::Program(executing_id)`.
Initial supply is owned by that program. With `skip_if_exists = 0`, an existing
asset rejects the entire call. With `1`, matching registration is skipped, with
no additional initial issuance. Register still incurs its static instruction fuel.

`ASSET_MINT` carries Borsh `MintAssetRequest`:

| Field | Encoding |
| --- | --- |
| asset | tag 0 + 32-byte AssetContract, or tag 1 for the preceding registered asset |
| recipient | Borsh Owner: tag 0 + 32-byte ProgramId |
| amount | positive u128 LE base units |

Tag 1 requires a preceding register instruction, including when registration is
skipped. It resolves the program-created asset without embedding an ID that depends
on this program's own code hash. The kernel reads the current mint nonce and uses
its checked successor. Mint succeeds only when this program is the asset's mint
authority. Supply and lifetime `total_minted` must stay within `max_supply`;
burning supply does not reopen the issuance cap. Program recipients must exist.

Settlement applies coin transfer, register, mint, then asset transfer, followed by
caller payment and the scalar state effect within the same staged transaction.
Registration, mint and transfer use distinct share origins. Their rollback journals
preserve the original values even when several operations touch the same asset.
The RPC quote uses that same settlement and charges the caller for state growth
and all instruction fuel. Any failure commits no effects.

Requests are fixed in deployed code, and invocation remains public. These
instructions add asset issuance, while dynamic recipients, sale pricing, payment
inspection and access rules remain future VM capabilities. See the buildable
[asset issuer example](../examples/asset_issuer/README.md).

These additional consensus rules change the chain specification identity to
version 3. All peers must use the matching build. Existing v1/v2 code is accepted
on the new chain, but development databases committed to an older chain identity
require a fresh data directory; no chain migration is included.


## Application bytecode (v4)

Version 4 supplies general application primitives instead of adding a built-in
application for each vault, controller or sale. Application code remains immutable:
deploy a new ProgramId for a new version. Existing v1–v3 interpreters and their
canonical program-record encodings are retained. Upgrading application code within
the v4 instruction set does not require a new node binary. Adding VM instructions
or changing their consensus semantics does.

The implementation is [vm_app.rs](../kernel/src/program/vm_app.rs). The stack has
three tagged runtime types: unsigned u128, bounded bytes, and Owner. Arithmetic
is checked; division by zero, incorrect operand types, stack underflow/overflow,
invalid slices, failed assertions and exhausted fuel trap the entire invocation.
Bytecode validation checks complete operands and jump destinations at instruction
boundaries. Stack types and depths along each executed branch are checked at runtime.
Return requires exactly one integer. Branch offsets are relative to byte 13.
There is no filesystem, network, clock, randomness, or arbitrary native-code host.

The following table is specific to v4; its integer constant encoding differs from
v1–v3. Operand lists show bottom-to-top order, with the last item popped first.

| Opcode | Instruction | Operands → result |
| --- | --- | --- |
| 00 | nop | unchanged |
| 01 | u128.const | next 16 LE bytes → integer |
| 02 | add | left, right → checked sum |
| 03 | return | sole integer → return value |
| 04 / 05 | scalar.get / scalar.set | legacy i64 slot → integer / integer → slot |
| 10 | bytes.const | u16 LE length + bounded bytes → bytes |
| 11 | owner.const | Borsh Owner (33 bytes) → Owner |
| 12 / 13 / 14 | caller / self / signer | authenticated immediate caller / current program / original signer |
| 15 | data | this frame's input bytes |
| 16 / 17 / 18 | dup / drop / swap | duplicate top / discard top / exchange top two |
| 19 | equal | two values → 0 or 1 |
| 20 | jump | next u32 LE body offset |
| 21 | jump.zero | condition; next u32 LE body offset, taken when zero |
| 22 / 23 | assert / revert | nonzero condition required / unconditional trap |
| 24 / 25 / 26 | sub / mul / div | two integers → checked result |
| 27 / 28 | less / less.equal | two integers → 0 or 1 |
| 29 | integer.decode | empty bytes → 0; exactly 16 LE bytes → u128 |
| 2a | integer.encode | u128 → 16 LE bytes |
| 2b | bytes.concat | left, right → concatenated bytes |
| 30 | storage.get | key → value bytes; missing key → empty bytes |
| 31 | storage.set | key, nonempty value → write own storage |
| 32 | storage.delete | key → remove own entry |
| 33 / 34 | owner.encode / owner.decode | Owner ↔ canonical 33 bytes |
| 35 | bytes.slice | bytes, start, length → checked slice |
| 36 / 37 | bytes.length / bytes.hash | bytes → length / XPARQ Raw-domain SHA3-256 hash bytes |
| 40 | coin.transfer | recipient Owner, positive u64-compatible amount → transfer from self |
| 41 | asset.transfer | asset ID bytes, recipient Owner, positive u128 amount → transfer from self |
| 42 | asset.mint | asset ID bytes, recipient Owner, positive u128 amount → mint under self's authority |
| 43 | program.call | target Program Owner, input bytes → child return integer |
| 44 | incoming.coin | authenticated coin payment to this frame → amount in zeno |
| 45 | asset.register | Borsh RegisterAssetRequest bytes → resolved asset ID bytes |
| 46 / 47 | asset.balance / coin.balance | asset ID bytes → own asset units / own coin zeno |
| 48 | program.call.value | target Program Owner, input bytes, positive coin amount → child return integer |
| 49 | height | consensus execution height → integer |
| 4a | deployer | deploying ProgramId as Owner; grants no implicit authority |
| 4b | asset.burn | asset ID bytes, positive u128 amount → burn own shares under kernel rules |

Static transfer/register/mint opcodes 06–09 are v2/v3 instructions and are not
accepted in v4. Registration uses the same bounded request and supply rules as v3.
Mint recipient and amount can now come from calldata or computed state. The kernel
still binds the mint authority and asset ownership to the executing program.

### Authenticated frames and atomic effects

At the root, caller is `Owner::Program(signer)`, the authenticated signature-policy account. In A → B, B's caller is
`Owner::Program(A)`; signer remains the original authenticated ProgramId. Calldata
can contain an Owner, but cannot replace the caller. Programs must explicitly
compare caller against their own controller or permission state. Deployment
ownership does not automatically authorize withdrawals.

`program.call.value` transfers the caller program's coin to the target before
execution and exposes exactly that amount as incoming coin in the child. Ordinary
`program.call` exposes zero incoming coin. Cycles/reentrancy into any active
program are rejected. Calls are synchronous and share one fuel budget; traps
cannot be caught by the caller. Scalar and key/value writes, all monetary effects,
child effects and caller payment commit together or are all discarded. Rollback
journals restore original entries, including intermediate outputs consumed by a
later frame. Legacy programs can be called internally with empty calldata.

At the root, incoming coin is the sum of signed payment outputs addressed to that
program. It is not a value claimed in calldata. Root payment is settled after VM
execution, so this incoming amount is not spendable during that same invocation.
A program can atomically record deposit rights against it; if payment fails, the
recorded rights also disappear. A plain transfer to a program does not execute its
code or credit an internal depositor mapping. Deposits require an explicit call.

Version 4 dynamic transfers select the largest owned shares first, with share ID
breaking equal-amount ties, and consume at most 256 shares per transfer. This makes
amounts, input counts and fuel independent of fee-dependent new share hashes.
Change remains owned by the executing program. Legacy root transfers retain their
historical share-ID selection. Per-invocation account lookups are derived from
canonical state and are not serialized or trusted for ownership validation.

### Resource limits and charges

* Input and each bytes value: 4,096 bytes. Storage key: 1–128 bytes.
* Per-program storage: up to 4,096 entries and 1 MiB canonical map bytes.
  Values are 1–4,096 bytes; deletion is a separate instruction.
* Stack: up to 256 items, with total payload bounded by declared pages.
* Depth: eight frames including the root. Total calls: 64 including the root.
* Total state-write/monetary actions: 256 per invocation.
* Shared fuel: 65,536, including all child frames and memory declarations.

Base instructions cost 1; storage.get costs 2 and set/delete cost 5. Transfers, asset burn and
mint cost 20, program.call costs 20, and register adds 40 to its base instruction.
call.value adds 20 for the call and 20 for the transfer to its base instruction.
Copied calldata, byte constants, duplicated byte values, concatenation, slices,
hashing, storage key/value access and child input additionally charge by byte.
Dynamic coin/asset transfers additionally charge one fuel per selected input.
Balance lookups use invocation-local aggregates. An internal legacy call charges
its legacy fuel plus the outer call cost and selected coin-input cost; its monetary actions remain bounded.
Fuel is burned separately from archival and positive net state growth.

Burn quotes and commits use the same interpreter and settlement. Growth is
measured from touched-entry journals without serializing every deployed program
or asset share, and checked against full canonical encoding in tests. Growth covers
positive net canonical registry storage plus extension asset-state growth, and
coin UTXO counts are calculated after removing transient create/consume pairs.
Changing an existing value without increasing its encoding size adds no state
growth burn; shrinking state gives no refund.

### Wallet and protocol envelope

```sh
wallet program-call --program-id HEX_ID --data HEX_CALLDATA
wallet program-call --program-id HEX_ID --deposit 1 --data HEX_CALLDATA
```

`--data` is raw hex, up to 4,096 decoded bytes. `--deposit` is XPQ denominated and
adds a signed payment output owned by that program; it is included in input
selection, quotes and automatic fees. Both work with `--offline`, which still
requires RPC for state and quotes. The root caller pays fuel, archival/state burn
and miner fee for the whole call tree.

Opcode 0 envelopes retain exactly the 32-byte ProgramId payload. Opcode 1 envelopes
carry ProgramId followed by up to 4,096 input bytes. The signed commitment includes
all input bytes and payment outputs. `/program/quote` additionally returns
`vm_return_value` as a decimal string (null for non-VM calls); this is a preview,
not a committed transaction receipt.

The current protocol uses chain-spec version 1 and database schema 1. Coin and
asset share IDs are full 32-byte hashes. Bytecode
versions 1–4 remain supported with the current program-only Owner encoding, but databases committed to
an older chain identity are rejected. No migration of an existing chain is included.

Read public application storage with `GET /program/state/HEX_ID/HEX_KEY`.
The key is 1–128 decoded bytes. The response contains a hex value (null for a
missing key), height and tip hash. Applications define the key layout; the node
needs no application-specific endpoint or binary change. Storage is public ledger
state and must not contain secrets.

All Owner values encode Borsh tag 0 followed by a 32-byte ProgramId. There is no
separate address type or display encoding. `signer` and `deployer` instructions
return program instances. Transfers can receive at undeployed IDs; these resolve
to the stateless signature policy until a deployed instance exists. Executing a
bytecode call still requires a registered program. Application logic must check
caller authorization explicitly.
