# Single-prefix hash protocol v2

Status: design proposal. This document and its candidate vectors do not activate
v2 hashing. Production continues to use the active v1 context tags.

## Objective and limits

Use one global hash-domain prefix and one implementation of SHA3-256 framing.
Keep explicit purpose context inside the hashed message. One global prefix does
not mean one undifferentiated security context: headers, transactions, share IDs,
state roots, and PoW inputs must remain distinguishable even for equal payloads.

NIST SP 800-185 describes explicit customization and unambiguous input framing:
[official publication](https://csrc.nist.gov/pubs/sp/800/185/final). This proposal
retains SHA3-256 with XPARQ-specific framing; it is not an implementation of cSHAKE
or a claim of SP 800-185 conformance.

## Exact framing

Define:

```text
HASH_DOMAIN  = ASCII("XPARQ_HASH")       # exactly 10 bytes, no terminator
HASH_VERSION = 2                       # u16 little endian
context      = fixed purpose ID        # u16 little endian
payload_len  = encoded payload bytes   # u64 little endian

hash = SHA3-256(HASH_DOMAIN || LE16(HASH_VERSION) || LE16(context)
               || LE64(payload_len) || payload)
```

All integers use fixed-width little-endian encoding. The digest is 32 bytes.
Context IDs are protocol constants, never enum ordinals. Zero and unassigned IDs
are reserved; production callers cannot supply arbitrary integers. Assignments
must never be reused for a different purpose.

Preserve current payload bytes and their existing purpose/version tags for this
migration. Removing inner tags is a separate protocol change. In particular,
Artifact, Transaction, AssetIntent, and Emission currently serve multiple typed
inputs; their distinct payload shapes/tags must be retained. Different contexts
must produce different vector results for equal payloads.

The byte-slice and streaming implementations write the same prefix, version,
context and length before payload bytes. Streaming must reject length mismatch,
serialization failure and length overflow without returning a partial digest.

## Context assignments and current source ownership

| ID | Context | Primary source |
| --- | --- | --- |
| 1 | Transaction | `kernel/src/program/authorization.rs` |
| 2 | Operation | `kernel/src/operation.rs`, runtime mempool IDs |
| 3 | CoinTransition | `kernel/src/program/coin_transition.rs` |
| 4 | AssetIntent | Authorization, asset execution and VM monetary effects |
| 5 | Header | `kernel/src/blockchain/block.rs` |
| 6 | ChainSpec | `kernel/src/genesis/mod.rs` |
| 7 | MerkleNode | `kernel/src/blockchain/merkle.rs`, block proofs |
| 8 | AccountState | Runtime explorer UTXO snapshot fingerprint |
| 9 | Artifact | Program code hash, deployed ProgramId and deploy authorization |
| 10 | ProtocolState | `kernel/src/ledger/canonical/state_root.rs` |
| 11 | PoWSeed | `kernel/src/consensus/pow.rs` |
| 12 | PoWSalt | `kernel/src/consensus/pow.rs` |
| 13 | ProgramAccount | `crypto/src/program_id.rs` |
| 14 | Asset | `kernel/src/monetary/asset.rs` |
| 15 | Share | Asset share IDs |
| 16 | Output | Native coin output IDs |
| 17 | Emission | Emission hashes/origins and emission coin IDs |
| 18 | Raw | `crypto::hash_bytes`, including VM hashing |

AccountState is derived RPC data; it is not the canonical ledger root. Raw is
active even though callers use `hash_bytes` rather than naming its context.

## Proposed Rust interface

```rust
pub const HASH_DOMAIN: &[u8; 10] = b"XPARQ_HASH";
pub const HASH_VERSION: u16 = 2;

// Explicit #[repr(u16)] discriminants from the table; no public raw-ID constructor.
pub enum HashContext { /* Transaction = 1, ... Raw = 18 */ }

pub fn hash(context: HashContext, payload: &[u8]) -> Hash;
pub fn hash_serialized<T: BorshSerialize>(
    context: HashContext,
    encoded_len: u64,
    value: &T,
) -> Result<Hash, CodecError>;
```

Callers should prefer typed constructors such as `ProgramId::derive`,
`CoinShare::from_output`, and block/header hash helpers. The generic hash entry
point exists in crypto; context selection stays beside each canonical type.
`hash_bytes` uses Raw. A compatibility function name may be a re-export of the
same implementation rather than another forwarding function.

Signature-library internal hashing remains unchanged. This proposal affects
XPARQ protocol hashes, not ML-DSA/SLH-DSA algorithm internals or wallet KDF rules.
PoW Argon2 parameters remain unchanged; its seed and salt hashes change.

## Activation and compatibility

Every active XPARQ context changes digest under v2. Consequently genesis identity,
chain-spec hash, block/header IDs, state roots, Merkle roots/proofs, transaction
and operation IDs, ownership ProgramIds, code/asset/share IDs, authorization
commitments and PoW change. AccountState fingerprints and Raw VM hash results
also change.

Recommended activation is a new chain with fresh storage. Do not enable v2 on
an existing database or silently reinterpret historical blocks. Keep old-chain
funds and databases separate; key recovery does not transfer funds or preserve
old ProgramIds. Wallet salts/signature schemes still matter for identity.

Activation work must include:

1. Assign a new chain-spec identity/version and bind hash protocol version/context
   assignments in the chain specification. Bump database schema or explicitly
   reject stored v1 chain identity before loading state.
2. Update every protocol hash call site together, including runtime mempool IDs,
   explorer fingerprints, wallet identities, devkit and VM Raw hashing.
3. Rebuild genesis state/roots, compute genesis hash, and update all network
   identity/handshake fixtures. Resolve construction dependencies in the same
   order as current genesis generation; do not introduce genesis-dependent hash
   framing because chain-spec/genesis already determine chain identity.
4. Regenerate frozen vectors and compatibility fixtures intentionally. Existing
   v1 fixtures are preserved until activation; merely changing expectations is
   not proof of compatibility or correctness.
5. Update wallet/node/RPC docs and example ProgramIds. Reject v1 peers, snapshots,
   transactions and incompatible wallet identities consistently.

For an existing-chain hard fork instead, a separate height/version schedule and
v1 historical verifier are required. That design is outside this new-chain
proposal; mixing one global v2 setting with old-chain history is invalid.

## Required verification before activation

- Freeze exact context assignments and framing against independently computed
  SHA3-256 vectors. Candidate vectors are in `audit/hash-v2-vectors.json`.
- Cover empty and nonempty payloads, context distinction, length framing,
  streaming equivalence and serialization failures.
- Verify signature commitments, account salt/scheme binding and rejection across
  v1/v2 chain identities.
- Verify chain-spec/genesis identity, header PoW, Merkle proofs, ownership,
  monetary conservation, deterministic VM output, replay and atomic rollback.
- Verify snapshot restore/recovery, persistent mempool IDs, RPC fingerprints,
  node restart and legacy/litep2p handshakes for each network feature separately.

No production v2 implementation or activation has been performed in this audit.
