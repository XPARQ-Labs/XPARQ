# Hash domain and error audit — 2026-10-09

Scope: first-party Rust sources under crypto, kernel, extension, runtime, wallet,
and devkit, including tests/benches/examples. Vendored algorithms were excluded.
References, constructors, conversions and matches were checked; lack of a direct
`Type::Variant` call alone was not treated as evidence of dead code.

## Hash findings and cleanup

One `HashDomain` enum existed with 25 variants. Seven had no call sites outside
the declaration/tag mapping: TransactionCommit, Block, ChainParams,
AuthorizationProof, StateNode, BlockStateCommitment, XPQState. They were removed.
Eighteen active contexts remain. Raw is used by `hash_bytes`; MerkleNode flows
through a context argument; AccountState is an active explorer fingerprint.

`domain_hash` duplicated `domain` as a forwarding function. The compatibility
alias has been removed; all callers use `domain` directly.
The byte-slice and streaming implementations remain distinct because they serve
buffered and borrowed serialization inputs, with the same framing.

All active v1 tags and framing are unchanged. Independent SHA3-256 golden vectors
for the 18 active tags now guard that invariant. Removing unused enum variants
can break downstream Rust references or assumptions about enum ordinals; the
enum is not part of canonical wire encoding.

The requested single-prefix protocol redesign is specified in
[HASH_PROTOCOL_V2.md](../HASH_PROTOCOL_V2.md). It remains a proposal, with separate
candidate vectors, and has not replaced active v1 hashing.

## Error findings and cleanup

Removed six variants without constructors or consuming branches in the workspace:

| Error | Removed variant |
| --- | --- |
| CryptoError | InvalidKeyDerivationParameters |
| BlockError | InvalidEmission |
| BlockError | InvalidStateRoot |
| LedgerError | MissingParentEmission |
| ProgramConsensusError | SignatureSchemeInactive |
| AssetError | InsufficientBalance |

ConsensusError::InvalidEmission remains active. LedgerError::InvalidStateRoot
remains active. Amount/balance errors and authorization checks remain active;
removing the unused similarly named cases does not remove those checks.

The one-variant ProgramEncodingError duplicated IntentError::Encoding. Public
ProgramEncodingError paths remain as aliases to IntentError; authorization code
now uses IntentError directly. Formatting the encoding failure now yields
`intent encoding failed` instead of `program envelope encoding failed`.
The alias exposes the other IntentError variants, so downstream exhaustive
matches covering only Encoding must be updated. These are Rust API changes,
not serialized transaction/ledger changes.

Do not flatten every error into a string or an undifferentiated failure. The
existing LedgerError is already the application/ledger boundary error and wraps
useful consensus, deploy, state, chain and emission causes. Those wrappers are
constructed through From conversions even where qualified variant references
are absent. Error types encode different capabilities and recovery decisions.

A single boundary error can be achieved by standardizing ledger-facing entry
points on LedgerError and retaining typed causes internally. CodecError should
remain the shared serialization error; VM code/execute errors distinguish
malformed bytecode from execution failures. This audit reduces redundancy rather
than discarding recoverable error information.

## Remaining refactor candidates

- `consensus/program_call.rs`: validation phases and a narrower read-only state view.
- `consensus/fork.rs`: chainwork arithmetic, fork-choice graph and reorg planning.

Neither candidate was refactored as part of this audit.

## Verification

Default/mainnet checks passed: 3 crypto hash tests, 44 ledger tests, 23 VM tests,
3 program-call consensus tests, 2 authorization tests and 5 extension boundary
tests (80 passed, 8 deliberately ignored). Frozen mainnet lifecycle vectors and
the new active-domain golden vectors passed without changing expected hashes.
Workspace compilation, crypto/kernel Clippy with warnings denied, formatting
for crypto/kernel and the changed runtime file, and diff whitespace checks passed.
Optional signature/network feature builds were not executed in this audit.

The 36 candidate v2 vectors were independently computed with Python SHA3-256 for
empty and nonempty payloads across all 18 proposed contexts. They are design
artifacts; no Rust v2 hash implementation has been verified or activated.
