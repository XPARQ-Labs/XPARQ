# Program ID derivation and authorization

`ProgramId::signature_account(scheme, public_key)` validates the exact public-key
length before hashing. `program_id_from_public_key(&PublicKey)` returns the same
checked default identity using a zero salt. The `_with_salt` variants derive
additional account instances without changing keys. Neither function proves key possession: spending additionally
requires a valid signature against the chain-bound transaction commitment.

The SHA3-256 preimage is the framed domain `XPARQ_HASH_PROGRAM_ACCOUNT`, the
little-endian u64 material length, then `xparq:signature-policy:v2`, scheme ID,
full canonical public-key bytes, and 32 public salt bytes. Scheme IDs remain 1/2/3 for ML-DSA44/65/87; Pure SLH-DSA SHAKE128s/192s/256s use 5/6/7. See [signature schemes](SIGNATURE_SCHEMES.md).
The immutable policy domain distinguishes these instances from deployed code.

Program IDs use exactly 64 hexadecimal characters. Parsing checks length before
decoding; output is lowercase. No separate identity checksum, Base56 parser or
wallet address type remains. Receiving at an ID does not establish key possession.

The ledger has `Owner::Program(ProgramId)` only. Registered instances cannot fall
back to signature-policy spending. Kernel input ownership, supply, fees and burn
checks apply after authorization. See [ownership and APIs](OWNERSHIP.md).

Tests cover exact encoding bounds, independent derivation fixtures, scheme/key
and salt binding, wrong-key and cross-chain proofs, contract ownership, monetary conservation,
rollback, wallet workflows and database restart. Chain-spec 1/schema 1 separate
the new salted identities from old ledgers and proofs. Wallet-file version 2
preserves the active salt and salt list; old files require explicit restoration.
There is no automatic migration.
