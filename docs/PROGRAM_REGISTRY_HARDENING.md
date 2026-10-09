# Program registry hardening

Deploy burn quotes now prepare and serialize only the new program key/record.
The Borsh registry map has a fixed four-byte entry count, so adding an entry
increases its encoding by exactly the serialized key and record size. Quotes
no longer clone or serialize the existing registry. An auxiliary owner/nonce
index replaces the previous linear duplicate-deployment scan with a logarithmic
lookup. Quote work still depends on the submitted code and payment size.

The index is omitted from serialization and rebuilt during deserialization.
Insertion and rollback removal update both structures. Existing canonical state
bytes, program IDs, state roots, and burn amounts are preserved for valid state.
This change does not add a protocol version or alter valid deployment rules.

Registry deserialization rejects invalid bytecode, incorrect code hashes,
incorrect program IDs, duplicate owner/nonce deployments, and duplicate or
unordered map keys. Snapshot recovery additionally audits the registry and
rejects deployment heights beyond the recovered tip. Malformed snapshots that
previously decoded may now be rejected, even if their root was self-consistent.
This audit does not prove that every stored record was historically authorized;
that still depends on the existing trusted snapshot and verified chain model.
Rollback journals retain the existing parent-state-root validation.

## Verification

- A regression compares optimized quotes against the previous implementation
  over 32 successive deployments, including duplicate rejection and unchanged
  input state.
- A 128-entry test checks exact encoded growth and canonical bytes, rebuilding
  the index on each restore, rejecting reused owner/nonces with different code,
  and permitting redeployment after rollback.
- Corrupted record and duplicate-key tests cover decoder rejection; snapshot
  recovery tests cover future deployment heights and existing replay/reorg flow.
- Kernel and extension tests pass with the three known chain identity fixtures
  explicitly excluded: 89 kernel unit tests, five supply invariant tests, five
  application boundary tests, and four compile-fail documentation tests.
- All eight node snapshot/storage tests pass, including restart and rollback.
- Workspace compilation, formatting, and Clippy pass with existing warnings.

The unfiltered kernel unit run still fails the two previously documented chain
identity fixtures. The third known fixture is in the integration test suite.
These fixtures remain a release gate; they were not regenerated here.

See [verification results](audit/program-registry-verification.txt).
