# Program code decoding hardening

`DeployProgram` and `ProgramRecord` now use an explicitly bounded Borsh code
reader. A length prefix greater than the existing 1 MiB code limit is rejected
before payload reads or code-buffer allocation. This also covers deployment
operations nested in blocks and records nested in snapshot registries.

For permitted lengths, bytes are read in chunks of at most 8 KiB. The code
buffer grows after a complete chunk arrives, using fallible reservation. A
truncated input cannot force allocation of its entire claimed code length.
The buffer can still grow to the permitted code size when the data is present.
This is a per-code-field bound, not a total snapshot memory or network deadline.

The encoding, field order, and existing code limit are unchanged. Oversized
objects that previously decoded and then failed validation now fail decoding.
Structural bytecode validation remains in the existing deployment and registry
validation paths. Decoding alone does not authenticate a deployment.

## Regression coverage

`kernel/tests/decoding_bounds.rs` checks:

- Prefixes of 1 MiB plus one and `u32::MAX` for deployment, operation, record,
  and registry readers. A guarded reader fails if the decoder tries to read a
  payload after an oversized prefix, independently of EOF behavior.
- Encoding compatibility and roundtrips at zero, one, chunk boundaries,
  and exactly 1 MiB. Zero-length code still fails deployment validation.
- Every truncation point, trailing bytes, and 512 deterministic byte mutations
  each for deployment, record, registry, and program-call encodings. Accepted
  mutations must re-encode to exactly the input bytes.
- An impossible registry count and a maximum permitted code prefix without
  corresponding payload bytes.

These are bounded deterministic mutation tests, not a coverage-guided fuzzing
campaign or a proof that all decoders are safe. Block operation counts, program
call payload bounds, and coin list bounds retain their existing protections.

## Verification

Kernel and extension tests pass with the three previously documented chain
identity fixtures explicitly excluded. All eight node snapshot/storage tests
pass. Workspace compilation, formatting, and Clippy pass with existing warnings.
The existing chain identity fixture failures remain a release gate.

See [verification results](audit/program-decoding-verification.txt).
