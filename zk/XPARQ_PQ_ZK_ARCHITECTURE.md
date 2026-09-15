# XPARQ Post-Quantum Zero-Knowledge Architecture

## Status

**Design stage / research prototype**

This document defines a proposed architecture and production flow for a post-quantum-oriented zero-knowledge proof system for XPARQ.

The current direction is based on reusable Arkworks components that do not fundamentally depend on elliptic-curve discrete logarithms or pairings, combined with a new XPARQ proof layer.

This is **not yet a production-ready post-quantum ZK system**. The final security properties must be proven and independently reviewed before consensus deployment.

---

# 1. Objective

The goal is to build a zero-knowledge proof system for XPARQ private transactions with the following properties:

- No Groth16 dependency.
- No elliptic-curve pairing dependency.
- No discrete-log-based polynomial commitments.
- No KZG.
- No IPA-based commitment as a core security assumption.
- No trusted toxic-waste setup.
- Hash/Merkle-based commitments where possible.
- Compatible with XPARQ consensus requirements.
- Deterministic verification.
- Canonical serialization.
- Domain-separated hashing.
- Explicit versioning and future cryptographic agility.

The target is a proof stack that is **post-quantum-oriented by construction**, rather than a classical proof system with a post-quantum signature attached to it.

---

# 2. Main Architectural Decision

The original direction:

```text
XPARQ
  ↓
Groth16
  ↓
Pairing
  ↓
Elliptic Curve
```

is rejected for the PQ proof layer.

The new direction is:

```text
XPARQ Private Statement
        ↓
Private Witness
        ↓
Constraint / Polynomial Relation
        ↓
Zero-Knowledge Masking
        ↓
Multilinear Sumcheck
        ↓
Multilinear Brakedown PCS
        ↓
Merkle Tree + Hash
        ↓
Fiat-Shamir Transcript
        ↓
Non-Interactive Proof
```

The core idea is to separate:

1. **computation representation**
2. **zero-knowledge masking**
3. **sumcheck**
4. **polynomial commitment**
5. **transcript**
6. **blockchain verification**

Each layer should have a narrow interface and independently testable behavior.

---

# 3. Components Selected for Further Work

## 3.1 Arkworks Field Arithmetic

Candidate reusable components:

```text
ark-ff
ark-poly
```

Purpose:

- finite-field arithmetic
- multilinear polynomial representation
- polynomial evaluation
- common arithmetic abstractions

These are not inherently pairing-based.

---

## 3.2 Multilinear Sumcheck

Candidate:

```text
ark-linear-sumcheck
```

Relevant abstraction:

```rust
pub struct MLSumcheck<F: Field>(...);
```

Purpose:

- prove claims about sums of multilinear polynomial evaluations
- reduce a large computation claim into smaller evaluation claims
- provide the algebraic backbone of the proof protocol

Important:

**Sumcheck alone is not zero-knowledge.**

A separate masking layer is required.

---

## 3.3 Multilinear Brakedown Polynomial Commitment

Candidate:

```text
ark-poly-commit
└── linear_codes
    └── MultilinearBrakedown
```

Observed construction:

```text
Multilinear Polynomial
        ↓
Coefficient / Evaluation Vector
        ↓
Matrix Representation
        ↓
Linear Encoding
        ↓
Sparse Matrix Operations
        ↓
Reed-Solomon Encoding
        ↓
Column Hashing
        ↓
Merkle Tree
        ↓
Merkle Root Commitment
```

Core dependencies are based on:

```text
PrimeField
CRHScheme
MerkleTree
Linear Encoding
Reed-Solomon
```

No pairing or elliptic-curve group is required by the linear-code PCS interface.

### Important limitation

Current Arkworks `MultilinearBrakedown` explicitly does **not support hiding**.

Therefore:

```text
Brakedown PCS ≠ Zero-Knowledge
```

The protocol must mask private witness information before data is committed or opened.

---

## 3.4 Spongefish Transcript

Candidate:

```text
spongefish
```

Purpose:

- Fiat-Shamir transformation
- transcript binding
- prover messages
- verifier challenges
- secret prover coins
- non-interactive argument construction

The transcript layer should replace ad-hoc challenge generation.

Target use:

```text
Protocol Messages
      ↓
Spongefish Transcript
      ↓
Domain-Separated Challenges
      ↓
Non-Interactive Proof
```

---

# 4. Components Rejected for the PQ Core

## 4.1 Groth16

Rejected as the primary PQ proof system because its implementation is structurally bound to:

```text
Pairing
G1
G2
TargetField
Miller Loop
Final Exponentiation
```

Changing the signature algorithm around Groth16 does not make Groth16 post-quantum.

---

## 4.2 KZG

Rejected because KZG is pairing-based.

```text
KZG
 ↓
Pairing
 ↓
Elliptic Curve Discrete Log
```

---

## 4.3 IPA Polynomial Commitments

Rejected for the PQ core because the Arkworks implementation uses elliptic-curve group operations.

Even without pairings, elliptic-curve discrete logarithm remains vulnerable to Shor's algorithm.

---

## 4.4 Ark-Spartan as a Whole

Ark-Spartan is useful as a **reference architecture**, but not as a direct PQ implementation.

Its core types are strongly tied to:

```rust
G: CurveGroup
```

Examples include:

```text
PolyCommitment<G>
ZKSumcheckInstanceProof<G>
R1CSProof<G>
SNARK<G>
NIZK<G>
```

The useful part is the protocol design:

```text
R1CS
 ↓
Multilinear Polynomial
 ↓
ZK Sumcheck
 ↓
Blinding
 ↓
Polynomial Evaluation Proof
```

The classical commitment layer should be replaced.

---

# 5. Target XPARQ Proof Stack

```text
+---------------------------------------------------+
|                    XPARQ                          |
+---------------------------------------------------+
| Transaction / State Transition Statement          |
+---------------------------------------------------+
| Public Input       | Private Witness              |
+---------------------------------------------------+
| Constraint / Relation Builder                     |
+---------------------------------------------------+
| Multilinear Polynomial Representation             |
+---------------------------------------------------+
| Zero-Knowledge Masking Layer                      |
+---------------------------------------------------+
| Multilinear Sumcheck                              |
+---------------------------------------------------+
| Multilinear Brakedown PCS                         |
+---------------------------------------------------+
| Merkle Tree + Cryptographic Hash                  |
+---------------------------------------------------+
| Spongefish Fiat-Shamir Transcript                 |
+---------------------------------------------------+
| Canonical XPARQ Proof Encoding                    |
+---------------------------------------------------+
| Kernel Verification                               |
+---------------------------------------------------+
```

---

# 6. Production Proof Generation Flow

This section describes the intended prover pipeline.

## Step 1 — Build the Public Statement

The transaction defines the public statement.

For a future private UTXO spend, public inputs may include:

```text
chain_id
proof_version
state_root
nullifier(s)
output_commitment(s)
fee
transaction_domain
```

Private data must not be included in the public statement unless explicitly required.

Possible private witness:

```text
input ownership secret
input amount
input opening data
membership path
randomness
output amount
output randomness
authorization secret
```

---

## Step 2 — Validate Witness Locally

Before proof generation, the wallet/prover checks:

```text
input exists
input is spendable
ownership is valid
input amount is valid
output amounts are valid
fee is valid
value conservation holds
membership path is valid
nullifier derivation is valid
```

Invalid witnesses should fail before expensive proving begins.

---

## Step 3 — Convert the Statement Into Constraints

The statement and witness are translated into a deterministic relation.

Conceptually:

```text
R(public_input, private_witness) = true
```

For example:

```text
VerifyMembership(input_commitment, state_root)
AND
VerifyOwnership(secret, input_commitment)
AND
Nullifier = H(secret, input_id)
AND
sum(inputs) = sum(outputs) + fee
AND
output_commitments are correctly formed
```

The exact constraint representation is still an open design decision.

Possible options:

```text
R1CS
custom multilinear relation
GKR-style circuit
custom arithmetic constraint system
```

---

# 7. Zero-Knowledge Masking Layer

This is the most security-critical missing layer.

The goal is to prevent proof messages and polynomial openings from revealing the witness.

The design should be inspired by Spartan's blinding structure, but must not depend on elliptic-curve commitments.

A conceptual masking flow:

```text
Witness Polynomial W
        +
Random Mask Polynomial R
        ↓
Masked Polynomial W'
        ↓
Commit W'
        ↓
Run Sumcheck
        ↓
Open Only Required Queries
```

Possible mask domains include:

```text
witness polynomial
intermediate claims
sumcheck round polynomials
evaluation claims
opening values
```

Randomness must be fresh for every proof.

Never reuse prover secret randomness.

---

# 8. Sumcheck Production Flow

The masked multilinear relation is processed by sumcheck.

Conceptual sequence:

```text
Initial Claim
     ↓
Round 0 Polynomial
     ↓
Transcript Challenge r0
     ↓
Round 1 Polynomial
     ↓
Transcript Challenge r1
     ↓
...
     ↓
Final Evaluation Claim
```

Each challenge must be derived from the transcript.

No challenge should be chosen independently of previous protocol messages.

Example conceptual domain separation:

```text
XPARQ/ZK/SUMCHECK/ROUND/0
XPARQ/ZK/SUMCHECK/ROUND/1
XPARQ/ZK/SUMCHECK/ROUND/2
```

---

# 9. Brakedown Commitment Production

The multilinear polynomial is committed using the linear-code PCS.

Conceptual flow:

```text
Polynomial Evaluations
        ↓
Matrix Layout
        ↓
Sparse Linear Encoding
        ↓
Reed-Solomon Extension
        ↓
Encoded Matrix
        ↓
Hash Each Column
        ↓
Merkle Tree
        ↓
Merkle Root
```

The commitment published in the proof is primarily:

```text
metadata
merkle_root
```

Opening proofs contain:

```text
requested columns
Merkle authentication paths
linear-code opening data
well-formedness data
```

The zero-knowledge layer must ensure these openings do not expose witness data.

---

# 10. Fiat-Shamir Production Flow

The interactive protocol is converted into a non-interactive proof.

Prover:

```text
Initialize transcript
        ↓
Absorb protocol version
        ↓
Absorb chain domain
        ↓
Absorb public statement
        ↓
Absorb PCS commitment
        ↓
Absorb prover round message
        ↓
Derive challenge
        ↓
Absorb next message
        ↓
Derive next challenge
        ↓
...
        ↓
Finalize proof
```

Verifier performs exactly the same transcript reconstruction.

Any mismatch causes verification failure.

---

# 11. Canonical Proof Structure

A possible future representation:

```rust
pub struct XparqZkProof {
    pub version: u16,
    pub protocol: ProofProtocol,
    pub statement_hash: [u8; 32],

    pub commitments: Vec<Commitment>,
    pub sumcheck: SumcheckProof,
    pub openings: Vec<OpeningProof>,

    pub transcript_binding: TranscriptBinding,
}
```

Possible protocol enum:

```rust
pub enum ProofProtocol {
    BrakedownSumcheckV1,
}
```

Consensus code should reject unknown proof versions unless activated by protocol rules.

---

# 12. Verification Production Flow

Node verification should be deterministic.

```text
Receive Transaction
      ↓
Decode Canonically
      ↓
Check Proof Version
      ↓
Reconstruct Public Statement
      ↓
Reconstruct Fiat-Shamir Transcript
      ↓
Verify Sumcheck
      ↓
Verify Brakedown Openings
      ↓
Verify Merkle Paths
      ↓
Verify Final Polynomial Claims
      ↓
Verify Transaction-Level Conditions
      ↓
Accept / Reject
```

The node must never require the private witness.

---

# 13. Blockchain Integration

Recommended layering:

```text
wallet
  └── proof generation

zk crate
  ├── statement
  ├── witness
  ├── masking
  ├── sumcheck
  ├── commitment
  ├── transcript
  ├── proof encoding
  └── verifier

kernel
  └── verification only

runtime/node
  └── transaction admission + block validation
```

The kernel should not generate proofs.

The wallet or external prover generates them.

---

# 14. Proposed XPARQ Repository Layout

```text
XPARQ/
├── crypto/
├── kernel/
├── runtime/
├── wallet/
├── extension/
└── zk/
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── error.rs
        ├── protocol.rs
        ├── statement.rs
        ├── witness.rs
        ├── masking.rs
        ├── field.rs
        ├── relation/
        │   ├── mod.rs
        │   └── private_spend.rs
        ├── sumcheck/
        │   ├── mod.rs
        │   ├── prover.rs
        │   └── verifier.rs
        ├── commitment/
        │   ├── mod.rs
        │   └── brakedown.rs
        ├── transcript/
        │   ├── mod.rs
        │   └── spongefish.rs
        ├── proof/
        │   ├── mod.rs
        │   ├── encode.rs
        │   └── decode.rs
        └── tests/
```

---

# 15. Consensus Boundary

Consensus should only depend on stable, versioned interfaces.

Example:

```rust
pub trait ZkVerifier {
    fn verify(
        statement: &PublicStatement,
        proof: &XparqZkProof,
    ) -> Result<(), ZkError>;
}
```

The kernel should not know the internal prover implementation.

This allows future proof-system upgrades.

---

# 16. Proof Versioning

Never hard-code one proof system forever.

Example:

```rust
pub enum ZkProof {
    V1BrakedownSumcheck(BrakedownSumcheckProof),
    // future versions
}
```

Activation should be consensus-controlled:

```text
height < activation
    → reject new proof version

height >= activation
    → accept activated proof version
```

---

# 17. Parameter Generation

Brakedown public parameters should be deterministic for consensus use.

Do not allow every node to randomly generate its own parameter set.

Recommended model:

```text
Canonical Domain
      +
Canonical Seed
      ↓
Deterministic RNG
      ↓
Brakedown Public Parameters
      ↓
Parameter Hash
      ↓
Consensus Constant
```

Example conceptual domains:

```text
XPARQ/ZK/PARAMETERS/V1
XPARQ/ZK/BRAKEDOWN/V1
```

Nodes should verify the expected parameter hash.

---

# 18. Hash Strategy

The hash layer should support domain separation.

Example domains:

```text
XPARQ/ZK/MERKLE/LEAF/V1
XPARQ/ZK/MERKLE/NODE/V1
XPARQ/ZK/COLUMN/V1
XPARQ/ZK/TRANSCRIPT/V1
XPARQ/ZK/STATEMENT/V1
XPARQ/ZK/NULLIFIER/V1
```

The exact hash function and digest size must be selected with the target post-quantum security level in mind.

Do not assume:

```text
protocol security parameter = hash security
```

They must be analyzed separately.

---

# 19. Security Properties Required Before Mainnet

The final system must provide clear arguments for:

## Completeness

A valid witness produces a proof accepted by honest verifiers.

## Soundness

A prover without a valid witness cannot create an accepted proof except with negligible probability.

## Zero-Knowledge

The proof reveals no useful information about the private witness beyond the public statement.

## Binding

Commitments cannot be opened to conflicting values.

## Transcript Binding

All proof messages and public inputs are cryptographically bound to the Fiat-Shamir transcript.

## Replay Resistance

Proofs cannot be reused in unintended transaction or chain contexts.

## Domain Separation

Every hash/challenge context has a unique protocol domain.

## Canonical Encoding

No alternate byte encodings may represent the same semantic proof.

---

# 20. PQ Security Boundary

The current candidate stack avoids the most obvious classical dependencies:

```text
No Pairing
No EC Discrete Log
No KZG
No IPA Commitment
```

However this alone does **not prove post-quantum security**.

The following must still be analyzed:

```text
hash security under Grover
Fiat-Shamir security in the quantum random-oracle model
linear-code PCS soundness
sumcheck soundness
masking construction
parameter size
query complexity
proof composition
serialization attacks
implementation side channels
```

---

# 21. Development Phases

## Phase 0 — Research Freeze

Goal:

Define exactly what is being built before touching consensus.

Tasks:

```text
document protocol assumptions
select field
select hash
select transcript
select Brakedown parameters
define private-spend statement
define witness
define proof version
```

Output:

```text
XPARQ-ZK-SPEC-v0.md
```

---

## Phase 1 — Standalone Math Prototype

Create:

```text
xparq-zk
```

No kernel integration.

Implement:

```text
field
simple multilinear relation
sumcheck
Brakedown commitment
transcript
proof encoding
```

Test using a toy relation:

```text
a * b = c
```

Then:

```text
x + y = z
```

Then a small conservation relation.

---

## Phase 2 — Zero-Knowledge Masking Prototype

Implement witness masking.

Test:

```text
same statement
different witness randomness
→ different proofs

same witness
different randomness
→ different proofs

proof
→ no direct witness values visible
```

This phase requires mathematical review.

---

## Phase 3 — Private Spend Prototype

Implement a minimal private-spend relation.

Example:

```text
input commitment exists
ownership secret is valid
nullifier is correctly derived
input value = outputs + fee
output commitments are valid
```

The first prototype should use one input and two outputs.

Avoid multi-input complexity initially.

---

## Phase 4 — Deterministic Verification

Verifier must:

```text
not allocate unbounded memory
not trust serialized lengths
reject malformed proofs
reject trailing bytes
reject non-canonical field encodings
reconstruct transcript exactly
```

Fuzz proof decoding.

---

## Phase 5 — Benchmarking

Measure:

```text
proof size
proving time
verification time
peak RAM
parameter size
Merkle query count
sumcheck rounds
transaction size
block verification cost
```

Benchmark at:

```text
1 input / 2 outputs
2 inputs / 2 outputs
4 inputs / 4 outputs
8 inputs / 8 outputs
```

---

## Phase 6 — Kernel Integration

Only after the standalone verifier is stable.

Kernel integration should expose:

```rust
verify_private_spend(...)
```

The kernel must not expose prover internals.

---

## Phase 7 — Wallet Integration

Wallet responsibilities:

```text
collect witness
build statement
generate nullifier
generate output commitments
create proof
assemble transaction
submit transaction
```

Proof generation belongs here or in a dedicated prover service.

---

## Phase 8 — Testnet

Test:

```text
valid proofs
invalid proofs
mutated proofs
replayed proofs
wrong chain ID
wrong state root
wrong nullifier
wrong fee
malformed commitment
malformed Merkle path
wrong transcript challenge
incorrect proof version
oversized proof
```

---

## Phase 9 — Security Review

Before mainnet:

```text
protocol review
cryptographic review
implementation review
consensus review
fuzzing
differential testing
benchmark review
parameter review
```

A new custom ZK protocol should not be treated as production-safe without external cryptographic review.

---

# 22. Test Strategy

## Unit Tests

```text
field encoding
Merkle hashing
parameter derivation
sumcheck rounds
transcript challenges
commitment opening
proof encoding
proof decoding
```

## Negative Tests

```text
wrong root
wrong opening
wrong challenge
wrong claimed evaluation
wrong witness
wrong nullifier
wrong output amount
wrong fee
wrong chain domain
```

## Determinism Tests

Verification must be deterministic.

Parameter generation must be deterministic.

Proof generation should intentionally remain randomized for zero-knowledge.

---

# 23. Production Rules

The following rules should be treated as hard requirements:

1. **No prover randomness reuse.**
2. **No hidden consensus randomness.**
3. **No node-local parameter generation.**
4. **No ambiguous serialization.**
5. **No unbounded proof allocation.**
6. **No unversioned proof format.**
7. **No silent fallback to classical commitments.**
8. **No proof verification outside consensus rules.**
9. **No unchecked transcript fields.**
10. **No assumption that a hash-based design is automatically PQ-secure.**

---

# 24. Recommended Initial Prototype Scope

Do not begin with a full private cryptocurrency protocol.

Start with:

```text
Public:
    commitment_root
    nullifier
    output_commitment
    fee

Private:
    secret
    amount
    randomness
    Merkle path
```

Relation:

```text
input belongs to root
AND
nullifier is derived correctly
AND
output commitment is correctly formed
AND
input_amount = output_amount + fee
```

This is sufficient to test the complete architecture:

```text
statement
→ witness
→ masking
→ sumcheck
→ Brakedown
→ Fiat-Shamir
→ proof
→ verification
```

---

# 25. Long-Term Architecture

The final XPARQ design should preserve cryptographic agility.

```text
XPARQ ZK Interface
        │
        ├── BrakedownSumcheckV1
        │
        ├── FuturePQProofV2
        │
        └── FuturePQProofV3
```

The blockchain should depend on the stable verifier interface, not on one proof-system implementation forever.

---

# 26. Final Design Summary

The current most promising research direction is:

```text
XPARQ Private Transaction
        ↓
Arithmetic / Multilinear Relation
        ↓
Zero-Knowledge Witness Masking
        ↓
Multilinear Sumcheck
        ↓
Multilinear Brakedown PCS
        ↓
Hash-Based Merkle Commitment
        ↓
Spongefish Fiat-Shamir
        ↓
Canonical Versioned Proof
        ↓
XPARQ Kernel Verification
```

Arkworks should be used selectively.

Reuse:

```text
ark-ff
ark-poly
ark-linear-sumcheck
ark-poly-commit linear_codes
ark-crypto-primitives
Spongefish
```

Use only as a reference:

```text
ark-spartan
```

Do not use as the PQ core:

```text
Groth16
KZG
IPA PCS
pairing-based curves
curve-based Spartan commitments
```

The most important unresolved task is the **zero-knowledge masking construction**.

Until that layer is formally designed and reviewed, the system should be described as:

> **XPARQ post-quantum-oriented proof-system research**

and not yet as a production post-quantum zero-knowledge protocol.
