# PQ-RBBC v2.1 — source-grounded CAP.Commit reference core

Date: 2026-08-23

## Outcome

Version 2.1 implements the next route-2 milestone: a direct, independently
profiled reference for the initial CAP commitment logic in Protocols 8--10 of
Blind-UOV, plus an exact byte-level join from its canonical production encoding
to the v2.0 `H_RBBC` sponge.

This release does **not** claim a closed production proof.  The full 18-tree
native row stream and its inter-call wire identities have not been materialized
or executed.  The parent BR1CS archive therefore deliberately retains one
external assertion.

## Frozen CAP profile

- Relation: `pq-rbbc/cap/tcith-iii/anemoi-193-336/v1`.
- Profile SHA-256:
  `2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`.
- Field: `GF(2^193)`; symmetric primitive:
  `PQ-RBBC-Anemoi-193/336-Sponge-v1`.
- Witness upper bound: 2,048 bits = 576 mask bits + 1,472 later signature bits.
- Trees: two 4,096-leaf trees and sixteen 2,048-leaf trees; 40,960 leaves total.
- Safe extension degrees: 13 for the 4,096-leaf trees and 12 for the
  2,048-leaf trees, so every leaf maps injectively to a nonzero element.
- Degree-one polynomial profile, `rho = 16`.
- Consistency digest: two `GF(2^193)` evaluations = 386 bits.
- Random-polynomial tape: 2,450 bits per leaf.
- Canonical hidden CAP commitment `c_r`: exactly 5,378 bytes.

The implementation covers salted GGM seed derivation, leaf commitments, tape
expansion, random polynomial coefficients, cross-repetition corrections,
polynomial-universal consistency hashing, canonical randomness and commitment
serialization, derivation of the 576-bit mask, and the later signature-append
delta.

## Executable vector and strict ABI

The full production topology is opt-in and was intentionally not executed in
this release.  A reduced, explicitly non-secure two-tree fixture executes the
same code paths.  It freezes:

- profile SHA-256
  `5d067a55e2ea9104b2604dc7efa393f44d1ce1880c3974bdcaae32aeb825f2ea`;
- 215-byte commitment SHA-256
  `07a09a4f623233586af7ebca90d0eeba7d6a5bb94ff86c7dff29ade7be79b800`;
- derived mask `dd4907f4`;
- 23 domain-separated XOF calls.

`request_from_production_cap()` accepts only the frozen production profile,
exact 5,378-byte canonical encoding, and exact 576-bit derived mask.  It then
computes `H_RBBC(message, c_r)` and emits the same 72-byte public signer request
`y = r XOR h`.  It rejects reduced fixtures, wrong fingerprints, malformed
lengths, and wrong-width masks.  The message, CAP commitment, mask, and CAP
randomness remain hidden; the 5,378-byte commitment is not sent on the
satellite verification path.

## Exact production accounting

Under the frozen framing and sponge:

- seed derivations: 40,924;
- leaf seed commitments: 40,960;
- leaf tape expansions: 40,960;
- transcript XOF calls: 3;
- total XOF calls: 122,847;
- total Anemoi permutations: 389,974;
- permutation nonlinear rows: 131,031,264.

The row figure excludes extension-field operations, corrections, packing, and
wire equalities.  It is therefore a lower component count, not a complete
`pi_issue` benchmark.  It also shows that this aggressive small-online-request
profile is computationally heavy during offline issuance.

## Parent relation

The portable incremental archive contains:

- 2,971,580 total R1CS rows;
- 2,980,304 allocated wires;
- 685,571 nonlinear rows;
- 2,282,475 linear definitions and 3,534 linear assertions;
- one labelled external assertion for the full native 18-tree CAP row stream
  and exact `H_RBBC` wire join;
- 49,227,687 serialized bytes;
- archive SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

The 72-byte public issuance request and 368-byte signed payload remain exact.
The paper's 11,644-byte signature and derived 12,012-byte complete ticket are
comparison targets only; the independent fork has not reproduced or
benchmarked them.

## Verification

All 66 regression tests pass.  Coverage includes frozen CAP and sponge vectors,
field and extension-field arithmetic, direct-versus-constrained hashing,
domain/length separation, correction identities, salt/root/message/profile
mutation rejection, strict CAP-to-hash joining, witness-independent topology,
11 complete-circuit negative cases, BR1CS round trips, assignment tampering,
archive corruption, and fail-closed native import.

The 27-page proof PDF was compiled twice, rendered across all pages, and checked
without LaTeX warnings or layout overflow.

## Claim boundary and next step

Implemented now: source-grounded CAP reference semantics, canonical 5,378-byte
serialization, reduced executable vectors, strict production-profile ABI join,
and exact production call/permutation accounting.

Not implemented now: a full production execution, native 18-tree row stream,
inter-call wire identities, zero external assertions, fork-specific CAP
extraction/unique-mask proof, blindness and one-more-unforgeability proof,
simulation-extractable proof backend, and fresh signature/proof benchmarks.

The next engineering step is to lower the recorded CAP XOF calls into streaming
native `GF(2^193)` rows.  First reproduce the reduced frozen vector with no
callbacks; then execute and freeze the opt-in production vector, bind every CAP
wire into `H_RBBC`, and remove the parent archive's sole external assertion.
