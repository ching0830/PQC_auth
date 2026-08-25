# PQ-RBBC v2.9 — shared production global-tail native closure

Date: 25 August 2026

## Outcome

Version 2.9-R1a materializes the single shared global tail required by the
canonical eighteen-tree production CAP execution.  The relation consumes
bit-constrained ports for all tree outputs plus the shared salt and request
message.  It natively constrains the seventeen correction pairs, H1,
consistency-point derivation, shared alpha, all eighteen xi components, H2,
the canonical 5,391-byte commitment, and the request-binding hash.

This closes the global-tail assignment, not the full eighteen-tree
composition.  Tree-producer segments, exact cross-segment wire identity,
complete producer-plus-tail replay, the parent join, formal reductions, and a
qualified proof backend remain fail-closed.

## Canonical production evidence

- relation ID: `pq-rbbc/cap/production-global-tail/v1`;
- rows: `56,806,711`;
- wires: `40,194,596`;
- row-stream SHA-256:
  `c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df`;
- assignment archive bytes: `1,004,865,028`;
- assignment archive SHA-256:
  `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`;
- external assertions: zero;
- complete archive replay failures: zero; and
- stale-witness probes: six of six rejected.

The assignment is distributed separately as 21 byte-exact chunks: chunks
00--19 are 48,000,000 bytes each and chunk 20 is 44,865,028 bytes.  Their
individual digests and the reconstruction command are recorded in
`PQ_RBBC_v2_9_GLOBAL_TAIL_ASSIGNMENT.md`.

The output commitment SHA-256 remains
`12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62`.
The 576-bit request hash remains
`3f9ec0aeab100e4ebef8046068851874f08fcda6daa2e42178dd559f55e38a31da28af9ccd0653bb4ca574ec8264cce1f3c024c97e858e2c877bba7968c039dc61f516dfed995ba3`.
Thus the native tail agrees with the v2.8 canonical reference rather than
introducing a new transcript.

## Native port contract

The relation fixes one shared salt port (386 bits), one request-message port
(256 bits), and four ordered ports for every tree: leaf commitments, plain
witness polynomial, plain consistency polynomial, and extension-field xi
masks.  Each port records its tree position, bit width, local wire start, and
value digest.  Every port wire is Boolean-constrained inside the tail.

These are consumer-side ports.  Version 2.9 does not claim that the existing
one-tree archives already share those wire identifiers.  Producer-side
segmentation and exact relocation are the next checkpoint.

## Replay and mutation coverage

Generation writes every field-wire value in canonical fixed-width assignment
format.  Verification reopens the archive by mmap, regenerates the same
witness-independent row topology, and evaluates every row.  Six focused
mutations alter:

1. a tree-commitment source link;
2. a cross-tree correction source link;
3. alpha packing;
4. an H2 xi source link;
5. commitment publication; or
6. request-digest packing.

The selected row rejects every stale assignment.

The production construction took 2,884.913 seconds and the independent mmap
replay plus mutation phase took 963.015 seconds in this environment.  The
generator reported 1,565,296 KiB peak RSS.  These are relation-engineering
measurements, not prover or proof-verifier benchmarks.

## Fail-closed sealing

The first production run intentionally emits an unsealed manifest.  Its exact
row count, wire count, row-stream digest, and assignment digest are then frozen
in source.  A separate `--seal-existing` path revalidates the profile,
relation/format identifiers, all four frozen values, commitment and request
outputs, zero external assertions, zero replay failures, all six probes, and
every remaining false claim before changing only
`production_global_tail_native_closed` to true.  It does not rerun or mutate
the assignment archive.

## Upward propagation

The native profile, Blind-UOV ABI, executable reference, and BR1CS manifest now
record the global tail as native.  They continue to record:

- `tree_producer_segments_materialized = false`;
- `cross_segment_wire_identity_closed = false`;
- `monolithic_18_tree_assignment_verified = false`;
- `production_cap_native_rows_materialized = false`;
- `complete_cap_hash_implemented = false`;
- `fork_security_proof_revalidated = false`; and
- `production_closed = false`.

The parent BR1CS bytes and rows are unchanged because no external assertion is
deleted in this checkpoint.

## Regression evidence

The clean repository regression completed 138 tests in 744.323 seconds with
zero failures.  It includes the six new global-tail tests, all prior primitive
and native CAP tests, complete BR1CS round trips, archive corruption and
assignment mutation checks, both frozen production tree-shape manifests, and
the full incremental negative-circuit suite.  The proof PDF compiles in two
passes with no warnings, undefined references, overfull boxes, or underfull
boxes; all 36 rendered pages and the two new proposition pages were visually
inspected.

## Next checkpoint

Version 2.9-R1b should split the two existing tree-shape generators into
producer segments that omit the repeated global tail, generate all eighteen
position-specific assignments, freeze the exact global wire relocation/link
table, and replay producer segments, link rows, and this shared tail as one
composition with zero failures.  Parent linkage and formal security proofs
come only after that native composition closes.
