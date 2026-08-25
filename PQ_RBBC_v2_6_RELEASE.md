# PQ-RBBC v2.6 — assignment-backed production-tree shard

Date: 24 August 2026

## Outcome

Version 2.6 closes the complete-assignment and whole-shard satisfiability
checkpoint left by v2.5 for one real 2,048-leaf CAP tree. It preserves the
frozen 19,903,324-wire, 26,126,283-row topology while adding:

1. a canonical fixed-width assignment for every GF(2^193) wire;
2. a bounded-memory assignment producer for every sponge, Horner, aggregation,
   serialization, and request-binding value;
3. an mmap-backed replay of every native rank-one row;
4. exact equality of the generation and verification row-stream digests; and
5. five stale-witness probes spanning different subrelations.

The complete replay accepts with zero failures. This remains an explicitly
non-secure, one-tree engineering fixture. It is not the complete 18-tree CAP
relation, a production Blind-UOV instantiation, or a closed issuance proof.

## Assignment archive

`pq_rbbc_cap_shard_assignment.py` defines
`PQRBBC-F193-ASSIGNMENT-LE25-1`:

- 128-byte fixed header;
- field degree: 193;
- value width: 25 bytes, little-endian;
- one-based wire `i` at offset `128 + 25(i - 1)`;
- wire count and body length in the header;
- SHA-256 of the assignment body; and
- the frozen canonical row-stream SHA-256.

The production archive is:

- wires: 19,903,324;
- body bytes: 497,583,100;
- total archive bytes: 497,583,228;
- body SHA-256:
  `e16ca6a9228f9f13901d0e0228751010fa25889ed02a7291aaceebe69590843a`;
- archive SHA-256:
  `6df38b0cadc2390ea953511ed20c1c22668f85f63a0519965f2d5a78b44d0095`;
- embedded row-stream SHA-256:
  `2cfc3641a94635af35dfa5494c61e74a416ef2fb446975cd417891d244943dfc`.

The body is about 474.5 MiB. It replaces roughly twenty million retained Python
integers with direct fixed-width writes and random-access mmap reads.
The release source bundle does not duplicate this large archive internally;
the `.f193assign` file is distributed as a separate checksummed artifact.

## Assignment construction

The unchanged v2.5 row generator now optionally receives an assignment writer.
For all 6,146 XOF calls, a bounded ordered worker pool computes values in exact
allocation order:

- payload bits;
- framed rate-lane elements;
- all 352 native-template values for every Anemoi permutation;
- squeezed output decompositions; and
- source-linked transcript values.

The non-sponge path supplies concrete salt, root, message, point-inverse,
Horner-product, field-accumulator, output-decomposition, commitment, mask,
append-base, and request-binding values. Every allocation is required to carry
the exact number of assignment elements when archive writing is enabled.

The assignment-backed generation reproduces the v2.5 row counts, group counts,
wire-spool digest, canonical commitment digest, request-binding vector, virtual
stream byte count, and row-stream digest exactly.

## Whole-shard verification

The archive reader rejects wrong magic, profile fields, body width, file size,
metadata, body digest, or non-canonical field values. The verifier then reruns
the complete row generator and evaluates every emitted row from mmap:

`L(w) * R(w) = O(w)` in GF(2^193).

Bitness, linear, and square rows use algebraically equivalent specialized
evaluators. The production result is:

- rows checked: 26,126,283;
- wires loaded: 19,903,324;
- verification failures: 0;
- first failure: none;
- topology matches generation: yes; and
- replayed row-stream digest matches generation: yes.

This establishes satisfiability of the complete deterministic one-tree
assignment. It is stronger than the v2.5 topology digest, but it does not by
itself establish CAP extraction, zero knowledge, simulation extractability, or
security of the one-tree fixture.

## Stale-witness rejection

Five exact rows are captured during generation. For each probe, the low bit of
one archived wire is flipped while all other assignment values remain stale:

- GGM payload/source binding, wire 1;
- first leaf tape digest packing, wire 4,346,035;
- first leaf Horner multiplication at coefficient 9, wire 19,811,892;
- canonical commitment publication, wire 19,895,418; and
- request-binding digest packing, wire 19,902,738.

Every honest row accepts and every mutated row rejects. These are localized
exact-row mutations; the full honest assignment is replayed over all rows once.

## Frozen production measurements

The recorded eight-worker assignment generation took 581.792 seconds after
the concrete CAP execution was available. Full archive validation and
whole-shard row replay took 833.873 seconds. The generation summary records
peak RSS 139,456 KiB (about 136.2 MiB). These are relation-construction and
verification measurements, not proof-generation benchmarks.

The frozen topology remains:

- leaves: 2,048;
- extension degree: 12;
- witness bits: 2,048;
- Horner coefficients: 11;
- consistency points: 2;
- tape bits per leaf: 2,450;
- CAP XOF calls: 6,145;
- XOF calls including request binding: 6,146;
- Anemoi permutations: 19,505;
- nonlinear rows: 19,509,254;
- linear rows: 6,617,029;
- external assertions: 0; and
- virtual canonical row-stream bytes: 18,869,935,441.

## Regression evidence

The new assignment test module covers:

- frozen probe archive bytes and digests;
- one-based random-access archive reads;
- complete honest probe assignment verification;
- archive-body corruption rejection;
- all five stale-witness probes;
- explicit fail-closed claim boundaries for the small probe; and
- frozen production archive, full-row verification, and mutation evidence.

The complete suite passes 124 of 124 tests in 705.065 seconds.

## Parent relation preservation

The native profile, hidden-state ABI, executable reference, and BR1CS manifests
now record that the one-tree assignment is materialized and fully verified.
They still keep the production boundary fail-closed:

- one 2,048-leaf shard assignment closed: true;
- stale-witness probes rejected: true;
- shard profile secure: false;
- 4,096-leaf shard implemented: false;
- full 18-tree vector executed: false;
- exact parent wire join: false; and
- production closed: false.

The portable parent BR1CS archive remains byte-identical to v2.5:

- archive bytes: 49,227,687;
- rows: 2,971,580;
- wires: 2,980,304;
- external assertions: 1; and
- archive SHA-256:
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

The remaining external assertion still names the complete 18-tree native CAP
row stream and exact H_RBBC parent-wire join.

## Proof document

The 33-page proof PDF adds a one-shard assignment-satisfiability proposition,
the fixed-width archive semantics, the mmap replay argument, the five mutation
cases, and the remaining security boundary. It was compiled to a clean log;
all 33 pages were rendered and visually inspected.

## Claim boundary

Version 2.6 establishes that one deterministic 2,048-leaf production-shape
shard has a complete satisfying assignment with zero external assertions. It
does not establish:

1. either 4,096-leaf degree-13 tree;
2. composition of all eighteen trees and cross-tree corrections;
3. exact linkage into the parent issuance archive;
4. zero external assertions in the parent archive;
5. fork-specific CAP unique-mask and straightline-extraction proofs;
6. fork blindness and one-more-unforgeability;
7. a qualified post-quantum zero-knowledge/simulation-extractable backend; or
8. fresh signature, proof-size, time, and peak-prover-memory benchmarks.

Production remains fail-closed until those obligations are independently
reviewed and the parent archive reaches zero external assertions.

## Next checkpoint

Version 2.7 should implement one real 4,096-leaf, degree-13 shard under the same
fixed-width assignment and whole-row verification discipline. After both shard
types are closed, compose all eighteen trees and their corrections under one
canonical transcript, then replace the parent archive's final external
assertion with exact native wire identities.
