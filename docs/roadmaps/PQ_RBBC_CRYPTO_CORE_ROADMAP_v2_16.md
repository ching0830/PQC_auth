# PQ-RBBC crypto-core roadmap — after v2.16

Date: 26 August 2026

## Current checkpoint

| Gate | Status | Evidence |
| --- | --- | --- |
| Production global tail | Complete | v2.9 full assignment replay, zero failures |
| Phase-A / Phase-B exact H1 and point wires | Complete | v2.12 split-tail contract |
| Index-0 4,096/degree-13 producer | Complete | v2.13 full replay; planned delta is zero |
| Index-2 2,048/degree-12 standalone producer | Complete | v2.14 full replay |
| Representative four-port relocations | Complete | v2.15, eight maps / 2,386,102 equality rows |
| 18-tree global namespace | Complete | v2.16, 18 disjoint intervals / 72 planned output maps |
| Index-2 replay at planned offset | Open | planned start 118,102,257; no rebased archive yet |
| Remaining sixteen position-sensitive producers | Open | no archive replay yet |
| Complete 18-tree assignment | Open | namespace exists; monolithic replay does not |
| Parent `pi_issue` join | Open | parent BR1CS still has one external assertion |
| Formal fork security proof | Open | blindness, one-more UF, extraction, SE-NIZK/QROM |
| Production readiness | Open | `production_closed = false` |

## R1d-a — Replay the representative rebased producer

Tree 0 already has its planned wire start because its v2.16 rebase delta is
zero.  Replay tree 2 with:

- `local_wire_start = 118,102,257`;
- point imports at 39,945,673 and 39,945,866;
- exactly 19,478,436 allocated local wires;
- exactly 25,666,386 rows;
- the four planned output starts 136,713,057, 137,503,585, 137,505,633, and
  137,576,061;
- zero verification failures and zero external assertions; and
- the existing six stale-witness probes plus exact point-wire mutation probes.

Compare the v2.14 and rebased streams structurally.  Labels, relation values,
row counts, coefficients, constants, nonlinear/linear accounting, and output
digests must remain identical.  Only permitted local wire identifiers and
wire-dependent serialized digests may change.  Any tail wire reference outside
the two imported point ranges must reject.

Only after the complete replay may
`representative_producers_rebased_replayed` become true.

## R1d-b — Materialize the remaining producers

Using the frozen namespace plan:

1. materialize tree index 1 as the second 4,096-leaf/degree-13 producer;
2. materialize indices 3 through 17 as 2,048-leaf/degree-12 producers;
3. import the exact global consistency-point wires without local copies;
4. generate fixed-width assignments with checkpoint/resume;
5. fully replay every row with zero failures and zero external assertions;
6. seal all four output relocations per producer; and
7. reject tree-position swaps, stale outputs, wrong point imports, wrong
   relocation ranges, and wrong phase order.

Only after this succeeds may `tree_producer_segments_materialized` and
`all_72_output_relocations_closed` become true.

## R1e — Complete 18-tree composition replay

Build the single composition manifest and assignment over the v2.16 namespace.
Require exact segment identities, all 72 producer outputs connected to the
tail, zero cross-segment external assertions, complete assignment replay, and
mutation rejection for tree swaps, H1/H2 order, correction pairs,
serialization, commitment, and request binding.

Only this gate may set `complete_18_tree_assignment_replayed` and global
`cross_segment_wire_identity_closed` to true.

## R2 — Parent `pi_issue` join

Import the complete CAP commitment wires into the parent relation's canonical
`H_RBBC(m,c_r)` serialization, remove the final external assertion, regenerate
the parent backend, and require identical honest semantics plus rejecting
message, mask, commitment, serialization, and hash-image mutations.

## R3 — Formal security proof

After the engineering relation is closed:

1. state and prove CAP unique-witness / straightline extraction assumptions;
2. prove request blindness for the Blind-UOV fork;
3. prove one-more unforgeability with the message-bound `pi_issue` relation;
4. qualify SE-NIZK and QROM composition assumptions;
5. prove Signature-Gated Decryption confidentiality and authorization; and
6. rebenchmark public key, ciphertext, proof, signature, latency, and memory.

No engineering replay result alone may flip these proof claims.

## Next concrete implementation

Add a planned-offset execution entry point for tree 2, replay it at wire start
118,102,257 using the existing checkpoint/resume discipline, and seal the
rebased v2.17 archive and manifest.  Do not start the other sixteen large runs
until that representative replay proves the v2.16 remapping contract against a
full production row stream.
