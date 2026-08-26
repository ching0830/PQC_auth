# PQ-RBBC crypto-core roadmap — after v2.15

Date: 26 August 2026

## Current checkpoint

| Gate | Status | Evidence |
| --- | --- | --- |
| Production global tail | Complete | v2.9 full assignment replay, zero failures |
| Phase-A / Phase-B exact H1 and point wires | Complete | v2.12 split-tail contract |
| Index-0 4,096/degree-13 producer | Complete | v2.13 full replay |
| Index-2 2,048/degree-12 producer | Complete | v2.14 full replay |
| Representative four-port relocations | Complete | v2.15, eight maps / 2,386,102 equality rows |
| Remaining sixteen position-sensitive producers | Open | no archive replay yet |
| Complete 18-tree assignment | Open | no monolithic namespace or replay |
| Parent `pi_issue` join | Open | parent BR1CS still has one external assertion |
| Formal fork security proof | Open | blindness, one-more UF, extraction, SE-NIZK/QROM |
| Production readiness | Open | `production_closed = false` |

## R1c — Freeze the 18-tree global namespace

Before producing more large archives, define one deterministic namespace plan
for

`shared inputs + 18 tree-pre + tail Phase A + 18 tree-post + tail Phase B`.

The planner must assign a non-overlapping wire interval to every producer and
preserve the exact frozen global consistency-point ranges 39,945,673 and
39,945,866.  It must reject interval overlap, wrong tree order, wrong shape,
wrong point range, output-port overlap, and integer overflow.

This gate is necessary because the standalone representative producers both
use local wire start 40,194,597.  Their full internal namespaces overlap even
though the particular output ranges sealed by v2.15 do not.

## R1d — Materialize all remaining producers

Using the frozen namespace plan:

1. materialize tree index 1 as the second 4,096-leaf/degree-13 producer;
2. materialize indices 3 through 17 as 2,048-leaf/degree-12 producers;
3. import the exact global consistency-point wires without local copies;
4. generate fixed-width assignments with checkpoint/resume;
5. fully replay every row with zero failures and zero external assertions;
6. seal all four output relocations per producer; and
7. reject tree-position swaps, stale outputs, wrong point imports, wrong
   relocation ranges, and wrong phase order.

Only after this succeeds may `tree_producer_segments_materialized` become true.

## R1e — Complete 18-tree composition replay

Build the single composition manifest and assignment over the namespace frozen
in R1c.  Require:

- exact stream and assignment identities for every segment;
- all 72 producer output ports connected to the tail;
- zero cross-segment external assertions;
- complete assignment replay with zero failures; and
- mutation rejection for tree swap, H1/H2 order, correction pairs,
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

Implement a fail-closed `ProductionNamespacePlan` module for all 18 tree
positions.  First replay the two representative producers at their planned
rebased offsets and prove that only wire identifiers—not relation values or row
counts—change.  Then start the remaining sixteen checkpointed producer runs.
