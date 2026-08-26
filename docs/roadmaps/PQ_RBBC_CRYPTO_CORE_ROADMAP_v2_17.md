# PQ-RBBC crypto-core roadmap — after v2.17

Date: 26 August 2026

## Current checkpoint

| Gate | Status | Evidence |
| --- | --- | --- |
| Production global tail | Complete, artifact external | v2.9 full assignment replay; archive not in Git |
| Index-0 producer at planned offset | Complete | v2.13 replay; v2.16 delta is zero |
| Index-2 standalone producer | Complete | v2.14 full replay at start 40,194,597 |
| 18-tree global namespace | Complete | v2.16, 18 disjoint intervals / 72 planned maps |
| Index-2 planned-offset execution gate | Complete | v2.17 contract + real reduced two-offset replay |
| Index-2 production replay at 118,102,257 | Open | zero production rows replayed; external global archive absent |
| Remaining sixteen position-sensitive producers | Open | no planned-offset archives |
| Complete 18-tree assignment | Open | namespace exists; monolithic replay does not |
| Parent `pi_issue` join | Open | parent BR1CS still has one external assertion |
| Formal fork security proof | Open | engineering evidence is not a proof |
| Production readiness | Open | `production_closed = false` |

## R1d-a — Execute the frozen tree-2 production replay

First restore
`pq_rbbc_cap_global_tail_assignment_v2_9.f193assign` and verify its exact
1,004,865,028-byte identity and SHA-256
`946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`.
Restoring the completed v2.14 tree-2 execution cache is the fast path; without
it the v2.17 runner must regenerate producer material before assignment output.

The production run must close all of these checks together:

1. local interval 118,102,257–137,580,692 and no other start;
2. exact imported point ranges 39,945,673 and 39,945,866;
3. 19,478,436 local wires and 25,666,386 rows;
4. unchanged nonlinear, linear, group, sponge, and Horner accounting;
5. assignment value-body digest equal to the v2.14 standalone assignment body;
6. a new archive identity and new wire-dependent row-stream identity;
7. all four planned output ranges and values matched to the global tail;
8. zero external assertions and zero verification failures; and
9. all stale-witness and imported-point mutations rejected.

Only then may `production_tree2_rebased_assignment_materialized`,
`production_tree2_rebased_full_replay_closed`, and the combined
`representative_producers_rebased_replayed` claim become true.

## R1d-b — Materialize the remaining producers

Use the frozen namespace and the same checkpoint/resume discipline for tree 1
and trees 3 through 17.  Every producer must preserve the global point wire
IDs, replay every row, seal all four output relocations, and reject tree swaps,
wrong point imports, wrong output ranges, and stale witnesses.

## R1e — Complete 18-tree composition replay

Build one composition manifest over all producer segments, 72 output
relocations, and the v2.9 global tail.  Require exact segment identities, zero
cross-segment external assertions, complete assignment replay, and mutations
covering tree order, correction pairs, H1/H2, commitment serialization, and
request binding.

## R2 — Parent `pi_issue` join

Import the complete CAP commitment wires into canonical `H_RBBC(m,c_r)`, remove
the final parent external assertion, regenerate the backend, and require
message, mask, commitment, serialization, and hash-image mutations to reject.

## R3 — Formal security and benchmarking

After engineering closure, complete the fork-specific blindness, one-more
unforgeability, extraction, SE-NIZK/QROM, and signature-gated decryption
arguments.  Rebenchmark sizes, latency, and memory.  No replay result alone may
set a proof or production-readiness claim to true.

## Next concrete implementation

Obtain the external v2.9 global-tail archive (and preferably the v2.14 complete
tree-2 execution cache), verify their frozen identities, then invoke the v2.17
runner documented in `docs/artifacts/PQ_RBBC_v2_17_TREE2_REBASED_REPLAY.md`.
