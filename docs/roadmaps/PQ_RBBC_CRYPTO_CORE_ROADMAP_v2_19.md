# PQ-RBBC crypto-core roadmap — after v2.19

Date: 27 August 2026

## Current checkpoint

| Gate | Status | Evidence |
| --- | --- | --- |
| Checkpointable 18-tree composer recovery | Complete | v2.18 atomic level/batch checkpoints + reduced bit-exact resume |
| v2.8 production execution cache recovery | Complete | v2.19 trusted cache + exact frozen document revalidation |
| Production global tail | Previously complete, current archive absent | v2.9 sealed identity remains frozen; regeneration is R0-b |
| 18-tree global namespace | Complete | v2.16, 18 disjoint intervals / 72 planned maps |
| Index-2 planned-offset execution gate | Complete | v2.17 contract + reduced two-offset replay |
| Index-2 production replay at 118,102,257 | Open | zero production rows replayed at the planned offset |
| Remaining sixteen position-sensitive producers | Open | no planned-offset archives |
| Complete 18-tree assignment | Open | namespace exists; monolithic replay does not |
| Parent `pi_issue` join | Open | parent BR1CS still has one external assertion |
| Formal fork security proof | Open | engineering evidence is not a proof |
| Production readiness | Open | `production_closed = false` |

## R0-a — Frozen v2.8 composer cache: complete

The resumed production checkpoint reached phase `complete` with 18 trees and
40,960 canonical leaf outputs.  The trusted execution cache passes the original
v2.8 identity validator and reproduces all three frozen identities:

1. commitment SHA-256
   `12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62`;
2. XOF trace SHA-256
   `ccfa51ec2aee9501483c65023c4a877316eb6dd0557ccd6c42dfdf5f20f2c4e6`;
3. canonical document SHA-256
   `a7ef7eb4689d84c686074308d0d167e1567ab84578d66b5ad004970940ea0163`.

The checkpoint and cache remain trusted local pickle files outside Git.  The
tracked v2.19 evidence is path-free and records only sealed identities and
claim boundaries.

## R0-b — Regenerate the v2.9 global tail: next

Feed the recovered execution cache into the unchanged production global-tail
generator.  Require all of these checks together:

1. exact archive size 1,004,865,028 bytes;
2. assignment SHA-256
   `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`;
3. 40,194,596 wires and 56,806,711 rows;
4. zero verification failures and zero external assertions;
5. all six stale-witness probes rejected; and
6. independent archive verification before sealing the manifest.

Do not set `production_global_tail_archive_regenerated` merely because the
historical v2.9 relation identity is frozen.  That claim becomes true only
after the current external archive is rebuilt and independently verified.

## R1d-a — Execute the frozen tree-2 production replay

Use the regenerated v2.9 archive as the mandatory tail input for the v2.17
runner.  Prefer a verified v2.14 tree-2 cache; otherwise let the runner rebuild
its own resumable producer cache.  Replay all 25,666,386 rows at local wire
start 118,102,257 and require the exact interval, imported points, four output
ranges, assignment body, row-stream identity, zero failures, and every mutation
rejection recorded by the v2.17 contract.

Only that completed replay may make
`production_tree2_rebased_assignment_materialized` and
`production_tree2_rebased_full_replay_closed` true.

## R1d-b — Materialize the remaining producers

After tree 2 closes, execute tree 1 and trees 3 through 17 in the frozen v2.16
namespace with the same checkpoint/resume and fail-closed identity rules.  Do
not launch these sixteen large jobs before the tree-2 path is sealed.

## R1e — Complete 18-tree composition replay

Compose every producer segment, all 72 output relocations, and the shared
global tail.  Require exact segment identities, zero cross-segment external
assertions, complete assignment replay, and mutations for tree order,
corrections, transcript ports, commitment serialization, and request binding.

## R2 and R3 — Parent join, proof, and benchmarking

Only after R1e may the complete CAP commitment wires replace the final parent
external assertion.  Formal blindness, one-more unforgeability, extraction,
SE-NIZK/QROM, and signature-gated decryption arguments and new performance
claims follow engineering closure; replay evidence alone cannot close them.

## Next concrete implementation

Execute R0-b with the unchanged v2.9 production generator and the recovered
trusted cache, following
`docs/artifacts/PQ_RBBC_v2_19_PRODUCTION_RECOVERY_EVIDENCE.md`.  Preserve the
v2.8 cache and the regenerated v2.9 archive outside Git.  Advance to the v2.17
tree-2 replay only after the v2.9 archive identity and full replay both match.
