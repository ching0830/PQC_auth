# PQ-RBBC crypto-core roadmap — after v2.20

Date: 27 August 2026

## Current checkpoint

| Gate | Status | Evidence |
| --- | --- | --- |
| v2.8 production execution cache recovery | Complete | v2.19, 18 trees / 40,960 leaves |
| v2.9 production global-tail archive recovery | Complete | v2.20, 56,806,711 rows replayed |
| Index-2 planned-offset execution gate | Complete | v2.17 reduced two-offset preflight |
| Index-2 production replay at 118,102,257 | Open | R1d-a is next |
| Remaining sixteen position-sensitive producers | Open | no planned-offset archives |
| Complete 18-tree assignment | Open | namespace exists; monolithic replay does not |
| Parent `pi_issue` join | Open | one external assertion remains |
| Formal fork security proof | Open | engineering evidence is not a proof |
| Production readiness | Open | `production_closed = false` |

## R0 — External recovery: complete

R0-a recovered the deterministic v2.8 composer execution cache.  R0-b used
that cache to regenerate the exact 1,004,865,028-byte v2.9 global-tail archive
with SHA-256
`946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`.
Its 56,806,711 rows replay with zero failures and all six mutation probes
reject.  Both large artifacts remain outside Git behind portable evidence.

## R1d-a — Execute tree-2 at the planned offset: next

Run the v2.17 production path with the recovered global-tail archive and the
trusted local v2.14 tree-2 execution cache when available.  The runner must
produce all of the following together:

1. 25,666,386 rows and 19,478,436 local wires;
2. planned local wire interval 118,102,257 through 137,580,692;
3. imported point starts 39,945,673 and 39,945,866;
4. planned output starts 136,713,057, 137,503,585, 137,505,633, and 137,576,061;
5. assignment size 486,961,028 bytes;
6. assignment body SHA-256
   `632db9813ef41bb3af1d769189132d072208ca0a58e2810c76b844a39da3b501`;
7. exact output values equal to the recovered tail;
8. zero verification failures and zero external assertions; and
9. every standard stale-witness and global-point mutation rejected.

Do not set either tree-2 replay claim merely because the standalone v2.14
producer archive exists.  The planned-offset assignment and its exact imports
must be materialized and independently verified.

## R1d-b — Remaining producers

After tree 2 closes, execute tree 1 and trees 3 through 17 in the frozen v2.16
namespace.  Every producer must use the same fail-closed cache, archive, row
stream, output-relocation, and mutation discipline.

## R1e — Complete composition replay

Compose all eighteen producer segments, 72 output relocations, and the shared
global tail.  Require exact cross-segment wire identities, zero external
assertions, a complete assignment replay, and mutations covering tree order,
corrections, transcript ports, commitment serialization, and request binding.

## R2 and R3

Only after R1e may the final parent CAP assertion be replaced by native wires.
Formal blindness, one-more unforgeability, extraction, SE-NIZK/QROM, and
signature-gated decryption arguments and new performance claims follow that
engineering closure.

For a new work session, read `PQ_RBBC_CURRENT_HANDOFF.md` before executing
R1d-a.
