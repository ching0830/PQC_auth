# PQ-RBBC crypto-core roadmap — after v2.23

## Gate status

| Gate | Status |
| --- | --- |
| R0-a: v2.8 production-composer cache recovery | Complete |
| R0-b: v2.9 global-tail regeneration and replay | Complete |
| R1d-a: tree-index-2 planned-offset replay | Complete |
| R1d-b1: generic runner and tree-index-1 replay | Complete |
| R1d-b2 tree-index-3 iteration | Complete |
| Planned producer positions materialized | 4 of 18: indices 0, 1, 2, 3 |
| Remaining planned-offset producers | Open: indices 4 through 17 |
| All 72 output relocations | Open |
| Complete 18-tree assignment replay | Open |
| Parent CAP-to-H-RBBC join | Open |
| Fork-security and reduction proof work | Open |
| Production closure | False |

## R1d-b2 tree index 3 — complete

Tree index 3 closed under a frozen contract with 25,666,386 rows, 19,478,436
wires, a 486,961,028-byte assignment, and exact matching of all four
global-tail consumers.  Its archive SHA-256 is
`315e83340d10331188d27a99a82de6f1262e36468f1b6f8c6ef97283d83fc02b`.

Because the row-stream byte count was unknown before execution, the archive
was first fully replayed to observe that identity.  A fresh cache was then
built against the frozen value and a second full replay closed the gate.  This
two-stage procedure remains mandatory for each tree whose stream identity is
not already frozen.

Historical evidence builders must likewise bind their own sealed runner
version rather than read the latest mutable module version.  v2.23 adds this
guard to the v2.22 tree-1 evidence without changing its frozen bytes.

## Next R1d-b2 iteration — tree index 4

Execute tree index 4 alone through the v2.23 generic runner.  Do not launch the
remaining fourteen producers as a monolithic job.

| Property | Tree index 4 target |
| --- | --- |
| Leaves / degree | 2,048 / 12 |
| Planned local wires | 157,059,129 through 176,537,564 |
| Local wire count | 19,478,436 |
| Constraint rows | 25,666,386 |
| Output starts | 175,669,929; 176,460,457; 176,462,505; 176,532,933 |
| Relation | `pq-rbbc/cap/production-tree-producer-index-4/v1` |
| Rebase delta | 116,864,532 |
| Expected assignment bytes | 486,961,028 |
| Row-stream bytes | Unknown until complete replay |
| Initial stream-unfrozen contract SHA-256 | `2dec6831c7c80274dc40c299fe0ed4c6eb5188dc0438562f84f19ffb1fb8f3da` |

Run input gates first: verify the global-tail archive at its exact v2.20
identity, verify the v2.23 tree-3 evidence, validate the frozen namespace, and
rerun checkpoint/resume fixtures.  Then build an identity-bound trusted local
cache, generate the external archive with deterministic checkpoints,
independently replay every row, compare all four outputs, run stale-witness,
point, identity, offset, and archive mutations, and seal path-free evidence.
The initial contract digest above binds `stream_bytes = null`; it is a
pre-freeze execution identity, not the final contract digest.  Recompute and
freeze the final digest only after the observed stream byte count is included.

Never freeze an unreplayed tree's row-stream size from another tree.  Equal
leaf count, extension degree, wire count, row count, and archive size do not
establish byte-identical row encoding.  Never let a later generic-runner
release rewrite the version identity inside an earlier evidence document.

## Later producer iterations and proof work

Continue indices 5 through 17 one at a time after tree index 4 is sealed.
Only after all 18 positions and all 72 relocations are independently closed
may the complete assignment and parent join be attempted.  Fork-security and
reduction arguments must then be revalidated against the final frozen
semantics.  No producer checkpoint alone establishes production security.
