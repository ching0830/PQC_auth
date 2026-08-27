# PQ-RBBC crypto-core roadmap — after v2.22

## Gate status

| Gate | Status |
| --- | --- |
| R0-a: v2.8 production-composer cache recovery | Complete |
| R0-b: v2.9 global-tail regeneration and replay | Complete |
| R1d-a: tree-index-2 planned-offset replay | Complete |
| R1d-b1: generic runner and tree-index-1 replay | Complete |
| Planned producer positions materialized | 3 of 18: indices 0, 1, 2 |
| Remaining planned-offset producers | Open: indices 3 through 17 |
| All 72 output relocations | Open |
| Complete 18-tree assignment replay | Open |
| Parent CAP-to-H-RBBC join | Open |
| Fork-security and reduction proof work | Open |
| Production closure | False |

## R1d-b1 — complete

The generic runner `pq-rbbc/cap/planned-offset-tree-runner/v1` binds its
checkpoint to tree identity, the frozen namespace interval and point imports,
the four output starts, the recovered global-tail identity, and deterministic
execution material.  Resume generation preserves and byte-checks an existing
archive prefix; full replay and mutations remain an independent stage.

Tree index 1 closed with 51,325,080 rows, 38,953,830 wires, a 973,845,878-byte
assignment, and exact matching of all four global-tail consumers.  Its archive
SHA-256 is
`ab75aca6037e47fe38a1364d2c66f90d1a3856da901423b398fa2d8812fa609f`.

## R1d-b2 — next single implementation point

Execute tree index 3 alone with the v2.22 generic runner.  Do not launch the
remaining 15 producers as a monolithic job.

| Property | Tree index 3 target |
| --- | --- |
| Leaves / degree | 2,048 / 12 |
| Planned local wires | 137,580,693 through 157,059,128 |
| Local wire count | 19,478,436 |
| Constraint rows | 25,666,386 |
| Output starts | 156,191,493; 156,982,021; 156,984,069; 157,054,497 |
| Relation | `pq-rbbc/cap/production-tree-producer-index-3/v1` |
| Rebase delta | 97,386,096 |
| Expected assignment bytes | 486,961,028 |
| Row-stream bytes | Unknown until complete replay |

Run input gates first: verify the global-tail archive at its exact v2.20
identity, validate the frozen namespace, and rerun the reduced checkpoint and
resume fixtures.  Then build an identity-bound trusted local cache, generate
the external archive with deterministic checkpoints, independently replay all
rows, compare all four outputs, run stale-witness/point/identity/offset/archive
mutations, and seal a path-free evidence document.

The tree-1 run demonstrated that row-stream byte count is not shape-invariant:
tree indices 0 and 1 differ by five bytes despite both using 4,096 leaves and
degree 13.  Never freeze an unreplayed tree's stream size from another tree.

## Later R1d-b2 iterations

After tree index 3 is sealed, continue indices 4 through 17 one at a time.
Every position needs its own frozen contract, portable evidence, complete
replay, output matching, and mutation probes before its claim is promoted.

## R1e and proof work

Only after all 18 producer positions and all 72 relocations are independently
closed may the complete assignment and parent join be attempted.  Fork-security
and reduction arguments must then be revalidated against the final frozen
semantics.  No producer checkpoint alone establishes production security.
