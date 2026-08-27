# PQ-RBBC crypto-core roadmap — after v2.21

## Gate status

| Gate | Status |
| --- | --- |
| R0-a: v2.8 production-composer cache recovery | Complete |
| R0-b: v2.9 global-tail regeneration and replay | Complete |
| R1d-a: tree-index-2 planned-offset replay | Complete |
| Remaining sixteen planned-offset producers | Open |
| All 72 output relocations | Open |
| Complete 18-tree assignment replay | Open |
| Parent CAP-to-H-RBBC join | Open |
| Fork-security and reduction proof work | Open |
| Production closure | False |

## R1d-a — complete

Tree index 2 was replayed at planned local wires 118,102,257 through
137,580,692.  All 25,666,386 rows passed, all four outputs matched the recovered
global tail, and all nine negative probes rejected.  The external assignment is
486,961,028 bytes with SHA-256
`2d9932cd09848d70fece5d047206f580ed6efe1e7335ac8ff865947e0662d933`.

## R1d-b1 — next single implementation point

Generalize the existing tree-0/tree-2 producer machinery into a checkpointable
runner parameterized by tree index and planned namespace locations.  Preserve
deterministic resume metadata and independent full replay.  Then use it for
tree index 1 with this frozen target:

| Property | Tree index 1 target |
| --- | --- |
| Leaves / degree | 4,096 / 13 |
| Planned local wires | 79,148,427 through 118,102,256 |
| Local wire count | 38,953,830 |
| Constraint rows | 51,325,080 |
| Output starts | 116,373,499; 117,954,555; 117,956,603; 118,097,239 |
| Relation | `pq-rbbc/cap/production-tree-producer-index-1/v1` |
| Rebase delta | 38,953,830 |

The runner must reject a wrong tree index, offset, global point, output
relocation, execution identity, archive identity, or stale witness.  It must
checkpoint often enough that an interruption does not discard the full run.

## R1d-b2 — remaining planned producers

After tree index 1 is sealed, execute tree indices 3 through 17 one at a time.
Each tree needs its own frozen manifest, portable evidence, full replay, output
matching, and mutation probes before its claim can be promoted.

## R1e — complete production composition

Only after all 18 producer positions and all 72 relocations are replayed may the
complete assignment and parent join be attempted.  Keep the parent proof and
production claims false until their own independent checks pass.

## R2 / R3 — proof closure

Revalidate the fork-security and reduction arguments against the final frozen
execution semantics, then complete independent review.  No recovery checkpoint
alone establishes production security.
