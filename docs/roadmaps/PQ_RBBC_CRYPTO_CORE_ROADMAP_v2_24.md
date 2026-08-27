# PQ-RBBC crypto-core roadmap — after v2.24

## Gate status

| Gate | Status |
| --- | --- |
| R0-a: v2.8 production-composer cache recovery | Complete |
| R0-b: v2.9 global-tail regeneration and replay | Complete |
| R1d-a: tree-index-2 planned-offset replay | Complete |
| R1d-b1: generic runner and tree-index-1 replay | Complete |
| R1d-b2 tree-index-3 iteration | Complete |
| R1d-b2 tree-index-4 iteration | Complete |
| Planned producer positions materialized | 5 of 18: indices 0 through 4 |
| Remaining planned-offset producers | Open: indices 5 through 17 |
| All 72 output relocations | Open |
| Complete 18-tree assignment replay | Open |
| Parent CAP-to-H-RBBC join | Open |
| Fork-security and reduction proof work | Open |
| Production closure | False |

## R1d-b2 tree index 4 — complete

Tree index 4 closed under a frozen contract with 25,666,386 rows, 19,478,436
wires, a 486,961,028-byte assignment, and exact matching of all four
global-tail consumers.  Its archive SHA-256 is
`cd2430637f8ca07356727cb4349ca02368f2268f865092c71f3049140bacf52d`.

The first full replay observed the previously unknown row-stream size.  The
runner then froze that size, built a fresh cache against the final contract,
and replayed the unchanged archive a second time.  The pre-freeze manifest
keeps all formal tree-4 claims false; only the final replay closes them.

Historical evidence builders for trees 1 and 3 bind their own sealed runner
versions.  A later generic-runner release must never rewrite an earlier
portable evidence identity.

## Next R1d-b2 iteration — tree index 5

Execute tree index 5 alone through the v2.24 generic runner.  Do not launch the
remaining thirteen producers as a monolithic job.

| Property | Tree index 5 target |
| --- | --- |
| Leaves / degree | 2,048 / 12 |
| Planned local wires | 176,537,565 through 196,016,000 |
| Local wire count | 19,478,436 |
| Constraint rows | 25,666,386 |
| Output starts | 195,148,365; 195,938,893; 195,940,941; 196,011,369 |
| Relation | `pq-rbbc/cap/production-tree-producer-index-5/v1` |
| Rebase delta | 136,342,968 |
| Expected assignment bytes | 486,961,028 |
| Row-stream bytes | Unknown until complete replay |
| Initial stream-unfrozen contract SHA-256 | `5e06e6194e3b08d204f0922d99a39e05bcd16516877dc639d1ddfdcfaaf65527` |

Run input gates first: verify the v2.20 global-tail archive, v2.24 tree-4
evidence, frozen namespace, and checkpoint/resume fixtures.  Generate the
external archive with deterministic checkpoints, independently replay all
rows, compare all four outputs, and run stale-witness, point, identity, offset,
and archive mutations.  If the stream byte count is not already frozen,
include the observed value in the final contract and repeat the replay under a
fresh identity-bound cache before sealing evidence.

The equal row-stream byte count observed for trees 3 and 4 does not establish
the tree-5 value.  Preserve `stream_bytes = null` in the initial contract.

## Later producer iterations and proof work

Continue indices 6 through 17 one at a time after tree index 5 is sealed.  Only
after all 18 positions and all 72 relocations are independently closed may the
complete assignment and parent join be attempted.  Fork-security and
reduction arguments must then be revalidated against the final frozen
semantics.  No producer checkpoint alone establishes production security.
