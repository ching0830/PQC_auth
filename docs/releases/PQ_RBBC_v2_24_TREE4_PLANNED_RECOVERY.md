# PQ-RBBC v2.24 — Tree-4 planned-offset recovery

Date: 27 August 2026

## Outcome

The tree-index-4 iteration of R1d-b2 is closed.  The generic checkpointable
planned-offset runner materialized tree index 4 at its frozen v2.16 namespace
position, independently replayed every row, and matched all four outputs to
the recovered v2.9 global tail.  Git stores only path-free evidence; the
assignment, resume state, trusted pickle caches, and BR1CS remain external.

## Exact result

| Property | Value |
| --- | --- |
| Planned local wires | 157,059,129 through 176,537,564 |
| Rebase delta | 116,864,532 |
| Local wire count | 19,478,436 |
| Constraint rows | 25,666,386 |
| Assignment bytes | 486,961,028 |
| Assignment SHA-256 | `cd2430637f8ca07356727cb4349ca02368f2268f865092c71f3049140bacf52d` |
| Assignment body SHA-256 | `e105adcfc79c10089c72ecd059c9935a3032c4ab79ccc7d2e75dbdde245017fd` |
| Row-stream bytes | 8,961,160,824 |
| Row-stream SHA-256 | `975b8422a29b4b7c6ee338f6821eb56b4bb74957a899da61dda11531eb13dd12` |
| Tree-component SHA-256 | `a157dedd0a7bf408b5065a853bc29b9312b2cb8ce35397204d8680e9aaf24fd6` |
| Replay manifest SHA-256 | `69c46b27a2d61248ac817c308c3a0f85d0344492912d854f6055cc8c2dbdf8b8` |
| Portable evidence SHA-256 | `bb80e09bc0383444ac428a84912c828db096bd2ccd6165990bbe6464e4a7233e` |

Output starts are 175,669,929, 176,460,457, 176,462,505, and 176,532,933.
The leaf-commitment, plain-polynomial, consistency-polynomial, and xi-mask
values all match their global-tail consumers exactly.  The replay has zero
external assertions and zero failed rows.  Six stale-witness probes and three
point mutations were rejected.

## Frozen-contract procedure

The first run generated the archive and replayed it completely under the
pre-freeze contract whose `stream_bytes` field was null.  It observed
8,961,160,824 encoded row-stream bytes but intentionally left formal closure
false.  Generation took 539.399 seconds and verification took 650.153 seconds.

The observed byte count was then added to the final contract, whose SHA-256 is
`746e8af3bc2f1fdb17acb5e77bf1bf24be19b4e56dbcb86dc959df1e8bbf0e6d`.
A fresh identity-bound cache was built and the unchanged archive was replayed
again from first through last row in 645.527 seconds.  Only this second replay
has status `complete` and closes the tree-4 gate.  The equal stream byte count
of trees 3 and 4 is an observation, not a rule for any later tree.

## Historical seal stability

The tree-3 evidence builder now freezes generic-runner version 2.23 explicitly
for document construction and replay-manifest validation.  Advancing the
runner to v2.24 therefore leaves both the v2.22 tree-1 and v2.23 tree-3 seals
byte-for-byte unchanged.

## Claim boundary

Newly true:

- `production_tree4_planned_assignment_materialized`;
- `production_tree4_planned_full_replay_closed`;
- `materialized_planned_tree_indices == [0, 1, 2, 3, 4]`; and
- `materialized_planned_tree_count == 5`.

Remaining producer materialization, all 72 relocations, the complete 18-tree
assignment, cross-segment identity, parent join, fork-security proof, and
`production_closed` remain false.

## Validation

- portable evidence frozen and externally resealed;
- affected runner/evidence/parent regression: 55 tests passed in 199.537
  seconds with no skips;
- complete repository regression: 243 tests passed in 864.903 seconds with
  eleven optional external-artifact tests skipped;
- parent BR1CS: 49,227,687 bytes, unchanged SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Next checkpoint

Continue R1d-b2 with tree index 5 alone.  Its frozen namespace interval is
176,537,565 through 196,016,000.  Its row-stream byte count remains unknown
until the first complete replay; do not infer it from either tree index 3 or 4.
