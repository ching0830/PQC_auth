# PQ-RBBC v2.23 — Tree-3 planned-offset recovery

Date: 27 August 2026

## Outcome

The tree-index-3 iteration of R1d-b2 is closed.  The generic checkpointable
planned-offset runner materialized tree index 3 at its frozen v2.16 namespace
position, independently replayed every row, and matched all four outputs to
the recovered v2.9 global tail.  Git stores only path-free evidence; the
assignment, resume state, and trusted pickle caches remain external.

## Exact result

| Property | Value |
| --- | --- |
| Planned local wires | 137,580,693 through 157,059,128 |
| Rebase delta | 97,386,096 |
| Local wire count | 19,478,436 |
| Constraint rows | 25,666,386 |
| Assignment bytes | 486,961,028 |
| Assignment SHA-256 | `315e83340d10331188d27a99a82de6f1262e36468f1b6f8c6ef97283d83fc02b` |
| Assignment body SHA-256 | `b9c244e8fea051e6119a72733b845ab5dae4c247f5da618037d1864e9f51f2b1` |
| Row-stream bytes | 8,961,160,824 |
| Row-stream SHA-256 | `0ad71fd26237442e2f2e4b8b73324a98761341a405f362397f841d61e860439a` |
| Tree-component SHA-256 | `404d5eeccdf53e7656d3df2a5e584c8cfa0ac2e2b3c916c1e4dee61fd8659b43` |
| Replay manifest SHA-256 | `1054dd12e7144ba0e66cca98f57d697163c5b0bcd72292aecc486edff9918b15` |
| Portable evidence SHA-256 | `7369957afbcb4b5091ee06b914a2ef807392c857af941c06f412d80366c8aa93` |

Output starts are 156,191,493, 156,982,021, 156,984,069, and 157,054,497.
The leaf-commitment, plain-polynomial, consistency-polynomial, and xi-mask
values all match their global-tail consumers exactly.  The replay has zero
external assertions and zero failed rows.  Six stale-witness probes and three
point mutations were rejected.

## Frozen-contract procedure

The first complete replay established the previously unknown row-stream byte
count.  That observed count was added to the tree-index-3 frozen contract, a
fresh identity-bound cache was built, and the unchanged archive was replayed a
second time from first through last row.  Only the second replay closes the
formal frozen-contract gate.  The pre-freeze cache is not evidence and must
not be reused as a frozen result.

## Historical seal stability

Advancing the generic runner to v2.23 exposed one backward-compatibility
hazard: the v2.22 tree-1 evidence builder had read the runner's current version
instead of its historical sealed version.  The tree-1 evidence module now
freezes runner version 2.22 explicitly for both document construction and
external replay-manifest validation.  Its existing evidence bytes and SHA-256
remain unchanged.

## Claim boundary

Newly true:

- `production_tree3_planned_assignment_materialized`;
- `production_tree3_planned_full_replay_closed`;
- `materialized_planned_tree_indices == [0, 1, 2, 3]`; and
- `materialized_planned_tree_count == 4`.

Remaining producer materialization, all 72 relocations, the complete 18-tree
assignment, cross-segment identity, parent join, fork-security proof, and
`production_closed` remain false.

## Validation

- portable evidence frozen and externally resealed;
- affected runner/evidence/parent regression: 48 tests passed in 199.262
  seconds with no skips;
- complete repository regression: 236 tests passed in 788.495 seconds with
  ten optional external-artifact tests skipped;
- parent BR1CS: 49,227,687 bytes, unchanged SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Next checkpoint

Continue R1d-b2 with tree index 4 alone.  Its frozen namespace interval is
157,059,129 through 176,537,564 and its row-stream byte count remains unknown
until the first complete replay; do not infer it from tree index 3.
