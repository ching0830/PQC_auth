# PQ-RBBC v2.22 — Tree-1 planned-offset recovery

Date: 27 August 2026

## Outcome

R1d-b1 is closed.  A generic, checkpointable planned-offset tree runner now
derives its contract from the frozen v2.16 namespace without changing the
historical tree-0 or tree-2 implementations.  It materialized tree index 1 at
its planned offset, replayed every row independently, and matched all four
outputs to the recovered v2.9 global tail.  Git stores only path-free evidence;
the assignment and trusted pickle caches remain external.

## Exact result

| Property | Value |
| --- | --- |
| Planned local wires | 79,148,427 through 118,102,256 |
| Rebase delta | 38,953,830 |
| Local wire count | 38,953,830 |
| Constraint rows | 51,325,080 |
| Assignment bytes | 973,845,878 |
| Assignment SHA-256 | `ab75aca6037e47fe38a1364d2c66f90d1a3856da901423b398fa2d8812fa609f` |
| Assignment body SHA-256 | `00b175ebf9414e9d7a4bae49de4e0bf7ff568631dc8865f898a3ed084ab6061f` |
| Row-stream bytes | 18,008,277,115 |
| Row-stream SHA-256 | `1a9c11a716cb491517277c6e18c805683d85a75cb2c5306f13db7b7f13d1f516` |
| Tree-component SHA-256 | `0db861243dbc72fffb09799ea50c4b770c3cb2a847d4dd66fffc968b91790d81` |
| Replay manifest SHA-256 | `1777000ae991d384ee540e32b0d98a42645f494049ff96a20f365ecb08e3d9ce` |
| Portable evidence SHA-256 | `895c7d47209eb4f1bb3c56f5655ecc89b33b0cc7f1ce0d6e238ab5d9afa34712` |

Output starts are 116,373,499, 117,954,555, 117,956,603, and 118,097,239.
The leaf-commitment, plain-polynomial, consistency-polynomial, and xi-mask
values all match their global-tail consumers exactly.  The replay has zero
external assertions and zero failed rows.  Six stale-witness probes and three
point mutations were rejected.

## Contract lesson

The first attempted seal correctly failed closed after all rows passed because
the tree-1 row-stream byte count differed by five bytes from tree 0 despite the
same leaf count and degree.  The generic runner now freezes a stream byte count
only after a tree has been fully replayed.  Future trees must not infer this
identity from shape alone.

## Claim boundary

Newly true:

- `production_tree1_planned_assignment_materialized`;
- `production_tree1_planned_full_replay_closed`;
- `materialized_planned_tree_indices == [0, 1, 2]`; and
- `materialized_planned_tree_count == 3`.

Remaining producer materialization, all 72 relocations, the complete 18-tree
assignment, cross-segment identity, parent join, fork-security proof, and
`production_closed` remain false.

## Validation

- portable evidence frozen and externally resealed;
- affected runner/evidence/parent regression: 41 tests passed in 203.406
  seconds with no skips;
- complete repository regression: 229 tests passed in 804.496 seconds with
  nine optional external-artifact tests skipped;
- parent BR1CS: 49,227,687 bytes, unchanged SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Next checkpoint

R1d-b2 begins with tree index 3, executed alone through the generic runner.
Its stream byte count remains unknown until the first complete replay and must
not be predicted from the tree-2 archive.
