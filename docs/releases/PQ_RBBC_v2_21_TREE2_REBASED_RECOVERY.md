# PQ-RBBC v2.21 — Tree-2 planned-offset recovery

Date: 27 August 2026

## Outcome

R1d-a is closed.  The production tree-index-2 producer was materialized at its
planned namespace offset, replayed from the first through the last row, and
checked against the recovered v2.9 global tail.  The tracked result is portable
sealed evidence; large binary artifacts remain external.

## Exact result

| Property | Value |
| --- | --- |
| Planned local wires | 118,102,257 through 137,580,692 |
| Local wire count | 19,478,436 |
| Constraint rows | 25,666,386 |
| Assignment bytes | 486,961,028 |
| Assignment SHA-256 | `2d9932cd09848d70fece5d047206f580ed6efe1e7335ac8ff865947e0662d933` |
| Assignment body SHA-256 | `632db9813ef41bb3af1d769189132d072208ca0a58e2810c76b844a39da3b501` |
| Row-stream bytes | 8,961,160,824 |
| Row-stream SHA-256 | `37da12bffb023ae1b92e9d54b4bb34591c2cb1006bdca1aa28d7d2c04fe9770f` |
| Replay manifest SHA-256 | `487d32a77122e55f5bc753889aac22764104f0521c5f02e5855676dbf76ba78c` |
| Portable evidence SHA-256 | `3e63ca4c014c5971fadfeed9dc8062fbaa86cec82c732c691695d4c80d5e584f` |

All four outputs match their planned global-tail locations: leaf commitments,
plain polynomial, consistency polynomial, and xi mask.  Six stale-witness
probes and three planned-point mutations were rejected.  The replay contains
zero external assertions and zero verification failures.

## Claim boundary

Only these recovery claims are newly true:

- `production_tree2_rebased_assignment_materialized`;
- `production_tree2_rebased_full_replay_closed`; and
- `representative_producers_rebased_replayed`.

Complete remaining producer materialization, all 72 relocations, the complete
18-tree assignment, the parent join, fork-security proof revalidation, and
`production_closed` remain false.

## Validation

- six portable-evidence tests passed, including external resealing;
- 34 affected parent/evidence tests passed;
- the complete repository suite passed 216 tests in 1,120.579 seconds with
  eight optional external-artifact tests skipped;
- the parent BR1CS rebuilt to 49,227,687 bytes with unchanged SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`;
- BR1CS round-trip, honest assignment, archive-corruption rejection, and bit
  tamper rejection passed.

## Next checkpoint

R1d-b1: generalize the tree-0/tree-2 machinery into a checkpointable
planned-offset producer runner, then execute tree index 1 at planned local wire
start 79,148,427.  Do not launch all remaining producers as one monolithic job.
