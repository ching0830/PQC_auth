# PQ-RBBC v2.20 — Production global-tail recovery

Date: 27 August 2026

## Outcome

Version 2.20 completes R0-b.  The unchanged v2.9 generator consumed the
trusted v2.8 execution cache recovered in v2.19, regenerated the complete
production global-tail assignment, reopened it by mmap, replayed every native
row, and rejected all six stale-witness mutations.

This restores the external archive required by the v2.17 tree-2
planned-offset runner.  It does not materialize that rebased producer, the
remaining sixteen producers, the complete 18-tree assignment, the parent join,
or any formal fork security proof.

## Exact recovery result

| Evidence | Result |
| --- | --- |
| Relation | `pq-rbbc/cap/production-global-tail/v1` |
| Rows / wires | 56,806,711 / 40,194,596 |
| Row-stream SHA-256 | `c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df` |
| Archive bytes | 1,004,865,028 |
| Archive SHA-256 | `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1` |
| Body bytes | 1,004,864,900 |
| Body SHA-256 | `358266d106a1ac01cacb7c19c9bff1a7da2acceeb580a1d54462f31986cba925` |
| External assertions / replay failures | 0 / 0 |
| Stale-witness probes | 6/6 rejected |
| Generation time | 4,152.806 seconds |
| Replay and mutation time | 1,445.442 seconds |
| Reported peak RSS | 1,569,280 KiB |

An independent reader verified the fixed-width header, body digest, first and
last wire access, wire count, and row-stream digest.  A separate whole-file
SHA-256 pass reproduced the frozen archive identity before the manifest was
sealed.

## Historical equivalence

The recovered sealed manifest has SHA-256
`ef53b43f57dc5a740ab612caa4437f1e47273f645d3a8454c689bc4666a5bb5b`.
Its security-relevant content is byte-for-value equivalent to the historical
v2.9 sealed manifest.  The only differences are the environment-dependent
`generation_seconds`, `verification_seconds`, and `peak_rss_kib` values.

The path-free v2.20 evidence has canonical SHA-256
`47709b4483871f5d365738eca276700c329d0b2ed2d7a6f4956874dd433a78c4`.
The one-gigabyte archive remains outside Git.

## Claim boundary

Version 2.20 newly makes
`production_global_tail_archive_regenerated = true`.  The already frozen
`production_global_tail_native_closed` claim remains true.  These remain
false:

- `production_tree2_rebased_assignment_materialized`;
- `production_tree2_rebased_full_replay_closed`;
- `representative_producers_rebased_replayed`;
- `complete_18_tree_assignment_replayed`;
- `parent_cap_to_h_rbbc_join_closed`;
- `fork_security_proof_revalidated`; and
- `production_closed`.

## Validation

- global-tail reduced regression: 6 passed;
- portable recovery evidence: 6 passed, including external archive reseal;
- affected parent regression: 34 passed, with one optional external archive
  test skipped when its environment variable is absent;
- fresh parent BR1CS remains invariant at 49,227,687 bytes with SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`;
- BR1CS honest round trip, body digest, corruption rejection, and assignment
  tamper rejection pass with zero external failures and one unchanged external
  assertion; and
- complete repository regression: 210 tests passed in 1,058.920 seconds, with
  seven optional external-artifact tests skipped.

## Next checkpoint

Execute R1d-a with `pq_rbbc_cap_production_tree2_rebased.py`.  It must replay
all 25,666,386 producer rows at planned local wire start 118,102,257, preserve
the two global consistency-point wire ranges, match all four output ports, and
reject every standard and point mutation before any tree-2 production claim is
advanced.
