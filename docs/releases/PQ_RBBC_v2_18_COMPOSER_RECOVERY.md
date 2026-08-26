# PQ-RBBC v2.18 — Production composer recovery gate

Date: 26 August 2026

## Outcome

Version 2.18 adds the missing checkpoint/resume layer needed to reconstruct the
frozen v2.8 18-tree composer execution cache.  The original v2.8 implementation
could preserve a cache only after the entire expensive execution completed.
The v2.18 runner instead writes an atomic checkpoint after every GGM derivation
level and every configurable leaf batch while retaining the v2.8 task
functions, canonical tree order, transcript construction, and document
serialization.

This release closes a recovery *gate*, not a production artifact.  The tracked
manifest records zero production levels and zero production leaf outputs
checkpointed.  The v2.8 execution cache, v2.9 global-tail assignment, and v2.17
rebased tree-2 assignment have not been regenerated.

## Frozen recovery contract

| Evidence | Result |
| --- | --- |
| Relation ID | `pq-rbbc/cap/production-composer-recovery/v1` |
| Checkpoint format | `PQRBBC-CAP-COMPOSER-CHECKPOINT-1` |
| Recovery contract SHA-256 | `e5b0f0d188f4540f58c328d2c40296971bb5f1cb81cec35ef512df2aaaa61578` |
| Source v2.8 document SHA-256 | `a7ef7eb4689d84c686074308d0d167e1567ab84578d66b5ad004970940ea0163` |
| Production profile SHA-256 | `2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38` |
| Production topology | 2 × (4,096 leaves, degree 13) + 16 × (2,048 leaves, degree 12) |
| Default leaf batch | 128 |
| Production checkpoints written | 0 |

Each checkpoint binds its format, relation, profile, serialized deterministic
randomness, tree shapes, random-polynomial width, phase, next level, nodes,
derivation records, and canonical leaf-output prefix into one state digest.
Writes use a same-directory temporary file, `fsync`, and atomic replacement.

## Executed reduced recovery evidence

The evidence runs the actual v2.8 composer task functions on the reduced
two-tree `(4, 3)` fixture.  It first builds the direct execution, intentionally
interrupts after one atomic checkpoint, resumes the saved state, and requires
the two executions to be equal.

- direct and resumed execution SHA-256:
  `c29f87dcf144a2a3d303daf26ac3665eb09d5e241f8941123d2052a5c18d21a1`;
- final checkpoint state SHA-256:
  `926614ffc0862fab816c410314a6ec8769b8ac0bc97848210585a715829ce544`;
- resumed checkpoints written: 4;
- execution-cache identity failures: 0; and
- checkpoint mutations rejected: 8/8.

The mutation probes cover format, relation, profile, randomness, tree shape,
node count, leaf overflow, and state digest.  This fixture validates recovery
mechanics only; it is not production replay or security evidence.

## Parent stability

The v2.18 native profile, Blind-UOV ABI, executable reference, and BR1CS
manifest import the recovery contract and its conservative boundary.  A full
parent regeneration remains 49,227,687 bytes with SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.
It still contains one external assertion.

## Claim boundary

The following are true:

- `production_composer_checkpoint_recovery_gate_closed`; and
- `reduced_checkpoint_resume_bit_exact`.

The following remain false:

- `production_execution_cache_regenerated`;
- `production_global_tail_archive_regenerated`;
- `production_tree2_rebased_assignment_materialized`;
- `production_tree2_rebased_full_replay_closed`;
- `representative_producers_rebased_replayed`;
- `complete_18_tree_assignment_replayed`;
- `parent_cap_to_h_rbbc_join_closed`;
- all formal fork security reductions; and
- `production_closed`.

## Validation

- recovery regression: 6 passed;
- affected parent regression: 28 passed;
- complete regression suite: 198 passed, 5 optional external-artifact tests
  skipped;
- parent BR1CS full generation and round-trip succeeded; and
- the parent BR1CS SHA-256 is unchanged from v2.17.

## Next implementation point

Run the checkpointed production composer recovery documented in
`docs/artifacts/PQ_RBBC_v2_18_PRODUCTION_RECOVERY.md`.  After the regenerated
cache reproduces the exact v2.8 document identity, rebuild and seal the v2.9
global-tail archive, then run the already-frozen v2.17 tree-2 planned-offset
replay.  The other sixteen producer runs remain gated on that result.
