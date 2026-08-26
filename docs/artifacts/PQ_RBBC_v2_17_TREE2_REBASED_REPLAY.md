# PQ-RBBC v2.17 tree-2 planned-offset replay

## Repository state

The tracked v2.17 manifest is a preflight manifest.  It records
`production_replay.status = not_materialized` and exactly zero production rows
at the planned offset.  The large input and output artifacts are intentionally
excluded by `docs/ARTIFACT_POLICY.md`.

## Required external input

The mandatory input is:

- file: `pq_rbbc_cap_global_tail_assignment_v2_9.f193assign`;
- bytes: 1,004,865,028;
- SHA-256: `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`.

The completed v2.14 cache
`tree_2_execution_checkpoint_v2_14.pkl` is optional but strongly recommended.
It is identity-validated before reuse.  If omitted, producer material is
regenerated with checkpoint/resume in the v2.17 output directory.

## Preflight reproduction

```bash
PYTHONPATH=src python src/pq_rbbc_cap_production_tree2_rebased.py \
  --manifest manifests/pq_rbbc_cap_production_tree2_rebased_manifest_v2_17.json
```

This command runs the reduced two-offset generator replay.  It does not read or
write a production assignment.

## Production replay

With `PQRBBC_ARTIFACT_ROOT` pointing at restored external artifacts:

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_production_tree2_rebased.py \
  --manifest "$PQRBBC_ARTIFACT_ROOT/production_tree2_v2_17_rebased/pq_rbbc_cap_production_tree2_rebased_manifest_v2_17.json" \
  --output-directory "$PQRBBC_ARTIFACT_ROOT/production_tree2_v2_17_rebased" \
  --global-archive "$PQRBBC_ARTIFACT_ROOT/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign" \
  --global-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json \
  --execution-cache "$PQRBBC_ARTIFACT_ROOT/production_tree2_v2_14/tree_2_execution_checkpoint_v2_14.pkl" \
  --workers 8
```

If the optional cache is unavailable, omit `--execution-cache`; the default
v2.17 cache path in the output directory will be checkpointed and resumable.
Do not use `--replace` when resuming a partial assignment.  Use it only for an
explicit clean regeneration after preserving any needed partial evidence.

## Expected output names

- `pq_rbbc_production_tree_2_producer_v2_17_rebased.f193assign`;
- `tree_2_execution_checkpoint_v2_17_rebased.pkl` when the default cache is used;
- `tree_2_resume_state_v2_17_rebased.json`; and
- `pq_rbbc_cap_production_tree2_rebased_manifest_v2_17.json`.

The resulting manifest is accepted only if all 25,666,386 rows replay, the
19,478,436 assignment values match the v2.14 value-body digest, all output
values match the tail, and every mutation probe rejects.  Until that output is
independently verified and sealed, the tracked preflight claim boundary must
remain unchanged.
