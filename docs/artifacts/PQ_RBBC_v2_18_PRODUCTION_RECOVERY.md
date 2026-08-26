# PQ-RBBC v2.18 production artifact recovery

## Repository state

The tracked v2.18 recovery manifest is preflight evidence.  It records
`production_recovery.status = not_started`, zero production derivation levels,
and zero production leaf outputs.  No production cache or assignment is stored
in Git.

## Trust boundary

The checkpoint and execution cache are Python pickle files.  They are intended
only for local interruption/resume and are validated against the frozen
profile, randomness, topology, and execution identities after loading.  Pickle
deserialization itself is not safe for hostile input: never load a downloaded,
shared, or otherwise untrusted checkpoint/cache.  Rebuild locally instead.

## Preflight reproduction

```bash
PYTHONPATH=src python src/pq_rbbc_cap_composer_recovery.py \
  --manifest manifests/pq_rbbc_cap_composer_recovery_manifest_v2_18.json
```

This runs only the reduced interruption/resume fixture and eight mutation
probes.  It does not start the production composer.

## R0-a — Recover the v2.8 execution cache

Choose an external artifact root with enough durable storage, then run:

```bash
export PQRBBC_ARTIFACT_ROOT=/path/to/pq_rbbc_external_artifacts
mkdir -p "$PQRBBC_ARTIFACT_ROOT/production_recovery_v2_18"

PYTHONPATH=src python -u src/pq_rbbc_cap_composer_recovery.py \
  --manifest "$PQRBBC_ARTIFACT_ROOT/production_recovery_v2_18/pq_rbbc_cap_composer_recovery_manifest_v2_18.json" \
  --checkpoint "$PQRBBC_ARTIFACT_ROOT/production_recovery_v2_18/pq_rbbc_cap_composer_checkpoint_v2_18.pkl" \
  --execution-cache "$PQRBBC_ARTIFACT_ROOT/production_recovery_v2_18/pq_rbbc_cap_composition_execution_v2_8.pkl" \
  --composition-manifest "$PQRBBC_ARTIFACT_ROOT/production_recovery_v2_18/pq_rbbc_cap_composition_manifest_v2_8.json" \
  --workers 8 \
  --leaf-batch 128
```

If interrupted, rerun exactly the same command.  The runner validates and
continues the atomic checkpoint.  Do not add `--replace-checkpoint`; that flag
intentionally discards resumable progress.  Existing final outputs are also
refused unless `--replace-outputs` is explicitly requested for a clean,
preserved-and-reviewed regeneration.

Completion is accepted only when the recovered composition document SHA-256
is exactly
`a7ef7eb4689d84c686074308d0d167e1567ab84578d66b5ad004970940ea0163`.
The resulting production manifest may then record
`production_execution_cache_regenerated = true`; later artifact claims remain
false.

## R0-b — Regenerate and seal the v2.9 global tail

After independently checking the recovered cache and v2.8 document:

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_global_tail.py \
  --fixture production \
  --archive "$PQRBBC_ARTIFACT_ROOT/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign" \
  --manifest "$PQRBBC_ARTIFACT_ROOT/pq_rbbc_cap_global_tail_manifest_v2_9.json" \
  --execution-cache "$PQRBBC_ARTIFACT_ROOT/production_recovery_v2_18/pq_rbbc_cap_composition_execution_v2_8.pkl" \
  --workers 8

sha256sum "$PQRBBC_ARTIFACT_ROOT/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign"

PYTHONPATH=src python src/pq_rbbc_cap_global_tail.py \
  --seal-existing "$PQRBBC_ARTIFACT_ROOT/pq_rbbc_cap_global_tail_manifest_v2_9.json"
```

The archive must be 1,004,865,028 bytes with SHA-256
`946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`
before sealing.  Preserve both the cache and archive outside Git.

## R1d-a — Continue with the v2.17 tree-2 replay

Use the regenerated global-tail archive with the production command in
`docs/artifacts/PQ_RBBC_v2_17_TREE2_REBASED_REPLAY.md`.  A complete
25,666,386-row replay at local wire start 118,102,257 is still required before
either rebased-production claim may become true.
