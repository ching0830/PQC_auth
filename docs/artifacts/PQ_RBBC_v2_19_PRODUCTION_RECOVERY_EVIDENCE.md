# PQ-RBBC v2.19 production recovery evidence

## Repository state

Git stores only the portable evidence document:

`artifacts/metadata/production_recovery_v2_19/pq_rbbc_cap_composer_recovery_evidence_v2_19.json`

Its canonical SHA-256 is
`2b36ed1a4fb75e2ddbf826fa39ebd3d9b815a38873c93bd8635f56de2d8ad0f8`.
It contains no absolute path and no pickle bytes.  The complete checkpoint,
execution cache, and recovered v2.8 composition document remain in durable
external storage.

## Trust boundary

The checkpoint and execution cache are Python pickle files generated locally
by the v2.18 runner.  Never use the sealer with a downloaded, shared, or
otherwise untrusted pickle.  Profile and digest checks detect wrong evidence
after loading; they do not make pickle deserialization safe.

## Verify tracked evidence only

```bash
PYTHONPATH=src python src/pq_rbbc_cap_composer_recovery_evidence.py \
  --verify-frozen artifacts/metadata/production_recovery_v2_19/pq_rbbc_cap_composer_recovery_evidence_v2_19.json
```

## Rebuild the portable evidence from trusted local artifacts

Set the root to the completed v2.18 recovery directory and run:

```bash
export PQRBBC_RECOVERY_ROOT=/path/to/production_recovery_v2_18

PYTHONPATH=src python src/pq_rbbc_cap_composer_recovery_evidence.py \
  --manifest /tmp/pq_rbbc_cap_composer_recovery_evidence_v2_19.json \
  --recovery-manifest "$PQRBBC_RECOVERY_ROOT/pq_rbbc_cap_composer_recovery_manifest_v2_18.json" \
  --checkpoint "$PQRBBC_RECOVERY_ROOT/pq_rbbc_cap_composer_checkpoint_v2_18.pkl" \
  --execution-cache "$PQRBBC_RECOVERY_ROOT/pq_rbbc_cap_composition_execution_v2_8.pkl" \
  --composition-manifest "$PQRBBC_RECOVERY_ROOT/pq_rbbc_cap_composition_manifest_v2_8.json"

sha256sum /tmp/pq_rbbc_cap_composer_recovery_evidence_v2_19.json
```

The digest must be exactly
`2b36ed1a4fb75e2ddbf826fa39ebd3d9b815a38873c93bd8635f56de2d8ad0f8`.
The sealer validates the complete checkpoint, cache type and identity, tree
shape, execution digest, XOF trace, commitment, canonical document, original
document mutation probes, and conservative claim boundary.

## R0-b — Regenerate the v2.9 global tail

Keep the output outside Git and use the unchanged production generator:

```bash
export PQRBBC_ARTIFACT_ROOT=/path/to/pq_rbbc_external_artifacts
mkdir -p "$PQRBBC_ARTIFACT_ROOT/global_tail_v2_9_recovery"

PYTHONPATH=src python -u src/pq_rbbc_cap_global_tail.py \
  --fixture production \
  --archive "$PQRBBC_ARTIFACT_ROOT/global_tail_v2_9_recovery/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign" \
  --manifest "$PQRBBC_ARTIFACT_ROOT/global_tail_v2_9_recovery/pq_rbbc_cap_global_tail_manifest_v2_9.json" \
  --execution-cache "$PQRBBC_RECOVERY_ROOT/pq_rbbc_cap_composition_execution_v2_8.pkl" \
  --workers 8
```

Before sealing, require:

```bash
stat -c '%s' "$PQRBBC_ARTIFACT_ROOT/global_tail_v2_9_recovery/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign"
sha256sum "$PQRBBC_ARTIFACT_ROOT/global_tail_v2_9_recovery/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign"
```

The exact size is 1,004,865,028 bytes and the exact SHA-256 is
`946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`.
Then independently verify/replay the archive and seal the manifest using the
v2.9 procedure.  Until those checks finish,
`production_global_tail_archive_regenerated` remains false.
