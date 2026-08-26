# PQ-RBBC v2.20 global-tail recovery evidence

## Repository state

Git stores only the portable evidence document:

`artifacts/metadata/global_tail_recovery_v2_20/pq_rbbc_cap_global_tail_recovery_evidence_v2_20.json`

Its canonical SHA-256 is
`47709b4483871f5d365738eca276700c329d0b2ed2d7a6f4956874dd433a78c4`.
It contains no absolute path or assignment bytes.

## External archive identity

- file: `pq_rbbc_cap_global_tail_assignment_v2_9.f193assign`;
- bytes: 1,004,865,028;
- SHA-256: `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`;
- body SHA-256: `358266d106a1ac01cacb7c19c9bff1a7da2acceeb580a1d54462f31986cba925`;
- row-stream SHA-256: `c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df`.

The archive is a non-executable fixed-width binary assignment.  Preserve it
outside Git and verify its whole-file digest before reuse.

## Verify tracked evidence

```bash
PYTHONPATH=src python src/pq_rbbc_cap_global_tail_recovery_evidence.py \
  --verify-frozen artifacts/metadata/global_tail_recovery_v2_20/pq_rbbc_cap_global_tail_recovery_evidence_v2_20.json
```

## Reseal from external artifacts

```bash
export PQRBBC_GLOBAL_TAIL_ROOT=/path/to/production_global_tail_recovery_v2_20

PYTHONPATH=src python src/pq_rbbc_cap_global_tail_recovery_evidence.py \
  --manifest /tmp/pq_rbbc_cap_global_tail_recovery_evidence_v2_20.json \
  --archive "$PQRBBC_GLOBAL_TAIL_ROOT/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign" \
  --recovered-manifest "$PQRBBC_GLOBAL_TAIL_ROOT/pq_rbbc_cap_global_tail_manifest_v2_9.json" \
  --historical-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json
```

The digest must be exactly
`47709b4483871f5d365738eca276700c329d0b2ed2d7a6f4956874dd433a78c4`.
The sealer reads and hashes the complete external archive, revalidates the
sealed v2.9 manifest, and permits only the three recorded environment-dependent
performance measurements to differ from historical evidence.
