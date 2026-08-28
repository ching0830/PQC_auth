# PQ-RBBC v2.25 tree-5 through tree-7 batch evidence

The tracked, path-free seal is:

`artifacts/metadata/tree5_7_batch_recovery_v2_25/pq_rbbc_cap_tree5_7_batch_recovery_evidence_v2_25.json`

Its SHA-256 is
`0041ea819434e0099d419757fa217fcfa30b810ef391b4a4603d8aee7ad06c72`.

The seal binds, separately for trees 5, 6, and 7, the generic runner and final
contract identities, planned intervals, archive header/body/whole-file
identities, first and last wires, row-stream sizes and hashes, replay-manifest
identities, tree-component hashes, four output locations and values, all
25,666,386 replayed rows, six stale-witness rejections, three point-mutation
rejections, and conservative claim boundaries.

## Verify the tracked seal

```bash
PYTHONPATH=src python \
  src/pq_rbbc_cap_tree5_7_batch_recovery_evidence.py \
  --verify-frozen \
  artifacts/metadata/tree5_7_batch_recovery_v2_25/pq_rbbc_cap_tree5_7_batch_recovery_evidence_v2_25.json
```

## Reseal trusted external artifacts

Set `PQRBBC_V2_25_BATCH_ROOT` to the directory containing the three
`production_treeN_v2_25_batch_planned` subdirectories, then run:

```bash
PYTHONPATH=src python \
  src/pq_rbbc_cap_tree5_7_batch_recovery_evidence.py \
  --manifest /tmp/pq_rbbc_cap_tree5_7_batch_recovery_evidence_v2_25.json \
  --batch-root "$PQRBBC_V2_25_BATCH_ROOT" \
  --global-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json
sha256sum /tmp/pq_rbbc_cap_tree5_7_batch_recovery_evidence_v2_25.json
```

The digest must equal the tracked seal.  Each archive is 486,961,028 bytes;
their SHA-256 values in tree order are `e8717997…43a18`, `e1126861…3abe`, and
`3c6670f1…f6db`.  The pre-freeze and frozen pickle caches are trusted local
inputs only: never deserialize an untrusted checkpoint and never add a cache,
assignment, resume state, or BR1CS to Git.
