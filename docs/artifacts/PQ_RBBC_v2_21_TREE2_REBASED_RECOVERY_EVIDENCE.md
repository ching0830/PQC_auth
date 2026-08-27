# PQ-RBBC v2.21 tree-2 rebased recovery evidence

The tracked path-free seal is:

`artifacts/metadata/tree2_rebased_recovery_v2_21/pq_rbbc_cap_tree2_rebased_recovery_evidence_v2_21.json`

Its SHA-256 is
`3e63ca4c014c5971fadfeed9dc8062fbaa86cec82c732c691695d4c80d5e584f`.

## External identities

- replayed assignment: 486,961,028 bytes, SHA-256
  `2d9932cd09848d70fece5d047206f580ed6efe1e7335ac8ff865947e0662d933`;
- assignment body SHA-256:
  `632db9813ef41bb3af1d769189132d072208ca0a58e2810c76b844a39da3b501`;
- row-stream SHA-256:
  `37da12bffb023ae1b92e9d54b4bb34591c2cb1006bdca1aa28d7d2c04fe9770f`;
- replay manifest: 6,883 bytes, SHA-256
  `487d32a77122e55f5bc753889aac22764104f0521c5f02e5855676dbf76ba78c`.

The seal also binds the planned interval, four global output locations, source
global-tail identity, six stale-witness rejections, three point-mutation
rejections, and all output digests.

## Verify the tracked seal

```bash
PYTHONPATH=src python src/pq_rbbc_cap_tree2_rebased_recovery_evidence.py \
  --verify-frozen \
  artifacts/metadata/tree2_rebased_recovery_v2_21/pq_rbbc_cap_tree2_rebased_recovery_evidence_v2_21.json
```

## Reseal an external replay

After setting `PQRBBC_TREE2_ROOT` to the trusted external directory:

```bash
PYTHONPATH=src python src/pq_rbbc_cap_tree2_rebased_recovery_evidence.py \
  --archive "$PQRBBC_TREE2_ROOT/pq_rbbc_production_tree_2_producer_v2_17_rebased.f193assign" \
  --replay-manifest "$PQRBBC_TREE2_ROOT/pq_rbbc_cap_production_tree2_rebased_manifest_v2_17.json" \
  --global-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json \
  --output /tmp/pq_rbbc_cap_tree2_rebased_recovery_evidence_v2_21.json
```

The generated digest must equal the tracked evidence SHA-256 above.  Never
deserialize an untrusted execution-cache pickle while reconstructing this
artifact.
