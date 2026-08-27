# PQ-RBBC v2.22 tree-1 planned recovery evidence

The tracked, path-free seal is:

`artifacts/metadata/tree1_planned_recovery_v2_22/pq_rbbc_cap_tree1_planned_recovery_evidence_v2_22.json`

Its SHA-256 is
`895c7d47209eb4f1bb3c56f5655ecc89b33b0cc7f1ce0d6e238ab5d9afa34712`.

## External identities

- replayed assignment: 973,845,878 bytes, SHA-256
  `ab75aca6037e47fe38a1364d2c66f90d1a3856da901423b398fa2d8812fa609f`;
- assignment body: 973,845,750 bytes, SHA-256
  `00b175ebf9414e9d7a4bae49de4e0bf7ff568631dc8865f898a3ed084ab6061f`;
- row stream: 18,008,277,115 bytes, SHA-256
  `1a9c11a716cb491517277c6e18c805683d85a75cb2c5306f13db7b7f13d1f516`;
- tree component SHA-256:
  `0db861243dbc72fffb09799ea50c4b770c3cb2a847d4dd66fffc968b91790d81`;
- replay manifest: 6,963 bytes, SHA-256
  `1777000ae991d384ee540e32b0d98a42645f494049ff96a20f365ecb08e3d9ce`.

The seal binds the generic runner and tree-1 contract identities, planned
interval, four output locations and digests, source global-tail identity, all
51,325,080 replayed rows, six stale-witness rejections, three point-mutation
rejections, and conservative claim boundaries.

## Verify the tracked seal

```bash
PYTHONPATH=src python \
  src/pq_rbbc_cap_tree1_planned_recovery_evidence.py \
  --verify-frozen \
  artifacts/metadata/tree1_planned_recovery_v2_22/pq_rbbc_cap_tree1_planned_recovery_evidence_v2_22.json
```

## Reseal trusted external artifacts

Set `PQRBBC_V2_22_TREE1_ROOT` to the trusted external result directory, then:

```bash
PYTHONPATH=src python \
  src/pq_rbbc_cap_tree1_planned_recovery_evidence.py \
  --manifest /tmp/pq_rbbc_cap_tree1_planned_recovery_evidence_v2_22.json \
  --archive "$PQRBBC_V2_22_TREE1_ROOT/pq_rbbc_production_tree_1_producer_v2_22_planned.f193assign" \
  --replayed-manifest "$PQRBBC_V2_22_TREE1_ROOT/pq_rbbc_cap_planned_tree1_replayed_manifest_v2_22.json" \
  --global-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json
sha256sum /tmp/pq_rbbc_cap_tree1_planned_recovery_evidence_v2_22.json
```

The digest must equal the tracked seal.  The pickle checkpoints are trusted
local inputs only: never deserialize a downloaded or otherwise untrusted
checkpoint, and never add them or the assignment archive to Git.
