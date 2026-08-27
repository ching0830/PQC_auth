# PQ-RBBC v2.23 tree-3 planned recovery evidence

The tracked, path-free seal is:

`artifacts/metadata/tree3_planned_recovery_v2_23/pq_rbbc_cap_tree3_planned_recovery_evidence_v2_23.json`

Its SHA-256 is
`7369957afbcb4b5091ee06b914a2ef807392c857af941c06f412d80366c8aa93`.

## External identities

- replayed assignment: 486,961,028 bytes, SHA-256
  `315e83340d10331188d27a99a82de6f1262e36468f1b6f8c6ef97283d83fc02b`;
- assignment body: 486,960,900 bytes, SHA-256
  `b9c244e8fea051e6119a72733b845ab5dae4c247f5da618037d1864e9f51f2b1`;
- row stream: 8,961,160,824 bytes, SHA-256
  `0ad71fd26237442e2f2e4b8b73324a98761341a405f362397f841d61e860439a`;
- tree component SHA-256:
  `404d5eeccdf53e7656d3df2a5e584c8cfa0ac2e2b3c916c1e4dee61fd8659b43`;
- replay manifest: 7,073 bytes, SHA-256
  `1054dd12e7144ba0e66cca98f57d697163c5b0bcd72292aecc486edff9918b15`.

The seal binds the generic runner and tree-3 frozen contract identities,
planned interval, four output locations and digests, source global-tail
identity, all 25,666,386 replayed rows, six stale-witness rejections, three
point-mutation rejections, and conservative claim boundaries.

## Verify the tracked seal

```bash
PYTHONPATH=src python \
  src/pq_rbbc_cap_tree3_planned_recovery_evidence.py \
  --verify-frozen \
  artifacts/metadata/tree3_planned_recovery_v2_23/pq_rbbc_cap_tree3_planned_recovery_evidence_v2_23.json
```

## Reseal trusted external artifacts

Set `PQRBBC_V2_23_TREE3_ROOT` to the trusted external result directory, then:

```bash
PYTHONPATH=src python \
  src/pq_rbbc_cap_tree3_planned_recovery_evidence.py \
  --manifest /tmp/pq_rbbc_cap_tree3_planned_recovery_evidence_v2_23.json \
  --archive "$PQRBBC_V2_23_TREE3_ROOT/pq_rbbc_production_tree_3_producer_v2_23_planned.f193assign" \
  --replayed-manifest "$PQRBBC_V2_23_TREE3_ROOT/pq_rbbc_cap_planned_tree3_replayed_manifest_v2_23.json" \
  --global-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json
sha256sum /tmp/pq_rbbc_cap_tree3_planned_recovery_evidence_v2_23.json
```

The digest must equal the tracked seal.  The pre-freeze and frozen pickle
caches are trusted local inputs only: never deserialize a downloaded or
otherwise untrusted checkpoint, and never add them or the assignment archive
to Git.
