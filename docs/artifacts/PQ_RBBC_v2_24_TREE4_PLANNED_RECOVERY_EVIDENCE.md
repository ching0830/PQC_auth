# PQ-RBBC v2.24 tree-4 planned recovery evidence

The tracked, path-free seal is:

`artifacts/metadata/tree4_planned_recovery_v2_24/pq_rbbc_cap_tree4_planned_recovery_evidence_v2_24.json`

Its SHA-256 is
`bb80e09bc0383444ac428a84912c828db096bd2ccd6165990bbe6464e4a7233e`.

## External identities

- replayed assignment: 486,961,028 bytes, SHA-256
  `cd2430637f8ca07356727cb4349ca02368f2268f865092c71f3049140bacf52d`;
- assignment body: 486,960,900 bytes, SHA-256
  `e105adcfc79c10089c72ecd059c9935a3032c4ab79ccc7d2e75dbdde245017fd`;
- row stream: 8,961,160,824 bytes, SHA-256
  `975b8422a29b4b7c6ee338f6821eb56b4bb74957a899da61dda11531eb13dd12`;
- tree component SHA-256:
  `a157dedd0a7bf408b5065a853bc29b9312b2cb8ce35397204d8680e9aaf24fd6`;
- replay manifest: 7,195 bytes, SHA-256
  `69c46b27a2d61248ac817c308c3a0f85d0344492912d854f6055cc8c2dbdf8b8`.

The seal binds the generic runner and tree-4 final frozen contract identities,
planned interval, four output locations and digests, source global-tail and
prior-tree evidence identities, all 25,666,386 replayed rows, six stale-witness
rejections, three point-mutation rejections, and conservative claim boundaries.

## Verify the tracked seal

```bash
PYTHONPATH=src python \
  src/pq_rbbc_cap_tree4_planned_recovery_evidence.py \
  --verify-frozen \
  artifacts/metadata/tree4_planned_recovery_v2_24/pq_rbbc_cap_tree4_planned_recovery_evidence_v2_24.json
```

## Reseal trusted external artifacts

Set `PQRBBC_V2_24_TREE4_ROOT` to the trusted external result directory, then:

```bash
PYTHONPATH=src python \
  src/pq_rbbc_cap_tree4_planned_recovery_evidence.py \
  --manifest /tmp/pq_rbbc_cap_tree4_planned_recovery_evidence_v2_24.json \
  --archive "$PQRBBC_V2_24_TREE4_ROOT/pq_rbbc_production_tree_4_producer_v2_24_planned.f193assign" \
  --replayed-manifest "$PQRBBC_V2_24_TREE4_ROOT/pq_rbbc_cap_planned_tree4_replayed_manifest_v2_24.json" \
  --global-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json
sha256sum /tmp/pq_rbbc_cap_tree4_planned_recovery_evidence_v2_24.json
```

The digest must equal the tracked seal.  The pre-freeze and frozen pickle
caches are trusted local inputs only: never deserialize a downloaded or
otherwise untrusted checkpoint, and never add them, the assignment archive,
resume state, or BR1CS to Git.
