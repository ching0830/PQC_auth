# PQ-RBBC current work handoff

This is the stable entry point for a new ChatGPT/Codex conversation.  Update it
at every merged checkpoint.

## Start a new session

Ask the GitHub-connected agent to:

> Read `docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md`, the newest versioned roadmap
> and release note, confirm the latest `main` commit, inspect external artifact
> availability by exact SHA-256, and continue only the listed next checkpoint.

The agent should read, in order:

1. this file;
2. `README.md`;
3. `docs/roadmaps/PQ_RBBC_CRYPTO_CORE_ROADMAP_v2_20.md`;
4. `docs/releases/PQ_RBBC_v2_20_GLOBAL_TAIL_RECOVERY.md`;
5. `docs/ARTIFACT_POLICY.md`; and
6. the artifact note named in the next checkpoint.

Do not infer progress from old versioned manifests alone.  Confirm the newest
parent claim boundary and the external files before launching a large job.

## Current closed recovery gates

- R0-a: v2.8 composer cache recovered and canonical document revalidated;
- R0-b: v2.9 global-tail archive regenerated and independently replayed;
- production cache evidence SHA-256:
  `2b36ed1a4fb75e2ddbf826fa39ebd3d9b815a38873c93bd8635f56de2d8ad0f8`;
- global-tail recovery evidence SHA-256:
  `47709b4483871f5d365738eca276700c329d0b2ed2d7a6f4956874dd433a78c4`.

The current global-tail archive is external:

- `pq_rbbc_cap_global_tail_assignment_v2_9.f193assign`;
- 1,004,865,028 bytes;
- SHA-256 `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`.

If it is missing, stop and ask for restoration.  Do not silently regenerate a
closed checkpoint or use the known incomplete 302,596,096-byte old copy.

Latest validation: 210 repository tests passed in 1,058.920 seconds with seven
optional external-artifact tests skipped.  The invariant parent BR1CS is
49,227,687 bytes with SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Next single implementation point

R1d-a: execute the production tree-index-2 producer at planned local wire start
118,102,257 using `src/pq_rbbc_cap_production_tree2_rebased.py` and
`docs/artifacts/PQ_RBBC_v2_17_TREE2_REBASED_REPLAY.md`.

Required inputs:

- the verified global-tail archive above;
- tracked `manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json`;
- optionally the trusted local
  `tree_2_execution_checkpoint_v2_14.pkl` (976,793 bytes, SHA-256
  `63c01ed7c5087175fdfce59b2a37f2a8548cc41108cb850c65382e030fb35966`).

The pickle must be locally generated and trusted; never deserialize a
downloaded or untrusted cache.  If it is unavailable, omit `--execution-cache`
and use the v2.17 checkpoint/resume path.

Example after resolving external paths:

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_production_tree2_rebased.py \
  --manifest "$PQRBBC_TREE2_OUTPUT/pq_rbbc_cap_production_tree2_rebased_manifest_v2_17.json" \
  --output-directory "$PQRBBC_TREE2_OUTPUT" \
  --global-archive "$PQRBBC_GLOBAL_TAIL_ARCHIVE" \
  --global-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json \
  --execution-cache "$PQRBBC_TREE2_CACHE" \
  --workers 8
```

Expected rows, wire ranges, output starts, assignment size, body digest, and
mutation gates are listed in the v2.20 roadmap.  Independently verify and seal
the result before propagating claims.

## Claims that must remain false

- complete remaining producer materialization;
- all 72 production output relocations replayed;
- complete 18-tree assignment replayed;
- parent CAP-to-H-RBBC join closed;
- fork security proof revalidated; and
- `production_closed`.

## Git and artifact discipline

- commit source, tests, manifests, portable metadata, docs, and checksums;
- never commit checkpoints, pickle caches, `.f193assign` archives, BR1CS
  archives, or split archive parts;
- open a dedicated branch and PR; do not merge without the user's instruction;
- before handoff, record exact tests, artifact identities, next command, and
  conservative false claims in this file.
