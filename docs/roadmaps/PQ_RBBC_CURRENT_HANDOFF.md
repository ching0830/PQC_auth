# PQ-RBBC current work handoff

This is the stable entry point for a new ChatGPT/Codex conversation.  Update it
at every merged checkpoint.

## Start a new session

Ask the GitHub-connected agent to:

> Read `docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md`, the newest versioned roadmap
> and release note, confirm the latest `main` commit, inspect external artifact
> availability by exact SHA-256, and continue only the listed next checkpoint.

Read, in order:

1. this file;
2. `README.md`;
3. `docs/roadmaps/PQ_RBBC_CRYPTO_CORE_ROADMAP_v2_21.md`;
4. `docs/releases/PQ_RBBC_v2_21_TREE2_REBASED_RECOVERY.md`;
5. `docs/artifacts/PQ_RBBC_v2_21_TREE2_REBASED_RECOVERY_EVIDENCE.md`; and
6. `docs/ARTIFACT_POLICY.md`.

Do not infer progress from old manifests.  Confirm the newest parent claim
boundary and external files before launching a large job.

## Closed gates

- R0-a: v2.8 composer cache recovered and canonical document revalidated;
- R0-b: v2.9 global-tail archive regenerated and independently replayed;
- R1d-a: tree-index-2 producer replayed at its planned offset and sealed.

Portable evidence SHA-256 values:

- production cache v2.19:
  `2b36ed1a4fb75e2ddbf826fa39ebd3d9b815a38873c93bd8635f56de2d8ad0f8`;
- global tail v2.20:
  `47709b4483871f5d365738eca276700c329d0b2ed2d7a6f4956874dd433a78c4`;
- tree-index-2 planned replay v2.21:
  `3e63ca4c014c5971fadfeed9dc8062fbaa86cec82c732c691695d4c80d5e584f`.

## Required external artifact identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `pq_rbbc_cap_global_tail_assignment_v2_9.f193assign` | 1,004,865,028 | `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1` |
| `pq_rbbc_production_tree_2_producer_v2_17_rebased.f193assign` | 486,961,028 | `2d9932cd09848d70fece5d047206f580ed6efe1e7335ac8ff865947e0662d933` |
| `pq_rbbc_cap_production_tree2_rebased_manifest_v2_17.json` | 6,883 | `487d32a77122e55f5bc753889aac22764104f0521c5f02e5855676dbf76ba78c` |
| `pq_rbbc_incremental_v2_21.br1cs` | 49,227,687 | `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799` |

The optional tree-2 cache is trusted local input only:
`tree_2_execution_checkpoint_v2_14.pkl`, 976,793 bytes, SHA-256
`63c01ed7c5087175fdfce59b2a37f2a8548cc41108cb850c65382e030fb35966`.
Never deserialize a downloaded or otherwise untrusted pickle.

If a closed artifact is missing, stop and ask for restoration.  Do not silently
regenerate it, substitute an older standalone assignment, or use the known
incomplete 302,596,096-byte global-tail copy.

The invariant parent BR1CS remains 49,227,687 bytes with SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.
Latest validation: 216 repository tests passed in 1,120.579 seconds with eight
optional external-artifact tests skipped.  The affected v2.21 suite passed 34
tests in 248.484 seconds with one optional external test skipped.

## Next single implementation point

R1d-b1: create a checkpointable planned-offset producer runner by generalizing
the existing tree-0/tree-2 machinery, then execute tree index 1.  Do not launch
all remaining producers as a single job.

Frozen tree-index-1 target:

- 4,096 leaves, degree 13;
- planned local wires 79,148,427 through 118,102,256;
- 38,953,830 local wires and 51,325,080 constraint rows;
- output starts 116,373,499, 117,954,555, 117,956,603, and 118,097,239;
- relation `pq-rbbc/cap/production-tree-producer-index-1/v1`;
- rebase delta 38,953,830.

Implementation requirements:

- parameterize tree identity and all namespace points without weakening frozen
  tree-0/tree-2 behavior;
- write deterministic, identity-bound checkpoints frequently enough to resume;
- independently replay the completed archive from first to last row;
- compare all four outputs with the recovered global tail;
- run stale-witness, point, identity, offset, and archive mutations;
- seal only path-free portable evidence; and
- propagate only the exact newly closed claim.

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
