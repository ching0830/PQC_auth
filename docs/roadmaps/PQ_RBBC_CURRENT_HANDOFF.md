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
3. `docs/roadmaps/PQ_RBBC_CRYPTO_CORE_ROADMAP_v2_24.md`;
4. `docs/releases/PQ_RBBC_v2_24_TREE4_PLANNED_RECOVERY.md`;
5. `docs/artifacts/PQ_RBBC_v2_24_TREE4_PLANNED_RECOVERY_EVIDENCE.md`; and
6. `docs/ARTIFACT_POLICY.md`.

Do not infer progress from old manifests.  Confirm the newest parent claim
boundary and external files before launching a large job.

The v2.24 checkpoint work is based on merged `main` commit
`08e5a0cbaa060abb424da543277261c0ba23d240`.  A new session must still read the
current remote `main` rather than assuming this SHA remains the branch tip.

## Closed gates

- R0-a: v2.8 composer cache recovered and canonical document revalidated;
- R0-b: v2.9 global-tail archive regenerated and independently replayed;
- R1d-a: tree-index-2 producer replayed at its planned offset and sealed;
- R1d-b1: generic checkpointable runner implemented and tree index 1 replayed
  at its planned offset and sealed;
- R1d-b2 tree-index-3 iteration: tree index 3 replayed under its frozen stream
  identity and sealed; and
- R1d-b2 tree-index-4 iteration: tree index 4 replayed under its frozen stream
  identity and sealed.

Portable evidence SHA-256 values:

- production cache v2.19:
  `2b36ed1a4fb75e2ddbf826fa39ebd3d9b815a38873c93bd8635f56de2d8ad0f8`;
- global tail v2.20:
  `47709b4483871f5d365738eca276700c329d0b2ed2d7a6f4956874dd433a78c4`;
- tree-index-2 planned replay v2.21:
  `3e63ca4c014c5971fadfeed9dc8062fbaa86cec82c732c691695d4c80d5e584f`;
- tree-index-1 planned replay v2.22:
  `895c7d47209eb4f1bb3c56f5655ecc89b33b0cc7f1ce0d6e238ab5d9afa34712`;
- tree-index-3 planned replay v2.23:
  `7369957afbcb4b5091ee06b914a2ef807392c857af941c06f412d80366c8aa93`;
- tree-index-4 planned replay v2.24:
  `bb80e09bc0383444ac428a84912c828db096bd2ccd6165990bbe6464e4a7233e`.

## Required external artifact identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `pq_rbbc_cap_global_tail_assignment_v2_9.f193assign` | 1,004,865,028 | `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1` |
| `pq_rbbc_production_tree_2_producer_v2_17_rebased.f193assign` | 486,961,028 | `2d9932cd09848d70fece5d047206f580ed6efe1e7335ac8ff865947e0662d933` |
| `pq_rbbc_cap_production_tree2_rebased_manifest_v2_17.json` | 6,883 | `487d32a77122e55f5bc753889aac22764104f0521c5f02e5855676dbf76ba78c` |
| `pq_rbbc_production_tree_1_producer_v2_22_planned.f193assign` | 973,845,878 | `ab75aca6037e47fe38a1364d2c66f90d1a3856da901423b398fa2d8812fa609f` |
| `pq_rbbc_cap_planned_tree1_replayed_manifest_v2_22.json` | 6,963 | `1777000ae991d384ee540e32b0d98a42645f494049ff96a20f365ecb08e3d9ce` |
| `pq_rbbc_production_tree_3_producer_v2_23_planned.f193assign` | 486,961,028 | `315e83340d10331188d27a99a82de6f1262e36468f1b6f8c6ef97283d83fc02b` |
| `pq_rbbc_cap_planned_tree3_replayed_manifest_v2_23.json` | 7,073 | `1054dd12e7144ba0e66cca98f57d697163c5b0bcd72292aecc486edff9918b15` |
| `pq_rbbc_production_tree_4_producer_v2_24_planned.f193assign` | 486,961,028 | `cd2430637f8ca07356727cb4349ca02368f2268f865092c71f3049140bacf52d` |
| `pq_rbbc_cap_planned_tree4_replayed_manifest_v2_24.json` | 7,195 | `69c46b27a2d61248ac817c308c3a0f85d0344492912d854f6055cc8c2dbdf8b8` |
| `pq_rbbc_incremental_v2_24.br1cs` | 49,227,687 | `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799` |

The optional producer caches are trusted local inputs only.  Never deserialize
a downloaded or otherwise untrusted pickle.  The v2.24 tree-4 result directory
is `/workspace/pq_rbbc_external_artifacts_v2_24/production_tree4_v2_24_planned/`;
verify the non-pickle files by the identities above before use.

If a closed artifact is missing, stop and ask for restoration.  Do not
silently regenerate it, substitute an older standalone assignment, or use the
known incomplete 302,596,096-byte global-tail copy.

The invariant parent BR1CS remains 49,227,687 bytes with SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.
The affected v2.24 runner/evidence/parent suite passed 55 tests in 199.537
seconds with no skips.  The complete repository suite passed 243 tests in
864.903 seconds with eleven optional external-artifact tests skipped.

## Next single implementation point

Continue R1d-b2 with tree index 5 alone through the v2.24 generic
planned-offset runner.  Do not launch all remaining producers as one job.

Frozen tree-index-5 target:

- 2,048 leaves, degree 12;
- planned local wires 176,537,565 through 196,016,000;
- 19,478,436 local wires and 25,666,386 constraint rows;
- output starts 195,148,365, 195,938,893, 195,940,941, and 196,011,369;
- relation `pq-rbbc/cap/production-tree-producer-index-5/v1`;
- rebase delta 136,342,968;
- expected assignment size 486,961,028 bytes;
- row-stream bytes deliberately unfrozen until the first complete replay; and
- initial `stream_bytes = null` contract SHA-256
  `5e06e6194e3b08d204f0922d99a39e05bcd16516877dc639d1ddfdcfaaf65527`
  (pre-freeze only, not the final contract identity).

Implementation requirements:

- verify the v2.20 global-tail archive and v2.24 tree-4 evidence first;
- verify the frozen namespace and checkpoint/resume fixtures;
- build a deterministic identity-bound trusted local cache and resume state;
- independently replay the completed archive from first to last row;
- compare all four outputs with the recovered global tail;
- run stale-witness, point, identity, offset, and archive mutations;
- freeze the observed stream byte count and repeat under a fresh cache if it
  was not already part of the tree-5 contract;
- seal only path-free portable evidence; and
- propagate only the exact newly closed claim.

Historical evidence rule: every versioned evidence builder must use its own
frozen runner implementation identity.  Never source that field from the
latest generic runner.  The fact that trees 3 and 4 have equal row-stream
sizes is not evidence for tree 5.

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
