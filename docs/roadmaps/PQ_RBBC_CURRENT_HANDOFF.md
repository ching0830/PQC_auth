[Traditional Chinese](PQ_RBBC_CURRENT_HANDOFF_zh-TW.md)

# PQ-RBBC current handoff — v2.26 tree-8-through-tree-10 bounded recovery

> **Module scope:** this is the operational handoff for PQ-RBBC, not the
> whole-thesis roadmap. Start with [../../ARCHITECTURE.md](../../ARCHITECTURE.md),
> [../../RESEARCH_STATUS.md](../../RESEARCH_STATUS.md), and
> [../../ROADMAP.md](../../ROADMAP.md) for project-level context.

Date: 2 September 2026

In a new work session, read this file, the
[v2.26 fresh-rebuild progress note](../artifacts/PQ_RBBC_v2_26_FRESH_REBUILD_PROGRESS_zh-TW.md),
the [tree-8-through-10 preflight](../artifacts/PQ_RBBC_v2_26_TREE8_10_PREFLIGHT.md),
and `docs/ARTIFACT_POLICY.md`. Confirm the exact local and remote `main`
commits before starting; never infer that an unintegrated branch is active.

## Base and closed boundary

The v2.26 bounded recovery is integrated into local `main` commit
`b9c09f1266d269164fd9bded996e8cc38deb91c6`. Planned producer indices 0
through 10 are materialized and independently replayed under their applicable
frozen contracts: 11 of 18.

Trees 8, 9, and 10 each followed a two-stage process: a tree-specific
pre-freeze replay using an isolated directory, artifact tag, and cache; then a
frozen replay using that tree's own observed row-stream identity and a second
fresh cache. No observed stream identity was reused across trees.

Evidence-sealed bounded components now include:

- v2.8 composer recovery and the v2.9 global tail;
- tree-2 rebased replay;
- tree-1, tree-3, and tree-4 planned replays;
- the tree-5-through-tree-7 bounded batch; and
- tree-8-through-tree-10 bounded recovery.

This does not close all 72 relocations, the complete 18-tree replay,
cross-segment identity, parent join, fork-security proof, production proof
backend, signature benchmark, or production closure.

## v2.26 portable evidence

Path-free bounded evidence:

`artifacts/metadata/tree8_10_bounded_recovery_v2_26/pq_rbbc_cap_tree8_10_bounded_recovery_evidence_v2_26.json`

SHA-256:

`9a8ad3b2b5af242ef6ee6b33d99035505c1b8a5764d84766ce6d44f9cd00895f`

Its claim boundary advances only:

- `materialized_planned_tree_indices = [0, ..., 10]`; and
- `materialized_planned_tree_count = 11`.

`remaining_planned_tree_producers_materialized`,
`all_72_output_relocations_closed`, `complete_18_tree_assignment_replayed`,
`cross_segment_wire_identity_closed`, `parent_cap_to_h_rbbc_join_closed`,
`fork_security_proof_revalidated`, and `production_closed` all remain `false`.

## Required identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| v2.9 global-tail assignment | 1,004,865,028 | `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1` |
| incremental BR1CS | 49,227,687 | `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799` |
| tree-8 assignment | 486,961,028 | `bf3c1f6ef1fa34b3d5cb9e11d85e65b33a3dbe80c926cf2cd86be291d19c884c` |
| tree-8 frozen manifest | 7,685 | `6e7f4df14772370727940b9367430a8ad37d3eaa4e29a97f174133922c8e69cc` |
| tree-9 assignment | 486,961,028 | `6233e0639bfd09b93bfb1967f5a696fad09eadc7ca5e4f2c9df4fc804a015f19` |
| tree-9 frozen manifest | 7,686 | `f82ce1c1733d30e9c49e69551eeee80698230f01f4857b868764ff51d8f8b806` |
| tree-10 assignment | 486,961,028 | `23ad60862f387387aba139a8465891f7ada0fe4da5be8a318177217094c39bd8` |
| tree-10 frozen manifest | 7,699 | `8c56f7c426ad1f632af36c0d4e40536ff5726a5875734d7014d0b9c429fb067d` |

Tree-specific frozen identities:

| Tree | Final contract SHA-256 | Row-stream bytes | Row-stream SHA-256 | Component SHA-256 |
| ---: | --- | ---: | --- | --- |
| 8 | `15277b5065ef5b97dc7919306c3c1044826b98adee3a92f12be9cde5f9623c99` | 8,961,160,824 | `c6f593afc2afe6393800c26f27203cbc4e1bb3e83cfe57c2ac6cc812553285af` | `c0037cfb5a06379b463d8430e4b8ffbd114db452814283d2330a3cd57357075b` |
| 9 | `cd9c33b29af5472856219bde2541d4029cc747692202463012bae9000f622e34` | 8,961,160,824 | `b8e22f80732b78d8b0a0b02957b91c1b746cb26efe10a4e9d5302e0c8d8960fd` | `fab97914348c255bed04debc578cd8c9d27ab73d92744c0d5f24aaf5ec4409b0` |
| 10 | `011d3c249a7d60232074a7f0eb78b34618b097ffcd1c852040fd888263f6e554` | 8,986,785,870 | `44cf5ff0cdf222d58f1522e06afadccf3ad377ce4893575d1ef8f8317a2f3ba2` | `0378694c05c5236207cdb5d9c148e75f4d9ab5245787523d9de8739577bc8d89` |

Tree 10 has a different row-stream byte count from trees 8 and 9; later trees
must never inherit another tree's observed byte count.

## Replay validation status

Each of trees 8, 9, and 10 has:

- 25,666,386 rows replayed at its planned offset;
- 4 of 4 output ports matching exactly;
- zero verification failures;
- zero external assertions;
- 6 of 6 stale-witness probes rejected;
- 3 of 3 point-mutation probes rejected; and
- a fresh-cache frozen replay with no resume.

A/B integration validation:

- 45 system-access/replay and v2.26 targeted-validator tests passed with no
  skips;
- the frozen tree-8-through-tree-10 preflight manifest was accepted;
- the three frozen manifests reproduced the tracked portable evidence exactly;
  and
- the complete repository regression passed 295 tests in 575.086 seconds,
  with 12 existing optional external-artifact tests skipped and no failures or
  errors.

Tracked checksum inventories:

- `checksums/SHA256SUMS_v2_26_PREFLIGHT.txt`; and
- `checksums/SHA256SUMS_v2_26_TREE8_10_RECOVERY.txt`.

Large assignments, BR1CS, pickle, caches, resume state, and logs remain outside
Git. Never deserialize a downloaded or otherwise untrusted pickle; rebuild
identity-bound caches in a trusted local environment.

## Next bounded checkpoint

The next candidate batch is trees 11 through 13, but none has been preflighted,
materialized, or replayed:

| Tree | Planned interval | Initial contract SHA-256 |
| ---: | --- | --- |
| 11 | 293,408,181–312,886,616 | `9ecdb58979432dcbbcfd1b02d6b2d32ae104884bf9bde3a54f7b7d645fb02bc7` |
| 12 | 312,886,617–332,365,052 | `76f20f61ed29b2cf7b6ea203ed95a0c54f210c1b5124385c074451cd2a9e4db8` |
| 13 | 332,365,053–351,843,488 | `f67865f9af8a2bede8184987ca6921e3ba880e52565705a8822611b8b84249d7` |

All three initial contracts have `stream_bytes = null`. Before any large
replay, add and review a tree-11-through-13 preflight manifest and tests,
validate all external prerequisites, and keep every target formal claim
`false`. Continue to execute pre-freeze, tree-local observation freeze,
fresh-cache frozen replay, and portable evidence sealing separately per tree.

## Git and artifact discipline

- Re-read the latest `main` immediately before any write and build from that
  exact base tree.
- Never commit `.f193assign`, `.br1cs`, pickle, cache, resume, checkpoint, or
  log files.
- Commit only path-free portable metadata, code, tests, documents, manifests,
  and checksum inventories.
- Tree closure is not relocation, 18-tree composition, parent-join, proof, or
  production closure.
- Checkpoint merge and push still require explicit user authorization.
