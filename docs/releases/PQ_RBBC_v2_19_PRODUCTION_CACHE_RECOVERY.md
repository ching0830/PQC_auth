# PQ-RBBC v2.19 — Frozen production cache recovery

Date: 27 August 2026

## Outcome

Version 2.19 records the completed R0-a production run through the v2.18
checkpoint/resume implementation.  The runner resumed its locally generated
checkpoint, completed the canonical mixed 18-tree profile, rebuilt the trusted
v2.8 execution cache, and independently reproduced the frozen v2.8 linked
document byte for byte.

This closes production *cache recovery*.  It does not regenerate the v2.9
global-tail assignment, materialize the v2.17 tree-2 planned-offset archive,
replay the complete 18-tree native assignment, join CAP wires into the parent,
or establish the fork's security proof.

## Recovered identities

| Evidence | Result |
| --- | --- |
| Production topology | 2 × (4,096 leaves, degree 13) + 16 × (2,048 leaves, degree 12) |
| Trees / leaves | 18 / 40,960 |
| Checkpoint phase | `complete` |
| Checkpoint bytes | 19,524,889 |
| Checkpoint file SHA-256 | `01244778354875ff4f410bb5ca53a486369eb1760872c457f624108fc922279a` |
| Checkpoint state SHA-256 | `660c6b34072677abcfbf606c9c3ecc94171eb31e6ea1ebe7d1c418a78e338071` |
| Checkpointed derivation levels / records | 182 / 40,924 |
| Checkpointed seed nodes / leaf outputs | 40,960 / 40,960 |
| Execution-cache bytes | 35,509,449 |
| Execution-cache SHA-256 | `19b334a893fc839384010de54116f03d50b9f4fbae41e3e24dc21de833907b6e` |
| Compact execution SHA-256 | `69de49f5ad49f37ec461f2b22cd0bdf5293cb727644db5c23070cbd575efe61c` |
| Ordered CAP XOF calls | 122,847 |
| XOF trace bytes | 44,236,358 |
| XOF trace SHA-256 | `ccfa51ec2aee9501483c65023c4a877316eb6dd0557ccd6c42dfdf5f20f2c4e6` |
| Commitment bytes | 5,391 |
| Commitment SHA-256 | `12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62` |
| Canonical document bytes | 27,333 |
| Canonical document SHA-256 | `a7ef7eb4689d84c686074308d0d167e1567ab84578d66b5ad004970940ea0163` |
| Original document mutations | 5/5 rejected |

The production execution cache passes the unchanged v2.8 cache identity
validator.  The canonical document also passes the unchanged frozen-document
validator, including profile, commitment, request hash, XOF trace, tree order,
corrections, and mutation-sensitive link schedule.

## Portable evidence

The large checkpoint and pickle cache remain outside Git.  Version 2.19 adds a
path-free evidence document under
`artifacts/metadata/production_recovery_v2_19/` and a sealer that reconstructs
that document only after validating all four trusted local inputs.  Its
canonical SHA-256 is
`2b36ed1a4fb75e2ddbf826fa39ebd3d9b815a38873c93bd8635f56de2d8ad0f8`.

The sealer explicitly warns that identity checks do not make pickle safe:
checkpoint and cache inputs must be generated locally and trusted.  No absolute
workspace path or pickle bytes appear in the tracked evidence.

## Parent stability

The native profile, Blind-UOV ABI, executable reference, and BR1CS manifest now
import the same sealed recovery evidence.  This is metadata propagation only;
the parent relation and its single external assertion are unchanged.  A fresh
parent regeneration must remain 49,227,687 bytes with SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Claim boundary

Version 2.19 newly makes these claims true:

- `production_execution_cache_regenerated`; and
- `production_composition_document_revalidated`.

The v2.18 recovery-gate and reduced-resume claims remain true.  The following
remain false:

- `production_global_tail_archive_regenerated`;
- `production_tree2_rebased_assignment_materialized`;
- `production_tree2_rebased_full_replay_closed`;
- `representative_producers_rebased_replayed`;
- `complete_18_tree_assignment_replayed`;
- `parent_cap_to_h_rbbc_join_closed`;
- all formal fork security reductions; and
- `production_closed`.

## Validation

- portable evidence regression: 6 passed, including one trusted-external
  reseal when the local artifacts are supplied;
- affected parent regression: 34 passed, with the optional external reseal
  skipped when its environment variable is absent;
- complete regression: 204 passed in 1,257.076 seconds, with six optional
  external-artifact tests skipped;
- fresh parent archive: 49,227,687 bytes, SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`,
  zero internal failures, one unchanged external assertion, and honest
  accept/body-SHA/corruption/tamper checks passing; and
- every propagated parent manifest retains the conservative false claims
  listed above.

## Next implementation point

Execute R0-b: feed the recovered trusted cache to the unchanged v2.9
global-tail generator, require the exact 1,004,865,028-byte archive with
SHA-256 `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`,
then independently seal and replay it.  Only after that archive is restored may
the v2.17 tree-2 planned-offset production replay begin.
