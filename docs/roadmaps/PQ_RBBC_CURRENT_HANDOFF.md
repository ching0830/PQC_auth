[繁體中文版](PQ_RBBC_CURRENT_HANDOFF_zh-TW.md)

# PQ-RBBC current handoff — v2.25 tree-5 through tree-7 batch

> **Module scope:** this is the operational handoff for PQ-RBBC, not the
> whole-thesis roadmap. Start with [../../ARCHITECTURE.md](../../ARCHITECTURE.md),
> [../../RESEARCH_STATUS.md](../../RESEARCH_STATUS.md), and
> [../../ROADMAP.md](../../ROADMAP.md) for project-level context.

Date: 27 August 2026

Read this file first in a new work session.  Then read the v2.25 release note,
roadmap, artifact evidence note, and `docs/ARTIFACT_POLICY.md`.  Confirm the
latest remote `main` before starting work; never infer that an open PR has
merged.

## Base and closed boundary

The v2.25 work started from `aad5bed719af1db266377cb654ecc7824f34d04b`
and is merged on `main` at
`e823117269cde2b2428e2d71024d362a3dbc0401`.  Planned producer indices 0
through 7 are materialized and independently replayed: 8 of 18.  Trees 5, 6,
and 7 were executed as a bounded batch but have separate contracts, archives,
row streams, output checks, mutation probes, and replay-manifest identities.

Closed components include the v2.8 composer recovery, v2.9 global tail,
tree-2 rebased replay, tree-1/tree-3/tree-4 planned replays, and the new
tree-5-through-7 batch.  Remaining trees, all 72 relocations, complete 18-tree
assignment replay, cross-segment identity, parent join, fork-security proof,
signature benchmark, and production closure remain open.

## Required external identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| v2.9 global-tail assignment | 1,004,865,028 | `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1` |
| v2.25 tree-5 assignment | 486,961,028 | `e8717997e1e3d85c5dbbb59602924eeafb2ae7a643433794a8cbfb9966243a18` |
| v2.25 tree-5 final replay manifest | 7,564 | `8f032ced1c11c2acd3554240ab4d6e0e061b0c04fa9b985eb20fc6184a41478f` |
| v2.25 tree-6 assignment | 486,961,028 | `e112686118690036ffef126bccbbc0fbe69c973e624d86301683aea09dec3abe` |
| v2.25 tree-6 final replay manifest | 7,564 | `0061aaaa11096c4c49af41beb0a9688b9ea4b17a29518212c53e94be7df4553e` |
| v2.25 tree-7 assignment | 486,961,028 | `3c6670f17ef484c83781d4453f976b68a6159072d5d8cfff418c0afbacf3f6db` |
| v2.25 tree-7 final replay manifest | 7,564 | `be99ea2986c7c65269d6151c5c8280266110102024ca76e2a88f5579be48ab81` |
| incremental BR1CS | 49,227,687 | `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799` |

The batch evidence SHA-256 is
`0041ea819434e0099d419757fa217fcfa30b810ef391b4a4603d8aee7ad06c72`.
All three row streams contain 8,961,160,824 encoded bytes, but this remains an
observed per-tree value and must not be assumed for later trees.

External v2.25 artifacts are under
`/workspace/pq_rbbc_external_artifacts_v2_25/` when restored.  Verify all
non-pickle identities before use.  Never deserialize a downloaded or otherwise
untrusted pickle; rebuild identity-bound caches locally.

## Validation status

- batch portable evidence: 6 tests passed, including three external reseals;
- native/ABI/reference targeted regression: 23 tests passed in 105.497 seconds;
- BR1CS targeted regression: 5 tests passed in 87.454 seconds;
- affected runner/evidence/parent regression: 76 tests passed in 214.805
  seconds with one optional historical external-artifact reseal skipped;
- complete repository regression: 250 tests passed in 932.687 seconds with
  eight optional external-artifact tests skipped;
- parent BR1CS identity unchanged at 49,227,687 bytes and SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

Use the v2.25 checksum inventory for all tracked/external file identities.

## Next bounded checkpoint

Continue R1d-b2 with tree indices 8, 9, and 10 as a bounded batch.  The
planned targets are:

| Tree | Planned interval | Pre-freeze contract SHA-256 |
| --- | --- | --- |
| 8 | 234,972,873–254,451,308 | `3801f60ab7132fd850a10cf51a5f892624401988dedc64288b0807a34093ba70` |
| 9 | 254,451,309–273,929,744 | `1d64e086061717099bf1a189c34df22966ca1e67fb17ad74d373d6bdb4f9b1df` |
| 10 | 273,929,745–293,408,180 | `5d26dd745685f58b3cdfad652b9602cadf1f041d5169c4b5c4f10590cd4948aa` |

For every target, start with `stream_bytes = null` and all formal target-tree
claims false.  Verify global-tail and v2.25 batch evidence, use a distinct
external directory and cache identity, complete the first replay, freeze the
observed byte count, rebuild a fresh cache, and repeat the entire replay before
sealing.  Never allow one tree's result to satisfy another tree's identity.

## Git and artifact discipline

- Re-read remote `main` immediately before any write and build from that exact
  base tree.
- Never commit `.f193assign`, `.br1cs`, pickle, cache, resume, or checkpoint
  files.
- Upload only the explicit text-file allowlist; compare every GitHub blob SHA
  with local `git hash-object` before creating the commit.
- Keep complete-composition, parent-join, security-proof, and production claims
  false until their distinct gates are actually closed.
- A PR for a checkpoint must not be merged by the execution agent unless the
  user explicitly authorizes the merge separately.
