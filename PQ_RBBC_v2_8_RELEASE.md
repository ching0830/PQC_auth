# PQ-RBBC v2.8 — canonical full 18-tree CAP reference composition

Date: 25 August 2026

## Outcome

Version 2.8 executes the actual mixed production CAP reference profile for the
first time and freezes its complete composition schedule. The canonical order
is two 4,096-leaf/degree-13 trees followed by sixteen
2,048-leaf/degree-12 trees. The artifact binds all 18 tree positions to the
previously assignment-verified shard evidence, serializes 17 cross-tree
correction pairs, and records one 5,391-byte commitment plus one request hash.

This is reference-vector and linked-schedule closure, not native monolithic
assignment closure. The shared global transcript tail, exact cross-segment
wire identities, complete 18-tree assignment replay, parent join, and formal
security reductions remain fail-closed.

## Full production execution

The deterministic production run contains:

- 18 trees and 40,960 leaves;
- 40,924 seed-derivation calls;
- 40,960 leaf-commitment calls;
- 40,960 tape-expansion calls;
- three global transcript calls;
- 122,847 total CAP XOF calls;
- one request-binding XOF, for 122,848 calls including request binding;
- 389,974 CAP Anemoi permutations;
- 58 request-binding permutations, for 390,032 including request binding;
- 131,031,264 CAP permutation nonlinear rows and 19,488 request-binding
  permutation rows, for 131,050,752 in the end-to-end reference path;
- 17 `delta_P` and 17 `delta_Mhat` correction values; and
- one 5,391-byte canonical commitment.

The full run also found and corrected a pre-existing accounting bug. The
serializer byte-aligns `alpha`, every `delta_P`, and every `delta_Mhat`
separately, while the former size helper rounded the combined bit count only
once. It therefore undercounted this profile by 13 bytes (5,378 instead of the
actual 5,391) and undercounted the reduced profile by one byte. The strict ABI,
tests, manifests, proof, and roadmap now use the serializer-exact length.

The parallel executor is not a distinct semantic implementation: on the
reduced profile, its complete `CAPExecution` object is equal to the original
direct reference, including every polynomial and ordered XOF call.

Frozen production digests:

- linked document SHA-256:
  `a7ef7eb4689d84c686074308d0d167e1567ab84578d66b5ad004970940ea0163`;
- full commitment SHA-256:
  `12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62`;
- ordered XOF trace SHA-256:
  `ccfa51ec2aee9501483c65023c4a877316eb6dd0557ccd6c42dfdf5f20f2c4e6`;
- 576-bit request hash:
  `3f9ec0aeab100e4ebef8046068851874f08fcda6daa2e42178dd559f55e38a31da28af9ccd0653bb4ca574ec8264cce1f3c024c97e858e2c877bba7968c039dc61f516dfed995ba3`.

The successful eight-worker construction took 9,172.183 seconds (2 hours,
32 minutes, 52.183 seconds). The main process reported peak RSS 2,319,076 KiB;
this is not aggregate worker or cgroup peak memory and is not a prover
benchmark. The first complete attempt was correctly rejected because its
5,378-byte accounting expectation disagreed with the real 5,391-byte
serialization; only the corrected second run is frozen here.

## Canonical linked format

`PQRBBC-CAP-LINKED-18-1` records:

1. the production profile fingerprint and deterministic randomness digest;
2. the unique profile-order tree index, leaf count, extension degree, and
   tree-component digest for every tree;
3. the exact frozen one-tree row-stream and assignment evidence selected for
   each position;
4. cumulative template row/wire offsets;
5. all 17 correction pairs and their canonical component digest;
6. H1, H2, alpha, commitment, request-message, and request-hash digests; and
7. a length-framed digest over all 122,847 ordered XOF calls, including labels,
   domains, encoded payloads, output widths, and outputs.

Five mutation probes change tree order, shard evidence, a correction value,
the commitment digest, or the request-message digest. Every stale document is
rejected.

## Template envelope, not an exact native count

Summing the 18 already verified one-tree fixtures gives:

- wires: 398,032,312;
- nonlinear rows: 390,142,528;
- linear rows: 132,327,002;
- total rows: 522,469,530;
- virtual row-stream bytes: 377,830,939,120; and
- assignment archive bytes: 9,950,810,104.

These are conservative engineering envelope numbers. Each one-tree fixture
contains its own inputs, H1/points, H2/commitment, and request-binding tail.
The real 18-tree circuit must share those global components rather than repeat
them 18 times. Version 2.8 therefore does not label the envelope as an exact
row count and does not use digest linkage as a substitute for native R1CS
constraints.

## Parent relation preservation

The native profile, hidden-state ABI, executable reference, and BR1CS manifest
now distinguish:

- `production_cap_full_vector_executed = true`;
- `canonical_18_tree_link_schedule_closed = true`;
- `production_cap_native_global_tail_materialized = false`; and
- `monolithic_18_tree_assignment_verified = false`.

The portable parent archive is regenerated as v2.8 but keeps one named
external assertion for the exact native CAP-to-H_RBBC wire join. It is
49,227,687 bytes with 2,971,580 rows, 2,980,304 wires, and SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.
Those bytes are identical to v2.7, so the evidence propagation changed no
relation record. No parent assertion is deleted merely because the reference
composition is now known.

## Regression evidence

The clean regression run completed 132 tests in 735.133 seconds with zero
failures. New coverage checks:

- parallel/direct semantic equality on the reduced profile;
- exact production schedule `2x(4096,13) + 16x(2048,12)`;
- exact template-envelope accounting;
- ordered trace digest sensitivity to call order and outputs;
- canonical JSON stability;
- frozen linked-document validation; and
- fail-closed upward propagation without native or production overclaim.

## Proof document and roadmap

The updated proof PDF adds the full-reference composition proposition,
canonical linked-format definition, correction/transcript binding argument,
template-envelope caveat, and the new native-composition obligation. The
roadmap is included as `PQ_RBBC_CRYPTO_CORE_ROADMAP_v2_8.md` and moves the next
checkpoint to exact global-tail lowering plus segmented assignment replay,
before the parent exact wire join.

## Claim boundary

Version 2.8 establishes one deterministic full-profile CAP reference vector
and one mutation-sensitive canonical 18-tree link schedule over two separately
assignment-verified constituent shapes. It does not establish:

1. an exact deduplicated full-profile native row stream;
2. a complete 18-tree satisfying assignment replay;
3. native constraints for cross-segment or global-tail links;
4. exact linkage into the parent issuance archive;
5. zero external assertions in the parent archive;
6. CAP unique-mask or straightline extraction;
7. fork blindness or one-more unforgeability;
8. a qualified post-quantum proof backend or measured final sizes; or
9. satellite AKE and operational security.

`production_closed` remains `false`.

## Next checkpoint

Version 2.9 should lower the v2.8 linked schedule into one exact native
composition with a single shared global transcript tail. It should use
segmented fixed-width assignment archives or backend-native witness streaming,
freeze all cross-segment wire identities, replay every exact row with zero
failures, and reject mutations in correction order, H1/H2 field order,
serialization, commitment publication, and request binding.
