# PQ-RBBC v2.7 — assignment-backed 4,096-leaf degree-13 shard

Date: 24 August 2026

## Outcome

Version 2.7 closes the second constituent production CAP tree shape at the
same engineering boundary reached by the 2,048-leaf shard in v2.6. One real
4,096-leaf tree now has:

1. the safe degree-13 leaf extension field;
2. a complete canonical assignment for every GF(2^193) wire;
3. a canonical streamed digest for every native rank-one row;
4. an mmap-backed replay of all 52,224,501 rows with zero failures; and
5. five rejected stale-witness probes across independent subrelations.

Both production tree shapes are now closed separately. This is still not the
complete 18-tree relation, a production proof backend, or a formal security
closure. The parent relation remains fail-closed with one named external
assertion for 18-tree composition and the exact H_RBBC wire join.

## Why degree 13 is required

A 4,096-leaf tree needs 4,096 distinct nonzero evaluation points. The
multiplicative group of the degree-12 extension field contains only 4,095
nonzero elements. The minimum safe extension is therefore degree 13. The
frozen modulus remains the profile's `x^13 + x^4 + x^3 + x + 1`.

The one-tree fixture otherwise retains production widths:

- mask bits: 576;
- appended signature bits: 1,472;
- witness bits: 2,048;
- Horner coefficients: 11;
- consistency points: 2;
- rho: 16; and
- tape bits per leaf: 2,450.

## Complete assignment archive

The v2.6 fixed-width format is reused without alteration:

- format: `PQRBBC-F193-ASSIGNMENT-LE25-1`;
- 128-byte header;
- one canonical 25-byte little-endian GF(2^193) element per wire;
- one-based wire `i` at offset `128 + 25(i - 1)`;
- embedded body and row-stream SHA-256 digests.

The v2.7 degree-13 archive is:

- wires: 39,789,564;
- body bytes: 994,739,100;
- archive bytes: 994,739,228;
- body SHA-256:
  `e61fc4fec72b302a0eaf83680044242c5cc87aedc79db23fec6d681e55f04947`;
- archive SHA-256:
  `e4dea88f7f47849cd858d3ba2d5110bd1893efb1ac4544a8b2cb8a0e7fa87aa1`.

The large archive is distributed separately as 23 ordered parts. See
`PQ_RBBC_v2_7_ASSIGNMENT_PARTS.md` for per-part digests and reconstruction.

## Frozen native relation

The deterministic production-shape trace contains:

- leaves: 4,096;
- extension degree: 13;
- CAP XOF calls: 12,289;
- XOF calls including request binding: 12,290;
- Anemoi permutations: 38,999;
- wires: 39,789,564;
- nonlinear rows: 38,997,232;
- linear rows: 13,227,269;
- total rows: 52,224,501;
- external assertions: 0;
- wire spool bytes: 79,757,312;
- virtual canonical row-stream bytes: 37,955,986,032.

Frozen digests:

- row stream:
  `0d921a379af0f8c7bd34bb9c3804cbbb32daea51ea827d753a8493758c892530`;
- wire spool:
  `9c74039df1f21c2273eed511c29523514b156dd712abda3db3aa64dac1e37169`;
- commitment:
  `1eb53369c086e99ec55ddc90a49314924a42a61fee4d6b0ebf73d5ce75ad58e4`.

The 576-bit request-binding vector is recorded in
`pq_rbbc_cap_shard_assignment_4096_manifest_v2_7.json`.

## Whole-shard verification

The complete run first generated and sealed the archive, then independently
replayed the unchanged canonical row generator against the mmap-backed values.
The result is:

- rows checked: 52,224,501;
- wires loaded: 39,789,564;
- verification failures: 0;
- first failure: none;
- generation and verification topology equal: yes;
- replayed row-stream digest equal: yes.

Assignment generation after concrete reference execution took 1,130.766
seconds. Archive validation and full row replay took 1,619.663 seconds. The
generation summary recorded peak RSS 254,220 KiB. The complete command,
including reference execution, generation, archive hashing, verification, and
probes, took 61 minutes 8.130 seconds. These are relation-construction
measurements, not proof-generation or proof-verification benchmarks.

## Stale-witness rejection

Five exact captured rows accept honestly and reject after the low bit of one
archived wire is flipped while all other values remain stale:

- first GGM payload/source binding, wire 1;
- first leaf tape digest packing, wire 8,691,891;
- first leaf Horner multiplication at coefficient 9, wire 39,623,080;
- canonical commitment publication, wire 39,781,658; and
- request-binding digest packing, wire 39,788,978.

These probes demonstrate mutation-sensitive wiring at five locations. They do
not replace the one complete honest replay or establish a security reduction.

## Parent relation preservation

The native profile, hidden-state ABI, executable reference, and BR1CS manifests
now record both closed shard types. The portable parent archive was regenerated
and remains byte-identical to v2.6:

- archive bytes: 49,227,687;
- rows: 2,971,580;
- wires: 2,980,304;
- external assertions: 1;
- archive SHA-256:
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

The remaining assertion still names the complete 18-tree native CAP row
stream and exact H_RBBC parent-wire join. Separate shard closure does not
justify deleting it.

## Regression evidence

The complete suite passes 127 of 127 tests in 783.614 seconds. New coverage
checks:

- exact 4,096-leaf/degree-13 parameters and relation identity;
- all frozen 4,096-shard rows, wires, stream bytes, spool, commitment, and
  request vectors;
- assignment body/archive bytes and SHA-256 digests;
- 52,224,501-row zero-failure replay and topology equality;
- all five stale-witness probes;
- backward-compatible 2,048 profile identity and frozen digests;
- propagation into native profile, Blind-UOV ABI, reference, and BR1CS
  contracts; and
- explicit failure to claim 18-tree or production closure.

The existing suite additionally rechecks the field, permutation, sponge,
multi-squeeze, Horner, CAP reference, parent BR1CS round trip, archive
corruption, assignment mutation, honest relation, and all eight full-circuit
negative cases.

## Proof document and roadmap

The 34-page proof PDF adds the degree-13 injection argument, a complete-shard
satisfiability proposition, archive and row-stream digests, resource
measurements, stale-probe reasoning, and updated claim boundaries. All pages
were rendered and visually inspected after a clean two-pass build.

`PQ_RBBC_CRYPTO_CORE_ROADMAP_v2_7.md` explains the whole project rather than
only this checkpoint. It separates the remaining work into:

1. 18-tree canonical composition;
2. parent exact wire join and zero external assertions;
3. fork-specific CAP/request-binding/Blind-UOV/SE-NIZK/QROM proofs;
4. Signature-Gated Decryption proof and implementation;
5. backend qualification and fresh size/performance benchmarks; and
6. satellite AKE, replay, handover, revocation, and availability integration.

## Claim boundary

Version 2.7 establishes complete satisfying assignments for one deterministic
tree of each production shape, separately, with zero shard-level external
assertions. It does not establish:

1. composition of 16 degree-12 trees and 2 degree-13 trees;
2. cross-tree correction equations under one canonical transcript;
3. exact linkage into the parent issuance archive;
4. zero external assertions in the parent archive;
5. CAP unique-mask or straightline extraction;
6. fork blindness or one-more unforgeability;
7. a qualified post-quantum zero-knowledge/simulation-extractable backend;
8. actual fork signature/proof/ciphertext sizes or prover benchmarks; or
9. satellite AKE and operational security.

`production_closed` remains `false`.

## Next checkpoint

Version 2.8 should implement the canonical 18-tree composer for
16×2,048-leaf/degree-12 plus 2×4,096-leaf/degree-13 trees, including cross-tree
corrections, one commitment, and one request-binding transcript. Because a
naive full fixed-width assignment is roughly 10 GB and the relation is roughly
522 million rows, the next step should freeze streaming topology and shared
value scheduling before selecting segmented assignment or backend-native
witness streaming.
