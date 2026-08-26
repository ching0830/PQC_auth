# PQ-RBBC v2.15 — Representative output-relocation contract

Date: 26 August 2026

## Outcome

Version 2.15 materializes and independently replays the native output-wire
relocation relation for the two representative production producer shapes:

- tree index 0: 4,096 leaves, extension degree 13;
- tree index 2: 2,048 leaves, extension degree 12.

Each shape exports four ports: leaf commitments, `p-plain`, `mhat-plain`, and
`xi-masks`.  The contract therefore seals eight exact source/destination
ranges.  For every bit pair it emits the characteristic-two equality row

`(producer_bit + tail_consumer_bit) * 1 = 0`.

This is a representative relocation checkpoint.  It does not claim that the
other sixteen position-sensitive producers or the complete 18-tree assignment
have been materialized.

## Frozen relation

| Evidence | Result |
| --- | ---: |
| Relocations | 8 |
| Equality rows | 2,386,102 |
| Canonical assignment wires | 4,772,204 |
| Linear / nonlinear rows | 2,386,102 / 0 |
| External assertions | 0 |
| Replay failures | 0 |
| Row-stream bytes | 496,519,444 |
| Row-stream SHA-256 | `e81c1ce1aa07aae32ea166adea7c35a3b19f949c471fc17bdd5434dffe1dbeb0` |
| Assignment bytes | 119,305,228 |
| Assignment SHA-256 | `2f30c4d3d39e86e017dc9f8f78d20dfaf0a1fa40b99da56593d55297a7aa0b5c` |

Every relocation record separately seals its producer start, consumer start,
bit length, canonical value digest, canonical source/destination slot, equality
row count, group bytes, and group row-stream SHA-256.

## Source import discipline

Tree index 2 is read directly from the frozen v2.14 producer assignment slice.

The 973,845,878-byte tree-index-0 archive does not need to be restored for this
checkpoint.  v2.13 already replayed that full producer and sealed each output
digest.  v2.15 reconstructs its import slots from the independently replayed
global-tail range only after the producer digest, tail digest, source range,
destination range, producer archive identity, and producer row-stream identity
all match the frozen v2.13 manifest.  The manifest records this asymmetry
explicitly; it does not claim a fresh full tree-0 archive replay.

## Negative evidence

- 16/16 witness probes reject: each of the eight ports rejects a flipped
  producer-side bit and a flipped consumer-side bit.
- 6/6 configuration probes reject: wrong source range, wrong destination
  range, wrong width, wrong value digest, wrong producer archive, and wrong
  port order.
- All eight honest relocation ranges replay with zero failures.

## Evidence propagation and parent stability

The relocation relation identity is imported by the v2.15 native profile,
Blind-UOV ABI, executable reference manifest, and BR1CS backend manifest.

The generated v2.15 parent BR1CS is 49,227,687 bytes with SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`,
the same frozen identity recorded for v2.14.  It still contains one external
assertion.  The independent relocation relation was not silently counted as a
parent join.

## Claim boundary

The following are true:

- `production_representative_output_relocation_contract_closed`;
- `production_index0_all_four_output_relocations_closed`;
- `production_index2_all_four_output_relocations_closed`;
- `all_four_output_relocations_closed` for the two representative shapes; and
- `representative_cross_segment_wire_relation_closed`.

The following remain false:

- `tree_producer_segments_materialized`;
- `complete_18_tree_assignment_replayed`;
- global `cross_segment_wire_identity_closed`;
- `parent_cap_to_h_rbbc_join_closed`;
- CAP unique-witness and straightline-extraction review;
- fork blindness and one-more unforgeability proofs;
- SE-NIZK/QROM reduction completion;
- signature-size rebenchmarking; and
- `production_closed`.

## Validation

- v2.15 relocation regression: 7/7 passed.
- producer/checkpoint regression: 20 passed, 2 optional tree-0 artifact tests
  skipped because the 973 MB archive and cache are not stored in GitHub.
- native profile, ABI, reference, and BR1CS regression: 28/28 passed.

## Next implementation point

Freeze a non-overlapping global wire-namespace schedule for all 18 producer
instances, then materialize the remaining position-sensitive producers and
their relocation rows.  Standalone tree-0 and tree-2 producers both start their
local namespaces at wire 40,194,597, so their internal ranges cannot simply be
concatenated without explicit rebasing and replay.
