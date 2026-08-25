# PQ-RBBC v2.13 - production tree-index-0 producer closure

Date: 26 August 2026

## Outcome

Version 2.13 materializes and fully replays the first real production
tree-producer segment: tree index 0, 4,096 leaves, extension degree 13.  The
producer imports the two already-frozen global-tail consistency points by
their exact global wire IDs, 39,945,673 and 39,945,866.  It does not allocate
local copies of either point.

This checkpoint deliberately covers one position-sensitive producer only.  It
does not yet close tree index 2, output-wire relocations, the eighteen-tree
composition, the parent join, or the security proof.

## Frozen production vector

| Evidence | Result |
| --- | ---: |
| Tree index | 0 |
| Leaves / extension degree | 4,096 / 13 |
| Rows | 51,325,080 |
| Local wires | 38,953,830 |
| Local wire start | 40,194,597 |
| Maximum global wire ID | 79,148,426 |
| Assignment archive | 973,845,878 bytes |
| Generation time | 752.09 seconds |
| Replay time | 1,263.47 seconds |
| Peak RSS | 2,068,576 KiB |
| Verification failures | 0 |
| External assertions | 0 |
| Mutation probes | 9/9 rejected |

Frozen digests:

- row stream SHA-256:
  `496f5279f914d72b15864414f1a548089236de1e14cdde3a8d360c28a21ca43e`;
- assignment archive SHA-256:
  `213fa3c90b62db64436ec8e7dd7ee5a6e0ec6b546ae4fa02b3cbfb50fdf502db`;
- assignment body SHA-256:
  `011b17a0ec9cf8d7bc89a84a558432ba9dcd99855124292f004dab9279179347`;
- imported point values SHA-256:
  `eda567ca99c39229b5da8d526d23a36885230dddb33f6dbeb9e034c15d28e251`;
- frozen v2.8 tree component SHA-256:
  `1f780036168c0560a2cb7e7f994f8cd5c6bf60860bd387658b777bc976a8f33e`.

## Exact point binding

The producer's tree-post Horner rows reference the global-tail point ranges
directly:

| Input | Global start wire | Bits | Local copy |
| --- | ---: | ---: | --- |
| Consistency point 0 | 39,945,673 | 193 | none |
| Consistency point 1 | 39,945,866 | 193 | none |

Flipping either imported point and swapping the two points each leave a stale
producer assignment, and all three probes are rejected.  Six additional
producer probes cover input salt, last-leaf tape, and all four output classes.

## Output ports

All four producer values equal the corresponding frozen global-tail consumer
values, but their wire relocations are intentionally not yet closed.

| Port | Producer start | Bits | Value match | Wire identity |
| --- | ---: | ---: | --- | --- |
| leaf commitments | 77,419,669 | 1,581,056 | yes | no |
| p-plain | 79,000,725 | 2,048 | yes | no |
| mhat-plain | 79,002,773 | 386 | yes | no |
| xi-masks | 79,143,409 | 5,018 | yes | no |

## Checkpoint/resume behavior

Long production work is now restartable instead of being discarded:

- the position-sensitive XOF execution cache is sealed to the relation,
  profile, randomness label, and tree index;
- the cache is checkpointed after every GGM level and every 128 leaf outputs;
- assignment generation and relation replay are separate stages; and
- a partial assignment prefix is retained, byte-checked, and extended on
  resume.

This run resumed the already-sealed execution cache.  It began assignment
generation at wire zero, so the resume manifest correctly records zero reused
assignment-prefix wires for this particular run.

## Claim boundary

Version 2.13 establishes:

- `production_index0_4096_degree13_producer_native_closed = true`;
- `production_index0_point_wire_identity_closed = true`; and
- `production_index0_output_values_match_tail = true`.

It keeps these claims false:

- `production_index2_2048_degree12_producer_native_closed`;
- `all_four_output_relocations_closed`;
- `production_tree_producer_segments_materialized`;
- `complete_18_tree_assignment_replayed`;
- `parent_cap_to_h_rbbc_join_closed`;
- `fork_security_proof_revalidated`; and
- `production_closed`.

The parent BR1CS remains byte-for-byte unchanged at 49,227,687 bytes with
SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Validation

- Full regression: 164 tests passed in 815.037 seconds.
- Production tree-0 replay: 51,325,080 rows, zero failures, zero external
  assertions, and 9/9 rejected mutations.
- The v2.13 parent BR1CS is byte-for-byte identical to v2.9--v2.12.
- The formal proof PDF has 41 A4 pages.  Its final LaTeX build contains no
  warning, undefined reference, overfull/underfull box, or fatal error.  All
  41 pages were rendered; the cover, Proposition 8.10 and proof continuation,
  status table, and final page were visually inspected without clipping or
  overlap.

## Next checkpoint

Build and replay the position-sensitive tree-index-2 producer with 2,048
leaves and extension degree 12, importing the same two exact global point
wires.  After both shapes are closed, freeze the four output relocation maps
and only then expand the relation to all eighteen tree positions.
