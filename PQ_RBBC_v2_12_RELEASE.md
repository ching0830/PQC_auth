# PQ-RBBC v2.12 - production split-tail materialization

Date: 25 August 2026

## Outcome

Version 2.12 reuses the frozen v2.9 production assignment and replays the
unchanged global-tail relation through the v2.11 Phase-A/Phase-B observer.  No
production witness or eighteen-tree execution is regenerated.

The replay closes the production tail-internal split and fixes the exact H1
and two consistency-point wires.  It does not yet build the tree-producer
segments or join their point inputs to these outputs.

## Frozen production replay

| Evidence | Result |
| --- | ---: |
| Rows | 56,806,711 |
| Wires | 40,194,596 |
| Assignment archive | 1,004,865,028 bytes |
| Replay time | 812.44 seconds |
| Peak RSS | 1,023,720 KiB |
| Verification failures | 0 |
| External assertions | 0 |
| Boundary-wire probes | 5/5 rejected |

The row-stream SHA-256 remains:

`c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df`

The assignment archive SHA-256 remains:

`946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`

## Exact production ranges

All ranges are half-open.

| Segment | Row range | Wire range |
| --- | ---: | ---: |
| Input prelude | `[0, 15939162)` | `[1, 15939163)` |
| Phase A | `[15939162, 56375441)` | `[15939163, 39946062)` |
| Phase B | `[56375441, 56806711)` | `[39946062, 40194597)` |

Exact native boundary ports:

| Port | Start wire | Bits |
| --- | ---: | ---: |
| H1 | 39,943,623 | 386 |
| Consistency point 0 | 39,945,673 | 193 |
| Consistency point 1 | 39,945,866 | 193 |
| CAP commitment | 40,084,506 | 43,128 |
| Request hash | 40,194,018 | 576 |

## Mutation coverage

The frozen assignment was changed at five exact boundary wires:

1. point 0 at its native nonzero-validation row;
2. point 1 at its native nonzero-validation row;
3. H1 at the Phase-B H2 payload-source row;
4. the commitment at its publication link; and
5. the request hash at its sponge output-packing row.

All five stale assignments were rejected.

## Claim boundary

Version 2.12 establishes:

- `production_split_tail_materialized = true`;
- `production_h1_and_two_consistency_point_ports_native_closed = true`; and
- `production_tail_phase_a_to_phase_b_wire_identity_closed = true`.

It deliberately keeps these claims false:

- `producer_point_wire_identity_closed`;
- `production_tree_producer_segments_materialized`;
- `complete_18_tree_assignment_replayed`;
- `parent_cap_to_h_rbbc_join_closed`;
- `fork_security_proof_revalidated`; and
- `production_closed`.

The parent BR1CS remains byte-for-byte unchanged at 49,227,687 bytes, with one
external assertion and SHA-256:

`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`

## Validation

- Full regression: 156 tests passed in 792.843 seconds.
- Targeted v2.12 regression: 33 tests passed in 196.961 seconds.
- Production archive replay: 56,806,711 rows, zero failures, zero external
  assertions, and all five boundary mutations rejected.
- The v2.12 parent BR1CS is byte-for-byte identical to v2.9-v2.11.
- The formal proof PDF has 39 A4 pages.  The final LaTeX build reports no
  warnings, undefined references, overfull boxes, or fatal errors; visual
  inspection of the cover, Proposition 8.9, its proof continuation, and the
  final page found no clipping or overlap.

## Next checkpoint

Build one position-0 4,096-leaf/degree-13 producer and one position-2
2,048-leaf/degree-12 producer.  Their two local point inputs must be relocated
or equality-constrained to production wires 39,945,673 and 39,945,866.  Then
freeze every output-port relocation before expanding to all eighteen tree
positions.
