# PQ-RBBC v2.16 — 18-tree production namespace plan

Date: 26 August 2026

## Outcome

Version 2.16 freezes a deterministic wire namespace for all 18
position-sensitive CAP tree producers.  The plan removes the collision between
the standalone v2.13 tree-0 and v2.14 tree-2 producer namespaces: both had used
local wire start 40,194,597, so their full internal ranges could not coexist.

The new plan keeps the already replayed v2.9 global tail at wires
1–40,194,596, then places the 18 complete producer-local intervals in canonical
tree-index order.  It preserves the two global consistency-point imports at
wire starts 39,945,673 and 39,945,866.  Producer rows may reference only their
own rebased local interval and those two imported 193-bit ranges.

## Frozen plan

| Evidence | Result |
| --- | ---: |
| Tree positions | 18 |
| 4,096-leaf / degree-13 positions | 2 |
| 2,048-leaf / degree-12 positions | 16 |
| Planned producer wires | 389,562,636 |
| Planned producer rows | 513,312,336 |
| Planned output relocations | 72 ranges / 15,938,520 bits |
| Tail + producer + relocation rows | 586,057,567 |
| Maximum planned wire ID | 429,757,232 |
| Namespace plan SHA-256 | `810f9feb69df61dd9672d90fe74fcec54c3b28bd126013981aeceb1e9e156c4f` |

Representative interval anchors are:

| Tree | Shape | Planned interval | Rebase delta |
| ---: | --- | ---: | ---: |
| 0 | 4,096 / degree 13 | 40,194,597–79,148,426 | 0 |
| 1 | 4,096 / degree 13 | 79,148,427–118,102,256 | 38,953,830 |
| 2 | 2,048 / degree 12 | 118,102,257–137,580,692 | 77,907,660 |
| 17 | 2,048 / degree 12 | 410,278,797–429,757,232 | 370,084,200 |

The complete tree-2 planned output starts are 136,713,057, 137,503,585,
137,505,633, and 137,576,061.

## Fail-closed remapping rule

The module exposes row-level remapping for the existing native
`LinearForm`/`RankOneRow` representation:

1. a wire inside the standalone producer-local interval moves by the tree's
   exact planned delta;
2. a wire inside either frozen consistency-point range remains unchanged; and
3. every other external wire raises an error.

Labels, constants, coefficients, term counts, and row counts are not modified.
A small nonlinear/linear fixture checks that the relation values remain
satisfied after remapping.  This fixture validates the transformation rule; it
is explicitly not a substitute for replaying a production producer archive.

## Negative evidence

Eight configuration mutations fail closed:

- wrong tree order;
- wrong tree shape;
- wrong consistency-point range;
- overlapping producer intervals;
- overlapping producer output ranges;
- wrong tail consumer range;
- unsigned 64-bit wire overflow; and
- wrong output value digest.

The canonical plan also rejects noncanonical relation IDs, producer sizes, row
counts, output order, source identities, and rebase deltas.

## Parent stability

The v2.16 native profile, Blind-UOV ABI, executable reference, and BR1CS
manifest import the namespace identity and conservative claim boundary.  The
generated parent BR1CS remains 49,227,687 bytes with SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.
It still has one external assertion; no planned producer row was silently
counted as a parent join.

## Claim boundary

The following are true:

- `production_18_tree_namespace_plan_closed`;
- `production_namespace_intervals_nonoverlapping`;
- `production_global_point_imports_preserved`; and
- `representative_rebase_rule_fixture_verified`.

The following remain false:

- `representative_producers_rebased_replayed`;
- `tree_producer_segments_materialized`;
- `all_72_output_relocations_closed`;
- `complete_18_tree_assignment_replayed`;
- global `cross_segment_wire_identity_closed`;
- `parent_cap_to_h_rbbc_join_closed`;
- the formal security reductions; and
- `production_closed`.

Tree 0 has rebase delta zero, so its sealed v2.13 replay already occupies its
planned interval.  The combined representative replay claim remains false
until tree 2 is replayed at wire start 118,102,257 and the resulting stream and
assignment evidence are sealed.

## Validation

- namespace regression: 8/8 passed;
- all eight fail-closed configuration probes reject;
- complete regression suite: 186 passed, 5 optional external-artifact tests
  skipped;
- parent BR1CS full generation and round-trip succeeded; and
- parent BR1CS SHA-256 is unchanged from v2.15.

## Next implementation point

Replay tree 2 at planned wire start 118,102,257 while importing the exact
global consistency-point wires.  Verify unchanged row count and relation
values, seal its new row-stream and assignment identities, and only then begin
the checkpointed tree-1 and tree-3-through-tree-17 producer runs.
