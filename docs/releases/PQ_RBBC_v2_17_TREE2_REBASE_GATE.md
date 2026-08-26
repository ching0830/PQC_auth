# PQ-RBBC v2.17 — Tree-2 planned-offset execution gate

Date: 26 August 2026

## Outcome

Version 2.17 turns the v2.16 tree-index-2 namespace entry into an executable,
fail-closed replay contract.  The production runner now accepts an explicit
local wire start, artifact tag, and execution-cache path.  The v2.17 wrapper
permits only the frozen planned start 118,102,257 and produces independently
named checkpoint, stage, and assignment files.

This release closes an execution *gate*, not the production replay.  The
repository does not contain the separately distributed 1,004,865,028-byte v2.9
global-tail assignment.  Consequently zero production rows were replayed at
the new offset and no rebased production archive is claimed.

## Frozen contract

| Evidence | Result |
| --- | ---: |
| Namespace plan SHA-256 | `810f9feb69df61dd9672d90fe74fcec54c3b28bd126013981aeceb1e9e156c4f` |
| Planned tree index | 2 |
| Planned local interval | 118,102,257–137,580,692 |
| Rebase delta | 77,907,660 |
| Planned local wires | 19,478,436 |
| Planned production rows | 25,666,386 |
| Contract SHA-256 | `4d89e4dafc771801cf53db398f63e125b509d243bafd911882279ac7a9a8a3ea` |
| Production rows replayed at planned offset | 0 |

The four planned output starts are 136,713,057, 137,503,585, 137,505,633,
and 137,576,061.  The global consistency-point imports remain exactly
39,945,673 and 39,945,866.

## Executed reduced rebase evidence

The preflight uses the real generic tree-producer generator, not a synthetic
row-only transformation.  It executes the reduced index-1 fixture at local
wire starts 1,000 and 100,000 and checks:

- identical 23,135-value allocation-order assignments;
- identical 33,954-row nonlinear/linear accounting;
- identical port values and exact shifts for every local port ID;
- unchanged imported point wire IDs;
- exact permitted rebasing of all captured witness-sensitive rows;
- zero replay failures; and
- rejection of all six stale-witness probes.

The frozen assignment-value digest is
`693f553098bbcef948ad384902a594fcf517d607e7354d140ea4307c1b85e017`.
This reduced evidence validates execution mechanics only; it is not production
replay or cryptographic security evidence.

## Fail-closed configuration evidence

Eight mutations reject: wrong namespace digest, planned start, maximum wire,
output start, point range, row count, wire count, or standalone assignment
identity.  Unsafe artifact tags and local starts that overlap imported point
ranges are rejected before any artifact is opened or created.

## Parent stability

The v2.17 native profile, Blind-UOV ABI, executable reference, and BR1CS
manifest import the gate identity and its conservative claim boundary.  The
generated parent BR1CS remains 49,227,687 bytes with SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.
It still contains one external assertion.

## Claim boundary

The following are true:

- `production_tree2_planned_offset_execution_gate_closed`; and
- `planned_offset_reduced_fixture_replayed`.

The following remain false:

- `production_tree2_rebased_assignment_materialized`;
- `production_tree2_rebased_full_replay_closed`;
- `representative_producers_rebased_replayed`;
- `tree_producer_segments_materialized`;
- `all_72_output_relocations_closed`;
- `complete_18_tree_assignment_replayed`;
- global `cross_segment_wire_identity_closed`;
- `parent_cap_to_h_rbbc_join_closed`;
- all formal fork security reductions; and
- `production_closed`.

## Validation

- v2.17 gate, producer, and namespace regression: 18 passed, 2 optional
  external-artifact tests skipped;
- affected native-profile, ABI, and reference regression: 23 passed;
- complete regression suite: 192 passed, 5 optional external-artifact tests
  skipped;
- parent BR1CS full generation and round-trip succeeded; and
- the parent BR1CS SHA-256 is unchanged from v2.16.

## Next implementation point

Restore and verify the v2.9 global-tail assignment, preferably restore the
v2.14 completed execution cache, then run the v2.17 production entry point.
Only a complete 25,666,386-row replay with zero failures may flip the two
rebased-production claims.
