# PQ-RBBC v2.14 — Index-2 evidence propagation

## Completed

The sealed production tree-index-2 producer evidence is now imported by the
native profile, Blind-UOV ABI, executable reference relation, and BR1CS backend
manifest.  Every layer records the same frozen producer identity:

- tree index 2, 2,048 leaves, extension degree 12;
- 25,666,386 rows and 19,478,436 local wires;
- exact global consistency-point starts `39,945,673` and `39,945,866`;
- assignment SHA-256 `63ee82b2421cbb9b4c5346c72dbdb15e26f0ef8e0d2938357fb75228ef8c9a8b`;
- row-stream SHA-256 `ad31a74cdf00ee96c646a9142da459069655e528aca3cb58cad07dc2b3b26fb8`;
- output wire starts `58,805,397`, `59,595,925`, `59,597,973`, and `59,668,401`.

The following claims are true in all four manifests:

- `production_index2_2048_degree12_producer_native_closed`;
- `production_index2_point_wire_identity_closed`;
- `production_index2_output_values_match_tail`.

The following remain false: output relocation, complete producer-segment
materialization, complete 18-tree assignment replay, cross-segment wire
identity, parent CAP-to-H_RBBC join, fork security proof revalidation,
signature-size rebenchmarking, and production closure.

## Parent relation stability

Evidence propagation changes metadata only.  The v2.13 and v2.14 parent BR1CS
archives are byte-for-byte identical and both have SHA-256
`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Verification

The focused native-profile, ABI, reference, and BR1CS regression suite passes
28/28 tests.  The index-2 producer/checkpoint suite separately passes 7/7.

## Next implementation point

Define and freeze the output-wire relocation contract for the two representative
producer shapes.  This must bind producer output wire ranges to the corresponding
global-tail consumer ports without claiming that the remaining sixteen producer
instances or the complete 18-tree assignment have been replayed.
