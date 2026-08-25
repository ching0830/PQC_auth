# PQ-RBBC v2.10 — position-sensitive tree-producer segmentation

Date: 25 August 2026

## Outcome

Version 2.10 implements the producer side of the v2.9 shared-tail port ABI as
an independent native relation.  A segment retains the actual tree position
in every GGM and leaf domain, accepts the shared salt, the selected tree roots,
and the global consistency points, and constrains:

- GGM seed derivation;
- leaf seed commitments;
- tape expansion;
- plain witness and consistency-tail XORs;
- point-dependent mask Horner evaluation; and
- publication of contiguous bit-constrained producer ports.

The four outputs are named exactly as the v2.9 consumers:
`leaf-commitments`, `p-plain`, `mhat-plain`, and `xi-masks`.

## Executed reduced checkpoint

The deliberately non-secure reduced profile contains two position-sensitive
four-leaf/degree-3 trees.  Both segments were generated independently and
replayed from fixed-width assignment archives.

| Evidence | Tree 0 | Tree 1 |
| --- | ---: | ---: |
| Rows | 34,148 | 34,148 |
| Wires | 23,329 | 23,329 |
| Assignment bytes | 583,353 | 583,353 |
| Replay failures | 0 | 0 |
| External assertions | 0 | 0 |
| Stale-witness probes | 6/6 rejected | 6/6 rejected |

Frozen row-stream SHA-256 values:

- tree 0: `ff5ad52cd7d39777023b8ded3e4f8fcfd1e840172ac210e59d996232c9613da1`;
- tree 1: `fe0bcd20c92c58406bd86a0251b22ce92fabb781c3c132c7b407b7d9542f5eb7`.

Frozen assignment SHA-256 values:

- tree 0: `5413f331c706184dc7546c262c8541ee812aec4a1c3a5ba029fdd4f0a9bd6db0`;
- tree 1: `a165562be53216f89137efbc1c6b4d70cb5cb8145232d937f89f2781b29c947c`.

## Producer-to-tail ABI evidence

The two producers expose eight output ports in total.  Every port matches the
corresponding v2.9 tail consumer by:

- canonical port ID;
- profile-order tree index;
- exact bit width; and
- value SHA-256.

All eight matches pass.  This is value/ABI equality, not yet native wire
identity.  Producer-local wire IDs and tail-local wire IDs remain different,
and the consistency points are explicit producer inputs rather than the same
wires emitted by the tail H1 phase.

## Mutation coverage

For each tree, one stale assignment bit is injected at six selected rows:

1. GGM derivation source binding;
2. leaf-tape digest packing;
3. leaf-commitment port publication;
4. `p-plain` publication;
5. `mhat-plain` publication; and
6. `xi-masks` publication.

Every selected row accepts the honest assignment and rejects its stale value.

## Validation

The complete repository regression suite was executed after the v2.10
propagation into the native-profile, Blind-UOV ABI, reference relation, and
binary-R1CS manifests:

```text
Ran 144 tests in 745.539s
OK
```

The updated research proof compiles to a 37-page A4 PDF.  All rendered pages
were visually inspected; the LaTeX log contains no undefined references,
overfull boxes, or compilation warnings.  The parent incremental BR1CS remains
bit-for-bit identical to v2.9 because this checkpoint records the new reduced
producer evidence without yet joining its local wire namespace into the
parent circuit.

## Claim boundary

Version 2.10 establishes:

- `reduced_tree_producer_segments_native_closed = true`;
- `producer_to_tail_port_values_match = true`; and
- `producer_output_ports_are_native_bit_constrained = true`.

It deliberately keeps these claims false:

- `production_tree_producer_segments_materialized`;
- `point_wire_identity_to_global_tail_closed`;
- `cross_segment_wire_identity_closed`;
- `complete_18_tree_assignment_replayed`;
- `parent_cap_to_h_rbbc_join_closed`;
- `fork_security_proof_revalidated`; and
- `production_closed`.

The reduced profile is an engineering fixture and supplies no production
security claim.

## Next checkpoint

The next checkpoint should expose the v2.9 H1 consistency-point wires as a
formal phase-A output port, relocate those exact wires into one real
4,096-leaf/degree-13 producer and one real 2,048-leaf/degree-12 producer, and
materialize both production-shape assignments without duplicated H1/H2 tails.
Only after those two actual shapes replay cleanly should the run expand to all
2 + 16 position-specific producers and one complete producer/link/tail replay.
