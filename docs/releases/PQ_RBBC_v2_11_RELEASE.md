# PQ-RBBC v2.11 - split global-tail wire contract

Date: 25 August 2026

## Outcome

Version 2.11 exposes the canonical global tail as one input prelude followed by
two logical phases without changing the underlying relation:

1. Phase A consumes the tree commitments, `p-plain`, and `mhat-plain`, then
   produces the H1 digest and consistency-point wires.
2. Phase B consumes those exact H1/point wire IDs together with salt, message,
   the plain ports, and `xi-masks`, then produces H2, the CAP commitment,
   derived mask, append base, and request hash.

The observer allocates no wires and emits no rows.  Phase A and Phase B are
half-open ranges of relation `pq-rbbc/cap/production-global-tail/v1`, not two
independent relations joined by copied values or hashes.

## Executed reduced checkpoint

| Evidence | Result |
| --- | ---: |
| Rows | 36,801 |
| Wires | 24,992 |
| Stream bytes | 9,456,158 |
| Assignment archive | 624,928 bytes |
| Replay failures | 0 |
| External assertions | 0 |
| Boundary-wire probes | 4/4 rejected |

Frozen row-stream SHA-256:

`4d2f53ba3a039a9c88cd7dd0b7e0e19ad4f7e39d5db2bce67af19ee09302c6fa`

Frozen assignment-body SHA-256:

`ea4165dd32323a0ecf34cd21d7515571fdd6682f857266c0f3608aa1a4fd703c`

Frozen assignment-archive SHA-256:

`0915410fac94d6ab8ae9dcab487af7d8aca98aa187c6960e3472e77db990edc0`

## Exact phase ranges

All ranges are half-open.

| Segment | Row range | Wire range |
| --- | ---: | ---: |
| Input prelude | `[0, 5402)` | `[1, 5403)` |
| Phase A | `[5402, 19813)` | `[5403, 14499)` |
| Phase B | `[19813, 36801)` | `[14499, 24993)` |

The reduced profile has one consistency point.  Its Phase-A ports are:

| Port | Start wire | Bits |
| --- | ---: | ---: |
| `global.phase-a.h1` | 12,255 | 386 |
| `global.phase-a.consistency-points` | 14,305 | 193 |

Phase B names both ports as inputs and directly uses those same wire IDs.

## Canonical equivalence

Independent canonical generation and split-observed generation match on:

- row count, wire count, and complete row-stream SHA-256;
- all original input ports;
- the full fixed-width assignment-body SHA-256;
- commitment bytes; and
- request-hash bytes.

The split archive then replays the unchanged row generator with zero failures.

## Mutation coverage

The tests change the exact first wire of each named boundary port while keeping
the remainder of the assignment stale:

1. Phase-A consistency point at its native validation row;
2. Phase-A H1 digest at the Phase-B H2 payload-source row;
3. Phase-B commitment at its publication link; and
4. Phase-B request hash at its sponge output-packing row.

All four stale assignments are rejected.

## Claim boundary

Version 2.11 establishes:

- `reduced_split_tail_phase_contract_closed = true`;
- `canonical_tail_stream_and_assignment_equivalent = true`;
- `h1_and_consistency_point_ports_native_closed = true`; and
- `tail_phase_a_to_phase_b_wire_identity_closed = true`.

It deliberately keeps these claims false:

- `production_split_tail_materialized`;
- `producer_point_wire_identity_closed`;
- `production_tree_producer_segments_materialized`;
- `complete_18_tree_assignment_replayed`;
- `parent_cap_to_h_rbbc_join_closed`;
- `fork_security_proof_revalidated`; and
- `production_closed`.

The v2.9 production tail constants and v2.10 producer constants remain frozen
and unchanged.  The parent BR1CS also remains unchanged and retains one
external assertion.

## Validation

The complete repository regression suite was executed after propagation into
the native profile, Blind-UOV ABI, reference relation, and BR1CS manifests:

```text
Ran 151 tests in 786.399s
OK
```

The parent v2.9, v2.10, and v2.11 BR1CS files are all 49,227,687 bytes and have
the identical SHA-256:

`77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`

The research proof compiles to a 38-page A4 PDF.  Every rendered page was
visually inspected, including the new two-page proposition.  The final LaTeX
log contains no undefined references, warnings, underfull boxes, or overfull
boxes.

## Next checkpoint

Materialize this contract against the frozen production tail so that both
production consistency-point ports receive exact wire ranges.  Then build one
position-0 4,096-leaf/degree-13 producer and one position-2
2,048-leaf/degree-12 producer, with explicit relocation/equality records from
the two Phase-A point outputs into each producer's point inputs.
