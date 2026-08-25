# PQ-RBBC v2.3 — production-width native multi-squeeze

Date: 24 August 2026

## Outcome

Version 2.3 removes the one-rate-block restriction from the independent
PQ-RBBC Anemoi-193/336 native sponge. Every later squeeze block is produced by
a constrained Anemoi permutation whose eight input lanes are linked to the
preceding constrained state. No callback or external assertion supplies later
output bits.

The implementation is exercised in two layers:

1. a standalone 2,450-bit CAP tape expansion trace; and
2. an extended CAP fixture in which all eight leaf tapes have the production
   width and the final canonical commitment wires feed the exact
   `H_RBBC(message, commitment)` relation.

The extended fixture is explicitly non-secure. It retains a 64-bit witness and
two four-leaf trees so that the multi-squeeze boundary can be isolated without
claiming production polynomial hashing or production tree security.

## Standalone 2,450-bit native sponge

- requested output: 2,450 bits / 307 encoded bytes;
- absorbed rate blocks: 2;
- squeezed rate blocks: 4;
- additional squeeze permutations: 3;
- total Anemoi permutations: 5;
- wires: 4,845;
- rows: 4,858;
- permutation rows: 1,680;
- payload-bitness rows: 568;
- output-bitness rows: 2,509;
- linear rows: 101;
- row-stream bytes: 3,216,517;
- row-stream SHA-256:
  `c42aec869c6de08695bcb11e2fade158cc4683aa3ac999e440b78c6ad0314c34`;
- output SHA-256:
  `d0fbc03edf1db5b54ff76a56f4b5105b4698119ad6c2877f05dc0d20c12e9c79`.

Regression tests flip an output bit in the second squeeze block and an
intermediate squeeze-state wire. The stale witness violates, respectively, an
ordinary output packing row and the next permutation-input link. Replacing the
seed with another value of the same length changes the assignment and output
but leaves the complete row stream byte-for-byte identical.

The existing 576-bit request-binding vector is unchanged. Its row-stream
SHA-256 remains:

`3aa60bc6d8d507003fb541a6ac991e88da58aea05b7b278ab7e1859772aac9ed`.

## Extended CAP integration

The fixture `PQ-RBBC-CAP-EXTENDED-2450-TEST-ONLY` keeps the reduced 64-bit
witness and tiny tree topology, but chooses the unused degree-one rho region so
that every leaf tape has exactly 2,450 bits. This exercises eight independent
four-block tape expansions inside the complete zero-callback CAP replay.

- XOF calls, including final request binding: 24;
- Anemoi permutations: 81;
- permutation rows: 27,216;
- payload-bitness rows: 26,848;
- output-bitness rows: 26,248;
- source-link rows: 26,848;
- wires: 85,034;
- total rows: 113,802;
- nonlinear rows: 83,510;
- linear rows: 30,292;
- external assertions: 0;
- canonical commitment bytes: 215;
- row-stream bytes: 69,273,394;
- row-stream SHA-256:
  `98222b0cafeb944184e3939a878d1e3fb3af05d10c9795ef0701c87f95462855`;
- commitment SHA-256:
  `e6756238a3119c2b290e5181050cba6b77ecfb9f40dc8fefd33de33aa2722503`.

All payload bits remain linked to salt, roots, seeds, commitments, tapes,
corrections, consistency values, message bits, and final output wires. A later
tape-block mutation is rejected by an ordinary row. A second complete CAP trace
with changed salt, root, and message has the same 69,273,394-byte row stream.

## Regression preservation

The v2.2 reduced native CAP component is unchanged:

- rows: 88,282;
- wires: 59,602;
- external assertions: 0;
- row-stream SHA-256:
  `f6a6a0b65e6de16f7bb1d6b42302a12b004befa62b629d252861e2c986917263`.

The parent portable BR1CS relation is also byte-identical to v2.2:

- archive bytes: 49,227,687;
- rows: 2,971,580;
- wires: 2,980,304;
- external assertions: 1;
- archive SHA-256:
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

The remaining external assertion is intentional. It denotes the full
production CAP import, not the already closed reduced or extended fixtures.

## Verification

The complete suite contains 87 tests. All passed. It covers:

- source-pinned GF(2^193) arithmetic and Anemoi rows;
- short and arbitrary-length native sponge traces;
- the exact 2,450-bit fixed vector;
- squeeze-state, later-output, payload, commitment, and message tampering;
- witness-independent topology for short, standalone 2,450-bit, reduced CAP,
  and extended CAP relations;
- reference CAP accounting and canonical serialization;
- zero-callback reduced and extended CAP-to-H_RBBC joins;
- fail-closed native import contracts;
- issuance positive and negative circuits;
- BR1CS parsing, evaluation, assignment tampering, archive corruption, and
  witness-independent structure.

The 29-page proof PDF was compiled twice. The final log contains no undefined
references, overfull boxes, underfull boxes, or warnings. All pages were
rendered and visually inspected.

## Claim boundary

Version 2.3 closes the production-width multi-squeeze engineering blocker. It
does not close the production CAP relation and does not establish a production
post-quantum Blind-UOV implementation.

Still open:

1. native GF(2^193) multiplication rows;
2. the 11-coefficient Horner evaluation of the 2,048-bit witness at two
   transcript-derived points;
3. native hashing of the extension-field mask slices;
4. one streamed production tree shard;
5. the complete 18-tree production execution and parent wire join;
6. fork-specific CAP extraction, blindness, and one-more-unforgeability proofs;
7. proof-system qualification and fresh signature, proof-size, time, and memory
   benchmarks.

Production remains fail-closed until the parent archive reaches zero external
assertions and the cryptographic proof obligations are independently reviewed.

## Next checkpoint

Version 2.4 should implement a standalone native GF(2^193) multiplication
gadget, freeze honest and tampered multiplication vectors, and build a Horner
trace for a witness wider than one field element. Only after the 11-coefficient,
two-point production polynomial relation is stable should it be combined with
the completed 2,450-bit tape path and streamed through one production tree.
