# PQ-RBBC v2.4 — native GF(2^193) Horner integration

Date: 24 August 2026

## Outcome

Version 2.4 closes the independent arithmetic blocker left by v2.3:

1. a bit-bound native GF(2^193) multiplication gadget;
2. a generic multi-coefficient Horner lowering;
3. an exact 2,048-bit / 11-coefficient / two-point standalone trace; and
4. a zero-callback CAP integration using two coefficients, two consistency
   points, symbolic extension-mask slices, and 2,450-bit leaf tapes.

The combined CAP fixture is intentionally non-secure. It uses two four-leaf
trees and a 386-bit witness to exercise the missing algebra without claiming
the production 18-tree topology. The parent portable relation still contains
one named external assertion for the full production CAP import.

## Native field multiplication

The rank-one backend is already over GF(2^193), using the frozen polynomial
basis. One packed field multiplication is therefore one native row. The
standalone bit-facing relation also constrains both 193-bit operands, decomposes
the product into 193 bits, and links that decomposition back to the product.

- wires: 580;
- rows: 581;
- input-bitness rows: 386;
- field multiplication rows: 1;
- output-bitness rows: 193;
- output-pack rows: 1;
- external assertions: 0;
- row-stream bytes: 269,342;
- row-stream SHA-256:
  `1c2c2bb9fa869fd43f1bc1f7089e5e05a6f9e5cba1d1c8d0a6a80039417681f7`;
- product:
  `011e6dabdb4a6f680c8f194ffd9d0dfc4a7a20a7a5599900c9`.

Changing an operand bit or output bit rejects the stale witness through an
ordinary multiplication or packing row.

## Production-width standalone Horner relation

The 2,048-bit vector is split LSB-first into eleven GF(2^193) coefficients.
For each of two evaluation points, the relation evaluates from the highest
coefficient to the lowest in Horner form. It constrains both points to be
nonzero and distinct using three inverse-witness rows.

- vector bits: 2,048;
- coefficients: 11;
- evaluation points: 2;
- multiplication rows: 20;
- point-validation rows: 3;
- output-bitness rows: 386;
- output-pack rows: 2;
- wires: 2,843;
- rows: 2,845;
- nonlinear rows: 2,843;
- linear rows: 2;
- external assertions: 0;
- row-stream bytes: 1,714,967;
- row-stream SHA-256:
  `0c9d742d44808a20a35838be84a638924dc5b2f9183bba731eefba1cb9069850`;
- output SHA-256:
  `3efd441d53d4ecc3874e0cf3ffb0884a58bccfcf534392b3046c604a41efbc22`.

The constrained outputs equal the direct CAP polynomial evaluator. Tests
reject vector, point, intermediate-product, and output mutations; a second
valid vector and point pair produces the identical row stream.

## Symbolic-mask CAP integration

The fixture `PQ-RBBC-CAP-HORNER-386-2450-TEST-ONLY` uses:

- a 193-bit mask plus 193 appended-signature bits;
- two GF(2^193) witness coefficients;
- two transcript-derived consistency points;
- rho = 1,678, giving 386 + 1,678 + 386 = 2,450 tape bits; and
- two four-leaf trees, each with extension degree three.

The plain polynomial needs one Horner call. Each tree contributes three
extension-bit slices, so the symbolic mask algebra needs six more calls. The
point constraints are emitted once and reused by all seven calls.

- Horner calls: 7;
- Horner multiplication rows: 14;
- point-validation rows: 3;
- Horner output-bitness rows: 2,702;
- Horner output-pack rows: 14;
- XOF calls, including final request binding: 24;
- Anemoi permutations: 84;
- wires: 92,816;
- rows: 125,401;
- nonlinear rows: 91,232;
- linear rows: 34,169;
- external assertions: 0;
- canonical commitment bytes: 304;
- row-stream bytes: 77,156,408;
- row-stream SHA-256:
  `ca391f7d64f649b26c98d646dd1c382aebcf848ab849316cb1f65d040c184525`;
- commitment SHA-256:
  `52888b6f229d4e252534d594d0ceaf9b991be649a1230e269ea6273762499e21`.

The native commitment and request-binding hash equal the direct reference.
Separate stale-witness tests mutate a plain Horner product, a symbolic-mask
Horner product, and an output bit. A second complete trace with changed salt,
root, and message has the same 77,156,408-byte row stream.

## Regression preservation

The v2.3 production-width multi-squeeze component remains byte-identical:

- rows: 113,802;
- wires: 85,034;
- external assertions: 0;
- row-stream SHA-256:
  `98222b0cafeb944184e3939a878d1e3fb3af05d10c9795ef0701c87f95462855`.

The v2.2 reduced CAP component also remains byte-identical:

- rows: 88,282;
- wires: 59,602;
- external assertions: 0;
- row-stream SHA-256:
  `f6a6a0b65e6de16f7bb1d6b42302a12b004befa62b629d252861e2c986917263`.

The parent portable BR1CS relation is unchanged:

- archive bytes: 49,227,687;
- rows: 2,971,580;
- wires: 2,980,304;
- external assertions: 1;
- archive SHA-256:
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

## Verification

The complete suite contains 107 tests. It covers:

- source-pinned GF(2^193) arithmetic and Anemoi rows;
- bit-bound native multiplication and tamper rejection;
- exact 2,048-bit / 11-coefficient / two-point Horner evaluation;
- nonzero and pairwise-distinct consistency-point constraints;
- production-width multi-squeeze traces;
- symbolic extension-mask Horner integration;
- frozen row-stream digests and witness-independent topology;
- canonical CAP serialization and exact CAP-to-H_RBBC wire joins;
- issuance positive and negative circuits;
- fail-closed native import contracts; and
- BR1CS parsing, evaluation, assignment tampering, archive corruption, and
  witness-independent structure.

The 30-page proof PDF was compiled twice. The final log contains no undefined
references, overfull boxes, underfull boxes, or warnings. All pages were
rendered; the complete contact sheet and the new arithmetic/integration pages
were visually inspected.

## Claim boundary

Version 2.4 closes native multiplication, generic multi-coefficient Horner
evaluation, the exact standalone production-width polynomial vector, and the
small symbolic-mask CAP integration. It does not establish a production
post-quantum Blind-UOV implementation.

Still open:

1. integrate all eleven witness coefficients with every symbolic mask slice in
   one production tree shard;
2. stream the shard without retaining a monolithic JSON trace;
3. execute the complete 18-tree production relation and exact parent wire join;
4. remove the parent archive's final external assertion;
5. prove fork-specific CAP unique-mask and straightline extraction;
6. revalidate blindness and one-more unforgeability for the fork; and
7. qualify a post-quantum zero-knowledge/simulation-extractable backend and
   produce fresh signature, proof-size, time, and memory benchmarks.

Production remains fail-closed until those obligations are independently
reviewed and the parent archive reaches zero external assertions.

## Next checkpoint

Version 2.5 should use the generic v2.4 Horner gadget with the complete
2,048-bit witness and every extension-mask slice inside one real production
tree shard. The implementation should stream rows directly into a hashed shard
format, freeze its commitment and row-stream digests, and measure peak memory
before attempting the full 18-tree execution.
