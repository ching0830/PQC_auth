# PQ-RBBC v2.2 — zero-callback reduced native CAP lowering

Date: 2026-08-23

## Outcome

Version 2.2 lowers the complete reduced CAP fixture and its final
`H_RBBC(message, c_r)` join into one native `GF(2^193)` rank-one row stream.
Verification uses only the serialized rows and assignment: there are no CAP or
hash callbacks and no external assertions inside this reduced component.

This is an explicitly non-secure 64-bit fixture.  It validates native XOF
lowering, canonical serialization, inter-call wire identity, and stale-witness
rejection.  It does not close the production 2,048-bit, 18-tree profile.

## Frozen reduced native component

- Relation: `pq-rbbc/cap/reduced-native/anemoi-193-336/v1`.
- CAP profile SHA-256:
  `5d067a55e2ea9104b2604dc7efa393f44d1ce1880c3974bdcaae32aeb825f2ea`.
- Sponge profile SHA-256:
  `4fa0eb276ebba70a9f6c2f38f3f55d197c094121a2b614cc6ef9b7e8522cac87`.
- CAP XOF calls: 23.
- Final request-binding XOF calls: 1.
- Total XOF calls: 24.
- Anemoi permutations: 57.
- Wires: 59,602.
- Rows: 88,282.
- Nonlinear rows: 58,462.
- Linear rows: 29,820.
- External assertions/callbacks: 0.
- Canonical JSON row-stream bytes: 51,845,969.
- Row-stream SHA-256:
  `f6a6a0b65e6de16f7bb1d6b42302a12b004befa62b629d252861e2c986917263`.

The 58,462 nonlinear rows consist of 19,152 Anemoi permutation rows, 26,848
payload-bitness rows, 9,264 XOF-output-bitness rows, and 3,198 boundary
input/output-bitness rows.  The trace also contains 26,848 explicit source-link
rows and 1,784 links for the canonical commitment, derived mask, and append
base outputs.

## Frozen output vector

- Canonical reduced commitment: 215 bytes.
- Commitment SHA-256:
  `07a09a4f623233586af7ebca90d0eeba7d6a5bb94ff86c7dff29ade7be79b800`.
- `H_RBBC` output:
  `3ff3bcd5d5097524beb5765f45ae0d2159de80d81773837c79a66de6337f5ab92ab9b7e30f24397e630a894ae9406e4a561497e112f8b1adbe6ef5f207a3aff66e8ce000ea404486`.

The trace exposes canonical output wires for all 215 commitment bytes and
feeds those exact wires, together with 32 message bytes, into the 576-bit
request hash.  Changing salt, one GGM root, and the message changes the
assignment and outputs but leaves the row-stream digest unchanged.

Stale-witness tests separately flip salt, message, commitment, and request-hash
bits.  Every mutation violates an ordinary row.

## Sponge implementation extension

The frozen sponge profile and its original 576-bit row stream are unchanged.
The implementation now supports native traces with 193-, 259-, 386-, and
576-bit outputs up to one 772-bit rate block.  Direct and constrained results
are checked after masking unused final-byte bits.

Outputs longer than 772 bits are rejected.  Production CAP tape expansion
requires 2,450 bits and therefore remains a named next-step obligation.

## Production boundary

The independent production CAP reference still has:

- 2,048 witness bits;
- 18 trees and 40,960 leaves;
- a hidden 5,378-byte canonical commitment;
- 122,847 XOF calls;
- 389,974 Anemoi permutations;
- at least 131,031,264 permutation nonlinear rows.

The full production vector and native row stream have not been executed.
Production additionally requires a 2,048-bit multi-coefficient polynomial hash
over `GF(2^193)` and multi-squeeze native traces for the 2,450-bit tape.

The 72-byte online signer request and 368-byte signed satellite payload remain
unchanged.  The 5,378-byte CAP commitment and issuance proof stay off the
satellite verification path.

## Parent incremental BR1CS

The parent archive is unchanged at:

- 2,971,580 total R1CS rows;
- 2,980,304 wires;
- 49,227,687 bytes;
- one production external assertion;
- archive SHA-256
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

The parent assertion now explicitly means the full production 18-tree row
stream and exact parent-circuit wire join.  The zero-assertion reduced component
must not be substituted as production evidence.

## Verification

All 77 tests pass in 345.754 seconds in the reference environment.  Coverage
includes:

- original Anemoi, sponge, CAP, ABI, reference relation, and BR1CS vectors;
- native 193/259/386-bit XOF output widths;
- all 24 reduced native XOF calls and their source links;
- exact commitment and request-hash wire joins;
- row-count and row-stream digest freezing;
- witness-independent topology after changing salt, root, and message;
- stale-witness rejection after input/intermediate/output mutation;
- 11 complete parent-circuit negative cases;
- parent BR1CS assignment and archive corruption rejection;
- fail-closed production manifests.

The 28-page proof PDF was compiled twice and all pages were rendered and
visually inspected without LaTeX warnings or layout overflow.

## Claim boundary and next step

Implemented now: a complete zero-callback native lowering for the reduced CAP
fixture and exact reduced CAP-to-`H_RBBC` join.

Not implemented now: a security-level production native trace, a 2,450-bit
multi-squeeze relation, production multi-coefficient polynomial hashing, a
full-tree streaming backend, an 18-tree digest, zero external assertions in the
parent archive, fork-specific extraction/security proofs, and fresh signature
or proof benchmarks.

The next checkpoint should implement and freeze the generic multi-squeeze
trace and native Horner multiplication rows first.  Both should be exercised in
a small extended fixture before attempting one full production tree shard.
