# PQ-RBBC v2.0 — independent Anemoi-193/336 fork

Date: 2026-08-23

## Outcome

Version 2.0 takes route 2: it deliberately forks away from the unreproduced
240-constraint Blind-UOV Anemoi instance and freezes an independent profile,
`PQ-RBBC-Anemoi-193/336-Sponge-v1`.  The fork retains the hidden-state issuance
ABI and the 72-byte public request `y`, but it makes no bit-exact Blind-UOV
compatibility claim.  Blind-UOV's published security reduction and 11,644-byte
signature size are not automatically inherited.

The profile fingerprint is:

`4fa0eb276ebba70a9f6c2f38f3f55d197c094121a2b614cc6ef9b7e8522cac87`

## Frozen hash profile

- Field: `GF(2^193)` in the polynomial basis frozen by v1.9.
- State: eight field elements; four rate and four capacity elements.
- Rate/capacity: 772 bits / 772 bits.
- Permutation: 14 rounds, 336 nonlinear rows per permutation.
- Framing: `magic || u16le(domain_bytes) || domain || u64le(payload_bytes) || payload || pad10*1`.
- Byte bits and polynomial coefficients: least-significant bit first.
- Tuple encoding: a field count followed by 64-bit little-endian byte lengths and field contents.
- Request domain: `PQ-RBBC/v2.0/H_RBBC`.
- Request-hash output: 576 bits (72 bytes).

For the frozen 32-byte zero message and 48-byte `00..2f` test commitment, the
encoded transcript is 118 bytes and requires two permutations.  Its output is:

`d7e05c906d029478056894a134577e10461af7da21bf1e91da1ff9a14c3674dedcd6ce709d63b37e2339d8f1cf9dd8e20d2203e029b7fdc35c0b91b38203b9860c194841e51f2661`

The constrained trace contains 944 input-bitness rows, 672 permutation rows,
579 output-bitness rows, and 43 linear packing/chaining rows: 2,238 rows and
2,235 wires in total.  Its row-stream SHA-256 is:

`3aa60bc6d8d507003fb541a6ac991e88da58aea05b7b278ab7e1859772aac9ed`

## Parent relation

The portable incremental archive remains an F2 relation with:

- 2,971,580 total R1CS rows;
- 2,980,304 allocated wires;
- 685,571 nonlinear rows;
- 2,282,475 linear definitions and 3,534 linear assertions;
- one labelled external assertion for production `CAP.Commit -> H_RBBC` wiring;
- 49,227,687 serialized bytes;
- archive SHA-256 `7a92ed3bc4037cbd98fa0952325cabf9e0f43aafeaf246ba7c45108f14b7973e`.

The 368-byte signed payload is exact.  A 12,012-byte complete ticket remains
only provisional arithmetic (`368 + 11,644`), because the fork's actual blind
signature and proof sizes have not yet been benchmarked.

## Verification

The v2.0 regression suite runs 54 tests.  All pass.  Coverage includes direct
versus constrained hashing, domain and length separation, frozen vectors and
row counts, witness-independent topology for fixed public lengths, stale
witness rejection after payload/output mutation, fail-closed native import,
complete-circuit negative cases, binary-archive round trips, and assignment or
archive tamper rejection.

## Claim boundary and next step

The included 48-byte CAP commitment is a labelled SHAKE256 test fixture.  It is
not the production CAP encoding.  Production closure therefore remains false,
and the parent archive intentionally retains one external assertion.

The next implementation step is to freeze the forked CAP witness/randomness
serialization and level-III tree topology, implement `CAP.Commit` as native
`GF(2^193)` rows, and feed its exact output wires into the implemented
`H_RBBC(m,c_r)` sponge.  The remaining GGM, consistency, and Fiat-Shamir
components follow; only after the external-assertion count reaches zero should
the fork-specific blindness/one-more-unforgeability proof and size benchmarks
be treated as production evidence.
