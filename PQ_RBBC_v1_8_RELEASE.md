# PQ-RBBC cryptographic-core release v1.8

Date: 2026-08-23

## Outcome

Version 1.8 internalizes the 576-bit Blind-UOV mask equation in the ordinary characteristic-two relation. The executable circuit now allocates secret `r` and secret `h_BUOV`, constrains both as bits, and emits 576 ordinary linear rows for

`y_j + r_j + h_BUOV,j = 0`.

This removes the public request `y` from the trust placed in the external boundary. The remaining external assertion is narrower and exact:

`h_BUOV = H_BUOV(m, CAP.Commit(r; rho))`.

This is a meaningful integration step, but it is not a completed native Blind-UOV-III proof. Production closure remains fail-closed until a bit-exact TCitH/Anemoi generator supplies the native CAP-plus-hash rows and passes the import contract.

## Frozen online profile

- Blind-UOV profile: NIST III / Shorter / TCitH.
- Public issuance request: 72 bytes.
- Final Blind-UOV signature: 11,644 bytes.
- Online ticket: 12,012 bytes.
- Security parameter: 192 bits.
- Repetitions: 18.
- GGM trees: 2 trees with 2^12 leaves and 16 trees with 2^11 leaves.
- Opened parties: 174.
- Explicit proof of work: 9 bits; total proof of work: 13.9 bits.
- Native target field: GF(2^193).

The test adapter's 32-byte deterministic nonce is not claimed to represent native CAP randomness. Native `rho` includes the salt and GGM-tree randomness required by the paper's CAP construction.

## Executable evidence

- Public input bits: 4,032.
- Secret input bits: 8,224.
- Allocated wires: 2,980,304.
- Nonlinear rows: 685,571.
- Linear definitions: 2,282,475.
- Linear assertions: 3,534.
- External assertions: 1.
- Materialized portable R1CS rows: 2,971,580.
- Portable archive size: 49,227,687 bytes.
- Archive SHA-256: `e6b376d0cc3fe8a6896ea6148ac41bcc70a60a2bc75e4850c82bcf9f94e2816f`.

The mask-binding block contributes 1,152 bitness rows plus 576 linear equality rows. Those 1,152 rows overlap semantically with a future native pi_1 implementation, so the paper-anchored combined estimate adds only the 684,419 non-overlapping shared rows to the estimated native baseline.

## Tests

The complete suite contains 26 tests and passes. It includes eleven full-circuit negative cases: wrong weight, syndrome, masked identity, holder hash, tag, serial, blind request, blind mask, Blind-UOV hash image, CAP randomness, and common context. A malicious boundary that always accepts cannot bypass the internal `y = r + h_BUOV` rows.

## Closure status

`production_closed = false`.

The current portable archive is over F2 and contains one named external assertion. Closure requires a native GF(2^193) row stream with zero external assertions, witness-independent topology, locked serialization and domain separation, verified Anemoi vectors, exact wire identity, honest acceptance, and independent rejection of message, mask, CAP-randomness, and hash-image mutations.

## Next proof step

Implement or obtain a bit-exact TCitH/Anemoi constraint generator for Blind-UOV Protocols 8-10, pin its source and parameter files, compile the CAP.Commit-plus-hash subrelation over GF(2^193), and import it through `blind-uov-iii/cap-hash/v1`. The resulting combined archive must pass the contract with zero external assertions before it is eligible for a production security claim.
