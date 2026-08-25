# PQ-RBBC / SGTD v1.9 research checkpoint

Date: 23 August 2026

Status: research-only, fail-closed, not production-ready.

## Outcome

Version 1.9 implements the first actual native-field component of the
Blind-UOV boundary: polynomial-basis arithmetic for `GF(2^193)`, a source-pinned
eight-element Anemoi permutation, and ordinary rank-one constraints that are
evaluated against honest and tampered assignments.

It does **not** claim to implement Blind-UOV's full CAP hash. The public
artifacts expose a parameter/reproducibility gap that must be resolved before
the external assertion can be removed:

| Source or lowering | Rounds | Nonlinear rows |
|---|---:|---:|
| Blind-UOV level-III paper report | not independently reproducible | 240 |
| Pinned current Anemoi upstream rule | 14 | 336 |
| Anemoi paper characteristic-two rule | 15 | 360 |

No local parameters were tuned merely to reproduce the reported number. The
native-import validator now explicitly rejects evidence unless this gap is
resolved and a bit-exact Blind-UOV match is demonstrated.

## Native component

- Field modulus: `X^193 + X^8 + X^7 + X^6 + X^5 + X^4 + X^2 + X + 1`.
- Upstream commit: `3e86ff0cafa54839709b2fa2de0e75d7dd2db464`.
- Pinned Sage source SHA-256:
  `d170bef2a32382e6d644ac3500ca150506cbd543d95d4efe5bbaf550f753941c`.
- Parameter fingerprint:
  `5718d003de2fed43e675d36949320e7a140d0f278d7a44e825175f1ea0789b12`.
- Constraint archive: 336 nonlinear rows, 8 output-binding rows, 344 total
  rows, and 352 wires.
- Deterministic row-stream SHA-256:
  `25deba5f7fa3f54f1ccc2fd165f2755f8d7137eaa924def12f0c28ba5cdbae4d`.
- The source pin was verified locally when the manifest was generated.

The implemented rows cover one permutation only. The following seven native
components remain mandatory: CAP commitment, GGM seed derivation, GGM seed
commitments, GGM seed expansion, Fiat-Shamir hash, consistency check, and
message-commitment hash.

## Preserved core

The v1.8 relation and wire format are preserved:

- request: 72 bytes;
- final Blind-UOV signature: 11,644 bytes;
- online ticket: 12,012 bytes;
- incremental nonlinear constraints: 685,571;
- portable materialized R1CS rows: 2,971,580;
- portable archive size: 49,227,687 bytes;
- remaining external assertions: 1, exactly the native
  `H_BUOV(m, CAP.Commit(r; rho))` boundary.

The v1.9 portable archive SHA-256 is
`e6b376d0cc3fe8a6896ea6148ac41bcc70a60a2bc75e4850c82bcf9f94e2816f`.

## Verification

The complete regression suite ran 37 tests successfully. It covers:

- Blind-UOV request visibility and mask binding;
- native field arithmetic, parameter derivation, and exact row counts;
- direct-versus-constrained permutation outputs on three inputs;
- witness-independent native and portable row topology;
- native input/output tampering;
- every complete-relation negative case;
- independent SHAKE256 and KMAC256 checks;
- full 2,971,580-row archive parsing and evaluation;
- assignment and archive corruption rejection; and
- fail-closed rejection of incomplete CAP imports and the unresolved
  240/336/360 parameter gap.

## Next blocking input

Obtain an authoritative bit-exact Blind-UOV level-III Anemoi parameter and
constraint specification, ideally from a published release or the authors.
Independently reproduce the reported 240 rows and output vectors in Sage.
Only then should the seven CAP/GGM/transcript components be compiled and joined
to the existing message, mask, and hash-image wires.

Production closure still additionally requires a qualified post-quantum
zero-knowledge and simulation-extractable proof backend, a production Goppa
key and threshold decoder, and a robust threshold-share transcript.
