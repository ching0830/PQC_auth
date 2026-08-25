# PQ-RBBC cryptographic core v1.7

Date: 2026-08-23

Status: research construction; not deployment-ready.

## Outcome

Version 1.7 removes the unsound v1.6 claim that two independently openable
256-bit Blind-UOV request lanes multiply their generic quantum collision
security.  For a fixed pair of messages, the two lane claws can be solved
separately, so the work is additive rather than multiplicative.

The corrected profile uses one Blind-UOV-III / NIST III / identity-F / Shorter /
TCitH instance.  Its 576-bit masked target gives a generic QROM collision scale
of about 2^192 queries, subject to the CAP extraction and unique-committed-mask
conditions stated in the proof.

## Frozen interface and sizes

- Public blind-signing request, excluding the issuance proof: one 72-byte `y`.
- Hidden request state: ticket digest `m`, 576-bit mask `r`, CAP randomness
  `rho`, and derived commitment `c_r`.
- Blind-UOV public key: 189.2 KB (paper value).
- Final Blind-UOV signature: 11,644 bytes (paper value).
- Ticket payload: 368 bytes.
- Online ticket: 12,012 bytes before transport framing.
- Reduction from a 70 KB online credential: approximately 5.83x.

## Executable relation

- Public input bits: 4,032.
- Secret input bits: 7,072.
- Allocated wires: 2,976,848.
- Incremental nonlinear constraints: 684,419.
- Materialized total R1CS rows: 2,968,700.
- Native Blind-UOV-III request assertions still external: 1.

The complete 18-test suite passes.  This includes eight full-circuit negative
instances, assignment tampering, archive corruption, witness-independent
circuit structure, and independent evaluation of every serialized row.

## BR1CS archive

- File: `pq_rbbc_incremental_v1_7.br1cs`
- Size: 49,184,487 bytes.
- Archive SHA-256: `6f771f085e510b27308a7d736cfc1d22ce9cc6bfe1aea9ac445068abbe5f207b`.
- Body SHA-256: `310227aa2d0a0d480b1832a0f823b0c57dfd8852e5a0f53b3fd8b2f6ebcdf6a3`.
- Assignment SHA-256: `36a64b57e37d321042def45fc66b34ae35b53869f1e9b569daaf561acec605a9`.

## Cost qualification

The Blind-UOV paper reports the exact level-III key and signature sizes but
does not report the level-III Shockwave/Anemoi NIZK cost used here.  The draft
therefore labels the following as a rough extrapolation from its NIST-I row,
not as a paper result or local benchmark:

- Native level-III baseline: about 36.57 million constraints.
- Augmented issuance relation: about 37.26 million constraints.
- Proof size: about 4.27 MB.
- Proving time: about 74.5 seconds.
- Verification time: about 5.82 seconds.

## Remaining blockers

1. Import the native Blind-UOV-III TCitH/Anemoi well-built-request constraints
   and remove the one external assertion.
2. Validate the CAP straight-line extraction, unique-mask, commit-before-hash,
   and domain-separation conditions required by the QROM reduction.
3. Select and qualify a post-quantum zero-knowledge,
   simulation-extractable proof backend, including sound affine elimination.
4. Import a production Goppa key and robust threshold decoder; the current
   deterministic matrix remains a test fixture.
5. Resolve the explicit August 2026 Classic McEliece cryptanalytic hold before
   freezing trace-encryption deployment parameters.

The PDF is the normative human-readable specification.  The Python files,
JSON manifests, and BR1CS archive are executable/auditable research artifacts;
none is a production cryptographic implementation.
