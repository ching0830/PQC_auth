# PQ-RBBC v2.5 — bounded-memory production-tree shard

Date: 24 August 2026

## Outcome

Version 2.5 closes the one-tree production-shape topology checkpoint left by
v2.4. It executes one real 2,048-leaf CAP tree with:

1. the complete 2,048-bit witness split into eleven GF(2^193) coefficients;
2. two transcript-derived, constrained nonzero distinct consistency points;
3. all twelve degree-12 extension-mask slices;
4. production-width 2,450-bit leaf tapes; and
5. a canonical request-binding hash after the one-tree CAP commitment.

The implementation streams canonical native rows directly into SHA-256 and
keeps only a compact wire-ID spool. It does not retain the virtual 18.9 GB row
stream or a complete witness assignment.

This is explicitly a non-secure, one-tree engineering fixture. It is not the
complete 18-tree CAP relation, a production Blind-UOV instantiation, or a
closed issuance proof.

## Streaming architecture

`pq_rbbc_cap_shard_stream.py` adds:

- a canonical `F193-R1CS-NDJSON-SHA256-1` row sink that counts and hashes rows
  without retaining them;
- a frozen locally satisfiable Anemoi permutation template remapped to disjoint
  wire ranges for each call;
- ordinary bitness, packing, state-link, source-link, Horner, aggregation,
  serialization, and request-binding rows with zero callbacks;
- an mmap-backed `PQRBBC-WIRE-SPOOL-U64LE-1` spool holding only each leaf's
  2,048 witness wire IDs and 386 M-hat wire IDs; and
- deterministic parallel concrete XOF execution whose call order is preserved.

The degree-12 masks use linearity: each leaf's 2,048 witness bits are Horner
evaluated once at each point, then the two field outputs are accumulated into
the plain result and the selected inverse-index extension slices. This avoids
materializing 2,450 coordinate-wide symbolic mask vectors.

## Frozen production-tree shard

Profile: `PQ-RBBC-CAP-PRODUCTION-TREE-SHARD-2048-v1`.

- leaves: 2,048;
- extension degree: 12;
- witness bits: 2,048;
- coefficients: 11;
- consistency points: 2;
- tape bits per leaf: 2,450;
- CAP XOF calls: 6,145;
- XOF calls including request binding: 6,146;
- Anemoi permutations: 19,505;
- wires: 19,903,324;
- rows: 26,126,283;
- nonlinear rows: 19,509,254;
- linear rows: 6,617,029;
- external assertions: 0;
- assignment materialized: no;
- virtual canonical row-stream bytes: 18,869,935,441;
- row-stream SHA-256:
  `2cfc3641a94635af35dfa5494c61e74a416ef2fb446975cd417891d244943dfc`;
- wire-spool bytes: 39,878,656;
- wire-spool SHA-256:
  `87960a5803e2663a40b3c0bda1611840806e649f3927c238bd63bdce08812f49`;
- one-tree canonical commitment bytes: 206;
- commitment SHA-256:
  `14fab7548083411124176bb8e094628fe6d20347cd78929573b76ab2cd3e757a`.

The recorded eight-worker run completed in 781.757 seconds with peak RSS
140,932 KiB (about 137.6 MiB). These are relation-construction measurements,
not proof-generation benchmarks.

## Exact Horner and sponge accounting

The shard contains:

- 2,048 leaf Horner calls;
- 40,960 native field-multiplication rows;
- 28,546 field-aggregation rows;
- three point-validation rows;
- 5,018 final Horner-output bitness rows;
- 26 final Horner-output pack rows;
- 6,553,680 Anemoi permutation rows;
- 6,184,416 payload-bitness rows;
- 6,184,416 payload source-link rows; and
- 6,720,453 sponge-output bitness rows.

All group row counts sum exactly to the global row count, and nonlinear plus
linear rows also sum exactly to 26,126,283.

## Regression evidence

The new shard test module contains ten tests covering:

- exact production-tree parameters;
- exact parallel-reference equality against the canonical CAP implementation
  on a small probe;
- frozen probe rows, wires, digests, vectors, and accounting;
- local permutation-template tamper rejection;
- witness-independent streamed topology on changed roots, salt, and message;
- frozen production manifest values and accounting identities; and
- explicit fail-closed rejection of wrong tree counts and security claims.

The complete suite passes 117 of 117 tests in 575.512 seconds.

## Parent relation preservation

The upper native-profile, hidden-state ABI, executable reference, and BR1CS
manifests now record the one-tree evidence. They keep the semantic boundaries
separate:

- one 2,048-leaf shard executed: true;
- streamed row digest frozen: true;
- shard external assertions: zero;
- complete shard assignment materialized: false;
- shard profile secure: false;
- full 18-tree vector executed: false; and
- production closed: false.

The portable parent BR1CS archive is deliberately unchanged:

- archive bytes: 49,227,687;
- rows: 2,971,580;
- wires: 2,980,304;
- external assertions: 1;
- archive SHA-256:
  `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799`.

The v2.5 archive is byte-identical to v2.4. The remaining external assertion
still names the complete 18-tree native CAP row stream and exact H_RBBC parent
wire join.

## Proof document

The 31-page proof PDF adds the one-shard streamed-topology proposition, its
accounting argument, the bounded-memory benchmark, and the limitation that a
row-topology digest without a complete assignment is not a whole-shard
satisfiability proof. The PDF was compiled to a clean log and all pages were
rendered and visually inspected.

## Claim boundary

Version 2.5 establishes a reproducible native row topology for one real
2,048-leaf production tree shape. It does not establish:

1. a complete backend-linked witness assignment for that shard;
2. whole-shard stale-witness mutation rejection;
3. the two 4,096-leaf degree-13 trees;
4. composition of all eighteen trees and cross-tree corrections;
5. replacement of the parent archive's final external assertion;
6. fork-specific CAP unique-mask and straightline-extraction proofs;
7. fork blindness and one-more-unforgeability; or
8. a qualified post-quantum zero-knowledge/simulation-extractable backend and
   fresh signature/proof benchmarks.

Production remains fail-closed until those obligations are independently
reviewed and the parent archive reaches zero external assertions.

## Next checkpoint

Version 2.6 should first make the 2,048-leaf streamed shard assignment-backed:
either materialize its complete assignment in a bounded format or connect the
row stream directly to a backend witness provider, then run honest and stale-
witness mutation checks over the whole shard. After that, implement the
4,096-leaf degree-13 shard and compose all eighteen trees under one transcript.
