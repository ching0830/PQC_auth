# PQ-RBBC v2.9 production global-tail assignment

The canonical assignment archive is distributed separately from the source
release because it is approximately one gigabyte.

## Frozen identity

- File: `pq_rbbc_cap_global_tail_assignment_v2_9.f193assign`
- Format: `PQRBBC-F193-ASSIGNMENT-LE25-1`
- Header bytes: 128
- Value width: 25 bytes per GF(2^193) wire
- Wires: 40,194,596
- Archive bytes: 1,004,865,028
- Archive SHA-256: `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`
- Body SHA-256: `358266d106a1ac01cacb7c19c9bff1a7da2acceeb580a1d54462f31986cba925`
- Canonical rows: 56,806,711
- Row-stream SHA-256: `c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df`
- Replay failures: 0
- External assertions: 0
- Stale-witness probes: 6/6 rejected

The sealed evidence is
`pq_rbbc_cap_global_tail_manifest_v2_9.json`, whose SHA-256 is
`a8667bdfcfa64e3f2498ea4fea806257fdd031f091c21445f7a9c1f27bd705fa`.

## Distributed parts

The archive is stored as 21 byte-exact chunks named
`pq_rbbc_cap_global_tail_assignment_v2_9.f193assign.chunk.00.part` through
`.chunk.20.part`.  Chunks 00--19 are each 48,000,000 bytes and chunk 20 is
44,865,028 bytes.  `SHA256SUMS_v2_9.txt` records and verifies every individual
chunk digest.

Reconstruct and verify:

```bash
cat pq_rbbc_cap_global_tail_assignment_v2_9.f193assign.chunk.*.part \
  > pq_rbbc_cap_global_tail_assignment_v2_9.f193assign
sha256sum pq_rbbc_cap_global_tail_assignment_v2_9.f193assign
```

The reconstructed digest must equal
`946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`.

## Reproduction

The production execution cache is trusted only after
`validate_execution_cache_identity` rechecks the profile, deterministic
randomness, canonical tree order, and frozen v2.8 reference digests.

```bash
python -u pq_rbbc_cap_global_tail.py \
  --fixture production \
  --archive pq_rbbc_cap_global_tail_assignment_v2_9.f193assign \
  --manifest pq_rbbc_cap_global_tail_manifest_v2_9.json \
  --execution-cache pq_rbbc_cap_composition_execution_v2_8.pkl \
  --workers 8 \
  --replace
```

The first run is intentionally unsealed.  After independently checking and
freezing the canonical row count, wire count, row-stream digest, and assignment
digest in `pq_rbbc_cap_global_tail.py`, seal the existing manifest without
regenerating the archive:

```bash
python pq_rbbc_cap_global_tail.py \
  --seal-existing pq_rbbc_cap_global_tail_manifest_v2_9.json
```

The sealing command revalidates the production profile and format IDs, all
four frozen counts/digests, commitment and request outputs, zero external
assertions, zero replay failures, all six mutation probes, and every remaining
false claim boundary.  It changes only
`production_global_tail_native_closed` to `true`.

## Scope

This archive proves satisfiability and mutation sensitivity of the shared
consumer tail.  It does not contain the eighteen position-specific
tree-producer segments or exact cross-segment relocated wire identities.
Consequently it is not a complete eighteen-tree CAP assignment and it does
not close the parent issuance assertion or any formal security reduction.
