# PQ-RBBC v2.10 reduced tree-producer assignments

The checkpoint contains two fixed-width GF(2^193) assignment archives for the
non-secure two-tree reduced profile.

## Files

- `pq_rbbc_tree_producer_reduced_tree_0_v2_10.f193assign`
  - 23,329 wires
  - 583,353 bytes
  - SHA-256 `5413f331c706184dc7546c262c8541ee812aec4a1c3a5ba029fdd4f0a9bd6db0`
- `pq_rbbc_tree_producer_reduced_tree_1_v2_10.f193assign`
  - 23,329 wires
  - 583,353 bytes
  - SHA-256 `a165562be53216f89137efbc1c6b4d70cb5cb8145232d937f89f2781b29c947c`

Every value is encoded as one canonical 25-byte little-endian GF(2^193)
element after the 128-byte assignment header.

## Reproduction

```bash
python -u pq_rbbc_cap_tree_producer.py \
  --output-directory producer_v2_10 \
  --workers 2 \
  --replace
```

The command regenerates both archives, verifies their body and archive
digests, replays every row through mmap, runs six stale-witness probes per
tree, checks all eight producer output ports against the v2.9 shared-tail
consumer ABI, and writes
`pq_rbbc_tree_producer_reduced_manifest_v2_10.json`.

These archives are engineering fixtures.  They do not contain either
production tree shape and make no production security claim.
