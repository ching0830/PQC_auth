# PQ-RBBC v2.13 production tree-0 assignment

This note identifies and reconstructs the large producer-only assignment that
is intentionally excluded from the compact source release archive.

## Canonical archive

- file: `pq_rbbc_production_tree_0_producer_v2_13.f193assign`
- format: `PQRBBC-F193-ASSIGNMENT-LE25-1`
- header: 128 bytes
- body: 973,845,750 bytes
- total: 973,845,878 bytes
- values: 38,953,830 field elements, 25 little-endian bytes each
- field degree: 193
- SHA-256:
  `213fa3c90b62db64436ec8e7dd7ee5a6e0ec6b546ae4fa02b3cbfb50fdf502db`
- body SHA-256:
  `011b17a0ec9cf8d7bc89a84a558432ba9dcd99855124292f004dab9279179347`

The archive is a local-wire assignment.  During replay, local wire 1 maps to
global wire 40,194,597; the largest global producer wire is 79,148,426.  The
two point inputs are imported separately from the frozen global-tail archive
at global wires 39,945,673 and 39,945,866.

## Companion evidence

- manifest: `pq_rbbc_cap_production_tree0_manifest_v2_13.json`;
- sealed execution cache: `tree_0_execution_checkpoint_v2_13.pkl`;
- resume state: `tree_0_resume_state_v2_13.json`.

The manifest records 51,325,080 replayed rows, zero failures, zero external
assertions, nine rejected stale-witness probes, and all four output-value
matches.  The cache and state are convenience artifacts; the canonical
relation and assignment digests remain the authority.

## Reconstruction from chunks

The Library copy is split into fixed-size parts so that a failed transfer does
not invalidate the entire 973 MB object.  Concatenate the parts in lexical
order and verify the canonical SHA-256 above.  On a POSIX shell:

```sh
while read -r digest size part; do
  test -n "$part" && cat "$part"
done < PQ_RBBC_v2_13_TREE0_ASSIGNMENT_PARTS.txt \
  > pq_rbbc_production_tree_0_producer_v2_13.f193assign
```

The release's generated parts manifest contains the exact ordered filenames,
sizes, per-part SHA-256 digests, and the reconstruction command.  Do not treat
a reconstructed file as valid until its full SHA-256 equals the canonical
archive digest.

## Resume rule

Future long producer jobs must use checkpoint/resume.  The writer retains a
partial prefix, recomputes the deterministic prefix, byte-compares it, and
only then appends.  A mismatching prefix, cache profile, randomness label,
tree index, or component digest fails closed; it is never silently reused.
