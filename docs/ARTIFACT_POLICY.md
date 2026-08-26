# Generated artifact policy

Git stores source, tests, frozen manifests, release documentation, proof PDFs,
and checksum inventories.  Large or reproducible binary outputs are kept out of
the repository:

- `*.br1cs` and `*.f193r1cs` circuit archives;
- `*.f193assign` production assignments and split parts;
- execution checkpoints (`*.pkl`), logs, release archives, and download cache;
- reconstructed global-tail and producer assignment bodies.

Manifests and checksum inventories remain tracked so the exact identity, byte
length, row-stream digest, wire count, and claim boundary of an external
artifact can be reviewed without storing hundreds of megabytes in Git.

The v2.10 release archive contains a rebuildable `pq_rbbc_incremental_v2_10.br1cs`
whose bytes do not match its release checksum.  It is intentionally not
published here.  All source, tests, manifests, documentation, and proof PDFs
selected from v2.6 through v2.13 were independently checked against their
release checksum inventories before publication.

Production artifacts should be distributed through release storage or another
large-file channel, then verified against the tracked checksum/manifest before
use.  Do not weaken a claim boundary merely because an external binary is
unavailable.

Checkpoint and execution-cache `*.pkl` files are a narrower local-only trust
boundary.  Identity validation after loading does not make Python pickle safe
for hostile input.  Never resume from a downloaded or otherwise untrusted
pickle; rebuild it locally from the tracked source and deterministic inputs.

The v2.19 production-composer recovery follows this rule.  Its 19.5 MB
checkpoint and 35.5 MB trusted execution-cache pickle remain external; Git
stores only the path-free sealed evidence under
`artifacts/metadata/production_recovery_v2_19/`.

The v2.20 global-tail recovery also remains external.  Its fixed-width binary
assignment is 1,004,865,028 bytes and is non-executable, but still exceeds the
repository artifact limit.  Git stores only the path-free sealed evidence
under `artifacts/metadata/global_tail_recovery_v2_20/`.  Preserve the archive
by exact SHA-256 identity; do not substitute the old incomplete workspace copy
or commit split archive parts.
