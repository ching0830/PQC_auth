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
