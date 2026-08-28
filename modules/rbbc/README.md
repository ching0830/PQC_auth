# PQ-RBBC module

PQ-RBBC is the relation-bound blind-ticket and signature-gated trace-opening
cryptographic module of the complete satellite authentication thesis.

## Current locations

Migration phase 1 intentionally preserves these historical paths:

- implementation: [../../src](../../src);
- tests: [../../tests](../../tests);
- manifests: [../../manifests](../../manifests);
- formal proof: [../../docs/proof](../../docs/proof);
- RBBC roadmaps: [../../docs/roadmaps](../../docs/roadmaps);
- release notes: [../../docs/releases](../../docs/releases);
- artifact documentation: [../../docs/artifacts](../../docs/artifacts);
- portable metadata: [../../artifacts/metadata](../../artifacts/metadata); and
- checksums: [../../checksums](../../checksums).

## Exported system boundary

The intended system-facing operations are:

- setup and public-parameter publication;
- authenticated relation-bound blind issuance;
- canonical ticket parsing and `VerifyTicket`;
- gated `OpenShare`; and
- robust threshold combination.

The module must not expose a production API that partially decrypts a bare trace
ciphertext. It currently has no separate rerandomizable or zero-knowledge
presentation protocol; repeated presentation of the same ticket is linkable.

## Current checkpoint

Use [../../docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md](../../docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md)
as the authoritative operational handoff. A component checkpoint does not close
the complete module or the thesis system.

## Migration rule

Do not move or rename RBBC implementation and evidence paths while active
tree-producer work depends on them. A later path migration must be isolated,
history-preserving, mechanically verified, and must not change sealed artifact
contents or digests.
