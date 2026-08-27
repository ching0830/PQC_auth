# PQC Auth / PQ-RBBC research prototype

This repository contains the auditable cryptographic core developed for the
PQ-RBBC / Blind-UOV → signature-gated decryption research track.

## Layout

- `src/` — current Python reference and circuit-building implementation.
- `tests/` — regression, negative-case, mutation, and replay tests.
- `manifests/` — frozen machine-readable evidence and claim boundaries.
- `artifacts/metadata/` — metadata for large generated assignments and split runs.
- `docs/releases/` — release notes.
- `docs/roadmaps/` — implementation roadmaps.
- `docs/artifacts/` — assignment and reconstruction notes.
- `docs/proof/` — formal-proof source and rendered release PDFs.
- `checksums/` — original release checksum inventories.

## Current checkpoint

Version 2.23 continues R1d-b2 by materializing tree index 3 at planned local
wire start 137,580,693 through the generic checkpointable planned-offset
runner.  All 25,666,386 rows pass, all four outputs match the recovered global
tail, and six stale-witness plus three point mutations reject.  Planned
producer indices 0 through 3 are now materialized; trees 1, 2, and 3 have
complete planned-offset replays.  Git contains only portable sealed evidence;
the 486,961,028-byte tree-3 assignment, pickle caches, global tail, and BR1CS
remain external.  The remaining fourteen position-sensitive producers,
complete assignment, parent join, and formal security reductions remain open.
Start with
`docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md` in a new work session.

## Running tests

The implementation uses flat module imports inside `src/`:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Some production replay tests require large external assignment archives.  The
required identities and reconstruction procedure are recorded in manifests,
release notes, and `docs/ARTIFACT_POLICY.md`.  Tests that require an optional
large archive report `skipped` when that artifact has not been restored.

## Security status

This is a research prototype.  Read the newest manifest claim boundaries and
release roadmap before relying on a component.  A closed component checkpoint
does not imply that the complete 18-tree production system or its security
proof is closed.
