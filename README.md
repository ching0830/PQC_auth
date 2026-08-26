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

Version 2.18 closes the recovery gate needed to reconstruct the missing v2.8
production composer cache without risking an all-or-nothing 18-tree run.  The
new runner atomically checkpoints every derivation level and leaf batch, binds
the checkpoint to the frozen profile and deterministic randomness, and proves
bit-exact interruption/resume on the real reduced composer.  No production
recovery run has started: the v2.8 cache, v2.9 global-tail archive, v2.17
tree-index-2 rebased archive, remaining sixteen position-sensitive producers,
complete assignment, parent join, and formal security reductions remain open.
See the v2.18 release note and roadmap before interpreting the claim boundary.

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
