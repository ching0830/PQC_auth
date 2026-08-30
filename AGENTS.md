# PQC_auth Agent Guidance

## Start here

Before changing this repository, read the files relevant to the task:

1. `research-notes.md`, `methodology.md`, `experiments.md`, and `thesis-outline.md` for cross-task research context.
2. `docs/DOCUMENTATION_POLICY_zh-TW.md` for document ownership and update rules.
3. `ARCHITECTURE_zh-TW.md`, `RESEARCH_STATUS_zh-TW.md`, and `ROADMAP_zh-TW.md` for the canonical system definition, claim boundary, and project plan.
4. `docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md` before any PQ-RBBC production work.
5. `docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md` before system access, replay, revocation, or handover work.

Use Traditional Chinese for research and thesis documentation unless the task explicitly requests English. Keep code identifiers, manifest fields, protocol labels, and cryptographic terminology stable in English.

## Claims and research integrity

- Keep Defined, Instantiated, Implemented, Tested, Evidence-sealed, Proof-closed, and Production-closed distinct.
- A passing unit test is not a cryptographic proof. Artifact identity verification is not a full relation replay.
- PQ-RBBC `VerifyTicket` is stateless. Strictly one-use access is a system-profile M6 property that additionally depends on holder authentication and linearizable FGS consumption state.
- Do not expand a system, proof, implementation, or production claim beyond the tracked manifests, tests, proof, and portable evidence.
- Record design reasons in `methodology.md`, experiment commands/results in `experiments.md`, and current claim status in `RESEARCH_STATUS_zh-TW.md`.

## Parallel task ownership

- Use one Git worktree per live implementation task. Do not run multiple writing agents against the same checkout.
- Each task owns a disjoint file set. If the requested change overlaps another active lane, stop before editing the shared files and report the dependency.
- The integration lane owns root canonical documents: `ARCHITECTURE*`, `RESEARCH_STATUS*`, `ROADMAP*`, `methodology.md`, `experiments.md`, and `thesis-outline.md`.
- Literature lanes write new files under `docs/literature/`; security-game lanes write under `docs/security/`; they do not independently rewrite canonical status.
- PQ-RBBC lanes own `src/pq_rbbc_*`, corresponding tests/manifests, and RBBC release/artifact/roadmap evidence. They do not edit system lifecycle semantics.
- Commit bounded work on a task-specific `codex/` branch. Do not merge, push, rebase other active branches, or modify another worktree unless the user explicitly requests it.

## Repository and artifact safety

- Preserve existing PQ-RBBC source, test, manifest, proof, and producer paths while artifact identities or active producer work depend on them.
- Never commit `*.f193assign`, `*.br1cs`, `*.f193r1cs`, pickle, cache, checkpoint, resume state, logs, release archives, or split artifact parts.
- Treat `docs/ARTIFACT_POLICY.md` as mandatory. Never deserialize downloaded or otherwise untrusted pickle data.
- External artifacts are local inputs. Verify exact size and SHA-256 against the tracked manifest/checksum before use.
- A worktree does not automatically receive ignored `external_artifacts/`. Do not copy large artifacts into every worktree; use a deliberately provisioned external path and separate writable cache identities.

## Implementation expectations

- Use canonical, versioned, domain-separated encodings. Reject unknown versions, alternate encodings, length mismatches, and trailing bytes.
- Production code must fail closed at unresolved cryptographic or evidence boundaries. Test-only adapters must be visibly named and unable to cross a production boundary.
- Add positive, negative, mutation, concurrency, replay, and crash-recovery tests as applicable.
- For one-time access, failed validation must not consume a ticket; a committed successful access must never allow a second initial session; same-attempt retry must be idempotent.
- Keep satellite online-path messages and computations separately measurable from offline issuance and opening.

## Validation

Run targeted tests during development. The complete baseline is:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The full suite can take roughly ten minutes and optional external-artifact tests may skip when their exact inputs are not installed. Report passed, failed, and skipped counts separately. Before committing documentation or code, run `git diff --check` and inspect `git status` for prohibited artifacts.
