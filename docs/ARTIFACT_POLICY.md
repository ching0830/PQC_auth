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

The v2.21 tree-index-2 planned-offset replay follows the same rule.  Its
486,961,028-byte assignment and trusted local pickle cache remain external;
Git stores only path-free sealed evidence under
`artifacts/metadata/tree2_rebased_recovery_v2_21/`.  The old standalone v2.14
assignment is not a substitute: only a full replay at planned local wire start
118,102,257 closes the tree-index-2 planned-offset gate.

The v2.22 tree-index-1 planned-offset replay also remains external.  Its
973,845,878-byte assignment has SHA-256
`ab75aca6037e47fe38a1364d2c66f90d1a3856da901423b398fa2d8812fa609f`;
trusted identity-bound pickle caches and resume state are local-only.  Git
stores only path-free sealed evidence under
`artifacts/metadata/tree1_planned_recovery_v2_22/`.  An archive with the right
shape is not a substitute: accept only the exact identity after a full
51,325,080-row replay at planned local wire start 79,148,427.

The v2.23 tree-index-3 planned-offset replay follows the same rule.  Its
486,961,028-byte assignment has SHA-256
`315e83340d10331188d27a99a82de6f1262e36468f1b6f8c6ef97283d83fc02b`;
trusted identity-bound pre-freeze and frozen pickle caches plus resume state
are local-only.  Git stores only path-free sealed evidence under
`artifacts/metadata/tree3_planned_recovery_v2_23/`.  The frozen row-stream
identity was established by a first complete replay and then revalidated by a
second complete replay under the frozen contract; neither the archive nor any
pickle may be committed.

The v2.24 tree-index-4 planned-offset replay also remains external.  Its
486,961,028-byte assignment has SHA-256
`cd2430637f8ca07356727cb4349ca02368f2268f865092c71f3049140bacf52d`;
trusted identity-bound pre-freeze and frozen pickle caches plus resume state
are local-only.  Git stores only path-free sealed evidence under
`artifacts/metadata/tree4_planned_recovery_v2_24/`.  The row-stream size was
observed by a first complete replay and accepted only after a fresh-cache
second replay under the final frozen contract.  The archive, BR1CS, resume
state, and every pickle remain prohibited from Git.

The v2.25 tree-index-5-through-7 batch follows the same rule independently for
each tree.  Each 486,961,028-byte `.f193assign` archive, its pre-freeze and
frozen identity-bound pickle caches, and all resume state remain external.
Git stores only the path-free batch seal under
`artifacts/metadata/tree5_7_batch_recovery_v2_25/`.  A batch directory is not
a trust boundary: verify all three archive, body, row-stream, replay-manifest,
contract, output, and tree-component identities before use.  None of the
three assignments, any checkpoint or pickle, or the v2.25 BR1CS may be
committed.

The v2.26 tree-index-8-through-10 bounded batch follows the same two-replay
rule.  Each tree's row-stream size is learned only from its own pre-freeze
replay and is accepted only after a second complete replay with a separate
fresh local cache.  Git stores only the path-free bounded seal under
`artifacts/metadata/tree8_10_bounded_recovery_v2_26/`.  Assignments, BR1CS,
pickle caches, resume state, and logs remain external and prohibited from Git.
This bounded seal materializes trees 0 through 10 only; it does not close the
remaining tree producers, all output relocations, parent join, complete
18-tree replay, or production.

The v2.27 tree-index-11-through-17 bounded batch completes the individually
materialized producer positions and their 72 individual output relocations.
Each tree still has an independent pre-freeze replay, frozen contract, and
second replay with a separate fresh local cache.  Git stores only the
path-free seal under `artifacts/metadata/tree11_17_bounded_recovery_v2_27/`.
The seven assignments, BR1CS, pickle caches, resume state, and logs remain
external.  Individual producer closure is not an aggregate 18-tree assignment
replay and does not close cross-segment identity, the parent join, security
proofs, or production.

The v2.28 aggregate recovery streams all 18 frozen planned assignments in
namespace order, checks all 72 relocation ranges wire by wire, and replays the
shared global tail for 586,057,567 total rows with zero verification failures.
The 18 assignments, global-tail assignment, incremental BR1CS, locally rebuilt
pickle caches, JSON checkpoint, and runtime output remain external.  Git stores
only the fail-closed runner and sealer, frozen preflight manifest, tests,
documentation, checksums, and path-free recovery evidence under
`artifacts/metadata/aggregate_recovery_v2_28/`.  This evidence closes the
aggregate replay and cross-segment wire-identity gates only; it does not close
the parent CAP-to-H-RBBC join, fork-security proof, or production.

The v2.29 parent CAP-to-H-RBBC checkpoint starts from the exact legacy F2 BR1CS
but does not splice its mismatched deterministic fixture into the v2.28
zero-message aggregate.  The unchanged parent ticket digest becomes the
message of a fresh parent-bound global tail; production CAP supplies the mask
and commitment, and native H_RBBC supplies the hash image.  The lifted
GF(2^193) parent relation rebases only non-constant parent wires after the
aggregate namespace and replaces the single external assertion with 1,408
native equality rows.  The parent-bound global-tail assignment, 72 MB joined
relation archive, 75 MB parent assignment, trusted cache, checkpoints, resume
state, and runtime output remain external.  Git stores only path-free evidence,
source, tests, frozen manifests, documentation, and checksums.  Closing this
exact parent join does not revalidate the fork-security proof and does not make
the wider system production-ready.

The v2.30 fork-security preflight is read-only and does not create or replay a
large assignment.  Git stores its fail-closed checker, frozen manifest, tests,
documentation, and checksum inventory.  The authoritative Blind-UOV revision,
fork proof packet, CAP extraction review, QROM review, blindness/one-more
review, independent-review attestation, and candidate inventory reports remain
external until their exact identities and review scope are frozen.  Merely
providing a candidate file records its size and digest but cannot promote any
security claim.  Fork-security revalidation, backend qualification, signature
benchmarking, and production closure remain false.

The bounded v2.30 proof audit subsequently freezes the authoritative
2025-10-31 Blind-UOV PDF, an internally authored fork proof-audit PDF, three
machine-readable fail-closed gap reviews, an independent-review request, and an
audit manifest in the external v2.30 directory.  Git stores the reviewable HTML
source, deterministic generators and validators, tests, documentation,
checksums, and path-free audit evidence only.  The generated reviews explicitly
identify themselves as internal and non-independent.  They may close the
internal-audit and independent-review-readiness gates, but they cannot discharge
CAP, QROM, blindness, one-more, backend, size, fork-security, or production
claims.  An independent-review request is not an attestation; the expected
attestation remains absent and must never be fabricated or self-signed.
