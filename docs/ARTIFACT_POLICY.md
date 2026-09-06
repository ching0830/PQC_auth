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

The v2.31 CAP-security qualification checkpoint is read-only and binds the
v2.30 audit findings to the exact v2.29 execution semantics and production CAP
profile.  Git stores its checker, sealer, tests, frozen contract manifest,
documentation, checksum inventory, and path-free checkpoint evidence only.
The straight-line extractor specification, unique committed-mask reduction,
contract-bound full-transcript qualification candidate, independent-review
attestation, and environment reports remain external.  The first three
candidate identities are now frozen and validated; Git stores their reviewable
HTML and executable authoring sources plus compact path-free authoring evidence,
but not the PDFs or the 78 MB full-value transcript.  Identity and schema
validation do not promote a security claim.  The independent attestation remains
absent and must not be fabricated.  Moreover, the candidate records a raw
degree-soundness term of only 2^-182 without the paper profile's proof of work,
and leaves complete Prove/Verify, production c2 serialization, and concrete
Anemoi ROM/QROM justification open.  No large replay is part of this gate, and
no assignment, BR1CS, pickle/cache, checkpoint/resume state, or log may be
committed.  CAP security, fork security, QROM review, backend qualification,
and production closure remain false until the findings are dispositioned and an
independent review is frozen and accepted.

The v2.32 CAP Prove/Verify preflight is read-only.  Git stores its checker,
frozen requirements manifest, tests, documentation, checksum inventory, and a
compact path-free seal.  The Prove/Verify specification, production proof
serialization candidate, PoW/security-profile disposition, implementation
evidence, independent-review attestation, and initial inventory report remain
external.  The checkpoint generates no proof and replays no relation rows.  It
freezes only the outer envelope requirements; the production c_x, PoW nonce,
pi_2 payloads, and complete public-statement encoding remain unfrozen.  The
v2.31 candidate c2 is not a production serialization.  No assignment, BR1CS,
pickle/cache, checkpoint/resume state, or log may be committed.  Schema validity
alone cannot authorize implementation, a large proving run, a profile change,
or any CAP, fork-security, backend, or production claim.

Bounded v2.32 implementation work may add tracked canonical-codec source,
tests, and reviewable specification source.  Generated PDFs and machine-readable
candidate inventories remain external.  Until the complete pi_2 grammar,
unified-GGM opening, counter grinding, Protocol-11 polynomial verifier, concrete
ROM/QROM bound, and independent review are frozen, Prove must be unavailable and
Verify must fail closed.  A generic leading-zero nonce is not a substitute for
the paper-compatible combination of an interleaved unified GGM tree,
T_open rejection sampling, and explicit challenge bits.  The current 18-root
CAP profile must not be silently relabelled as the optimized one-tree profile.

The v2.33 unified-tree migration preflight records explicit authorization for a
separate candidate namespace while preserving the existing 18-root profile and
all v2.19-v2.32 evidence as immutable historical evidence.  Git may store the
read-only checker, frozen migration manifest, tests, documentation, checksum
inventory, and compact path-free evidence.  The environment report and all
source PDFs/candidate JSON inputs remain external.  Reserving the namespace is
not implementation, profile freezing, security qualification, or production
closure.

The unified-tree profile must generate new per-profile domains, row streams,
assignments, relocation evidence, aggregate evidence, parent-bound global tail,
parent join, incremental BR1CS, and complete relation identity.  Existing tree
0-17 observed stream sizes, row-stream digests, assignments, and the v2.29 replay
transcript must not be reused as observations for the new profile.  No large
pre-freeze, replay, or proving command may run until the migration checker
reports its corresponding gate safe.  The new algorithm specification, reduced
prototype evidence, runner qualification, resource reservation, and independent
design review remain external gate artifacts; the independent review must not be
fabricated or self-attested.  New assignments, BR1CS, pickle/cache, resume or
checkpoint state, and logs remain prohibited from Git.

The subsequently authorized v2.33 exact specification and reduced prototype
remain bounded by the same policy.  Git may store the unified-tree source,
reduced runner, tests, reviewable HTML specification source, and compact
path-free reduced seal.  The rendered PDF, reduced execution evidence, runner
qualification, post-reduced environment report, and JSON state/cache remain in
the independent external directory.  The reduced runner expands 12 leaves and
must reject the production profile; it creates no assignment, BR1CS, proof,
pickle, or log.  A schema-valid reduced run does not authorize production
pre-freeze or replay.  Those phases still require an operator-approved resource
reservation, independent design/cryptographic review, and a later read-only
checker that binds the exact reduced seal and production contract.

The v2.34 production pre-freeze checkpoint supplies that read-only checker and
a closed-world JSON Schema for operator resource reservations.  Git may store
the checker, schema, frozen checkpoint manifest, tests, documentation, checksum
inventory, and compact path-free evidence.  The environment report, completed
operator reservation, independent-review attestation, and all future production
outputs remain external.  The printed reservation template is deliberately
unapproved and is not an operator attestation.

The v2.34 checker freezes only the unified-tree production descriptor
fingerprint, pre-freeze contract, prospective command digest, reservation
grammar, and v2.33 evidence bindings.  Host capacity does not authorize
execution, and schema validity does not freeze an external identity.  The
current runner remains reduced-only, so the production runner, production
relation contract, resource reservation identity, review identity, and explicit
execution authorization are all required blockers.  Production pre-freeze,
frozen replay, large proving, CAP/fork security, and production closure remain
false.  A later checkpoint must implement and qualify the production runner and
freeze the external identities; no one may enable the prospective command by
editing booleans in the v2.34 checker or manifest.

The v2.35 production-runner authoring checkpoint may store the independent
runner skeleton, authored relation-stage contract, frozen manifest, tests,
documentation, checksum inventory, and compact path-free portable evidence in
Git.  Its 40-leaf production-shaped execution evidence, runner qualification,
canonical JSON state, interrupted/resumed output, and resource measurements
remain external.  No pickle, cache directory, checkpoint/resume state, log,
assignment, BR1CS, or proof output may be committed.

The bounded v2.35 fixture preserves all 18 logical-vector positions but is
explicitly test-only and insecure.  It qualifies runner control flow, not the
production runner, production relation, resource projection, CAP security, or
fork security.  Production observations remain null, and legacy tree 0-17
observed stream sizes, digests, assignments, and the v2.29 transcript cannot be
reused as observations.  The production branch must continue to reject before
creating output until its checkpoint payload and relation generator are
implemented, operator reservation and independent-review identities are frozen,
the user authorizes production pre-freeze, and a later launch manifest binds all
of those inputs.

The v2.36 bounded relation checkpoint may store the checkpoint-payload and
relation-generator source, frozen manifest, tests, documentation, checksum
inventory, and compact path-free portable evidence in Git.  The interrupted
and completed checkpoint payloads, private witness bytes, bounded relation
document, run evidence, qualification report, resource measurements, and all
audit reruns remain external.  No checkpoint/resume state, assignment, BR1CS,
pickle/cache, log, or proof output may be committed.

The v2.36 payload format is qualified only on the 40-leaf, 18-vector test
fixture.  Its 144 equality records are checkpoint-contract IR, not BR1CS or
production relation rows; the 122,904-record production-shape projection is
not an observation or a substitute for the production relation.  Resume must
bind an externally supplied expected payload SHA-256 in addition to validating
the internal stage chain.  Production execution must continue to fail before
creating output until production-scale materialization, final statement
encoding, operator reservation, independent review, explicit authorization,
and an identity-frozen launch manifest are complete.  Legacy tree observations
and the v2.29 transcript remain historical evidence and may not be reused as
unified-profile observations.

The v2.37 unified-statement checkpoint may store the strict statement and
parent-input codec, frozen manifest, tests, documentation, checksum inventory,
and compact path-free portable evidence in Git.  Deterministic statement and
bounded-parent vectors, run evidence, qualification reports, and preliminary
audit reruns remain external.  No private witness bytes, checkpoint/resume
state, assignment, BR1CS, pickle/cache, log, or proof output may be committed.

The production-profile statement artifact is a serialization test vector only.
It does not imply that a production unified-tree commitment, parent envelope,
parent join, relation, proof, or benchmark exists.  A production parent envelope
must not be materialized until an exact production `c_r` exists under the same
profile fingerprint.  The v2.36 bounded `c_r` may qualify the ABI but cannot be
relabelled as a production observation.  The legacy v2.32 codec and 18-tree
profile remain immutable; their tree stream sizes, digests, assignments, and
v2.29 transcript must not be reused as unified-profile observations.

V2.37 permits authoring the production streaming/checkpoint path, but does not
authorize its execution.  Production pre-freeze remains blocked on an
operator-approved resource reservation, independent review, explicit execution
authorization, and an identity-frozen launch manifest.  Large replay, proving,
CAP/fork security, and production closure remain false.

The v2.38 streaming-prefreeze checkpoint may store the chunk/checkpoint codec,
frozen manifest, tests, documentation, checksum inventory, and compact
path-free portable evidence in Git.  Binary stream chunks, interrupted and
completed checkpoints, stream indexes, run evidence, qualification, capacity
observations, launch-preflight reports, and audit reruns remain external.
Stream chunks may contain private seed or tape material and must never be
committed, even when their aggregate identities appear in portable evidence.

The 163,859-record, 163-chunk, 16,631,418-byte production layout is a plan, not
an execution observation.  It excludes relation streams, assignments, BR1CS,
proofs, and replay cost, and must not replace the 589,054,075-row planning lower
bound.  Bounded runtime and byte counts must not be linearly extrapolated to a
production wall-clock claim.  Existing tree 0-17 stream sizes, digests,
assignments, and the v2.29 transcript remain forbidden as unified-profile
observations.

V2.38 may validate external reservation, review, and launch candidates only as
inputs for a later identity-freeze checkpoint.  A schema-shaped or
format-shaped candidate is not an attestation and does not authorize execution.
Production pre-freeze remains prohibited until the exact operator reservation,
independent review, launch manifest, implementation, predecessor seal, and
command are frozen together by a later read-only checkpoint.  Large replay,
proving, CAP/fork security, and production closure remain false.

The v2.39 launch-preflight checkpoint may store the strict resource-reservation,
independent-review, and launch-manifest schemas, their validators and generator,
the frozen authoring manifest, tests, documentation, checksum inventory, and a
compact path-free portable seal.  Deliberately invalid draft templates,
qualification output, host-capacity observations, and preflight reports remain
external.  Completed operator or reviewer attestations and any authored launch
manifest must also remain external.

A draft template is never an attestation.  The tool must not invent an operator,
reviewer, affiliation, approval, signature reference, resource reservation, or
review disposition.  Schema validity and file presence do not freeze identity.
Even an exact candidate set may only become ready for a later identity-freeze
checkpoint; v2.39 does not grant production execution authorization.

Production stream/checkpoint materialization, scale qualification, replay,
proving, CAP/fork security, and production closure remain false.  Legacy tree
0-17 observations and the v2.29 transcript remain forbidden as unified-profile
observations.  No assignment, BR1CS, pickle/cache, checkpoint/resume state, log,
private stream payload, or production output may be committed.
