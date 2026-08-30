[繁體中文版](ROADMAP_zh-TW.md)

# Thesis research roadmap

This is the project-level roadmap. Module-specific roadmaps remain authoritative
for their internal checkpoints.

## Work tracks

| Track | Goal | Dependency | Can proceed now? |
| --- | --- | --- | --- |
| T0 — architecture and claims | freeze roles, phases, interfaces, threat model, and claim vocabulary | none | in progress |
| T1 — PQ-RBBC core | finish production composition, parent join, fork proof, backend, and benchmarks | existing RBBC artifacts | yes; current tree work |
| T2 — federation authorization | specify FAC threshold issuer/configuration authorization and its evidence format | T0 | yes |
| T3 — opening governance | specify case authorization, OA gate, robust shares, combine, and public audit evidence | T0; stable RBBC ticket digest | yes |
| T4 — satellite access and PQ AKE | define UE–FGS transcript, LEO/FLEO role, freshness, channel binding, and session keys | T0; stable VerifyTicket interface | yes |
| T5 — replay and lifecycle | one-time policy selected; define atomic consumption, serial state, revocation, expiry, and recovery | T0; T4 interfaces | yes |
| T6 — handover | define serving-context transition and continuous authentication | T4; T5 | specification can start |
| T7 — security proof composition | compose module games into end-to-end theorems | stable T1–T6 semantics | later |
| T8 — evaluation | communication, computation, storage, latency, throughput, jitter, and baselines | executable modules | instrumentation can start |
| T9 — paper integration | system model, proposed scheme, proofs, evaluation, limitations | all tracks | incremental |

## Immediate parallel plan

### Lane A — existing RBBC work

Continue the current module handoff at
[docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md](docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md).
Do not change its tree-producer paths or artifact identities during the
architecture reorganization.

### Lane B — system specification

1. Freeze the selected short-lived, strictly one-use ticket policy as an exact
   state-transition specification; retain unlinkable presentation as a future
   extension.
2. Freeze the exact UE, HNCC, FAC, OA, FGS, FLEO/LEO, and Operator APIs.
3. Freeze the access and opening transcripts.
4. Write the end-to-end threat model and security games.
5. Add machine-readable protocol schemas and cross-module conformance tests.

### Lane C — implementation outside RBBC

The lowest-conflict starting points are:

- canonical system/context encodings;
- FAC authorization objects and verification interface;
- opening-request and opening-evidence schemas;
- replay-state reference implementation;
- UE–FGS transcript state machine;
- communication-size accounting; and
- end-to-end test vectors using a stubbed RBBC adapter.

These can be implemented without changing the RBBC tree producer.

## Integration gates

- **G0 Architecture freeze:** roles, phases, trust, ticket-use semantics, and
  module ownership fixed.
- **G1 Interface freeze:** canonical encodings and APIs fixed.
- **G2 Module closure:** each module passes positive, negative, mutation, and
  replay tests with conservative claims.
- **G3 Cross-module closure:** the same byte strings flow across issuance,
  authentication, opening, and audit without reinterpretation.
- **G4 End-to-end security:** composed games and reductions reviewed.
- **G5 Satellite evaluation:** online communication and LEO/FGS computation
  measured against baselines.
- **G6 Paper-ready closure:** claims, implementation, evidence, and manuscript
  agree.

## Repository migration

Phase 1 preserves current RBBC paths while adding project-level documentation
and module ownership. Phase 2 may move RBBC source, tests, manifests, artifacts,
and proof history under a dedicated module layout only after active long-running
RBBC branches are merged or rebased. Every move must preserve history and exact
artifact identities.
