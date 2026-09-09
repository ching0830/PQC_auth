[繁體中文版](RESEARCH_STATUS_zh-TW.md)

# Research status

Synchronized at the 9 September 2026 integration checkpoint, including the
system control plane and PQ-RBBC through v2.41. The Traditional Chinese version
remains the primary editorial source.

## Whole-thesis status

| Area | Specification | Implementation | Evidence / proof |
| --- | --- | --- | --- |
| Overall architecture | initial top-level definition and system-profile v0.1 contracts | canonical configuration and public-initialization bundle codecs | deterministic vectors and negative tests; production key ceremony open |
| FAC issuer authorization | v0.1 epoch/policy/quota-bound grant contract | bounded control plane and process-local atomic quota reference store | canonical vectors and quota/replay tests; FAC PQ signature and distributed store open |
| PQ-RBBC issuance and ticket | formal core defined | research relation and substantial circuit implementation | conditional reductions; production closure false |
| Opening authorization | v0.1 canonical request, authorization statement, replay, and share gate | bounded fail-closed `OpenShareService` control flow | deterministic codecs and gate tests; production signature/share proof open |
| Threshold trace opening | abstract construction plus v0.1 share/combiner boundary | share consistency, threshold combine, and serial check under a test-only backend | robust decoder, OA DKG, real keys, and production transcript open |
| Satellite access and PQ AKE | v0.1 draft access-object layouts, transcript/attempt identities, and test-only suite profile; PQ AKE not selected | ServingContext and AccessInit/Challenge/Finish/Accept codecs implemented; no holder authenticator or AKE | 13 object/binding tests; no authentication-security or production-closure claim |
| Anti-replay and revocation | v0.1 has a draft one-time state machine, atomic consumption, retry/crash semantics, and framing; G1 is not frozen | canonical frame/opaque parser, use identity, and a test-only process-local linearizable replay model implemented | 16 replay/framing tests; not a durable/distributed store and no production closure claimed |
| Handover | requirements only | not started | not claimed |
| End-to-end evaluation | metrics identified | not started | no system benchmark |

## RBBC checkpoint

Integrated through v2.41:

- the legacy 18-tree profile has executable evidence for every tree, all 72
  relocations, the complete replay, and the parent CAP-to-$H_{RBBC}$ join;
- v2.30 through v2.32 freeze the fork/CAP audit and Prove/Verify contracts while
  preserving unresolved proof, QROM, PoW, and backend blockers;
- v2.33 through v2.38 define a separate unified-tree candidate and bounded
  runner, checkpoint, statement, relation, and streaming primitives without
  claiming a production-scale execution; and
- v2.39/v2.41 provide closed-world launch contracts and hardened fail-closed
  validation. Identity, parsing, binding, and validation consume one immutable
  captured byte snapshot. Filesystem immutability remains a deployment
  precondition, and the successful AI technical re-review is not an external
  human review or execution authorization.

Still open:

- production-scale unified-tree materialization, replay, and runner
  qualification;
- a real operator reservation, external human design/cryptographic review,
  trusted producer handoff, identity freeze, and launch manifest;
- fork-specific CAP/QROM, blindness, and one-more proof;
- qualified PQ zero-knowledge / simulation-extractable backend;
- real trace-encryption key and robust threshold transcript;
- fresh size, time, and memory benchmarks; and
- production closure.

The authoritative RBBC operational handoff remains
[docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md](docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF.md).

## Status vocabulary

- **Defined:** prose or formal interface exists.
- **Instantiated:** concrete primitive or protocol choice exists.
- **Implemented:** executable code exists.
- **Tested:** positive and negative tests exist.
- **Evidence-sealed:** portable evidence binds the claimed execution.
- **Proof-closed:** required theorem assumptions and reductions are reviewed.
- **Production-closed:** all required implementation, integration, proof, and
  benchmark gates are closed.

These terms are not interchangeable.
