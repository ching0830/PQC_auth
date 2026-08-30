[繁體中文版](RESEARCH_STATUS_zh-TW.md)

# Research status

Updated from merged `main` checkpoint v2.25.

## Whole-thesis status

| Area | Specification | Implementation | Evidence / proof |
| --- | --- | --- | --- |
| Overall architecture | initial top-level definition | not applicable | review required |
| FAC issuer authorization | requirements known | not started | not started |
| PQ-RBBC issuance and ticket | formal core defined | research relation and substantial circuit implementation | conditional reductions; production closure false |
| Opening authorization | abstract verifier interface defined | not started | authorization unforgeability assumed |
| Threshold trace opening | abstract construction defined | concrete full protocol not closed | robust transcript and real key open |
| Satellite access and PQ AKE | v0.1 draft access-object layouts, transcript/attempt identities, and test-only suite profile; PQ AKE not selected | ServingContext and AccessInit/Challenge/Finish/Accept codecs implemented; no holder authenticator or AKE | 13 object/binding tests; no authentication-security or production-closure claim |
| Anti-replay and revocation | v0.1 has a draft one-time state machine, atomic consumption, retry/crash semantics, and framing; G1 is not frozen | canonical frame/opaque parser, use identity, and a test-only process-local linearizable replay model implemented | 16 replay/framing tests; not a durable/distributed store and no production closure claimed |
| Handover | requirements only | not started | not claimed |
| End-to-end evaluation | metrics identified | not started | no system benchmark |

## RBBC checkpoint

Closed through v2.25:

- production composer cache recovery;
- global-tail regeneration and replay;
- planned producer positions 0 through 7 materialized;
- all eight positions independently replayed under their applicable frozen
  contracts; and
- portable path-free evidence for closed checkpoints, including the separately
  bound tree-5-through-tree-7 batch.

Still open:

- tree positions 8 through 17;
- all 72 output relocations;
- complete 18-tree assignment replay;
- cross-segment wire identity;
- parent CAP-to-$H_{RBBC}$ join;
- fork-specific blindness and one-more proof;
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
