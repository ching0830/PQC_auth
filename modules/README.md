[繁體中文版](README_zh-TW.md)

# Module registry

This directory records thesis-level module ownership. During migration phase 1,
existing RBBC source and evidence remain in their historical locations so active
work and artifact identities are not disturbed.

| ID | Module | Owner paths today | Status |
| --- | --- | --- | --- |
| M1 | Federation configuration and issuer authorization | architecture only | open |
| M2 | PQ-RBBC relation-bound blind ticket | `src/pq_rbbc_*.py`, `tests/test_pq_rbbc_*.py`, `manifests/`, `docs/proof/` | active |
| M3 | Opening authorization | core proof abstract interface | open |
| M4 | Signature-gated threshold opening | core proof and reference relation boundaries | partially defined |
| M5 | Satellite authentication and PQ AKE | architecture only | open |
| M6 | Anti-replay, revocation, and handover | architecture only | open |
| M7 | Evaluation and evidence | current RBBC artifacts plus future system benchmarks | partial |

New modules should receive a module README, interface document, implementation
directory, tests, and conservative machine-readable claim boundary before being
reported as implemented.
