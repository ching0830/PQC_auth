# Protocol 模組 Registry

這個目錄是人類可讀的模組入口，不複製程式或歷史 evidence。正式狀態仍由
[`../RESEARCH_STATUS_zh-TW.md`](../RESEARCH_STATUS_zh-TW.md) 與 machine evidence 約束。

| 模組 | Architecture | 主要程式 | 短入口 |
| --- | --- | --- | --- |
| System | M1 | `src/pq_rbbc/contracts/`、`governance/` | [`system/`](system/README_zh-TW.md) |
| Issuance | M2 | `src/pq_rbbc_issuance_*`、PQ-RBBC core | [`issuance/`](issuance/README_zh-TW.md) |
| Opening | M3–M4 | `src/pq_rbbc/opening/` | [`opening/`](opening/README_zh-TW.md) |
| Access | M5 | `src/pq_sat_auth/v2/`、prototypes | [`access/`](access/README_zh-TW.md) |
| Lifecycle | M6 | replay／wallet／revocation／reconciliation | [`lifecycle/`](lifecycle/README_zh-TW.md) |
| Threshold research | supporting | `src/pq_threshold_candidates/` | [`threshold/`](threshold/README_zh-TW.md) |
| Evaluation | M7 | `benchmarks/`、`experiments.md` | [`evaluation/`](evaluation/README_zh-TW.md) |

機器可檢查版本：
[`../manifests/project_module_registry_v0_1.json`](../manifests/project_module_registry_v0_1.json)。
