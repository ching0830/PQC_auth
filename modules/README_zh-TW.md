[English](README.md)

# 模組 Registry

此目錄記錄論文級 module ownership。遷移第一階段會保留既有 RBBC source 與 evidence 路徑，以免干擾 active work 或 artifact identities。

| ID | 模組 | 目前歸屬路徑 | 狀態 |
| --- | --- | --- | --- |
| M1 | Federation configuration 與 issuer authorization | 僅架構 | 未完成 |
| M2 | PQ-RBBC relation-bound blind ticket | `src/pq_rbbc_*.py`、`tests/test_pq_rbbc_*.py`、`manifests/`、`docs/proof/` | 進行中 |
| M3 | Opening authorization | core proof abstract interface | 未完成 |
| M4 | Signature-gated threshold opening | core proof 與 reference relation boundaries | 部分定義 |
| M5 | Satellite authentication 與 PQ AKE | 僅架構 | 未完成 |
| M6 | Anti-replay、revocation 與 handover | 僅架構 | 未完成 |
| M7 | Evaluation 與 evidence | 目前 RBBC artifacts 加未來 system benchmarks | 部分完成 |

新模組在被宣稱為 implemented 前，應具有 module README、interface document、implementation directory、tests 與保守的 machine-readable claim boundary。
