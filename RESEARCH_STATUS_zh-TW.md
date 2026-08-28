[English](RESEARCH_STATUS.md)

# 研究狀態

依已合併的 `main` v2.25 checkpoint 更新。

## 整篇論文狀態

| 項目 | Specification | Implementation | Evidence／proof |
| --- | --- | --- | --- |
| 整體架構 | 初版頂層定義 | 不適用 | 待 review |
| FAC issuer authorization | requirements 已知 | 未開始 | 未開始 |
| PQ-RBBC issuance 與 ticket | formal core 已定義 | research relation 與大量 circuit implementation | conditional reductions；production closure false |
| Opening authorization | abstract verifier interface 已定義 | 未開始 | 假設 authorization unforgeability |
| Threshold trace opening | abstract construction 已定義 | 具體完整 protocol 未封閉 | robust transcript 與 real key 未完成 |
| Satellite access 與 PQ AKE | 只有 requirements | 未開始 | 未宣稱 |
| Anti-replay 與 revocation | 只有 requirements | 未開始 | 未宣稱 |
| Handover | 只有 requirements | 未開始 | 未宣稱 |
| End-to-end evaluation | 已辨識 metrics | 未開始 | 無 system benchmark |

## RBBC checkpoint

截至 v2.25 已完成：

- production composer cache recovery；
- global-tail regeneration 與 replay；
- planned producer positions 0–7 materialized；
- 八個位置皆依各自適用 frozen contracts 獨立 replay；
- closed checkpoints 的 portable path-free evidence，包括分別綁定的 tree 5–7 batch。

仍未完成：

- tree 8–17；
- 全部 72 個 output relocations；
- 完整 18-tree assignment replay；
- cross-segment wire identity；
- parent CAP-to-(H_{RBBC}) join；
- fork-specific blindness 與 one-more proof；
- 合格 PQ zero-knowledge／simulation-extractable backend；
- real trace-encryption key 與 robust threshold transcript；
- 新的 size、time、memory benchmarks；
- production closure。

RBBC 操作上的 authoritative handoff 仍為 [docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md](docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md)。

## 狀態詞彙

- **Defined：**已有文字或 formal interface。
- **Instantiated：**已有具體 primitive 或 protocol choice。
- **Implemented：**已有 executable code。
- **Tested：**已有 positive 與 negative tests。
- **Evidence-sealed：**portable evidence 已綁定宣稱的 execution。
- **Proof-closed：**所需 theorem assumptions 與 reductions 已 review。
- **Production-closed：**implementation、integration、proof 與 benchmark gates 全部封閉。

上述詞彙不可互換使用。
