[English](RESEARCH_STATUS.md)

# 研究狀態

依目前工作 branch 的 PQ-RBBC v2.30 bounded proof-audit checkpoint 更新；尚未宣稱已合併至
`main`。

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

截至 v2.29 已完成：

- production composer cache recovery；
- parent-bound global-tail regeneration 與 replay；
- planned producer positions 0–17 materialized，且18個位置均依適用的frozen
  contracts完成獨立及aggregate replay；
- 全部72個output relocations逐wire核對；
- complete 18-tree assignment replay與cross-segment wire identity；
- legacy F2 parent relation確定性lift至GF(2^193)，以1,408個native equality
  rows取代唯一external assertion；
- exact parent CAP-to-H-RBBC join，合計589,030,555 rows、0 failures、0 external
  assertions；
- 上述bounded checkpoints的portable path-free evidence。
- v2.30 fork-security唯讀preflight已綁定v2.29 final semantics；authoritative
  Blind-UOV 2025-10-31 revision、fork-specific proof-audit packet、CAP／QROM／
  blindness-one-more internal gap reviews與independent-review request均已凍結並由
  path-free evidence封存。Internal audit已完成且可交付獨立review；由於review
  明確找到CAP extractor、concrete QROM、fork proof、PQ SE-NIZK與獨立attestation
  等blockers，沒有提升任何security claim，也沒有啟動large replay。

仍未完成：

- fork-specific CAP extraction、blindness 與 one-more proof及其獨立review；
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
