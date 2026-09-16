# Threshold backend research

這是支援 issuance／opening 的研究候選區，不是正式 protocol module，也不是 production
cryptography。

## 程式與文件

- `src/pq_threshold_candidates/`：contracts、accounting、GF reference、strict research codecs。
- `tests/threshold_candidates/`：binding、mutation、partial-evaluator tests。
- `docs/literature/threshold_backends/`：來源、candidate comparison、ABI 與 handoff。

## 目前邊界

GF reference、research ABI、partial issuance evaluator 與 CAP hash consumer 已有 bounded
implementation／tests；它們沒有真實 threshold privacy、robust DKG、production key lifecycle
或 production provider qualification。不要把 non-threshold reference 稱為 threshold backend。

