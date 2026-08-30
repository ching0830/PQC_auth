# 研究筆記（Research Notes）

> 最後更新：2026-08-30
> 用途：保存文獻脈絡、理論基礎、研究問題與概念上的研究缺口。新任務開始時應優先閱讀本文件及 `methodology.md`。文件權責見 `docs/DOCUMENTATION_POLICY_zh-TW.md`。

## 研究主題

本論文研究一套適用於衛星網路的後量子、隱私保護且可追責之認證機制。核心目標是在資源受限且不預設可信的 LEO／FLEO 路徑上，兼顧：

- 後量子認證與 session-key establishment；
- 匿名、issuer-unlinkable 的接入；
- 受門檻治理控制的 conditional identity opening；
- replay、revocation 與 serving-context 變動下的安全 handover；
- 可稽核、可重現，而且不超出實際證據的研究宣稱。

PQ-RBBC 是目前最成熟的密碼學核心，但不是整篇論文。完整系統邊界與角色定義以 `ARCHITECTURE_zh-TW.md` 為準。

## 理論與概念基礎

目前架構涉及下列理論主題；正式文獻引用尚待逐項整理與核對，未核對前不得把本節當作 bibliography：

- post-quantum signatures、KEM 與 authenticated key exchange；
- blind signatures、relation-bound blind issuance 與 issuer unlinkability；
- zero-knowledge／simulation-extractable proof systems；
- threshold authorization、threshold decryption 與 robust share transcripts；
- anonymous credentials、traceability 與 non-frameability；
- anti-replay、revocation、one-time／bounded-use credentials；
- satellite network authentication、handover latency 與受限節點計算模型；
- composable security 與跨模組 canonical encoding。

## 已形成的核心研究問題

1. 如何將離線發行的匿名可追責票券，安全地接入衛星在線認證與 PQ AKE？
2. 如何把重型 issuance proof 與 opening 流程留在地面端，同時讓衛星在線路徑保持精簡？
3. 如何阻止 HNCC 或 operator 透過可見 metadata 對使用者加入個人化 watermark？
4. 在目前沒有可 rerandomize／zero-knowledge `Show` protocol 的情況下，票券應採 strictly one-use、bounded-use，還是新增 unlinkable presentation？
5. 如何讓 conditional opening 同時滿足 authorization gating、threshold privacy、trace soundness、non-frameability、purpose limitation 與公開稽核？
6. 如何在 serving context 改變時完成 fresh、抗 replay 且不暴露註冊身分的 handover？
7. 如何組合各模組的安全 games，使端到端 theorem 的假設、實作與 evidence 一致？

## 研究缺口框架

本節記錄需要由論文回答的持續性問題，不作為最新工程狀態清單。精確的已完成／未完成項目與 production claim boundary 一律以 `RESEARCH_STATUS_zh-TW.md` 為準。

### PQ-RBBC core

- 如何封閉完整 composition、cross-segment identity、parent join 與 fork-specific reductions？
- 哪一種合格的 PQ zero-knowledge／simulation-extractable backend 能滿足安全性與實作成本要求？
- 如何把 circuit、replay 與 portable evidence 組合成可審核、但不過度宣稱的 closure argument？

### 系統與治理

- 如何具體化 FAC authorization 與 OA opening，同時維持獨立金鑰、門檻與 compromise domains？
- ticket-use semantics 如何影響 unlinkability、replay state、revocation 與 handover？
- UE–FGS PQ AKE 如何在 satellite-path 成本、freshness 與 channel binding 之間取捨？
- 如何建立可比較、可重現的端到端 benchmark 與 security-composition proof？

## 文獻追蹤表

正式加入文獻時，至少記錄「可驗證來源、使用位置、支持或反駁何種 claim」，避免只堆 citation。

| 文獻／標準 | 主題 | 對本研究的用途 | 閱讀狀態 | 預計章節 |
| --- | --- | --- | --- | --- |
| 待補 | PQ satellite authentication | baseline 與 threat model | 未開始 | 第 2、3 章 |
| 待補 | blind／anonymous credentials | unlinkability 與 ticket lifecycle | 未開始 | 第 2、4 章 |
| 待補 | robust threshold opening | opening governance 與 audit | 未開始 | 第 2、4、5 章 |
| 待補 | PQ AKE／KEM composition | session establishment | 未開始 | 第 2、4、5 章 |

## 筆記更新規則

- 新增論文時附 DOI、IACR ePrint、標準或 publisher 的穩定連結，並核對原文。
- 將「來源明確支持的事實」、「本論文設計決策」與「尚待驗證的推測」分開寫。
- 研究問題或缺口改變時，同步檢查 `methodology.md` 與 `thesis-outline.md`；工程狀態改變則更新 `RESEARCH_STATUS_zh-TW.md`，不在此複製清單。
- 實驗結果只放摘要；命令、環境與完整結果放在 `experiments.md`。
