# 論文大綱與進度（Thesis Outline）

> 最後更新：2026-09-02
> 用途：追蹤論文章節、所需證據、完成度與下一個可交付成果。章名可依學校格式調整。文件權責見 `docs/DOCUMENTATION_POLICY_zh-TW.md`。

## 論文暫定主題

後量子、隱私保護且可追責之衛星網路認證機制設計與實作。

## 章節結構

| 章節 | 主要內容 | 目前進度 | 完成條件 |
| --- | --- | --- | --- |
| 第 1 章 緒論 | 背景、動機、問題、研究目標、貢獻與範圍 | 骨架待寫 | 問題與貢獻不超出 evidence |
| 第 2 章 背景與相關研究 | 衛星認證、PQC、blind credentials、threshold opening、AKE、handover | 文獻待整理 | 完成可核對引用與比較表 |
| 第 3 章 系統與威脅模型 | 角色、信任假設、系統階段、攻擊者能力與安全目標 | 初版架構已定義 | G0 architecture freeze |
| 第 4 章 提出之機制 | FAC、PQ-RBBC、opening、satellite access、lifecycle、handover | PQ-RBBC planned trees 0–10 evidence-sealed；one-time lifecycle 與 access wire objects 已有 draft／test-only reference，其餘多為 requirements | G1 interface freeze 與完整 protocol |
| 第 5 章 安全性分析 | games、reductions、trace／privacy／AKE／replay／composition | RBBC 有 conditional reductions；整體未開始 | G4 end-to-end security |
| 第 6 章 實作與實驗設計 | reference implementation、環境、baselines、metrics | RBBC implementation 與局部 system codecs／replay model 已存在 | 可重現實驗 protocol |
| 第 7 章 結果與討論 | communication、computation、storage、latency、限制與 trade-offs | 未開始 | G5 satellite evaluation |
| 第 8 章 結論與未來工作 | 貢獻總結、限制、後續研究 | 未開始 | claims 與全篇一致 |

## 預期研究貢獻（暫定，尚待證據封閉）

1. 一個將 relation-bound blind ticket、門檻治理與衛星 PQ authentication 組合的模組化架構。
2. 將高成本 issuance／opening 留在地面端、縮減衛星在線路徑負擔的協定設計。
3. 具明確 ticket lifecycle、anti-replay、revocation 與 handover semantics 的端到端流程。
4. 對 privacy、traceability、non-frameability、AKE 與 opening governance 的組合安全分析。
5. 可重現的 reference implementation、negative tests、portable evidence 與衛星路徑評估。

以上是研究目標，不是目前已證明的成果。投稿或口試版本須依 `RESEARCH_STATUS_zh-TW.md` 收斂措辭。

## 近期寫作順序

1. 由現有 `ARCHITECTURE_zh-TW.md` 整理第 3 章初稿。
2. 建立第 2 章的 systematic literature matrix，優先支撐 ticket-use、PQ AKE、threshold opening 三項設計決策。
3. 以已決定的 D-001 ticket-use semantics 完成 access、replay 與 revocation interfaces review。
4. 將第 4 章現有 draft canonical transcripts／schemas 推進至 G1 freeze。
5. 在實作進行時同步撰寫第 5 章 game definitions 與第 6 章實驗 protocol，避免最後才補證據。

## 進度里程碑

本表的狀態表示論文章稿與所需材料的準備程度，不等同 protocol、proof 或 production closure；後者以 `RESEARCH_STATUS_zh-TW.md` 為準。

| Gate | 論文產物 | 狀態 |
| --- | --- | --- |
| G0 Architecture freeze | 第 3 章可 review 初稿 | 進行中 |
| G1 Interface freeze | 第 4 章協定與 encoding 定稿 | 未完成 |
| G2 Module closure | 各模組實作、tests 與局部 proofs | PQ-RBBC 部分完成 |
| G3 Cross-module closure | 端到端 vectors 與 exact-byte conformance | 未完成 |
| G4 End-to-end security | 第 5 章完整 proof composition | 未完成 |
| G5 Satellite evaluation | 第 6、7 章實驗與結果 | 未完成 |
| G6 Paper-ready closure | 全文 claims、code、evidence 一致 | 未完成 |

## 章節更新規則

- 每完成一項實作或 proof，只在對應 evidence 可定位時調整進度。
- 新增或刪除安全目標時，同步更新第 3、4、5、7 章。
- 實驗結果從 `experiments.md` 引用，不在本文件複製 raw logs。
- 每次準備 proposal、投稿或口試稿前，以 `RESEARCH_STATUS_zh-TW.md` 做一次 claim audit。
