# 研究方法（Methodology）

> 最後更新：2026-09-10
> 用途：記錄研究設計、威脅模型、決策理由、評估方法及尚未決定事項。文件權責見 `docs/DOCUMENTATION_POLICY_zh-TW.md`。

## 研究方法概覽

本研究採 design-and-evaluate 路線：先固定系統角色、信任假設與安全目標，再以模組化方式定義協定、建立 reference implementation 與 negative tests，最後進行安全歸約、跨模組一致性驗證及衛星路徑效能評估。

研究成熟度須使用以下詞彙，不得互換：Defined、Instantiated、Implemented、Tested、Evidence-sealed、Proof-closed、Production-closed。完整定義見 `RESEARCH_STATUS_zh-TW.md`。

## 系統範圍與信任假設

- UE／holder 可為惡意。
- HNCC 為 honest-but-curious issuer，負責身分驗證與離線發行，但不得個人化 anonymity-set metadata。
- FAC 與 OA 即使由相同 organizations 營運，也必須使用不同門檻金鑰、ceremony、threshold 與 compromise domain。
- FGS 原則上承擔較重的 policy verification、anti-replay state 與 session endpoint 工作。
- LEO／FLEO 資源受限且不預設可信，只能中繼或執行協定指定的輕量檢查。
- 大型 issuance proof 與 threshold opening 不進入衛星在線路徑。

## 模組化研究設計

| 模組 | 研究方法 | 主要輸出 |
| --- | --- | --- |
| Federation authorization | 定義 canonical authorization object、PQ threshold 驗證與治理流程 | specification、schemas、test vectors |
| PQ-RBBC | relation／circuit 實作、replay、mutation tests、形式化 reduction | code、tests、manifests、proof |
| Opening governance | gated API、robust shares、combine 與 audit evidence | protocol、implementation、proof |
| Satellite access／PQ AKE | transcript state machine、freshness 與 channel binding | protocol、implementation、vectors |
| Replay／revocation／handover | lifecycle state machine 與 failure-recovery 分析 | semantics、implementation、tests |
| End-to-end composition | game-based composition 與 byte-level conformance | theorems、integration tests |

各模組最新成熟度不在本文件重複維護，以 `RESEARCH_STATUS_zh-TW.md` 為準。

## 目前設計決策與理由

1. **離線發行、在線驗證。** 將高成本的 identity verification 與 issuance relation 留在 HNCC，避免衛星路徑承載大型 proof。
2. **FAC 與 OA 權限分離。** 發行治理與身分開啟具有不同風險與門檻要求，分離可降低單一 compromise domain。
3. **Opening 採 signature-gated API。** OA 不提供任意 ciphertext 的裸 partial-decrypt API，opening request 必須綁定 ticket、case、purpose、evidence 與 expiry。
4. **保留 RBBC 現有路徑。** active artifact identities 與 long-running producer 仍依賴既有路徑，完成相關工作前不做破壞性遷移。
5. **以 exact bytes 作為跨模組邊界。** issuance、authentication、opening 與 audit 必須使用同一 canonical encoding，避免語意重新解讀。
6. **保守 claim boundary。** circuit checkpoint 的完成不等於端到端系統安全或 production closure。

## 待決策紀錄

每個重大決策應記錄日期、選項、選擇、理由、影響及需要重跑的實驗。

| ID | 問題 | 選項 | 狀態 | 阻擋項目 |
| --- | --- | --- | --- | --- |
| D-001 | ticket-use semantics | **short-lived、strictly one-use**；unlinkable Show 為未來擴充 | 已決定（2026-08-30） | v0.1 draft 待 cross-lane review 與 G1 freeze |
| D-002 | PQ AKE composition | 待比較候選 KEM／signature／transcript | 待研究 | access 與 handover |
| D-003 | FAC threshold primitive | 待比較 PQ threshold signature 與 DKG | 待研究 | issuer authorization |
| D-004 | OA threshold encryption | robust、auditable PQ construction | 待研究 | production opening |
| D-005 | SE-NIZK backend | 合格 PQ backend 候選 | 待研究 | RBBC proof closure |
| D-006 | Launch artifact snapshot boundary | 同一 immutable captured bytes；filesystem 強不可變性列為部署前提 | 已決定（2026-09-09） | unified-tree launch／execution handoff |
| D-007 | Append-only recovery durability ordering | external digest先驗；same capture驗證；既存entries依相依順序補directory fsync | 已決定（2026-09-10） | unified-tree production-scale qualification |

### D-001 — System profile v0.1 採 strictly one-use ticket

- **決定日期：**2026-08-30。
- **選擇：**每張 ticket 具有短效期，且最多只能成功建立一個 access session。FGS 以 canonical ticket digest 與 visible serial 執行原子 check-and-consume。
- **核心邊界：**RBBC core 的 `VerifyTicket` 是 stateless；核心 proof 中 fresh serial、issuance-side `sid` replay control、opening-authorization replay control、one-more unforgeability，以及 trace DEM 的 one-time privacy，都不等於 access ticket one-use。此決策是 system lifecycle policy，不回溯擴張 RBBC theorem。
- **理由：**目前沒有 rerandomizable／zero-knowledge `Show` protocol。允許同一 ticket 多次出示會產生明確 linkability，並使 replay、quota、revocation 與 handover semantics 更複雜。
- **必要條件：**canonical digest、transactional store、並行請求互斥、驗證失敗不消耗、成功後不得 rollback 重用，以及明確的 timeout／crash recovery。
- **代價：**UE 需要預先取得足夠的短效 ticket，FGS 需要維護 consumption state；離線或 partition 情境的 availability 必須單獨評估。
- **未來擴充：**若後續加入 unlinkable `Show`，必須建立新的 presentation relation、security game、encoding、proof backend 與 benchmark，不能只移除 consumption check。
- **實作規格：**`docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md` 定義 draft state machine、atomic commit、retry／crash、handover boundary、framing 與 machine-test invariants。Canonical access codecs、transcript／use identities 與 test-only process-local replay model 已實作／測試；holder authenticator、PQ AKE、UE wallet journal 與 durable／distributed production store 仍未實作。

### D-006 — Launch artifact 採 captured-byte consistency boundary

- **決定日期：**2026-09-09。
- **選擇：**launch validation 對每個輸入執行 single-open、single bounded read，後續
  identity、strict parse、binding 與 semantic validation 全部只消費同一 immutable
  `Snapshot.raw`。Inode、size、mtime、ctime 僅作 best-effort mutation signals。
- **理由：**一般 filesystem 的 metadata equality 無法證明 capture 期間完全沒有 writer；
  反覆 `stat` 或重讀 pathname 不能建立該保證，後者還可能重新引入 hash／parse TOCTOU。
- **必要條件：**future executor 必須直接消費已驗證 `CandidateSet` 中的 snapshots，不得
  重開 pathname。Trusted producer handoff、writer quiescence、owner／mode／ACL、既有
  writable FD 與 mount namespace 由部署與正式授權流程負責。
- **claim boundary：**此決策封閉 byte-consistency contract，不證明 filesystem 強不可變性、
  reviewer authenticity／independence、execution authorization 或 production closure。

### D-007 — Append-only recovery 採 durability-ordered commit boundary

- **決定日期：**2026-09-10。
- **選擇：**resume在output lock內先capture latest checkpoint並比對外部提供的SHA-256，
  再讀取fixture及進行bounded重算；canonical與semantic validation持續使用同一份
  captured bytes。採用中斷後留下的既存chunk、journal或final entry前，依
  chunks → journal → output相依順序同步被pin住且驗證過的parent directories。
- **理由：**檔案內容fsync與pathname可見都不能單獨保證directory entry已持久化；若先
  發布承諾後才補barrier，system crash可能留下checkpoint但遺失它所承諾的chunk。錯誤或
  stale digest若延後檢查，也會無必要地啟動bounded重算。
- **必要條件：**exclusive cooperative writer、可信filesystem／mount fsync語義、可信
  producer handoff與writer quiescence；fsync錯誤必須fail closed且可重試，既存bytes／inode
  不得以truncate、replace或overwrite修補。
- **claim boundary：**fault injection、process death及syscall ordering支持bounded recovery
  contract，但不等於實體斷電、kernel crash、remount、跨主機durability或production-scale
  qualification。

## 驗證與評估方法

### 正確性與安全性工程

- 每個模組建立 positive、negative、mutation 與 replay tests。
- 對 canonical schemas 建立跨語言／跨模組 test vectors。
- 對大型外部 artifact 驗證 SHA-256、byte length、row-stream digest、wire count 與 manifest contract。
- 不把通過單元測試解讀成密碼學 proof；proof assumptions 與 implementation evidence 分別追蹤。

### 效能評估

至少量測：online communication bytes、FGS／LEO computation、issuance time、verification time、opening time、memory、storage、latency、throughput 與 jitter。所有量測必須在 `experiments.md` 保存環境、commit、命令、重複次數與原始輸出位置。

### 比較原則

- baseline 必須具有相近威脅模型與功能，否則明確標註不可直接比較之處。
- 分開報告 offline issuance、satellite online path、opening 與 handover 成本。
- 同時報告中央趨勢、變異及失敗案例，不只列最佳結果。

## 變更控制

- 架構真實來源：`ARCHITECTURE_zh-TW.md`。
- 全專案 claim 狀態：`RESEARCH_STATUS_zh-TW.md`。
- 執行優先順序：`ROADMAP_zh-TW.md`。
- RBBC 操作交接：`docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md`。
- 本文件記錄「為什麼這樣設計」；若上述文件改變，應同步更新本文件的決策與狀態。
