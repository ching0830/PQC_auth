# 文件權責與更新規則

> 最後更新：2026-08-30
> 目的：避免研究工作台、正式規格、歷史 checkpoint 與機器證據互相覆寫或產生不一致。

## 文件層級

### 1. 研究工作台（持續更新）

| 文件 | 唯一責任 | 不應承擔的內容 |
| --- | --- | --- |
| `research-notes.md` | 文獻、理論、研究問題及概念上的研究缺口 | 精確 implementation／evidence 狀態 |
| `methodology.md` | 研究設計、決策理由、替代方案及評估方法 | release history 或 raw result |
| `experiments.md` | 按時間保存環境、commit、命令、輸入 identity、結果及限制 | 系統 canonical specification |
| `thesis-outline.md` | 論文章節、寫作完成度及所需材料 | 密碼學 production-closure 宣告 |

新 Codex 任務先讀這四份文件，再依工作範圍進入正式定義或模組交接文件。

### 2. 正式專案定義（持續更新）

| 文件 | Canonical responsibility |
| --- | --- |
| `ARCHITECTURE_zh-TW.md` | 系統範圍、角色、信任假設、模組、協定階段與安全邊界 |
| `RESEARCH_STATUS_zh-TW.md` | 全專案最新 implementation、test、proof、evidence 與 claim boundary |
| `ROADMAP_zh-TW.md` | 工作線、相依關係、integration gates 與優先順序 |
| `docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md` | 目前 PQ-RBBC checkpoint 的操作交接與下一個 bounded task |

當其他文件的狀態摘要與本層衝突時，以本層相應的 canonical 文件為準。

### 3. 歷史 checkpoint（新增、不回寫）

- `docs/releases/`：各版本 release note。
- `docs/artifacts/`：artifact 產生、重建與 evidence 說明。
- `docs/roadmaps/PQ_RBBC_CRYPTO_CORE_ROADMAP_v*.md`：當時版本的 roadmap snapshot。
- `docs/proof/releases/`：形式化 proof PDF snapshot。

舊文件可以保留當時的未完成事項或舊 claim boundary；它們代表歷史，不應改寫成最新狀態。最新狀態由 `RESEARCH_STATUS_zh-TW.md` 與 `PQ_RBBC_CURRENT_HANDOFF_zh-TW.md` 提供。

### 4. 機器可驗證證據

- `manifests/`：結構化 identities、metrics 與 claims。
- `checksums/`：release checksum inventories。
- `artifacts/metadata/`：不含本機路徑與大型 binary 的 portable evidence。
- `src/`、`tests/`：可執行關係、實作與 regression evidence。

散文文件不得覆蓋機器證據；若不一致，先視為需要調查的 claim drift。

## 中英文規則

- 繁體中文版是論文研究與目前系統設計的主要編輯來源。
- 英文版在重要 checkpoint 或對外發布前同步，不要求每次微小筆記更新都立即翻譯。
- 中英文正式文件若出現實質差異，必須在下一個 checkpoint 修正，不能把兩者都當成不同的有效規格。
- 程式 identifier、manifest field、演算法名稱與 cryptographic terminology 保留穩定英文，避免翻譯造成 byte-level 或概念歧義。

## 一次變更應更新哪些文件

| 變更類型 | 必須更新 | 視需要更新 |
| --- | --- | --- |
| 新文獻或新理論比較 | `research-notes.md` | `thesis-outline.md` |
| 重大設計決策 | `methodology.md`、相應 architecture／protocol 文件 | `research-notes.md` |
| 實驗或 benchmark | `experiments.md` | status、manifests、論文章節進度 |
| implementation／proof closure 改變 | `RESEARCH_STATUS_zh-TW.md`、相應 evidence | roadmap、outline |
| 新 RBBC checkpoint | release、artifact evidence、versioned roadmap、current handoff | project status、experiments |
| 論文章節完成度改變 | `thesis-outline.md` | research notes |

## Claim-drift 檢查

每個 checkpoint 至少確認：

1. `RESEARCH_STATUS_zh-TW.md` 沒有超出 manifests、tests 與 proof evidence。
2. `ROADMAP_zh-TW.md` 和 current handoff 的下一步沒有互相競爭。
3. `research-notes.md` 的研究缺口沒有被誤寫成最新工程狀態清單。
4. `thesis-outline.md` 的章稿進度沒有被誤解為 protocol／proof 已封閉。
5. 大型 assignments、BR1CS、pickle、cache、logs 與 split parts 沒有進入 Git。
