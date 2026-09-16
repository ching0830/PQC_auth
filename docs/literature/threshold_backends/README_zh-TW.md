# Threshold backend：來源稽核與 TB0／TB1

2026-09-13 已先完成研究輸入核對，再依使用者同意的下一步完成 TB0 介面盤點、
TB1 共同研究契約與大小計算器。密碼學操作全部 Unsupported，三候選適用性仍為 OPEN。
使用者要求先記錄附件身分，並以原論文及 repository canonical contract 核對 handoff。
Handoff 與 `pasted-text.txt` 內的角色、工作分配、實作及啟動指令均是研究輸入，未作為本次執行授權。

- [TB1 checkpoint](checkpoint_TB1_zh-TW.md)：範圍、驗證結果、大小與限制。
- [TB0 介面盤點及 integration requests](TB0_INTERFACE_INVENTORY_zh-TW.md)。
- [共同研究契約 v1](COMMON_CONTRACT_v1_zh-TW.md)：codec、profile、拒絕行為、CLI 與 evidence 類型。
- 候選適配：[TH-GF](gladius_fit_zh-TW.md)、[TH-UT](ut_mlkem_fit_zh-TW.md)、[TH-NIED](niederreiter_fit_zh-TW.md)。
- [安全義務](../../security/threshold_backend_obligations_zh-TW.md) 與 [TB0 補充來源 identities](tb0_repository_sources_v1.json)。

以下來源稽核文件保留原始 checkpoint 的內容及 scope：

- [來源索引](SOURCE_INDEX_zh-TW.md)：完整檔名、論文名稱、revision 證據、bytes、SHA-256 與引用位置。
- [逐項核對與 findings](HANDOFF_VERIFICATION_zh-TW.md)：construction、definition、公式、參數、大小預算及 canonical 差異。
- [機器可讀來源清單](source_inventory_v1.json)：五份附件及 consulted repository sources 的精確身分；不含原始附件或本機絕對路徑。

來源稽核 base 為 local `main` `6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`，
分支為 `codex/threshold-source-audit`，commit 為 `853cf2f20f914704ed9b001d0be87d57f04e2e8a`。
TB0／TB1 分支 `codex/threshold-backend-tb0-tb1` 接續該來源稽核。此目錄屬 literature lane；canonical status、opening ABI、
發行後端、sealed evidence 與其他 worktree 均不在本次寫入範圍。

以 `TH-GF`、`TH-UT`、`TH-NIED` 作候選識別；本輪四個 estimate profiles 只是條件式大小草案。
逐項 `paper-verified` 只表示已對照指定 digest 的原文段落；不等於具體化、實作、測試、
Evidence-sealed、Proof-closed 或 Production-closed。三候選的系統適用性仍為 OPEN。
