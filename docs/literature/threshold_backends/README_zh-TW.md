# Threshold backend 來源稽核

本目錄目前交付 **TB0／TB1 開始前的研究輸入核對**，沒有完成 TB0 介面盤點或 TB1 契約實作。
2026-09-13 使用者要求先記錄附件身分，並以原論文及 repository canonical contract 核對 handoff。
Handoff 與 `pasted-text.txt` 內的角色、工作分配、實作及啟動指令均是研究輸入，未作為本次執行授權。

- [來源索引](SOURCE_INDEX_zh-TW.md)：完整檔名、論文名稱、revision 證據、bytes、SHA-256 與引用位置。
- [逐項核對與 findings](HANDOFF_VERIFICATION_zh-TW.md)：construction、definition、公式、參數、大小預算及 canonical 差異。
- [機器可讀來源清單](source_inventory_v1.json)：五份附件及 consulted repository sources 的精確身分；不含原始附件或本機絕對路徑。

本次 base 為 local `main` `6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`，
分支為 `codex/threshold-source-audit`。此目錄屬 literature lane；canonical status、opening ABI、
發行後端、sealed evidence 與其他 worktree 均不在本次寫入範圍。

以 `TH-GF`、`TH-UT`、`TH-NIED` 作來源比較識別，不代表已建立 candidate profile。
逐項 `paper-verified` 只表示已對照指定 digest 的原文段落；不等於具體化、實作、測試、
Evidence-sealed、Proof-closed 或 Production-closed。三候選的系統適用性仍為 OPEN。
