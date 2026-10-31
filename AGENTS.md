# Thesis publication snapshot

先讀 README.md、docs/REPRODUCE_zh-TW.md、CONTRIBUTING.md、provenance/baseline.json。
研究文件使用繁體中文；protocol labels、code identifiers 與 manifest fields 維持英文。
此分支只維護現行論文程式；完整研究倉庫的根 canonical 文件由 integration lane 管理。

使用一任務一 worktree 與 `codex/` 分支。保留 source/profile/CS identity；
不搬動證據耦合路徑、不將舊比較組接成 Hχ⁺ 全生命週期、不加入未採用新機制。
只覆寫 publication/runtime.py allowlist 中的路徑，不覆寫資格、Verify、gate 或資源限制。
Production 邊界維持 fail closed。VerifyTicket 為 stateless；one-use 另外依賴 holder authentication
與 linearizable FGS consumption，不能由此 runtime 推得完整系統資格。

完成前跑 release.py test、release.py compare、git diff --check，分報 passed/failed/skipped。
禁止提交 *.f193assign、*.br1cs、*.f193r1cs、pickle、cache、checkpoint、resume、logs、
archive、artifact parts、真實 secret/RID/wallet。遵守 docs/ARTIFACT_POLICY.md。
正常 bounded commit；不 bypass hook、不 force push、不改 main/default、不推所有 branches。
