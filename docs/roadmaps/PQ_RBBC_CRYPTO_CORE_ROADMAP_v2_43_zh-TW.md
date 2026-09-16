# PQ-RBBC crypto-core roadmap v2.43

日期：2026-09-11。這是歷史 checkpoint snapshot；最新狀態以
`PQ_RBBC_CURRENT_HANDOFF_zh-TW.md` 為準。

## 已完成於本 checkpoint

- 定義 v2.42-bound contract-review status、operator approval、resource reservation 與 named-human review
  closed-world grammars。
- 固定 v2.42 reviewed commit／tree、來源、manifests、bounded AI review archive、
  v2.43 contract source 與 production profile。
- 實作 canonical snapshot validation、exact root／location／command、時間窗、資源下限、
  approval／reservation／review cross-binding 與 production fail-closed boundary。
- 更正 Git review 摘要的一個 SHA-256 轉錄錯字，不修改 raw review evidence。
- 初始 `1f75dc8` review 找到三項 P2；corrective 增加 trusted reviewed Git target／blob
  verification、required evidence failure 的 downstream gate closure，以及 reviewer／operator
  same-identifier rejection。Corrective exact-commit review 已通過，status-only successor
  已驗證，新的 real operator reservation 已建立。

## Topological order

1. Exact v2.43 corrective commit 唯讀 technical re-review：已完成。
2. 整合並驗證綁定 exact review delivery 的 contract technical-review status：已完成。
3. Operator 在 repository 外建立 approval record 與 resource reservation：已完成。
4. 具名且獨立的人員審查 exact identities 與 command／resource boundary：下一步。
5. 建立 launch-manifest authoring successor 並跑唯讀 preflight。
6. 另行完成 production runner scale qualification 與必要 proof／security gates；只有
   新的明確授權才可啟動 production-prefreeze。

目前只有第 4 步可開始。初始失敗 review 沒有被誤轉成 passed status；新的 corrective
status 與 operator reservation 已建立，但 human review、launch manifest、production／
large replay／proving 與 security claims 均未凍結。
