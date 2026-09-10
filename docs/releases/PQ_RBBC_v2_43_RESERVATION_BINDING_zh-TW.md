# PQ-RBBC v2.43 reservation-binding release checkpoint

日期：2026-09-11

## 內容

- 新增 v2.42-bound contract-review status、operator approval、resource reservation
  與 named independent human review closed-world schemas。
- 新增 read-only validator，固定受審 v2.42 commit／tree、source／manifest、AI review
  archive、本 contract source、trusted roots、batch／window／resources 與 exact command。
- 新增 bounded builders，供合約通過技術審查後建立 canonical approval／reservation
  documents；本 checkpoint 未呼叫 builders 產生真實操作檔案。
- 初始 `1f75dc8` exact review 的三項 P2 已在 corrective tree 處理：可信 reviewed
  commit／tree 的 Git object/blob binding、tracked evidence failure 的 downstream gate
  propagation，以及 same-identifier operator/reviewer rejection。Exact corrective 重審
  已通過，三項 findings 均關閉。
- 更正 v2.42 review integration record 中一個 `findings.json` SHA-256 轉錄錯字；raw
  external artifacts 未修改。
- Production phase 無條件 fail closed；沒有 producer、launch authorization、large
  replay／proving 或 security closure。

詳細設計、identities、測試與 gate 見
[artifact note](../artifacts/PQ_RBBC_v2_43_RESERVATION_BINDING_zh-TW.md)。

## 狀態

初始 exact-commit review 未通過；corrective re-review 已通過。Status-only commit
`53a0909` 已整合並驗證，真實 v2.42-bound operator reservation 已在 repository 外建立。
具名獨立人員 review 與 launch candidate 仍未建立，全部 production／security claims
維持 false。

Corrective focused：26 passed；相依 targeted：129 passed；完整 regression 共 714 tests，
702 passed、12 個既有 optional skips、0 failures／errors。Machine result 見
`artifacts/metadata/cap_reservation_binding_v2_43/`。
