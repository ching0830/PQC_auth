# PQ-RBBC v2.43 real operator resource reservation

日期：2026-09-11。Contract version：2.43。Implementation target：2.42。

## 結果

通過的 v2.43 contract-review status 整合並驗證後，operator `ching0830` 在
repository 外建立新的 approval 與 resource reservation。Trusted artifact root：

`/home/ucheng0830/pq_rbbc_runtime/v2_43_launch`

該 directory mode 為 `0700`，兩份正式 candidate 檔案 mode 為 `0400`。這是 owner-controlled
local record；沒有 digital signature 或第三方身份認證。

| Artifact | bytes | SHA-256 |
|---|---:|---|
| `pq_rbbc_operator_approval_record_v2_42.json` | 679 | `d11c85814a72af4731aa73bc1175aa9b8764f7417bb72e16f2505acf3ee163c7` |
| `pq_rbbc_cap_unified_tree_resource_reservation_v2_43.json` | 6,164 | `687d855f4c60407c6c576e97de9cd36f157360d9a7e76aaee1a196847a5a5bc7` |

首次「尚無 human review」的唯讀 preflight report 為 2,193 bytes、SHA-256
`baccb2816a2d6d53aa30d7cc6ffa1d30a01c87ce59249b005979e692e108e014`。為保留
exclusive final-preflight pathname，它已移至：

`/home/ucheng0830/pq_rbbc_runtime/v2_43_launch_pre_human_preflight/pq_rbbc_cap_unified_tree_reservation_binding_report_v2_43.json`

正式 artifact root 內的 report pathname 因此維持不存在，供 human review 到齊後一次性
發布 final read-only preflight report。

Reservation ID：`PQRBBC-V242-RES-20260911-001`。Launch batch ID：
`PQRBBC-V242-PREFREEZE-20260911-001`。有效時間為
`2026-09-10T18:22:24Z` 至 `2026-09-17T18:22:24Z`，共 604,800 秒。
保留資源為 4 CPU cores、16 GiB available memory、80 GiB free disk，且 output 必須
exclusive、fresh、不可 overwrite。

## Exact binding

Reservation 綁定：

- v2.42 implementation commit `d6d349020f8ef22e65115130c335ea6db7e337b4` 與其
  tracked recovery／provenance dependencies；
- v2.43 reviewed contract commit `073582c948f1386908568bad85d2ea71bcad06e3`、tree
  `984abc3e07092562fe01aad5b37d4ce4abcbd25c`；
- status identity `9b57373a8c1a8f7e94ab832b5f7a07c7c5c878147f4f48e5418299f0906ec6bd`；
- v2.42 review root、v2.43 contract-review root、artifact root、candidate locations、
  production output location與完整 prospective command digest
  `8aa1580c261fd3895336be0219940c310f1ad4455c42ad3568ab1e9cdbed18e8`。

## Read-only preflight

建立後的唯讀 preflight 得到：

- `tracked_contracts.verified = true`；
- `v2_43_contract_technical_review_acceptable = true`；
- `resource_reservation_acceptable_for_freeze = true`；
- `safe_to_submit_named_independent_human_review = true`；
- `independent_review_acceptable_for_freeze = false`；
- `safe_to_author_launch_manifest_candidate = false`；
- `safe_to_start_production_prefreeze = false`。

因此下一步只有「將 exact reservation package 交給真正具名、且 identifier 不同於
operator 的獨立人員審查」。Reservation 尚未被 launch manifest 凍結；不得先建立
launch candidate 或執行 prospective production command。

Status-integrated regression：focused 26 passed、targeted 129 passed；完整 baseline
714 tests，702 passed、12 個既有 optional skips、0 failures／errors，813.660 秒。
Path-free machine evidence 位於
`artifacts/metadata/cap_reservation_binding_v2_43/pq_rbbc_cap_reservation_status_integration_v2_43.json`。
