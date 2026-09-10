# PQ-RBBC v2.43 reservation-binding checkpoint

日期：2026-09-11。Branch：`codex/pq-rbbc-v2-43-reservation-binding`。
基線：`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`。

本 checkpoint 補上 v2.42 recovery／provenance 通過 bounded AI technical re-review
之後缺少的 operator reservation contract。它建立 closed-world contract-review status、
approval、resource reservation 與 named independent human review schemas，並提供 single-snapshot、
canonical JSON、exact path／command／identity validator。它沒有建立真實 reservation、
human review 或 launch manifest，也沒有 production executor。

## 綁定對象

Resource reservation 必須逐 byte 綁定：

- reviewed implementation commit
  `d6d349020f8ef22e65115130c335ea6db7e337b4` 與 tree
  `1ce0af92a84aa3e5736e9f49929a37d42301f665`；
- integration baseline `6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`；
- v2.42 recovery、recovery I/O、provenance source，以及 recovery／provenance
  manifests 的 exact identities；
- Git 內 corrective re-review integration record；
- repository 外 `AI_TECHNICAL_RE_REVIEW_zh-TW.md`、`findings.json` 與
  `SHA256SUMS.txt` 的 exact bytes／SHA-256；
- 本 v2.43 contract source identity、production profile fingerprint、operator
  approval identity、reservation／batch IDs、UTC window、資源下限、trusted roots、
  candidate locations、external output 與完整 exact command／SHA-256。

`implementation_binding` 是 whole-object `const`，任何 commit、tree、source、manifest、
review 或 contract source identity 變更都需要新的 schema／checkpoint。Artifact root 與
review archive root 必須互不包含；兩者由 trusted caller 選定，candidate JSON 不能改選。

## External review identity 更正

建構合約時重新核對 operator archive 與原 reviewer output，發現 Git 內 v2.42 review
integration record 的 `findings.json` SHA-256 有人工轉錄錯字。原檔、archive 與
`SHA256SUMS.txt` 三者一致，正確 identity 是：

- 19,192 bytes；
- `a190e31fc0787064d6d1746a56c489776ea0ba26cc7171be738e063eef9b228d`。

本 branch 只更正該摘要的一個 digest；沒有改寫任何 raw review artifact。更正後摘要
仍為 3,882 bytes，SHA-256 為
`75fd61ed8fa1e3dd9d24dbabdc82fe19f7d178e4681a4c4e457e5c762783dcec`，並由 v2.43
`implementation_binding` 固定。

## 合約與 fail-closed 邊界

新增檔案：

- `src/pq_rbbc_cap_unified_tree_reservation_binding_v2_43.py`；
- `schemas/pq_rbbc_cap_unified_tree_contract_technical_review_status_v2_43.schema.json`；
- `schemas/pq_rbbc_cap_unified_tree_operator_approval_v2_43.schema.json`；
- `schemas/pq_rbbc_cap_unified_tree_resource_reservation_v2_43.schema.json`；
- `schemas/pq_rbbc_cap_unified_tree_independent_review_v2_43.schema.json`；
- `manifests/pq_rbbc_cap_unified_tree_reservation_binding_manifest_v2_43.json`；
- `tests/test_pq_rbbc_cap_unified_tree_reservation_binding_v2_43.py`。

Approval record 是 operator-controlled local accountability record，不宣稱 digital
signature 或第三方 authentication。Resource reservation 只表示指定時間窗與路徑上的
資源已保留。它必須綁定一份 tracked v2.43 contract technical-review status；該 status
另綁 exact reviewed commit／tree、contract source、manifest、四份 schemas 與三份
repository-external review artifacts。Status 不存在或任一 identity 不符時，builder 與
preflight 都拒絕，因此目前不能提前產生 real reservation。其 claim boundary 明定：

- `resources_reserved_for_prospective_prefreeze = true`；
- `authorizes_production_prefreeze = false`；
- named human review、launch manifest、large replay／proving、security claim 與
  `production_closed` 全部為 false。

Named human review schema 要求 `is_ai_only = false`、reviewer 與 operator／implementation
獨立，並綁定 exact reservation、approval、implementation binding 與 command digest。
即使該 review 未來通過，其 disposition 也只有
`approved_for_launch_candidate_authoring_only`，不直接授權 production。

`production-prefreeze` CLI 只驗證固定 location 並一律丟出
`ValidationError`；沒有 producer、stream materialization 或 scale qualification。
Prospective command 是 root-parameterized 的未執行 binding。Command、contract source
或 candidate locations 改變，必須建立新的 reservation。

## 驗證

Targeted v2.43 tests：22 passed、0 failures／errors／skips，0.150 秒。涵蓋：

- tracked schema／manifest／dependency 與 external raw review identities；
- approval、resource 與 named-human review 的 positive path；
- commit／tree／source／review digest mutations；
- root／output／candidate location／command mutations；
- 最低 CPU／memory／disk、exact int／bool、UTC ordering／active window；
- approval identity／subject、placeholder、unknown field、noncanonical JSON；
- AI-only reviewer 與 review subject／time mutation；
- artifact／review root separation；
- contract-review status 缺失、future time、contract／external identity mutation；
- production API 無條件 fail closed。

相依 targeted regression：125 passed、0 failures／errors／skips，24.032 秒。完整
repository regression：710 tests，其中 698 passed、12 個既有 optional skips、
0 failures／errors，731.489 秒。Path-free machine result 位於
`artifacts/metadata/cap_reservation_binding_v2_43/pq_rbbc_cap_reservation_binding_regression_results_v2_43.json`。
測試通過不等於具名獨立人員核准或 production／security closure。

## 下一個 gate

1. 對 exact v2.43 checkpoint commit 做新的唯讀 AI-assisted technical review。
2. 若沒有 blocking findings，整合一份只綁定該 exact commit／tree、四份 contracts 與
   external review delivery identities 的 technical-review status record。
3. Status validation 通過後，才由 operator 在 repository 外建立新的 approval record
   與 v2.42-bound resource reservation，使用 exclusive publication 並保存 identity。
4. 再交給真正具名且獨立的人員審查 exact reservation、approval、implementation 及
   command bindings。
5. 正式 human review 通過後，另建 launch-manifest authoring／preflight successor。

在上述 gates 完成前，不得建立 launch identity freeze、啟動 production-prefreeze、
large replay 或 proving；所有 production／security claims 維持 false。
