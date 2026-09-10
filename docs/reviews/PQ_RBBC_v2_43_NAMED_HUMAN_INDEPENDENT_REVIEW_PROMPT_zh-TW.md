# PQ-RBBC v2.43 named-human independent review instructions

本工作必須由真正具名、且獨立於 operator／implementation 的人員完成；另一個 Codex／
AI task 不能滿足此 gate。Reviewer identifier 不得為 `ching0830`，也不得只以文件中的
`independent_of_operator_and_implementation = true` 自我宣告取代實際治理判斷。

## Review target

- v2.42 implementation：`d6d349020f8ef22e65115130c335ea6db7e337b4`；
- v2.43 reservation contract：`073582c948f1386908568bad85d2ea71bcad06e3`；
- v2.43 contract tree：`984abc3e07092562fe01aad5b37d4ce4abcbd25c`；
- status-only integration：`53a09099485a33276cb6e6e83e122f09f853628d`；
- reservation ID：`PQRBBC-V242-RES-20260911-001`；
- launch batch：`PQRBBC-V242-PREFREEZE-20260911-001`。

External package：

```text
/home/ucheng0830/pq_rbbc_runtime/v2_43_launch/
  pq_rbbc_operator_approval_record_v2_42.json
  pq_rbbc_cap_unified_tree_resource_reservation_v2_43.json
```

必須核對的 exact identities：

- approval：679 bytes，SHA-256
  `d11c85814a72af4731aa73bc1175aa9b8764f7417bb72e16f2505acf3ee163c7`；
- reservation：6,164 bytes，SHA-256
  `687d855f4c60407c6c576e97de9cd36f157360d9a7e76aaee1a196847a5a5bc7`；
- tracked status：2,130 bytes，SHA-256
  `9b57373a8c1a8f7e94ab832b5f7a07c7c5c878147f4f48e5418299f0906ec6bd`。

## Reviewer 必須確認

1. Operator、reservation／batch IDs、UTC window、4 cores／16 GiB／80 GiB 與
   exclusive fresh output 是真實且可履行的 reservation，不是 draft template。
2. Approval、reservation、status、v2.42 implementation、v2.43 reviewed contract、
   external review roots、candidate locations 與 exact command／digest 的 binding 正確。
3. Trusted roots 互相分離；existing outputs 不會被覆寫；legacy evidence 維持 read-only。
4. Corrective AI technical review 只封閉 contract findings，並非本次 human approval。
5. `production_implementation_available = false`、`command_executable_now = false`，且
   approval／reservation 不授權 production-prefreeze、large replay、large proving 或
   security claim。
6. Reviewer 本人與 operator／implementation 獨立，並願意提供可追溯的 affiliation、
   attestation method 與 external reference。若無法證明，必須拒絕而非填寫 approved。

## 輸出

若發現任何 blocking finding，請輸出具名報告並停止；不要建立 approved candidate。

若全部通過，請提供：

- reviewer identifier／name；
- affiliation；
- canonical UTC completion time；
- attestation method：`signed-json`、`detached-signature` 或 `organization-record`；
- 可由 operator 保存及核對的 external attestation reference；
- 明確文字：只核准後續 launch-candidate authoring，不授權 production 或 security claim。

Operator 會依
`schemas/pq_rbbc_cap_unified_tree_independent_review_v2_43.schema.json` 將結果形成 canonical
candidate，固定寫入：

`/home/ucheng0830/pq_rbbc_runtime/v2_43_launch/pq_rbbc_cap_unified_tree_independent_review_v2_43.json`

寫入前必須重新核對 review subject 與 reservation snapshot；candidate 通過 direct
validator 與唯讀 preflight 後，才可開始 launch-manifest authoring successor。即使
human review 通過，`safe_to_start_production_prefreeze` 仍須維持 false。
