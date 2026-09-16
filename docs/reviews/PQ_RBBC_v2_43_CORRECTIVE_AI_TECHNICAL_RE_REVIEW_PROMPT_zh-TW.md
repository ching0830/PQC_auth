# PQ-RBBC v2.43 corrective exact-commit 唯讀重審 prompt

請在新的獨立乾淨 Git worktree，對 branch
`codex/pq-rbbc-v2-43-reservation-binding` 的 exact tip commit 進行唯讀 AI-assisted
corrective technical re-review。受審 tip 的 direct parent 必須是
`1f75dc85e9494ccb340c96e6cdc51ac61a600536`；開始時記錄：

```bash
git rev-parse HEAD
git rev-parse HEAD^
git rev-parse HEAD^{tree}
git status --short
```

若 parent 不符、worktree 不乾淨、branch 不存在或 target 不是 branch tip，停止並回報。
不得修改 repository、commit、merge 或 push。

## 範圍與停止條件

本次只判定 `TR243-01`、`TR243-02`、`TR243-03` 是否關閉，以及 corrective diff
是否造成新 regression。不得建立 passed technical-review status、真實 approval／resource
reservation、human review 或 launch manifest；不得啟動 production、large replay 或
proving。任何 blocking finding 代表重審不通過，全部 production／security claims 維持
false。

先讀 `AGENTS.md`、`docs/ARTIFACT_POLICY.md`、
`docs/reviews/PQ_RBBC_v2_43_INITIAL_AI_TECHNICAL_REVIEW_RESULT_zh-TW.md`、
`docs/artifacts/PQ_RBBC_v2_43_RESERVATION_BINDING_zh-TW.md`，並比較 exact parent-to-tip
diff。

## 必驗事項

1. `TR243-01`：trusted caller 必須提供 exact expected reviewed commit／tree；status
   candidate 不能自行選 target。驗證 commit 與 tree object 存在、commit 實際指向該
   tree、integration baseline ancestry，以及受審 commit 內 contract source、manifest、
   四份 schemas 的 exact bytes／identities。測試 nonexistent commit、錯配 tree、其他
   commit、blob drift，以及只新增 status 的 successor commit；不得硬綁當前 HEAD。
2. `TR243-02`：任一 tracked schema／manifest／七份 dependency／三份 v2.42 external
   archive identity 失敗時，`v2_43_contract_technical_review_acceptable`、resource freeze、
   submit-human-review、human-review freeze 與 launch-authoring gates 全部必須 false，並
   保留具名 failure diagnostics。
3. `TR243-03`：direct validator 與 end-to-end preflight 都必須拒絕 reviewer identifier
   完全等於 operator／approval identifier；同時確認這只排除已知自審，不能把文件內
   assertion 當作外部 authenticity／independence 的完整證明。
4. 確認 resource schema、exact command 與 SHA-256 都綁定 trusted expected reviewed
   commit／tree；任一 mutation 或 CLI 遺漏都 fail closed。
5. 重跑原審查的重要 mutation／path／time／TOCTOU probes，確認 single-snapshot、root
   separation、canonical JSON、whole-object implementation binding 及 unconditional
   production rejection 沒有 regression。
6. 重新 capture `/home/ucheng0830/pq_rbbc_runtime/v2_42_review` 的三份 v2.42 review
   artifacts，核對既有 frozen identities；另核對本次 negative review archive
   `/home/ucheng0830/pq_rbbc_runtime/v2_43_review_1f75dc8` 與 tracked 摘要，但不得把 raw
   artifacts 寫進 repository。
7. 確認 contract-review status pathname 仍不存在／未 tracked；real reservation、named
   human review、launch candidate 與 production outputs 均未建立。

## 測試與交付

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_cap_unified_tree_reservation_binding_v2_43 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
git status --short
```

分別報告 total／passed／failures／errors／skipped 與 skip reasons。另檢查 prohibited
artifacts、historical identities、schemas／manifest canonical bytes。輸出繁體中文報告、
machine-readable findings 與 SHA-256 inventory 到新的 repository-external directory。

結論必須明確區分：corrective technical re-review 是否通過、是否可在下一個
status-only commit 整合 passed status、named independent human approval（本次不是）、
以及 launch／production／security closure（全部仍為 false）。
