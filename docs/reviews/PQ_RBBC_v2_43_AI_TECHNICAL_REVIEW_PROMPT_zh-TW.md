# PQ-RBBC v2.43 reservation-binding exact-commit 唯讀技術審查 prompt

請在新的獨立乾淨 Git worktree，對 branch
`codex/pq-rbbc-v2-43-reservation-binding` 的 exact tip commit 進行唯讀 AI-assisted
technical review。開始時先執行 `git rev-parse HEAD`、`git rev-parse HEAD^{tree}`、
`git status --short`，在報告中記錄 exact commit／tree；若 branch 不存在、worktree
不乾淨或 target 不是該 branch tip，停止並回報，不要猜測。

## 目的與非目的

本次只審查 v2.43 是否正確建立「可驗證但尚未實際填寫」的 v2.42 operator
reservation／named-human-review binding contract。不得建立真實 approval、reservation、
human review 或 launch manifest；不得啟動 production、large replay 或 proving。
所有 production／security claims 必須維持 false。

## 必讀與受審檔案

先讀 `AGENTS.md`、`docs/ARTIFACT_POLICY.md`、
`docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md`、
`docs/artifacts/PQ_RBBC_v2_43_RESERVATION_BINDING_zh-TW.md`，再審查：

- `src/pq_rbbc_cap_unified_tree_reservation_binding_v2_43.py`；
- 四份 `schemas/*_v2_43.schema.json`；
- `manifests/pq_rbbc_cap_unified_tree_reservation_binding_manifest_v2_43.json`；
- `tests/test_pq_rbbc_cap_unified_tree_reservation_binding_v2_43.py`；
- v2.42 review integration record 的單一 digest correction。

## 必驗事項

1. 獨立重算 reviewed implementation commit／tree、七份 tracked dependency identities、
   v2.43 contract source identity、三份 schema identities 與 manifest canonical bytes。
2. 從 operator-controlled archive
   `/home/ucheng0830/pq_rbbc_runtime/v2_42_review` 重新 capture 三份 raw review artifacts；
   確認 `findings.json` 為 19,192 bytes、SHA-256
   `a190e31fc0787064d6d1746a56c489776ea0ba26cc7171be738e063eef9b228d`，且 archive
   `SHA256SUMS.txt` 內的 entry 相符。不要接受舊摘要中的錯誤轉錄值。
3. 驗證 `implementation_binding` 是 closed whole-object binding；mutation 任一 commit、
   tree、source、manifest、review artifact 或 contract source identity 均拒絕。
4. 驗證 candidate JSON 只接受 canonical strict integer-only encoding、無 unknown fields、
   placeholders、symlinks、hardlinks、FIFO、trailing bytes 或 alternate locations。
5. 驗證 artifact／review roots 由 trusted caller 提供且互不包含；resource 不能改選
   root、output、approval、candidate locations、command 或 command SHA-256。
6. 驗證 operator approval identity／reservation／batch／operator／time cross-binding；
   `approved <= start < end`、duration exact、trusted `now` 位於 active window，最低資源
   為 4 cores、16 GiB memory、80 GiB free disk，且 bool／float 不得冒充 integer。
7. 驗證 external AI review 明確不是 named-human approval。正式 review 必須
   `is_ai_only = false`、與 operator／implementation 獨立，並綁定 exact reservation、
   approval、implementation binding 與 command digest；其 disposition 只能允許後續
   launch-candidate authoring，不能授權 production。
8. 確認 prospective exact command 雖被 reservation 綁定，但
   `production_implementation_available = false`、`command_executable_now = false`，而
   API／CLI production path 不論 candidates 如何都 fail closed 且不產生 output。
9. 獨立增加 mutation／path／time／TOCTOU probes；特別檢查 schema whole-object const、
   dynamic contract source identity、single-snapshot consumption、external archive
   substitution，以及 preflight booleans 沒有因只有 AI review 而升格。
10. 確認目前 tracked contract-review status 尚不存在，因此 real reservation builder
   fail closed；review 通過後應可只新增 status record，status 必須綁定本次 exact
   commit／tree、contract source、manifest、四份 schemas 與 external review artifacts。
11. 重跑 targeted test 與完整 baseline：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_cap_unified_tree_reservation_binding_v2_43 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

分開報告 total／passed／failures／errors／skipped 與每個 skip reason。執行
`git diff --check`、`git status --short`，確認沒有 prohibited artifacts、logs、cache、
assignments、BR1CS、pickle 或外部 review 原文進入 Git。

## Findings 與交付

每項 finding 提供 ID、P0–P3、exact path／line、trigger、observed／expected、可重現
步驟與 claim impact。若沒有 finding，也要提供上述每一項的獨立 observation，不能只
引用作者測試。輸出繁體中文報告、machine-readable findings 與 SHA-256 inventory 至
新的 repository-external directory；不得修改 repository、commit、merge 或 push。

結論必須明確區分：

- contract technical review 是否通過；
- 是否可整合 contract-review status，以及整合後才可建立 real operator reservation；
- named independent human approval（本次不得宣稱）；
- launch／production／security closure（全部仍為 false）。
