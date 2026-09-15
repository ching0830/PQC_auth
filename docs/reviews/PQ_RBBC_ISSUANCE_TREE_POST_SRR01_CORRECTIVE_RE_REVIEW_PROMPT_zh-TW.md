# PQ-RBBC issuance tree-post SRR-01 corrective re-review prompt

請在新的獨立、乾淨 worktree，唯讀審查呼叫者指定的 **完整 exact corrective commit
SHA**。Branch 應為 `codex/pq-rbbc-tree-post-srr01-corrective`，該 commit 的 parent 必須是
`ca6d4a43d7b2ebf728c660b4df0abaf526714544`。先記錄 commit、parent、tree SHA、worktree
狀態及所有修改檔 identity；不要以移動中的 branch tip 代替 exact SHA。本文件不內嵌自身
所在 commit SHA，提交後須由交接者另行提供。

這是 SRR-01 的獨立 AI-assisted technical re-review，不是 human cryptographic review、
approval、attestation、production freeze、resource reservation 或 execution authorization。
不得修改 repository、amend、merge、push，亦不得啟動 production、large replay 或 proving。

## 必讀與保護範圍

完整閱讀 `AGENTS.md` 及其指定 canonical 文件、`docs/ARTIFACT_POLICY.md`，以及：

- `src/pq_rbbc_issuance_tree_post_continuation_v1.py`
- `src/pq_rbbc_issuance_tree_post_restart_v1.py`
- 對應兩份 tests、manifests、portable evidence 與 artifact notes
- base commit 的上述檔案及本 corrective exact diff
- v2.38／v2.39 historical identity inventory

根 canonical ownership policy，本 lane 不回寫 root project status 文件；但 active
`docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md` 的 tree-post 段落必須與新 artifact notes、
manifests 一致，明確 supersede 舊的 full-chain wording，且不得更動任何 historical evidence
bytes。

## SRR-01 必查性質

1. 確認舊 contract 的 `receipt_chain_sha256` 四筆 digest 已從 active continuation schema、
   manifest 與 evidence 移除；active claim 必須是 **verified ordinal 2→3 two-entry suffix
   only**，且 `full_receipt_chain_verified=false`。Ordinal 0／1 raw 未攜帶時，不得以 digest
   shape、名稱或間接 dependency 宣稱已驗證。
2. 對 ordinal 2 與 3 的 raw 分別核對 fixed filename、byte bound、strict canonical JSON、
   closed schema、relation/profile/plan、invocation、ordinal、stage、rows、total rows、owner
   cursors、relocations、point binding、native prefix inventory 與 claim booleans；確認
   `SHA256(ordinal2.raw) == ordinal3.previous_receipt_sha256` 使用相同 captured raw。
3. 確認 fresh capture、restart input load 與 completed capture 都攜帶這兩份 snapshots；每個
   pathname 每一 capture batch 只 single-open、single-bounded-read，identity、parse、binding
   與 consumer 使用同一 immutable `Snapshot.raw`。後續 pathname 改變不得取代 captured raw。
4. 確認上述 validation 在 `_PostSink`、tree-post compute、publication lock／plan／inputs／
   result publication之前完成適用的 gate；非法 fresh input 不得建立 output。Resume 的非法
   published receipt 必須在 compute 及新增 result/journal publication 前拒絕。
5. 確認沒有以重複 stat、sleep、重讀 pathname、second-content comparison 或 advisory lock
   宣稱 hostile writer 已被排除。Trusted producer handoff、writer quiescence、owner/mode/ACL、
   既有 writable FD、mount namespace 與 filesystem durability 必須維持外部部署前提。

## 獨立 probes

不要只重跑作者 tests。將 probes 與 outputs 放到新的
`/tmp/pq-rbbc-tree-post-srr01-rereview-*`：

1. 從 base commit 重現：只變更原四筆 chain 的 index 0 或 1、重算 continuation digest，舊
   `_continuation_document` 仍可進入 compute；記錄這只是 root-cause reproduction，不在
   corrective checkout 執行 production。
2. 在 corrective commit 對 legacy 四筆欄位 index 0／1／2／3 各做 re-pinned mutation，
   必須 closed-schema fail closed；另對 captured ordinal 2／3 raws 做 re-pinned wrong
   ordinal/stage/invocation、broken 2→3 link、swap、gap、duplicate key 與 trailing bytes。
3. 對每個拒絕 case spy `_PostSink`／compute／publication，確認均未觸發，fresh output 不存在；
   resume case 確認既有 bytes 不被覆寫且無新 result/checkpoint。
4. 覆蓋 tree 0、tree 1、alternate fixture、fresh、resume、repeated resume 與
   `capture_completed_result`；capture 後替換 receipt pathname，確認 executor 仍使用舊 raw。
5. 用 read spy 列出每個 receipt pathname 的 open/read 次數及順序，分開說明 fresh source
   capture 與 restart publication capture 是不同的受驗證 batch，不得把兩者混稱單一 open。

## 驗證與交付

至少執行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_tree_post_continuation_v1 \
  tests.test_pq_rbbc_issuance_tree_post_restart_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

另執行 prohibited-artifact inventory，確認沒有 `*.f193assign`、`*.br1cs`、`*.f193r1cs`、
pickle、cache、checkpoint、resume、log、release archive 或 proving output 被提交。逐檔核對
v2.38／v2.39 identities 與 base commit 一致；確認 production/security/large-run claims
仍為 false。

交付繁體中文 `AI_TECHNICAL_RE_REVIEW_zh-TW.md`、machine-readable `findings.json`、獨立
probe 程式/results、commands/logs 與 SHA-256 inventory。每個 finding 列 priority、exact
commit/path/line、trigger、observed/expected、reproduction 與 claim impact；沒有 finding
也須列實際觀察、測試 passed/failed/errors/skipped、剩餘風險與未驗證範圍。
