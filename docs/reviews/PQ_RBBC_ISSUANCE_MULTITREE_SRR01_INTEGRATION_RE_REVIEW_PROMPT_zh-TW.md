# PQ-RBBC multitree scheduler＋SRR-01 integration 唯讀 re-review prompt

請在新的獨立、乾淨 worktree，唯讀審查呼叫者提供的 **完整 exact integration commit
SHA**。該 commit 的 parent 必須是已完成 final security re-review 的 scheduler commit：

```text
13a75945a075630c1dc366615856239972efa6c6
```

Integration branch 應為 `codex/pq-rbbc-multitree-srr01-integration`。另以 SRR-01 corrective
commit `64d0947dada2dafb5eb8636f09ea868366e8ef49` 作內容來源核對；不要以任何移動中的 branch
tip 代替 exact commits。本文件不內嵌自身所在 commit SHA，提交後由交接者另行提供。

這是 AI-assisted technical/security re-review，不是 human cryptographic review、operator
authorization、production profile freeze、large replay/proving authorization 或 production
closure。不得修改 repository、建立 commit、merge、push或啟動 production／large run。

## 必讀與 lineage 核對

完整閱讀 `AGENTS.md` 及其指定 canonical 文件、`docs/ARTIFACT_POLICY.md`，以及：

- exact integration commit、parent `13a75945...` 與兩者 diff；
- SRR-01 source commit `64d0947d...` 及其 tracked re-review prompt；
- continuation、one-tree restart、multitree scheduler 的 source、tests、manifests、portable
  evidence 與 artifact notes；
- `docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md`；
- v2.38／v2.39 historical identity inventory。

先記錄 exact commit、parent、tree SHA、worktree status 與全部修改檔 identities。確認
continuation／one-tree restart 的 source、tests、manifests、portable evidence 與 artifact-note
bytes 等於 `64d0947d...` 的 successor objects；scheduler 與 active handoff 則必須是本
integration 的新 successor，不得仍 pin `ca6d4a43...` 的舊 receipt-chain identities。

## SRR-01 integration 必查性質

1. Active continuation schema、manifests、portable evidence、artifact notes 與 handoff 只宣稱
   **verified ordinal 2→3 two-entry suffix**，`full_receipt_chain_verified=false`；ordinal
   0／1 raw 未攜帶時不得宣稱完整 chain。
2. Scheduler `implementation_version=1.2`；execution plan、per-tree input roots、result roots、
   cache identities、one-tree checkpoint chains與scheduler journal identities都已重建，且
   1.0／1.1 outputs未被錯誤沿用。
3. 每棵 invocation 的 ordinal 2、3 `Snapshot.raw` 必須核對 exact identity，並由
   continuation validator 驗證 fixed name、bound、strict canonical JSON、closed schema、
   relation/profile/plan、invocation、ordinal、stage、rows、cursor、relocation、point binding、
   claim booleans及2→3 link。
4. 上述 validation 必須在 scheduler取得output lock、發布execution plan、建立child output、
   `_PostSink`或tree-post compute之前完成；非法fresh suffix不得建立任何output。
5. Resume、repeated resume、exact orphan adoption與completed capture仍只能消費one-tree restart
   API內已驗證的七份input snapshots，不得繞過receipt validation或重開原candidate pathname。
6. Sequential／bounded-parallel outputs仍須byte-identical且按`[0,1]`發布；不得共用writable
   cache、resume state或其他tree observed `stream_bytes`。

## Scheduler既有final-security性質不得回歸

獨立重跑並檢查：

- completed-child dependency durability ordering的五層EIO窗口；
- parallel post-complete EIO不得提前發布parent checkpoint，retry精確採用兩個orphans；
- closed-world parent／child inventories；
- competing scheduler rejection；
- exact orphan adoption及repeated resume idempotence；
- production API在I/O前拒絕；
- global-tail、legacy18 production provider、production durable resume、formal proof、
  security／production closure及large-run claims全部保持false。

不得把先前對`13a75945...`的finding-free結論自動套到combined tree；本次結論必須綁定新的
exact integration commit。

## Independent probes

不要只重跑作者tests。至少建立新的`/tmp/pq-rbbc-multitree-srr01-rereview-*` probes：

1. Re-pin ordinal 2或3 raw及continuation dependency identity，確認scheduler在publication
   lock／compute前拒絕且output不存在；另覆蓋wrong ordinal/stage/invocation、broken link、
   swap/gap、duplicate/trailing。
2. 執行sequential與reverse-completion parallel fixture，逐檔比較scheduler／兩個child roots，
   確認byte-identical與固定`[0,1]`順序。
3. 檢查兩個child input directories各恰有七份closed-world artifacts，包含ordinal 2／3 raws；
   capture後pathname內容不得取代已捕捉snapshot。
4. 對completed schedule執行capture與repeated resume，spy relation compute為禁止呼叫，確認
   沒有recompute、overwrite或新checkpoint。
5. 重跑既有五層durability EIO及parallel orphan probes，記錄syscall／publication順序。

## Commands與交付

至少執行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_tree_post_continuation_v1 \
  tests.test_pq_rbbc_issuance_tree_post_restart_v1 \
  tests.test_pq_rbbc_issuance_multitree_restart_scheduler_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
git diff <exact-parent> <exact-integration-commit> --check
```

執行prohibited-artifact inventory，確認沒有assignment、BR1CS、pickle、cache、checkpoint、
resume state、log、archive、private spool/result或proving output被提交；逐檔核對19份v2.38／
v2.39 historical identities不變。

交付繁體中文`AI_TECHNICAL_SECURITY_RE_REVIEW_zh-TW.md`、machine-readable
`findings.json`、獨立probe程式/results、commands/results與SHA-256 inventory。每個finding列
priority、exact commit/path/line、trigger、observed/expected、reproduction與claim impact；若
finding-free，仍須列實際觀察、passed/failed/errors/skipped、剩餘風險及未驗證範圍。
