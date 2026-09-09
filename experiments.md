# 實驗紀錄（Experiments）

> 最後更新：2026-09-09
> 用途：保存可重現的實驗環境、命令、結果、artifact identity 與結論。不得只寫「測試通過」。文件權責見 `docs/DOCUMENTATION_POLICY_zh-TW.md`。

## 記錄規範

每次正式實驗建立一個 `EXP-YYYYMMDD-NN` 區塊，至少包含：

- 研究問題或假設；
- UTC／本地日期、Git commit 與工作樹狀態；
- OS、CPU、RAM、Python／compiler 與重要 dependency 版本；
- exact command、輸入與 random seed；
- 重複次數、warm-up 與 timeout；
- stdout／stderr 或外部結果路徑；
- 結果摘要、失敗案例、限制與是否支持原假設。

大型或可重建 binary 不進 Git。`*.br1cs`、`*.f193r1cs`、`*.f193assign`、pickle checkpoint、logs 與 release archives 的規則以 `docs/ARTIFACT_POLICY.md` 為準；Git 只保存 portable metadata、manifest 與 checksum inventory。

## 快速驗證命令

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

正式執行前記錄 commit；若工作樹不乾淨，需列出會影響結果的變更。部分 production replay tests 需要 repository 外部的 assignments，不能以缺少外部 artifact 推論程式失敗或 claim 已封閉。

## 已封存的歷史實驗證據

目前 local `main` 的 RBBC v2.26 已記錄：

- production composer cache recovery；
- global-tail regeneration 與 replay；
- planned tree positions 0–10 materialization 與各自 frozen-contract replay；
- tree 5–7 的 independently bound batch evidence；
- tree 8–10 的 path-free bounded recovery evidence。

詳細 identities 與 claim boundary 位於：

- `manifests/`
- `checksums/`
- `artifacts/metadata/`
- `docs/releases/`
- `docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md`

這些歷史 evidence 不代表 tree 11–17、72 relocations、完整 18-tree replay、parent join、PQ proof backend 或端到端衛星協定已完成。

## 本次 repository 基線檢查

### EXP-20260830-01 — Clone 狀態與文件基線

- 目的：確認 Codex 接手時 repository 狀態，並建立研究連續性文件。
- 日期／時區：2026-08-30，Asia/Taipei。
- branch：`main`，追蹤 `origin/main`。
- 起始工作樹：乾淨。
- 起始 HEAD：`c128519`（Merge pull request #11 from `ching0830/codex/traditional-chinese-docs`）。
- 檢查：存在雙語 README、ARCHITECTURE、RESEARCH_STATUS、ROADMAP，以及 RBBC source、tests、manifests、metadata 與 checksums。
- 命令：`PYTHONPATH=src python -m unittest discover -s tests -v`
- 測試結果：`Ran 250 tests in 575.871s`；`OK (skipped=12)`，exit code 0。
- skipped 原因：repository 外部的 v2.13–v2.25 assignments、execution caches 或 recovery artifacts 未安裝；所有 skip 皆由測試明確標示，未出現 failure 或 error。
- 結論：clone 內可執行的 baseline tests 全數通過；此結果不擴張既有 production claim boundary。

### EXP-20260830-02 — v2.6 assignment 分片接收

- 目的：整理使用者上傳的 `pq_rbbc_cap_shard_assignment_v2_6.f193assign` 分片，確認是否足以重組 canonical archive。
- 預期整檔：497,583,228 bytes；SHA-256 `6df38b0cadc2390ea953511ed20c1c22668f85f63a0519965f2d5a78b44d0095`。
- 已收到：`part-00`～`part-04`、`part-06`～`part-11`，共 11 片。
- 大小：`part-00`～`part-10` 的已收到分片各 45,000,000 bytes；`part-11` 為 2,583,228 bytes。
- 缺少：`part-05`（預期 45,000,000 bytes）。
- 處理：已收到分片移至 Git 忽略的 `external_artifacts/pq_rbbc_cap_shard_assignment_v2_6/parts/`；個別 SHA-256 保存於同目錄的本機 `SHA256SUMS.received.txt`。
- 補件：`part-05` 後續收到，大小 45,000,000 bytes，SHA-256 `b8b2e9cfdabcfbc18d4d7a409d31dced54d8bae5bae8416fae9bc342d1e14e10`。
- 重組結果：按 `part-00`～`part-11` 重組後為 497,583,228 bytes；SHA-256 `6df38b0cadc2390ea953511ed20c1c22668f85f63a0519965f2d5a78b44d0095`，符合 frozen manifest。
- Reader 驗證：archive magic／profile／size、19,903,324 wires、497,583,100-byte body、body SHA-256 `e16ca6a9228f9f13901d0e0228751010fa25889ed02a7291aaceebe69590843a` 與 row-stream SHA-256 `2cfc3641a94635af35dfa5494c61e74a416ef2fb446975cd417891d244943dfc` 全部通過。
- 結論：canonical archive identity 與格式已驗證；本次未重跑歷史上的 26,126,283-row relation replay，因此不擴張 production claim boundary。

### EXP-20260830-03 — One-time ticket reference state model

- 研究問題／假設：v0.1 的 canonical framing、ticket-use identity 與 `UNSEEN → RESERVED → CONSUMED` semantics，能否以最小 process-local reference model 表達並接受 deterministic、mutation、retry、collision 與 concurrency tests。
- 日期與時區：2026-08-30，Asia/Taipei。
- Git branch／基線：`codex/system-vertical-slice`，基線 `853a239`；測試時含尚未 commit 的 `src/pq_sat_auth/`、`tests/system/` 與本次文件更新。
- 環境：Linux 6.8.0-138-generic x86_64；AMD Ryzen 5 7600X（6 cores／12 logical CPUs）；30 GiB RAM；Python 3.12.9。
- 實作：strict frame／opaque parser、`use_key` derivation、immutable identity，以及加鎖的 `InMemoryLinearizableReplayStore`。Store 明確標記 `production_ready = False`，沒有 durability 或跨程序／跨 FGS consistency。
- focused command：`PYTHONPATH=src python -m unittest discover -s tests/system -v`
- focused 結果：`Ran 16 tests in 0.004s`；`OK`，exit code 0。
- full regression command：`PYTHONPATH=src python -m unittest discover -s tests -v`
- full regression 結果：`Ran 266 tests in 586.769s`；`OK (skipped=12)`，exit code 0。
- concurrency coverage：24 個不同 attempt 並行 reserve 僅一個新 winner；24 個相同 attempt retry 產生一個新 reservation 與 23 個 idempotent results。
- skipped 原因：與基線相同，為 repository 外部的 v2.13–v2.25 assignments、execution caches 或 recovery artifacts 未安裝；無 failure 或 error。
- 結論：支持局部 framing、identity 與 process-local state semantics 已 Implemented／Tested；不支持 durable／distributed replay、holder authentication、PQ AKE、完整 Access object、proof closure 或 production closure 宣稱。

### EXP-20260831-01 — Canonical access objects 與 transcript identities

- 研究問題／假設：能否在不選定 production holder authenticator／PQ AKE 的前提下，建立唯一的 ServingContext、AccessInit／Challenge／Finish／Accept bytes，並讓 transcript、attempt 與 response identities 對跨 object mutation fail closed。
- 日期與時區：2026-08-31，Asia/Taipei。
- Git branch／基線：`codex/system-vertical-slice`，基線 `8d84725`；測試時含尚未 commit 的 `src/pq_sat_auth/access.py`、新增 tests 與本次狀態文件更新。
- 環境：Linux 6.8.0-138-generic x86_64；AMD Ryzen 5 7600X（6 cores／12 logical CPUs）；30 GiB RAM；Python 3.12.9。
- 實作：168-byte draft `ServingContextV1`、四個 framed access object codecs、private-use `suite_id=0xffff` test-only limits、domain-separated init／challenge／transcript／attempt／accept digests，以及 cross-object binding checks。
- focused command：`PYTHONPATH=src python -m unittest discover -s tests/system -v`
- focused 結果：`Ran 29 tests in 0.008s`；`OK`，exit code 0。其中 13 項為新增 access object／binding tests，原有 16 項 framing／replay tests 亦通過。
- full regression command：`PYTHONPATH=src python -m unittest discover -s tests -v`
- full regression 結果：`Ran 279 tests in 661.962s`；`OK (skipped=12)`，exit code 0。
- frozen vectors：ServingContext digest、init／challenge digests、transcript digest、attempt ID、accept digest，以及四種 object encoded lengths 均在 tests 中固定。
- negative coverage：wrong frame type、unknown suite、suite-specific maximum、opaque truncation、trailing field、ServingContext alternate length、cross-object suite／context／nonce／cookie mismatch，以及 ticket／key-share mutation。
- skipped 原因：與基線相同，為 repository 外部的 v2.13–v2.25 assignments、execution caches 或 recovery artifacts 未安裝；無 failure 或 error。
- 結論：支持 draft byte-level access boundary 與 transcript identities 已 Implemented／Tested；`0xffff` 不是 production suite，且結果不支持 holder authentication、PQ AKE、UE wallet、durable／distributed replay、G1 freeze、proof closure 或 production closure 宣稱。

### EXP-20260902-01 — A／B v2.26 integration regression

- 研究問題／假設：local `main` 的 PQ-RBBC v2.26 tree 8–10 bounded recovery，能否與 A 的 one-time access codecs／replay model 共存，且 portable evidence、保守 claim boundary 與完整既有 regression 均維持一致。
- 日期與時區：2026-09-02，Asia/Taipei。
- Git branch／基線：`codex/system-vertical-slice`；local `main` `b9c09f1` 合併後的 A checkpoint `7cca274`，測試時含尚未 commit 的 root status 與 handoff 更新。
- 環境：Linux 6.8.0-138-generic x86_64；AMD Ryzen 5 7600X（6 cores／12 logical CPUs）；30 GiB RAM；Python 3.12.9。
- v2.26 bounded evidence：`artifacts/metadata/tree8_10_bounded_recovery_v2_26/pq_rbbc_cap_tree8_10_bounded_recovery_evidence_v2_26.json`，SHA-256 `9a8ad3b2b5af242ef6ee6b33d99035505c1b8a5764d84766ce6d44f9cd00895f`。
- targeted command：`PYTHONPATH=src python -m unittest -v tests.system.test_pq_sat_auth_access tests.system.test_pq_sat_auth_framing tests.system.test_pq_sat_auth_replay tests.test_pq_rbbc_cap_global_tail_fresh_recovery tests.test_pq_rbbc_cap_tree5_7_fresh_recovery tests.test_pq_rbbc_cap_tree8_10_preflight tests.test_pq_rbbc_cap_tree8_frozen_replay tests.test_pq_rbbc_cap_tree9_frozen_replay tests.test_pq_rbbc_cap_tree10_frozen_replay`
- targeted 結果：`Ran 45 tests in 0.011s`；`OK`，exit code 0。
- additional validators：frozen tree 8–10 preflight manifest accepted；由三份 external frozen manifests 重建的 portable evidence bytes 與 tracked evidence 完全相同，SHA-256 同為 `9a8ad3…895f`；`compileall` 通過。
- full regression command：`PYTHONPATH=src python -m unittest discover -s tests -v`
- full regression 結果：`Ran 295 tests in 575.086s`；`OK (skipped=12)`，exit code 0。
- skipped 原因：既有 optional v2.13–v2.25 external assignments、execution caches 或 recovery artifacts 未安裝；無新增 skip、failure 或 error。
- 結論：支持 A system reference 與 B v2.26 bounded evidence 在目前 branch 上整合相容，且 planned trees 0–10 可維持 Evidence-sealed 宣稱；不支持 tree 11–17、72 relocations、完整 18-tree replay、parent join、holder authentication、PQ AKE、proof closure 或 production closure 宣稱。

### EXP-20260909-01 — PQ-RBBC v2.41 launch validation 整合驗證

- 研究問題／假設：v2.41 hardening 與 snapshot-contract corrective effective tree 能否在
  不改寫 v2.38/v2.39 historical identities、且不提升 production/security claims 的前提
  下，通過獨立技術重審與 local `main` regression。
- 日期與時區：2026-09-09，Asia/Taipei。
- Git commit／branch：code effective tree `1a1d576ef3868a1c997063db80171c9f2cb4f5f8`
  （直接包含 `1b89ebea12110a655dc1dc6abb5a00d4bd38a338`，base `3885b01`）；
  於乾淨 integration worktree fast-forward 至 local `main` 後執行。
- 主要契約：single-open／single bounded-read；identity、strict parse、binding 與
  validation 只使用同一 immutable `Snapshot.raw`。Metadata 只提供 best-effort signal，
  不證明 filesystem 強不可變性。
- local targeted command：
  `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src TMPDIR=<private-0700-tmp> python -m unittest tests.test_pq_rbbc_cap_unified_tree_launch_preflight tests.test_pq_rbbc_cap_unified_tree_launch_preflight_evidence tests.test_pq_rbbc_cap_unified_tree_launch_validation_v2_41 tests.test_pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41 -v`
- local targeted 結果：code merge 後 `Ran 69 tests in 2.096s`；integration docs 更新後
  再跑為 `Ran 69 tests in 2.279s`。兩次均69 passed、0 failed/errors/skips，exit 0。
- local full command：
  `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src TMPDIR=<private-0700-tmp> python -m unittest discover -s tests -v`
- local full 結果：`Ran 641 tests in 717.047s`；629 passed、12 skipped、0 failures/errors，
  exit 0。Skips 均為既有 optional v2.13–v2.25 external artifacts 未安裝。
- 獨立重審：69 targeted、629 full-suite passed 加12既有skips、17/17八項probe groups、
  4/4 corrective probes及17/17額外cases；新 findings 為空。完整暫存報告在審查時為
  23,637 bytes、SHA-256
  `34ca21f07a1adb150692712b4d2227bb0d0cb874fdda6e2d5f951e59066250de`；持久摘要見
  `docs/reviews/PQ_RBBC_v2_41_AI_TECHNICAL_RE_REVIEW_RESULT_zh-TW.md`。
- Artifact 核對：19份v2.38/v2.39 historical identities、三版inventories與negative
  portable rebuild均相符。Integration 更新current handoff後，v2.41 checksum的該一entry
  依`1a1d576:<path>`歷史Git object核對（24,839 bytes、SHA-256 `689f3306…cf`），其餘
  15項直接符合current tree；未回寫歷史inventory，也未執行production、large replay或proving。
- 結論：支持v2.41 launch validation為Implemented／Tested且negative portable evidence
  可重建；不支持external human review、真實reservation、identity freeze、filesystem
  強不可變性、CAP/fork proof closure或Production-closed宣稱。
- 下一步：provision可信external artifact root，取得真實operator reservation及external
  human independent review，之後才可產生launch manifest candidate並跑唯讀preflight。

## 實驗模板

```markdown
### EXP-YYYYMMDD-NN — 短標題

- 研究問題／假設：
- 日期與時區：
- Git commit／branch／dirty state：
- 環境：
- 輸入與 artifact SHA-256：
- 命令：
- seed／重複次數／timeout：
- 原始輸出位置：
- 結果：
- 結論：
- 限制與下一步：
```
