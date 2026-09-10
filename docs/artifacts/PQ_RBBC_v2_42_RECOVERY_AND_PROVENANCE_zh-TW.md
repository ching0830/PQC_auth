# PQ-RBBC v2.42 recovery 與 provenance checkpoint

日期：2026-09-10。Branch：`codex/pq-rbbc-v2-42-recovery-and-provenance`。
基線：`973deee5b5603ee47ceadabd870004e214c81a96`。獨立 worktree；只 commit，等待整合。

初始 `81374602b5c1e304f396f54ef6f2d5b9bf2f06e9` 依 Codex AI-assisted cryptographic review 的 CR-01／CR-02 修正 bounded streaming
的中斷恢復與規格來源歸屬。Production 核准條件仍未成立。原 review 不是具名獨立人員
attestation，本工程 checkpoint 也不替代該項要求。

## RR242-01／RR242-02 corrective commit

本次接續 `81374602` 的 AI technical re-review，只修正 RR242-01（P2：existing entry
缺少恢復 directory fsync）與 RR242-02（P3：外部 digest 晚於 bounded 重算）。新增
corrective commit，不 amend、merge 或 push；修正後 effective tree 仍待新的獨立唯讀重審。

原報告：`/tmp/pq-rbbc-v242-ai-rereview-Cdl2UHKZ/AI_TECHNICAL_RE_REVIEW_zh-TW.md`
（19,959 bytes，SHA-256 `ded8c9a7fcb45b87183b1d5add2093cb97c4ba358741ab343c149f29c39fd083`）；
machine findings：同目錄 `findings.json`（27,830 bytes，SHA-256
`46c5487ee1b18024c62c0040e28c226239c18a3ffe2508b86b555b88904e4b3c`）。原檔未改寫。

CR-02 provenance manifest、PDF verifier、既有 provenance tests 與 erratum 保持逐 byte
不變；不更換三份 PDF revisions、參數、sealed predecessors 或 v2.41 reservation。
Recovery manifest 與 source identities 已改變，因此本 corrective contract 要求新的
fresh output；`81374602` 的 checkpoint／qualification 保留為歷史，不原地改 hash 升格。

## Protocol 位置與版本過渡

變更位於 unified CAP tree materialization 的 execution／evidence 層，不改 ticket、
CAP 算法、statement／parent ABI 或 system lifecycle。V2.38 的 40-leaf／18-vector
fixtures 仍是唯一可執行輸入，輸出仍是 179 records、15 chunks。Production profile
的 layout plan 與 proof／relation blockers 保持原有邊界。

V2.38 source、tests、manifest、portable evidence、binary chunks 與其他歷史輸出均
不回寫。V2.42 使用新 runner、checkpoint format／filenames、manifest 與新 output。
**不對 v2.38 output 進行原地 migration／resume**；既有失敗窗口由歷史 probes 保留，
修正後的等價窗口在 v2.42 fresh output 上重現並恢復。

## 設計與檔案

| 檔案 | 改變及理由 |
| --- | --- |
| `src/pq_rbbc_cap_unified_tree_recovery_v2_42.py` | 對 exact bounded input snapshots 重建預期 chunks；驗證全部 journal／chunk prefix 與下一個 orphan；冪等 finalization；production API／CLI 一律拒絕。 |
| `src/pq_rbbc_recovery_io_v2_42.py` | Linux `O_TMPFILE`、file fsync、exclusive `linkat`、directory fsync；不留下有名稱的 staging file。Directory flock 只協調守規則的 writers，程序退出自動釋放。 |
| `src/pq_rbbc_cap_provenance_v2_42.py` | 2 MiB bounded PDF capture 與 exact revision／bytes／SHA-256 verifier；provenance identity 與 parse 使用同一 snapshot，無 network fallback。 |
| `manifests/pq_rbbc_cap_unified_tree_recovery_manifest_v2_42.json` | 固定 78 份 predecessor identities、successor transition、recovery grammar、blocked gates 與原 v2.41 rejected reservation identities。 |
| `manifests/pq_rbbc_cap_unified_tree_provenance_v2_42.json` | 固定三個 PDF revisions；明確區分 BAVC、generic TCitH、Blind-UOV CAP parameters／performance。 |
| `tests/test_pq_rbbc_cap_unified_tree_recovery_v2_42.py`、`tests/test_pq_rbbc_cap_provenance_v2_42.py` | 初始 38 項 tests 加本次 9 項 corrective tests，共 47 項；涵蓋 publication boundaries、process death、fsync retry、capture 順序與 strict parser。 |
| `docs/specs/PQ_RBBC_v2_42_PROVENANCE_ERRATUM_zh-TW.md` | 只新增 citation erratum，保留 sealed v2.33 spec。 |
| 新 portable metadata、checksums、release／roadmap／re-review prompt 與 current handoff | 保存可重現結果、歷史保留證據與後續 review gates。 |

Root canonical documents 屬 integration lane，本 branch 不編輯 `methodology.md`、
`experiments.md`、`RESEARCH_STATUS*`、`ARCHITECTURE*`、`ROADMAP*` 或 thesis outline。
本 note 保存該 lane 待整合的設計理由、命令、結果與 claim boundary。

## Recovery contract

每個 output 有兩個目錄：`chunks/` 與 `checkpoints/`。Journal 為
`0000-prefix-v2_42.json` 至 `0015-prefix-v2_42.json`，再新增
`complete-v2_42.json`。每份 prefix 都是 immutable publication，包含 exact input／
implementation／manifest identity、完整 chunk identity chain 及 previous checkpoint SHA。

Resume 必須提供 **latest durable checkpoint 的 externally trusted SHA-256**。工具的
`latest_checkpoint()` 是 inventory helper，不能將它觀察到的 digest 自動當成外部信任。
Digest 正確後仍須比對所有 prefix 的預期 canonical bytes；舊 prefix、錯誤 bool/int、
改動的 chain、未知欄位與非 canonical JSON 都會拒絕。

恢復順序如下：

1. 先驗證 tracked contracts。Resume 取得 output directory lock，並 pin 住 journal／
   chunks directories；單次 capture latest checkpoint，先比對 externally supplied
   SHA-256。錯誤／stale digest 在 bounded fixture read 與 `bounded_chunks` 前拒絕。
   `latest_checkpoint()` 仍只是 inventory helper，不能自動提供外部信任。
2. Digest 相符後才於明確可信 input root 單次擷取兩份 bounded fixtures，確認 frozen
   bytes／SHA-256 後才 decode，重建全部預期 chunks／documents。Historical fixture
   timing float 只在 exact allowlist 通過後使用 legacy parser；新 journal 仍用 strict
   integer-only parser。Fresh run 保持先驗證 inputs 再建立 output。
3. 驗證全部 journal 與已記錄 chunks、唯一下一個 orphan，以及 existing finals。
   Latest checkpoint 的 canonical parse／semantic checks 使用第 1 步同一份 captured
   raw，不重讀 pathname 替代；其他 prefixes 亦完整驗證。相符的 external digest 不會
   使 malformed／非 canonical／錯誤 chain／type／contract 成立。Latest namespace
   若在擷取後變動，也拒絕。
4. Existing state 全部驗證通過後，依相依順序同步 pinned／validated `chunks/`、
   `checkpoints/` 及 output directories，補足前次 link 後中斷或 fsync EIO 遺留的
   durability barriers。每次 fsync 前後均驗證 pinned directory 仍對應原 pathname；
   fsync 錯誤直接傳出，不能繼續 publication，也不能回傳已完成結果。
5. 採用 existing orphan 前再次 capture exact chunk，然後再次同步其 pinned chunks
   directory，成功後才發布 successor prefix。僅接受唯一 next ordinal 與 exact raw／
   SHA／stage／first item／count／decoded contents。新 chunk 仍採 exclusive publication，
   完整 file fsync、linkat、directory fsync 後才記錄 checkpoint。
6. `0015-prefix` 的 `complete=false` 可完成 complete／index／evidence。既有 prefix、
   complete、index、evidence 都必須通過原本 strict 驗證與 parent-directory barrier；
   只新增缺少的檔案。即使三份 finals 已齊，retry 仍需補足 barriers 才可成功，原檔
   bytes／inodes 不覆寫。Unknown、corrupted、missing、gapped、multiple orphan、links
   與 FIFO 仍 fail closed，不隔離、不修補、不 overwrite。

Checkpoint 的名稱、存在與 identity 不證明前次 directory fsync 已完成。外部 digest
綁定 latest captured bytes；本次採用前的 barriers 才補足可能中斷的同步步驟。

因此 chunk 已發布而 prefix 尚未提交，以及全部 chunks 已提交而 `complete=false`
的兩個 CR-01 窗口均能恢復。Complete 已提交但 index／evidence 尚缺也可補完。
第一份 prefix 尚未發布時沒有 resumable checkpoint identity；該 initialization failure
必須選用新 output。V2.42 不把沒有 trusted checkpoint 的 directory 當成可 resume state。

新 checkpoint journal 不覆寫 mutable checkpoint pointer，可避免 compare-then-replace
的覆寫競態。Publication 只在 Linux filesystem 支援 `O_TMPFILE`、procfs FD links 及
`linkat` 時成立；不支援即拒絕，沒有 truncate／rename overwrite fallback。檔案及目錄
均 fsync，但本次只驗證 process interruption、post-link fsync EIO 與 retry 順序，沒有做實體斷電、kernel crash、remount 或跨主機 filesystem 測試。

Output 必須是 caller 指定 trusted artifact root 的 direct child。Root 必須事先 provision，
不能位於任何 Git worktree，也不能由 candidate 內容選定。Trusted producer handoff、
writer quiescence、ACL、既有 writable FDs、mount namespace 與同帳號惡意 writer 仍是
部署前提；flock 和 metadata signals 不證明 filesystem 強不可變性。歷史 source 的
imported code 亦須來自可信 checkout；checkpoint source hashes 不會把不可信 Python
interpreter／被替換的已載入 module 自動變成可信執行環境。

## Corrective 順序測試

在 `tests/test_pq_rbbc_cap_unified_tree_recovery_v2_42.py` 新增 9 個 test methods；
以下 subcases 不另外加入 unittest test count：

- `test_orphan_link_fsync_eio_retry_requires_barrier_before_prefix`：first／last orphan
  的真實 linkat 後 directory fsync EIO；retry 連續 EIO 兩次均無新 publication；成功
  fsync 必須緊接於 successor prefix 前，保留原 bytes／inodes。
- `test_existing_prefix_and_complete_link_fsync_eio_retry_requires_barrier`：prefix
  0／1／15、complete 的相同窗口、失敗重試及成功恢復。
- `test_existing_index_and_evidence_link_fsync_eio_retry_requires_barrier`：index、
  evidence 的相同窗口；全部檔案齊全時也不能略過 barrier。
- `test_wrong_and_stale_digest_reject_before_fixture_read_or_recompute`：兩種 digest
  都在 fixture read／bounded_chunks 前拒絕。
- `test_latest_capture_is_locked_once_and_precedes_fixture_reads`：capture 在真實
  output lock 內，只讀一次；其後才兩次 input capture 與 bounded reconstruction。
- `test_matching_digest_cannot_rescue_bad_latest_snapshot_by_replacing_path`：正確
  digest 後仍拒絕 chain、type、canonical、UTF-8、duplicate key mutations；path 換回
  good bytes 不能挽救原 bad snapshot，且驗證失敗不執行 barriers／publication。
- `test_latest_valid_snapshot_is_not_reopened_for_semantic_validation`：後續使用原
  good captured raw，不能以未來 pathname bytes 替代；這不宣稱 writer immutability。
- `test_latest_namespace_change_after_capture_is_rejected`：不得改採另一個 latest。
- `test_directory_barrier_rejects_parent_substitution_before_and_after_fsync`：fsync
  前後的 directory substitution 都拒絕，不把另一個 directory 當成原 pinned parent。

## Findings 與測試對照

以下 tests 位於上述兩個 v2.42 modules；subtests 數量與 unittest test count 分開報告。

| Finding／邊界 | Tests 與證據 |
| --- | --- |
| CR-01，窗口 A | `test_cr01_window_a_exact_orphan_is_recomputed_and_adopted`；相同 inode／bytes 被採用，非覆寫 |
| CR-01，窗口 B | `test_cr01_window_b_all_chunks_complete_false_finalizes`；15-chunk incomplete prefix 冪等完成 |
| 所有提交點 | `test_every_durable_publication_boundary_recovers_identically`，33 個 boundaries；`test_real_process_death_at_both_reported_windows_releases_lock`，兩個 child 直接 `os._exit` |
| Corrupted／陌生 orphan | `test_corrupted_orphan_bytes_sha_ordinal_stage_fail_closed`（5 種 mutation）；`test_unknown_missing_gapped_and_multiple_orphans_rejected`；所有原有文件保留 |
| 重複 resume／finalization | `test_repeated_resume_is_byte_and_inode_idempotent`；`test_finalization_missing_index_or_evidence_is_idempotent`；`test_fresh_and_controlled_resume_have_identical_bytes` |
| Checkpoint／index mutation | `test_checkpoint_mutations_strict_types_and_chain`；`test_duplicate_noncanonical_utf8_and_trailing_checkpoint_rejected`；`test_corrupt_final_or_premature_complete_never_overwritten`；`test_existing_journal_gap_unknown_and_changed_old_prefix_rejected`；`test_missing_wrong_and_stale_external_digest_rejected` |
| TOCTOU／race | `test_corrupted_orphan_cannot_be_rescued_by_post_capture_replacement`；`test_orphan_mutation_between_inventory_and_adoption_rejected`；`test_unknown_chunk_introduced_before_finalization_rejected`；`test_competing_chunk_publication_never_overwritten` |
| I/O 與 concurrency | `test_chunk_symlink_dangling_hardlink_and_fifo_rejected`；`test_atomic_publication_rejects_existing_and_dangling_symlink`；`test_second_writer_is_rejected_by_output_lock`；8 processes 的 `test_real_parallel_exclusive_publish_has_one_winner`；`test_process_death_after_link_leaves_one_complete_file_no_staging`；`test_failure_before_publish_leaves_no_temporary_or_final` |
| CR-02，正確來源／參數 | `test_cr02_source_roles_revisions_and_tables_are_distinct`；`test_cap_row_matches_unchanged_implementation_parameters`；`test_three_exact_pdf_revisions_pass_byte_and_sha_verification` |
| CR-02，mutation／capture | `test_wrong_role_truncated_mutated_and_alternate_revision_rejected`；`test_erratum_mutation_cannot_relabel_a_source_or_table`；`test_pdf_symlink_size_limit_and_outside_root_rejected`；`test_pdf_validation_consumes_captured_bytes_after_path_mutation`；`test_provenance_hash_and_semantics_use_one_captured_document` |
| 歷史與 production 邊界 | `test_exact_input_identities_checked_before_parse_or_output`；`test_tracked_contract_and_predecessor_mutations_reject_before_output`；`test_v238_checkpoint_namespace_cannot_be_adopted_in_place`；`test_fresh_output_root_boundaries_and_overwrite_refusal`；`test_production_api_and_cli_reject_before_any_output`；`test_sealed_v233_and_historical_authorizations_are_not_rewritten` |

## 驗證與重現

環境及各項結果的 machine-readable 摘要見
[`pq_rbbc_cap_recovery_regression_results_v2_42.json`](../../artifacts/metadata/cap_recovery_v2_42/pq_rbbc_cap_recovery_regression_results_v2_42.json)。
本次 corrective stdout／stderr、fault-injection outputs、PDF snapshots、checkpoint journal
與 index 留在 `/tmp/pq-rbbc-v242-corrective-d5d17smp/`，沒有進 Git。初始
`81374602` 的 `/tmp/pq-rbbc-v242-validation/` 全部保留為歷史。

### Corrective effective tree 本次驗證

- Focused：47 passed、0 failures、0 errors、0 skipped，21.429 秒。
- Targeted：128 passed、0 failures、0 errors、0 skipped，36.181 秒。
- 完整 regression：676 passed、0 failures、0 errors、12 skipped（共 688 tests），
  735.905 秒。Skip reasons 逐項保存在 regression metadata；都是既有 optional external
  artifacts 未安裝，沒有將略過列為通過。
- 新的真實 bounded qualification：fresh、7-chunk stop/resume、repeated resume 結果
  相符，179 records／15 chunks／7,899 bytes；chunk identity stream SHA-256 為
  `b3ee7d5659380d629b1baece4dedf8aa3342beba16d0c5cae765e842161c5c11`。
  額外對最後一個 orphan、complete、index、evidence 四種 link 後 fsync EIO 窗口，
  分別觀察 retry 持續 EIO 時無新 publication，成功 fsync 後才繼續；原 bytes／inodes
  均保留。Wrong digest 的 fixture reads 與 bounded_chunks calls 都是 0。
- Unit fault tests 只 cache 已核對 exact identity 的 immutable bounded fixtures；上述
  額外 qualification 使用真實 bounded 重算，fault injection 僅介入 publication fsync
  與順序 tracing。這些都是實作者驗證，不是新的獨立 re-review 結論。
- 三份 PDF exact revisions 重新 capture／比對 bytes 與 SHA；CR-02 四份 tracked
  source／test／manifest／erratum 逐 byte 等同 `81374602`。78 pinned predecessors
  仍等同 baseline Git objects，歷史 review 與 v2.41 reservation／approval 不變。
- Qualification 腳本為 external `qualify.py`；執行與 stdout／stderr 由同目錄
  `run_validation.py qualification`、`qualification-run.json`、`qualification.log`
  保存。所有 unittest 的暫存 root 為該目錄的 `tmp/`，使用
  `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src`。原 15 組 legacy review probes 本次
  未重跑，其歷史結果保留在 `81374602` 的 metadata，不混入本次 counts。

本次只驗證 syscall／process fault 與 recovery 順序，未做實體斷電測試；沒有新增
reservation、launch candidate、identity freeze 或任何 production／security claim。

### 初始 81374602 歷史驗證（非本次測試結果）

- Targeted：119 passed、0 failures、0 errors、0 skips，32.738 秒。包括原 v2.39 的
  13 tests、v2.41 的 56 tests、v2.38 的 12 tests，以及新 v2.42 的 38 tests。
- 完整 suite：667 passed、0 failures、0 errors、12 skipped（共 679 tests），734.518 秒；skips 均為既有 optional external artifacts 未安裝。
- 原 cryptographic review 的 15 組 probes 以腳本副本執行，保留原 review 目錄。
  全部預期斷言通過；其中兩組仍在未改動的 **historical v2.38** 重現 CR-01，
  不可把這兩組稱為 v2.38 recovery 通過。新 runner 的對應恢復由上述測試證明。
- 額外 bounded qualification 沒有 mock：fresh、7-chunk stop/resume 與 repeated resume
  相符；chunk identity stream 與原 15 個 bounded chunk bytes 一致。這是新計算／核對的
  bounded 觀察，不沿用 legacy 18-tree production rows／digests。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_cap_unified_tree_streaming_prefreeze \
  tests.test_pq_rbbc_cap_unified_tree_streaming_prefreeze_evidence \
  tests.test_pq_rbbc_cap_unified_tree_launch_preflight \
  tests.test_pq_rbbc_cap_unified_tree_launch_preflight_evidence \
  tests.test_pq_rbbc_cap_unified_tree_launch_validation_v2_41 \
  tests.test_pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41 \
  tests.test_pq_rbbc_cap_unified_tree_recovery_v2_42 \
  tests.test_pq_rbbc_cap_provenance_v2_42 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

Private input root 已 provision exact v2.36／v2.37 fixtures，CLI qualification 用法：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python \
  src/pq_rbbc_cap_unified_tree_recovery_v2_42.py --phase bounded \
  --artifact-root /tmp/pq-rbbc-v242-corrective-d5d17smp \
  --input-root /tmp/pq-rbbc-v242-corrective-d5d17smp/inputs \
  --checkpoint-payload /tmp/pq-rbbc-v242-corrective-d5d17smp/inputs/pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json \
  --bounded-parent-vector /tmp/pq-rbbc-v242-corrective-d5d17smp/inputs/pq_rbbc_cap_unified_parent_input_bounded_vector_v2_37.json \
  --output /tmp/pq-rbbc-v242-corrective-d5d17smp/new-cli-run --fresh-output --stop-after-chunks 7
```

Resume 使用相同 inputs／output，將 `--fresh-output --stop-after-chunks 7` 換成
`--resume --expected-checkpoint-sha256 <externally-trusted-latest-digest>`。不要對已存在
output 重跑 fresh。歷史 inputs 的原目錄權限不符合新 trusted-root 規則，因此只將
exact 21,530-byte／3,062-byte fixtures 複製至私有 input root，沒有修改原目錄權限或檔案。

## 歷史證據與保守 gates

[`pq_rbbc_cap_recovery_preservation_v2_42.json`](../../artifacts/metadata/cap_recovery_v2_42/pq_rbbc_cap_recovery_preservation_v2_42.json)
記錄每份 baseline tracked file 的 identity 比對，以及以下兩份 external 原檔：

| 歷史文件 | Bytes | SHA-256 |
| --- | ---: | --- |
| `pq_rbbc_cap_unified_tree_resource_reservation_v2_41.json` | 1,708 | `523edb3e477f8d1c8d174c4054db7729b537ae35324e307e0946797b8040f732` |
| `pq_rbbc_operator_approval_record_v2_41.json` | 469 | `cc0a4e2955938c3642c0a46ddeb662adb09d3f96c3fd76ebe62ee0b1a6c1dca2` |

這些 identities 保存被拒流程的歷史，沒有證明 operator authentication，也不授權
v2.42 effective tree。V2.41 checksum 的 current-handoff entry 仍應以
`1a1d576:<path>` 歷史 Git object 核對；本 branch 不回寫該 inventory。

本次沒有建立 v2.42 reservation、具名 independent review、launch candidate 或正式
launch identity freeze。`safe_to_create_resource_reservation` 與
`safe_to_create_launch_manifest_candidate` 在此 checkpoint 都是 false。
Production-prefreeze、large replay、large proving、CAP／fork-security、QROM 與
production closure 全部維持 false。新 engineering evidence 仍待
[corrective AI technical re-review](../reviews/PQ_RBBC_v2_42_CORRECTIVE_AI_TECHNICAL_RE_REVIEW_PROMPT_zh-TW.md)。
AI review 通過也不能取代後續具名獨立人員核准。
