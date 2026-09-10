# PQ-RBBC v2.42 recovery 與 provenance checkpoint

日期：2026-09-10。Branch：`codex/pq-rbbc-v2-42-recovery-and-provenance`。
基線：`973deee5b5603ee47ceadabd870004e214c81a96`。獨立 worktree；只 commit，等待整合。

本次依 Codex AI-assisted cryptographic review 的 CR-01／CR-02 修正 bounded streaming
的中斷恢復與規格來源歸屬。Production 核准條件仍未成立。原 review 不是具名獨立人員
attestation，本工程 checkpoint 也不替代該項要求。

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
| `tests/test_pq_rbbc_cap_unified_tree_recovery_v2_42.py`、`tests/test_pq_rbbc_cap_provenance_v2_42.py` | 38 項新增 tests，含 33 個 publication boundaries、實際 process death、mutation、並行與 strict parser 回歸。 |
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

1. 在明確可信 input root 單次擷取兩份 bounded fixtures，確認 frozen bytes／SHA-256
   後才 decode，從它們重建全部預期 chunks。Historical checkpoint 含 timing float；
   該 legacy parse 僅允許在 exact fixture allowlist 命中後使用。新 recovery JSON 全部
   使用 v2.41 strict integer-only parser。
2. 驗證整份 durable journal 與所有已記錄 chunks。Sequential writer 最多留下一份
   checkpoint 尚未記錄的 **下一個 ordinal** chunk；只有 raw bytes、SHA-256、ordinal、
   stage、first item、record count 及 decoded contents 全部等於重算結果才可採用。
3. Unknown、corrupted、missing、gapped、multiple orphan、symlink、dangling symlink、
   hardlink、FIFO 皆 fail closed，不隔離、不修補、不覆寫。對既存 state 的初次驗證
   全數成立後才允許 publication；orphan 在採用前再擷取核對，以拒絕觀察到的干擾。
4. `0015-prefix` 的 `complete=false` 是合法的待 finalization 狀態。再次驗證完整 chunk
   inventory 後，只新增缺少的 complete checkpoint、index 與 evidence。若 final artifacts
   已存在，必須符合 exact expected bytes；重複 resume 的文件 bytes／inodes 均不變。

因此 chunk 已發布而 prefix 尚未提交，以及全部 chunks 已提交而 `complete=false`
的兩個 CR-01 窗口均能恢復。Complete 已提交但 index／evidence 尚缺也可補完。
第一份 prefix 尚未發布時沒有 resumable checkpoint identity；該 initialization failure
必須選用新 output。V2.42 不把沒有 trusted checkpoint 的 directory 當成可 resume state。

新 checkpoint journal 不覆寫 mutable checkpoint pointer，可避免 compare-then-replace
的覆寫競態。Publication 只在 Linux filesystem 支援 `O_TMPFILE`、procfs FD links 及
`linkat` 時成立；不支援即拒絕，沒有 truncate／rename overwrite fallback。檔案及目錄
均 fsync，但本次只驗證 process interruption，沒有做實體斷電或跨主機 filesystem 測試。

Output 必須是 caller 指定 trusted artifact root 的 direct child。Root 必須事先 provision，
不能位於任何 Git worktree，也不能由 candidate 內容選定。Trusted producer handoff、
writer quiescence、ACL、既有 writable FDs、mount namespace 與同帳號惡意 writer 仍是
部署前提；flock 和 metadata signals 不證明 filesystem 強不可變性。歷史 source 的
imported code 亦須來自可信 checkout；checkpoint source hashes 不會把不可信 Python
interpreter／被替換的已載入 module 自動變成可信執行環境。

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
完整 stdout／stderr、fault injection 的 private outputs、PDF snapshots、checkpoint journal
與 index 都留在 `/tmp/pq-rbbc-v242-validation/`，沒有進 Git。

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
  --artifact-root /tmp/pq-rbbc-v242-validation \
  --input-root /tmp/pq-rbbc-v242-validation/inputs \
  --checkpoint-payload /tmp/pq-rbbc-v242-validation/inputs/pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json \
  --bounded-parent-vector /tmp/pq-rbbc-v242-validation/inputs/pq_rbbc_cap_unified_parent_input_bounded_vector_v2_37.json \
  --output /tmp/pq-rbbc-v242-validation/new-cli-run --fresh-output --stop-after-chunks 7
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
[AI technical re-review](../reviews/PQ_RBBC_v2_42_AI_TECHNICAL_RE_REVIEW_PROMPT_zh-TW.md)。
AI review 通過也不能取代後續具名獨立人員核准。
