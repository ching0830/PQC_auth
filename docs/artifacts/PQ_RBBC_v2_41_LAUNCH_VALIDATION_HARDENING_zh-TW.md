# PQ-RBBC v2.41 launch validation hardening

日期：2026-09-08。Task branch：`codex/pq-rbbc-v2-41-launch-validation-hardening`。
基線：local `main@3885b01d2b7bccd8ae0cb5e465c4b63aa48d4442`；未 fetch。
本 checkpoint 等待整合，不代表已發布或已 merge 至 main。

## Protocol 位置與交付範圍

本次修正 unified-tree production launch 的文件驗證控制面。它不改 CAP relation、
ticket bytes、Trace KDF、system lifecycle 或 `pq_sat_auth`。輸入是 operator reservation、
independent review 與 launch candidate；輸出是唯讀驗證報告，或在前置條件成立時建立
一份尚未 freeze 的 candidate。沒有 production executor。

依 AI-assisted v2.39 技術預審及 `probe-results.json` 的八項 findings，建立獨立 v2.41
successor。V2.39 的 source、tests、schemas、manifest、portable evidence、artifact note
與 checksum inventory 均保留 exact historical bytes。舊 validator 僅供歷史重建；
它回報的 `safe_to_freeze_launch_identity_set=true` 不具 v2.41 acceptance 效力。
不得把舊文件自動改 version 後當成新 attestation。

Commit `1b89ebe` 的後續 AI technical re-review 找到一項 P2：同 inode、同長度原地
改寫可能沒有產生不同的 inode／size／mtime／ctime observation，因此 metadata tuple
不能證明 capture 期間沒有 writer。本 corrective checkpoint 明確縮限 F1 contract：
每份輸入只 single-open、single bounded-read 一次；identity、strict JSON parse、binding
與所有 validation 均只使用該次擷取的 immutable `Snapshot.raw`。Metadata 比較只提供
best-effort mutation signals，不是一般 filesystem 上的強不可變性證明。

| Contract 面向 | `1b89ebe` 原文字義 | Corrective contract |
| --- | --- | --- |
| Metadata | 將 `stat` 描述成會偵測 read-time 變動 | 只作 best-effort signal；tuple 相等不證明無 writer |
| Acceptance authority | Immutable snapshot 已存在，但 in-place mutation 被要求一律拒絕 | 可接受完整 capture 的舊 raw；identity、parse、binding、validation 必須全由該 raw 得出 |
| Execution handoff | Future executor 使用已驗證 bytes | 明定只能消費同一 `CandidateSet` snapshots，不得重開 pathname |

## 變更檔案與設計理由

| 檔案 | 理由與新行為 |
| --- | --- |
| `src/pq_rbbc_launch_io_v2_41.py` | 共用 single-open／single bounded-read immutable raw snapshot、1 MiB byte limit、strict JSON、directory-FD traversal 及 exclusive publication。Identity、parse 與 validation 共用同一 raw；metadata 僅是 best-effort signal。 |
| `src/pq_rbbc_cap_unified_tree_launch_validation_v2_41.py` | 新版本 grammar、strict schema subset validator、exact execution mapping、reservation/review/batch/time binding、authoring/prelaunch gates；production branch 一律拒絕。 |
| `src/pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41.py` | 只接受指定 identity 的「缺少三份候選」negative report；同一 snapshot 負責 identity 與 parse。不封存真實 attestation 或 launch freeze。 |
| `schemas/pq_rbbc_cap_unified_tree_{resource_reservation,independent_review,launch_manifest}_v2_41.schema.json` | 新 formats 分別為 reservation `-4`、review `-4`、launch `-3`，新增 batch、review subject 與 execution locations；所有 nested identities 明定 integer bytes。 |
| `manifests/pq_rbbc_cap_unified_tree_launch_validation_manifest_v2_41.json` | 明定 v2.39 → v2.41 transition、19 份歷史 identities、exact v2.38 predecessor、schema hashes、I/O/time/root 政策與不可執行的預定 command。 |
| `tests/test_pq_rbbc_cap_unified_tree_launch_validation{,_evidence}_v2_41.py` | Synthetic-only positive/negative/mutation、TOCTOU、concurrency、CLI、evidence 與保守 claims 回歸。 |
| `artifacts/metadata/cap_unified_tree_launch_validation_v2_41/` | 新的 path-free negative-observation seal，以及測試／probe mapping、歷史保留驗證結果。 |
| `checksums/SHA256SUMS_v2_41_LAUNCH_VALIDATION_HARDENING.txt` | 新版本、repository-relative paths 的 inventory；不修改舊 inventories。 |
| 本 artifact note、v2.41 release/roadmap/re-review prompt、current handoff | 提供設計、重現方式與下一個 bounded gate。Root canonical status/methodology/experiments 由 integration lane 整合，本 note 保存本 lane 的對應決策與實驗紀錄。 |

新實作只使用 historical v2.39 的純 schema/template 描述函式，透過明確 successor
轉換建立新 grammar；不使用舊 validator、candidate reader、writer 或 evidence sealer。
V2.39 source 本身亦列入 exact historical contract，不能無聲改動此相依來源。

## 八項 findings 的實作與測試

下表的 `test_` 名稱位於上述新 test module；evidence 測試位於 `_evidence_v2_41`。
完整 probe-key → executed-test mapping 與執行結果見同目錄的 machine-readable
`pq_rbbc_cap_unified_tree_launch_validation_regression_results_v2_41.json`。

| Finding | Positive／negative／mutation | TOCTOU／race regression |
| --- | --- | --- |
| F1 單次 bytes snapshot | `test_f1_positive_single_open_and_read_each_candidate` 計數三檔各一次 open/read；`test_f1_snapshot_is_immutable_and_parser_mutation_is_detached`；`test_f1_bounded_size_empty_and_nonregular_input_rejected` | `test_f1_negative_hash_unapproved_parse_approved_toctou`、`test_f1_builder_never_hashes_unvalidated_replacement`、inode replacement rejection，以及 `test_p2_same_inode_rewrite_keeps_one_authoritative_snapshot`：受控同 inode／同長度改寫即使 metadata signal 相同，也只接受先前完整擷取的舊 raw，pathname 新內容不能替換它。Evidence tests 同樣不重讀。 |
| F2 exact command locations | `test_f2_positive_command_binds_all_exact_locations`；`test_f2_same_basename_other_directory_rejected_before_read`；`test_f2_command_and_mapping_mutations_rejected`；`test_f2_rebinding_requires_new_attestations` | `test_f2_and_f7_input_parent_rename_race_cannot_rebind_command`；F1 replacement cases 亦確認 bytes identity 不隨 pathname 變更。 |
| F3 strict canonical JSON | `test_f3_positive_canonical_utf8_roundtrip`；`test_f3_all_prereview_encoding_probes_rejected` 包括 duplicate/UTF-8/BOM/whitespace/float/exponent/NaN/Infinity/escape/surrogate/depth；evidence 的 `test_f3_evidence_rejects_noncanonical_and_duplicate_report` | `test_f3_and_f4_malformed_snapshot_cannot_be_rescued_by_replacement`；bad snapshot 不因隨後換成好檔而通過。 |
| F4 exact bool/int 與 nested identity | Positive fixture 通過；`test_f4_every_boolean_rejects_numeric_and_other_types`；`test_f4_every_nested_identity_rejects_float_bool_and_mutations`；`test_f4_resource_integer_bounds_and_versions`；`test_f4_unhashable_attestation_method_is_structured_rejection` | 共用 F3/F4 replacement regression；evidence `test_f4_evidence_rejects_numeric_claims_and_identity_sizes` 拒絕 numeric false 與 float bytes。 |
| F5 trusted now 與共同時序 | `test_f5_window_boundaries_and_trusted_now`；`test_f5_expired_and_future_reservations_rejected`；`test_f5_approval_review_and_direct_launch_time_mutations` | `test_f5_clock_sampled_after_candidate_io`、`test_f5_clock_rollover_between_validation_and_builder_rejected`、`test_f5_prelaunch_revalidation_uses_fresh_clock_and_same_snapshots`，以及 production refusal 的時鐘跨 expiry 測試。 |
| F6 review 綁定 reservation／batch | `test_f6_positive_exact_reservation_subject_and_batch`；`test_f6_review_cannot_be_reused_for_changed_reservation`；`test_f6_review_subject_identity_and_batch_mutations` | `test_f6_review_swapped_after_capture_keeps_old_exact_identity`；reservation 於 review capture 時替換的 F1 builder regression。 |
| F7 exclusive output／trusted root | `test_f7_positive_exclusive_complete_canonical_output`；`test_f7_existing_and_dangling_symlink_never_followed`；`test_f7_candidates_symlinks_and_hardlinks_rejected`；`test_f7_other_worktree_and_untrusted_root_rejected` | `test_f7_competing_writer_at_publication_not_overwritten`、12 writers 的 `test_f7_real_parallel_writers_have_exactly_one_winner`、`test_f7_parent_rename_symlink_race_never_writes_external_target`、`test_f7_failure_before_publish_leaves_no_partial_final`。Sealer 共用相同 publication primitive。 |
| F8 authoring contracts／predecessor | `test_f8_exact_contracts_positive_and_missing_predecessor_authoring_negative`；`test_f8_mutated_tracked_contracts_refuse_authoring_and_preflight`；evidence `test_f8_evidence_requires_exact_contracts`；CLI 缺 predecessor 不建立 output | `test_f8_contract_hash_parse_toctou_cannot_rescue_bad_snapshot`；prelaunch 重新驗證 contracts，不能繼承舊 report 的 boolean。 |

另外，`test_prereview_closed_world_all_objects_and_required_fields` 對每層 object
逐一加未知欄位、刪除每個 required field。所有新 candidate identities 都保持
`identity_frozen=false`。同 operator/reviewer identifier 的 probe 明確保留為「不能單憑
JSON 證明獨立性」測試，沒有假裝以字串不相等驗證人員關係。

## Byte、time 與 filesystem contracts

`read_snapshot` 以 `O_NOFOLLOW | O_NONBLOCK` 單次開啟 regular、single-link file，
先拒絕過大檔案，再以一個 `read(MAX_JSON_BYTES + 1)` 擷取 bytes。Size、digest、
UTF-8 decode、duplicate-key rejection、JSON parse、canonical equality 與 semantic
validation 全部使用該 immutable `bytes`。`stat` 不作為回報 length 的來源；前後
inode／size／mtime／ctime 或 pathname／parent location 不一致時會提供額外拒絕訊號，
但相等不能證明 capture 期間沒有 writer，也不能排除同長度原地改寫。Snapshot 不保留
可被外部 mutation 的 parsed dict；後續 parse 可重算，但只從原 bytes 進行。若 writer
在 bounded read 完整取得舊 bytes 後改寫 pathname，該舊 immutable snapshot 可被驗證；
後續 pathname 內容不得替換或改變已 capture 的 raw。

Canonical encoding 是 sorted keys、ASCII escapes、無多餘空白、單一末尾 LF；
raw 必須等於 `canonical_json(parsed)`。本 grammar 沒有 floating-point fields，
所以拒絕所有 decimal/exponent/nonfinite number tokens。Boolean 必須 `type(x) is bool`；
integer 必須 `type(x) is int`。JSON Schema 的 mathematical integer 可能接受 `7390.0`，
本專案額外的 encoding contract 明確禁止。沒有安裝／執行第三方 `jsonschema`；
測試檢查 frozen schema/runtime 及所有對應型別、欄位 mutations。

Trusted clock 由 caller 注入；CLI 使用系統 UTC，不提供 `--now`，也不從 candidate
取得 now。先 capture inputs，再取時鐘判定。有效條件：

```text
approved_at <= reservation_start < reservation_expiry
approved_at <= review_completed <= launch_created <= trusted_now
reservation_start <= trusted_now < reservation_expiry
wall_clock_seconds == reservation_expiry - reservation_start
```

未生效與已過期窗口都不能 freeze-ready。Builder 再取一次時鐘；prelaunch primitive
也重新驗證 contracts、相同 snapshots 與新 now。未來 executor 必須消費同一份
`CandidateSet` 內已驗證的 snapshots，不能把 report 的 boolean 或再次開啟 candidate
pathname 當成延續信任的方式。
本版本 production branch 在重新驗證後仍無條件拒絕。

Default trusted root 為 `/tmp/pq_rbbc_v2_41_launch_artifacts`，須由 trusted caller
先行 provision，工具不根據 candidate 自動建立 root 或 parents。可以由可信 CLI/API
caller 明確指定另一個 root，但 root 必須 privately writable、非 Git worktree、
非 symlink，ancestors 亦須通過 ownership/write-permission 檢查。`/` 的 owner 作為
system owner trust anchor，兼容 user-namespace uid mapping；system-owned sticky
`/tmp` 只允許作 ancestor。空的 sandbox `.git` protection mount 不是 repository；
真實 `.git` directory 的 HEAD/config 與 linked-worktree gitfile 都會被拒絕。

三份候選的完整 location 必須是 root 內固定檔名。Command 包含 trusted root、三份
exact paths 與 output；launch 還保存 `candidate_locations`。Rebind 會改變 command
digest，必須重新取得針對新 root 的 reservation/review，並重建 launch candidate；
直接搬移同名 files 不成立。

輸出先在 pinned parent FD 建立隨機 `O_CREAT|O_EXCL|O_NOFOLLOW` temporary file，
完整寫入並 fsync 後，以 `link` 原子發布到尚不存在的 final name。既有 file、symlink、
dangling symlink 或 concurrent winner 全都觸發 `EEXIST`，不會 truncate。失敗注入測試
確認 final name 不暴露部分 JSON；process crash 可能留下未發布 temporary file，
不能將它當成完整 report。Parent 競態以 directory FD 限定實際操作，location 變更會拒絕；
若發布後才偵測 parent rename，完整 file 可能留在原 directory inode，但不跟隨新 symlink
寫入其他 target，也不承諾這次呼叫成功。

信任邊界仍包括 trusted source/interpreter、kernel/filesystem、system clock 與 artifact
root 的擁有者。這不是對可任意修改同一 UID 記憶體、source、mounts 的攻擊者之證明；
也不提供 signed-attestation verification、resource allocator proof、host execution lock、
revocation service 或 production executor。

部署前提另包括 trusted producer handoff、candidate writer quiescence、正確的 inode
owner／mode／ACL、沒有不可信方持有既有 writable file descriptor，以及受信任的 mount
namespace。若政策要求「capture 期間任何 writer 都必須被偵測或排除」，必須由可信的
immutable handoff 或 OS／filesystem enforcement 提供；不得以增加 `stat` 次數、sleep、
advisory lock、重讀 pathname 或比較第二次內容宣稱已建立該強保證。

## 實驗與歷史 evidence

環境：Linux 6.8.0-138-generic x86_64、glibc 2.35、Python 3.12.9、12 logical CPUs。
沒有複製大型 external artifacts 到新 worktree。全部 Python 命令使用
`PYTHONDONTWRITEBYTECODE=1`。

Targeted（包含原有 13 tests）：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_cap_unified_tree_launch_preflight \
  tests.test_pq_rbbc_cap_unified_tree_launch_preflight_evidence \
  tests.test_pq_rbbc_cap_unified_tree_launch_validation_v2_41 \
  tests.test_pq_rbbc_cap_unified_tree_launch_validation_evidence_v2_41 -v
```

Corrective 結果：69 tests，69 passed、0 failed、0 errors、0 skipped，2.092 s，exit 0。
原有 13 tests 未修改；另一次 baseline 單獨執行為 13 passed、0 skipped，0.007 s。
完整 suite 命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

Corrective 完整 suite 結果：641 tests，629 passed、0 failed、0 errors、12 skipped，711.966 s，
exit 0。12 項 skip 都是既有 optional v2.13–v2.25 external artifacts 未安裝，沒有新增
skip。Raw stdout/stderr 留在獨立 `/tmp/pq-rbbc-v241-corrective-validation-*`，不加入 Git。

重審提供的 `inplace_probe.py` 另在獨立目錄執行 200 次：200 次同 inode／同長度改寫
均已執行，178 次 metadata tuple 未變且回傳完整舊 raw，22 次因 best-effort metadata
signal 改變而拒絕；所有接受案例的磁碟 pathname 均已是完整新 raw。這個比例只是一輪
本機 observation，不是 filesystem 保證。它支持 captured-byte consistency contract，
不支持「所有 writer 都會被偵測」宣稱。

原 `probe-results.json` 的 27 個 keys 已逐一對應到 17 項等價回歸測試，另行執行得到
17 passed、0 failed、0 errors、0 skipped，0.555 s，exit 0。可由 regression-results
JSON 的 `probe_mapping[*].test_id` 去重後作為 `python -m unittest <test_ids> -v`
參數重跑；上述 targeted 命令也完整涵蓋這些測試。Closed-world mutations 實際拒絕
26 個 object 的未知欄位與 129 次 required-field deletion。

19 份 v2.38/v2.39 tracked historical files 的 size/SHA-256 全數符合 baseline，
並以 `git diff 3885b01 -- <historical paths>` 確認沒有變更。完整 mapping 在 v2.41
manifest 與 regression results。核心 identities：

| Historical artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| v2.38 manifest | 7,581 | `b601af812865b190e76a7fe22d184f29ee2036dc907a56ad4dcf8da8fbf9a4a4` |
| v2.38 portable | 7,390 | `7f846858350deefa6a6d4df2dec43a852f8e6deb9c55c99e289c2062f822979e` |
| v2.39 manifest | 6,462 | `da2e8a80c2391c218b265414648d2877d840c626b6b669ed8d85343e55f2db51` |
| v2.39 portable | 6,792 | `a4d1f8e2d7f206a070a820a801ceded5edd0f0c4250498124354d9453aa3c978` |
| v2.39 checksum inventory | 2,295 | `904c3cd38f7accd80146a97377b2083e60065e74aa632f8561ffe2f4105310e0` |

舊 v2.38/v2.39 inventories 中 current handoff 與 research status 的 digests 對應
`b3a00f36bedc9d65a56f1153357c5db5f20d21aa` 的 historical docs；它們在 `7769a2e`
integration 已有更新。本次不重寫舊 checksum 讓它看似匹配 current docs；v2.41 inventory
另外綁定目前 task 的文件。V2.38/v2.39 source/schema/manifest/portable 與 external
draft/report identities 不因本次修正而變動；corrective source/test/manifest 則以新的
v2.41 successor identities 重封。

V2.41 negative report 的 observed time 是 `2026-09-08T15:19:46.174028+00:00`。
它明確記錄三份 candidates 都未提供，authoring/freeze/production gates 皆 false。
Report 為 1,975 bytes，SHA-256
`07a80a7de2f947803beb164ef62594e1f2111f91acdf9ee50d3c723dee173add`。
新 portable seal 只綁定此 negative report、successor source/tests/contracts 與歷史 identities；
沒有 candidate bytes、人員 attestation 或正式 identity freeze。Corrective portable 為
7,992 bytes，SHA-256
`0ead1e9913e9b449f8eaa2bca652a2b08e68cdff72b2970169d027b1405084b4`。

## 保守 claim boundary 與下一步

完成的是 launch validation engineering 與 bounded regression。它不是 independent human
cryptographic review、operator approval、attestation authentication、identity freeze 或
execution authorization。沒有填寫真實 reservation、偽造 independent review、展開
production leaves、materialize production stream/checkpoint、large replay/proving，
也沒有建立 assignment、BR1CS、pickle/cache 或 proof。

`production_prefreeze_authorized`、`production_prefreeze_started`、
`production_runner_scale_qualified`、`launch_manifest_frozen`、
`cap_security_qualified`、`fork_security_proof_revalidated`、`production_closed`
及所有 large-run gates 保持 false。Legacy 18-tree observations、assignments 與 v2.29
transcript 沒有被重用為 unified-profile observations。

下一個 bounded gate 是依更新後的
`docs/reviews/PQ_RBBC_v2_41_AI_TECHNICAL_RE_REVIEW_PROMPT_zh-TW.md` 做 AI-assisted
technical re-review；通過仍不代表獨立密碼學審查或執行授權。真實 reservation、independent
review、後續 identity-freeze checkpoint 與 production 授權必須另行成立。
