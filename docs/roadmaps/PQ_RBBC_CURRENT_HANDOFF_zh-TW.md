[English](PQ_RBBC_CURRENT_HANDOFF.md)

# PQ-RBBC 目前交接 — v2.41 launch validation successor（待整合）

> **模組範圍：**這是 PQ-RBBC 的操作交接，不是整篇論文 roadmap。專案級背景請先讀 [../../ARCHITECTURE_zh-TW.md](../../ARCHITECTURE_zh-TW.md)、[../../RESEARCH_STATUS_zh-TW.md](../../RESEARCH_STATUS_zh-TW.md) 與 [../../ROADMAP_zh-TW.md](../../ROADMAP_zh-TW.md)。

日期：2026 年 9 月 8 日

## V2.41 branch checkpoint

`codex/pq-rbbc-v2-41-launch-validation-hardening` 從 local main `3885b01` 建立獨立
worktree，修正 v2.39 AI technical pre-review 的八項 validation findings。新版本採
single-read immutable snapshots、exact command locations、strict canonical JSON 與
bool/int、trusted time、reservation/batch-bound review、exclusive atomic publication，
並讓 authoring 與 builder 都要求 exact contracts/v2.38 predecessor。

V2.38/v2.39 source、tests、schemas、manifests、portable evidence、artifact notes 與
checksums 的 19 份 historical identities 均未變動。下方 v2.39 freeze-ready 敘述
屬歷史 checkpoint；不得用其舊 validator 的結果取代 v2.41 驗證。V2.41 不自動升級
attestations，也沒有正式 launch identity freeze。

新 portable evidence 只保存缺少真實候選的 negative observation。原 13 項及新增
55 項 targeted tests 全部通過；完整 suite 為 628 passed、12 既有 optional skips、
0 failures/errors（共 640 tests）。結果與每個 finding 的 regression 對照見
[`../artifacts/PQ_RBBC_v2_41_LAUNCH_VALIDATION_HARDENING_zh-TW.md`](../artifacts/PQ_RBBC_v2_41_LAUNCH_VALIDATION_HARDENING_zh-TW.md)。
下一步為唯讀 AI technical re-review，再等待 integration。此 branch 不 merge/push；
root canonical status 由 integration lane 更新。

沒有真實 reservation、偽造 review、production-prefreeze、large replay/proving 或
新的 production observation；所有 production/security claims 維持 false。

新工作階段先讀本文件、v2.29 recovery note、v2.30 fork-security audit、
v2.31 CAP-security qualification evidence、v2.32 CAP Prove/Verify preflight、
v2.33–v2.39 unified-tree checkpoints與`docs/ARTIFACT_POLICY.md`。本 handoff 記錄
已納入整合 checkpoint 的bounded evidence；精確發布位置仍須以 Git commit 與
branch 驗證，不得只由散文推測。

## 已封閉邊界

V2.29已依frozen namespace重放18份planned tree assignments、逐wire核對72個
relocations、重放parent-bound global tail，並在GF(2^193)中驗證joined parent
relation。Row accounting：

| Segment | Rows | Failures |
| --- | ---: | ---: |
| Tree producers | 513,312,336 | 0 |
| Relocations | 15,938,520 | 0 |
| Parent-bound global tail | 56,806,711 | 0 |
| Aggregate | 586,057,567 | 0 |
| Joined parent | 2,972,988 | 0 |
| Combined | 589,030,555 | 0 |

因此`complete_18_tree_assignment_replayed`、
`cross_segment_wire_identity_closed`、`parent_bound_global_tail_replayed`、
`gf193_parent_lift_replayed`與`parent_cap_to_h_rbbc_join_closed`均已由本次exact
execution封閉。這不封閉fork-security proof或production。

## Portable evidence identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Frozen preflight manifest | 5,731 | `4e83d260121df7bc9f73f03a3c427f494577cdcabb8808a9e67a2987d137ab78` |
| External preparation manifest | 4,539 | `32f246e13f06e956bb4b39262f41b53d83c2874a646b1f9671381520f1ceb852` |
| External full-replay manifest | 5,685 | `055790dffe51781cff2f2f7893931da5550b9d730bec7ae72927a93f9e352a2a` |
| Portable recovery evidence | 5,695 | `1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e` |

Frozen input identity：
`b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a`

Ordered replay transcript：
`1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514`

Path-free Git evidence位於
`artifacts/metadata/parent_join_recovery_v2_29/pq_rbbc_parent_join_recovery_evidence_v2_29.json`。
完整external identities由該JSON與v2.29 checksum inventory綁定。

## External artifacts

執行產物位於獨立的
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_29_parent_join/`，包含：

- 1,004,865,028-byte parent-bound global-tail assignment；
- 72,354,912-byte joined parent relation archive；
- 74,507,694-byte joined parent assignment；
- full-replay manifest、local checkpoints與tree execution caches。

Tree 0–17 assignments仍分別留在v2.28 recovery、v2.25 batch、v2.26 batch與
v2.27 batch external directories。不得將任何assignment、BR1CS、pickle、cache、
checkpoint/resume state或log加入Git，也不得以其他tree的observed stream bytes
替代目標tree identity。

## V2.30 proof audit

V2.30已將fork-specific proof scope綁定至v2.29 final semantics。官方
ePrint 2025/895之2025-10-31 revision、proof-audit packet、CAP／QROM／
blindness-one-more internal gap reviews、independent-review request與audit manifest
均已凍結。Path-free evidence為
`artifacts/metadata/fork_security_audit_v2_30/pq_rbbc_fork_security_audit_evidence_v2_30.json`
（4,491 bytes，SHA-256
`ab82fe91e2e71cbfdf90bc171b0e62f6be6021365f0870e5878edd8a8496de60`）。

Internal audit結論為fail-closed：paper reductions需要的fork CAP extractor／ZK、
request-proof extractor、concrete QROM boundary、完整fork signer/finalizer、PQ
SE-NIZK backend及independent review均未由functional replay建立。因此目前只關閉
`v2_30_internal_proof_audit_closed`與`v2_30_independent_review_ready`；
`fork_security_proof_revalidated`仍為false。

Initial candidate inventory command及檔名見
[`../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_PREFLIGHT_zh-TW.md)。Candidate artifacts必須放在獨立
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/`。Audit結果與全部frozen
identities見
[`../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_AUDIT_zh-TW.md`](../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_AUDIT_zh-TW.md)。下一個gate是由合格的獨立
cryptographic reviewer出具綁定全部digests的attestation；專案不得自行補造。
不得把v2.29 parent-join execution evidence擴張解讀成security-proof或production
closure。

System architecture、ticket lifecycle與`pq_sat_auth`在v2.29均未修改。

## V2.31 CAP-security qualification

V2.31已綁定v2.30 audit evidence、v2.29 final semantics與production CAP source，
並凍結CAP oracle transcript、admissible commitment、Definition-10 straight-line
extractor interface及unique committed mask game。Mixed production profile維持
2 × 4,096-leaf degree-13 trees與16 × 2,048-leaf degree-12 trees；不得以其他tree
的observed `stream_bytes`代替任何identity。

Path-free checkpoint evidence為
`artifacts/metadata/cap_security_qualification_v2_31/pq_rbbc_cap_security_qualification_evidence_v2_31.json`
（5,606 bytes，SHA-256
`6a447112809ae999d72a4c6886f353ffa1f38720870364009dc7e8155c29edfd`）。
候選authoring seal為同directory下的
`pq_rbbc_cap_security_artifact_evidence_v2_31.json`（4,720 bytes，SHA-256
`eb5b1c901b7fd55d2092e71caadf797f8ac510ad857c8199c9f77cd5b6c544e8`）。

Straight-line extractor specification、unique-mask reduction與包含122,847筆完整
Q_CAP records的candidate evidence均已撰寫、凍結identity並驗證。10／10 negative
vectors均拒絕，且現在`safe_to_request_independent_review = true`。External
inventory只缺independent-review attestation。

然而numeric accounting得到未含PoW的degree term只有`2^-182`，低於192-bit
target；完整CAP Prove／Verify、paper約13.9-bit PoW、production `c_2`
serialization與concrete Anemoi ROM／QROM justification仍缺。因此
`safe_to_start_cap_security_qualification = false`與
`cap_security_qualified = false`。詳細schema、frozen digests、exact authoring與
inventory commands見
[`../artifacts/PQ_RBBC_v2_31_CAP_SECURITY_QUALIFICATION_zh-TW.md`](../artifacts/PQ_RBBC_v2_31_CAP_SECURITY_QUALIFICATION_zh-TW.md)。
在獨立review與上述profile dispositions完成前，不提供qualification execution
command，也不啟動large replay。

## V2.32 CAP Prove/Verify preflight

V2.32已將下一階段限定為完整CAP Prove／Verify、public-statement encoding、
production proof serialization及PoW／security-profile disposition。它綁定v2.31
exact identities與v2.29的589,030,555 rows、0 failures、0 external assertions，
不重播relation也不產生proof。

Frozen outer envelope使用`PQRBBC-CAP-PROOF-V1`、version 1、profile fingerprint及
canonical `c_r`／`c_x`／`pow_nonce`／`pi_2` sections。只有`c_r`的5,391-byte
payload已知；其餘production payloads與完整statement encoding仍未凍結。V2.31的
252-byte candidate `c_2`明確不得升格為production `c_x`。

PoW disposition保留192-bit target並記錄目前raw degree security只有182 bits；
paper的約13.9 PoW bits不會自動繼承。任何tree/profile變更都會使目前production
shape失效並需要新namespace與replay，本preflight未授權該變更。

Path-free evidence為
`artifacts/metadata/cap_prove_verify_preflight_v2_32/pq_rbbc_cap_prove_verify_preflight_evidence_v2_32.json`
（5,445 bytes，SHA-256
`0fcba15c45dda36df82606a49a197eb85aa20e8ac38f1c31c557eba639258657`）。

Initial inventory缺少Prove／Verify specification、production serialization、PoW
disposition、implementation evidence及independent review五份external artifacts。
現已直接開始bounded v2.32 implementation：strict candidate statement codec與outer
proof envelope已實作並測試，且external directory已有specification PDF、
serialization candidate、PoW disposition及partial implementation evidence四份
schema-valid candidates；preflight checker依使用者要求未調整，故其identities仍為
`identity_not_frozen`。Independent review仍缺少。

Paper cross-check確認13.9-bit PoW依賴單一interleaved unified GGM tree、
`T_open=174` rejection sampling與9-bit explicit condition；目前fork為18個獨立roots。
在不改architecture/profile且不建立新namespace/replay的限制下，不能安全補成
paper-compatible PoW。因此`prove()`明確unavailable，`verify()`strict parse後fail
closed，沒有產生accepting proof。結果仍為
`safe_to_implement_cap_prove_verify = false`、
`safe_to_start_large_proving_run = false`及`cap_security_qualified = false`。
詳細schema、資源估算與exact command見
[`../artifacts/PQ_RBBC_v2_32_CAP_PROVE_VERIFY_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_32_CAP_PROVE_VERIFY_PREFLIGHT_zh-TW.md)。

## V2.33 unified-tree CAP migration preflight

使用者已明確授權建立獨立的unified-tree CAP namespace/profile，條件是保留現有
18-tree profile、不覆寫既有evidence，且大型重建與replay只能在preflight安全後
啟動。V2.33已完成唯讀migration preflight並保留新的candidate namespace：

- profile name：
  `PQ-RBBC-CAP-TCitH-III/Anemoi-193-336-Unified-GGM-CANDIDATE-v1`；
- relation ID：
  `pq-rbbc/cap/tcith-iii/anemoi-193-336/unified-ggm/candidate/v1`；
- domain prefix：`PQ-RBBC/v2.33/CAP-UGGM/`；
- topology：one root、40,960 leaves；
- logical mapping：position-major interleaving，且已驗證40,960-entry bijection。

Legacy fingerprint
`2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`
與全部v2.19–v2.32 evidence保持historical、read-only。新profile不得沿用tree
0–17的observed `stream_bytes`、digests或assignments，也不得把v2.29完整transcript
當成新profile evidence。

七份source artifacts已逐byte驗證，環境容量也超過planning minimum，因此
`safe_to_author_unified_tree_specification = true`及
`safe_to_implement_reduced_prototype = true`。Initial report當時列出algorithm
specification、reduced evidence、runner qualification、operator resource reservation
及independent design review五個blockers，所以`safe_to_start_production_prefreeze = false`、
`safe_to_start_large_replay = false`與`safe_to_start_large_proving_run = false`。

Exact specification與12-leaf reduced prototype已依後續明確授權完成。Specification
凍結單root L−1 derivations、π/inverse、new domains、commitment/opening encoding、
LSB-first challenge slicing、minimal frontier、explicit bits與`T_open`驗證。Reduced
run接受1個deterministic opening，9/9 mutations拒絕，並通過fresh-cache、resume
identity與overwrite-refusal qualification；production leaves、relation rows與proofs
全部為0。Path-free reduced seal為
`artifacts/metadata/cap_unified_tree_migration_v2_33/pq_rbbc_cap_unified_tree_reduced_portable_evidence_v2_33.json`
（5,894 bytes，SHA-256
`758f101d9e825da2d4315d69d46a48b6c5ef563c49d05633cb3b68cde4fbcdd3`）。

保守projection為至少589,054,075 combined rows；兩個完整passes至少
1,178,108,150 row checks。這不是frozen count；reduced benchmark與exact opening
grammar不足以安全外推production elapsed time。後續需取得operator-approved
resource reservation與independent design/cryptographic review，並以綁定新seal的
read-only production pre-freeze checker維持gate。完整影響範圍、external blockers、
資源估算與exact commands見
[`../artifacts/PQ_RBBC_v2_33_UNIFIED_TREE_MIGRATION_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_33_UNIFIED_TREE_MIGRATION_PREFLIGHT_zh-TW.md)。

Path-free evidence為
`artifacts/metadata/cap_unified_tree_migration_v2_33/pq_rbbc_cap_unified_tree_migration_preflight_evidence_v2_33.json`
（7,293 bytes，SHA-256
`624a5c723403a8273d427e40f9160e40463c22dc06a88ce9f448a836d72e4ef7`）。

## V2.34 unified-tree production pre-freeze checkpoint

V2.34已建立綁定v2.33 reduced portable seal的read-only、fail-closed production
pre-freeze checker，並凍結resource-reservation JSON Schema、independent-review
contract、production descriptor fingerprint
`c270e4681f23955667a6c0640317e7beccc666d60a0cffb40bfdccfcee811b7a`
及prospective command digest。四份v2.33 external outputs均逐byte驗證；目前環境12
cores、available memory約29.7 GB、free disk約664 GB，通過4 cores／16 GiB／80 GiB
capacity minimum，但capacity observation本身不是execution authorization。

Initial v2.34 report為`safe_to_run_read_only_checker = true`及
`safe_to_request_independent_review = true`。Resource reservation與independent review
尚未提供；而現有runner只支援reduced phase，production runner尚未實作、production
relation contract尚未凍結、本次亦未授權production execution。因此
`safe_to_start_production_prefreeze = false`、`safe_to_start_large_replay = false`與
`safe_to_start_large_proving_run = false`。

Resource schema要求外部operator只授權fresh、exclusive、no-overwrite的
production-prefreeze，明確禁止重用其他tree observed `stream_bytes`，且不得授權
frozen replay、large proving或security claim。由工具輸出的template故意不通過
approval gate；專案不得替operator或independent reviewer補造attestation。

Path-free v2.34 evidence為
`artifacts/metadata/cap_unified_tree_production_prefreeze_v2_34/pq_rbbc_cap_unified_tree_production_prefreeze_evidence_v2_34.json`
（3,816 bytes，SHA-256
`7778bdad550baa31e530c739e916e14d5e5ce4738846c64f2c0729b663a9e341`）。
完整schema、blockers、resource boundary與exact commands見
[`../artifacts/PQ_RBBC_v2_34_UNIFIED_TREE_PRODUCTION_PREFREEZE_zh-TW.md`](../artifacts/PQ_RBBC_v2_34_UNIFIED_TREE_PRODUCTION_PREFREEZE_zh-TW.md)。

## V2.35 unified-tree production runner authoring checkpoint

V2.35已建立新的production runner skeleton與machine-readable relation-stage contract，
並以保留18個logical vectors及兩大／十六小比例的40-leaf test-only fixture驗證
fresh run、plan後中斷／resume、deterministic identity、overwrite refusal及production
branch在建立output前fail closed。Bounded run接受opening，production leaves、relation
rows、assignment、BR1CS與proofs全部為0。

Relation contract凍結stage ordering及planned counts，但所有production observations
仍為`null`；589,054,075 rows仍只是lower bound。Production checkpoint payload與
relation generator尚未實作，resource reservation及independent-review identities亦未
凍結，且沒有production execution authorization或launch manifest。因此只有
`runner_skeleton_qualified = true`；`production_runner_qualified`及三個large-run gates
均為false。

Path-free v2.35 evidence為
`artifacts/metadata/cap_unified_tree_production_runner_v2_35/pq_rbbc_cap_unified_tree_production_runner_evidence_v2_35.json`
（4,836 bytes，SHA-256
`5284654b909158c18c3f3df50b9de190e50bf06469b1d1f1036bfeb860cf292e`）。
完整protocol位置、bounded observation、blockers與exact commands見
[`../artifacts/PQ_RBBC_v2_35_UNIFIED_TREE_PRODUCTION_RUNNER_AUTHORING_zh-TW.md`](../artifacts/PQ_RBBC_v2_35_UNIFIED_TREE_PRODUCTION_RUNNER_AUTHORING_zh-TW.md)。

## V2.36 unified-tree bounded checkpoint payload與relation generator

V2.36已實作canonical checkpoint payload及bounded relation generator。Qualification
使用與v2.35相同的40-leaf／18-vector test-only profile，先在`unified-tree`stage中斷，
再以精確payload SHA-256授權resume；generator獨立重算seed、mapping、leaf/tape、
vector hashes、root、codec、opening、reference ticket relation及downstream parent-input
candidate binding，共144條contract-IR equality rows，全部成立。

這些rows不是BR1CS或production constraints。Production-shape的122,904 contract-row
數字只是grammar projection；沒有取代589,054,075-row lower bound，也沒有沿用其他
tree的observed `stream_bytes`或v2.29 transcript。Bounded qualification成立，但
production-scale payload、relation qualification、final statement encoding、resource
reservation、independent review、execution authorization及launch manifest仍缺少，故
production pre-freeze與所有large-run gates維持false。

Path-free v2.36 evidence為
`artifacts/metadata/cap_unified_tree_bounded_relation_v2_36/pq_rbbc_cap_unified_tree_bounded_relation_portable_evidence_v2_36.json`
（5,719 bytes，SHA-256
`660d4c0d9cf36bbb5ecf02dc66d65721e077171de5b1e9c6b010d19871235fad`）。
完整payload規則、row accounting、resource observation與exact commands見
[`../artifacts/PQ_RBBC_v2_36_UNIFIED_TREE_BOUNDED_RELATION_zh-TW.md`](../artifacts/PQ_RBBC_v2_36_UNIFIED_TREE_BOUNDED_RELATION_zh-TW.md)。

## V2.37 unified statement serialization與parent-input ABI

V2.37已在新的unified-tree namespace凍結strict canonical statement codec與parent-input
envelope。Statement固定`common_parameters_digest`、`ctx`、`sid`、`rid`及72-byte `y`；
parent envelope固定statement、unified commitment `c_r`、32-byte ticket message及
domain-separated binding digest，且statement與commitment profile必須相同。Ticket
mapping直接沿用既有`IssueStatement`及`PQ-RBBC/TICKET` message derivation，沒有修改
ticket lifecycle。

Qualification產生production-profile statement test vector，但沒有production `c_r`，
所以只以v2.36 completed checkpoint的158-byte bounded commitment建立643-byte bounded
parent envelope。兩種statement均為314 bytes，16/16格式、profile、binding及mapping
mutations全部拒絕。Production leaves、relation rows、BR1CS與proofs全部為0；沒有重播
v2.29 parent join，也沒有沿用legacy tree observations。

因此`safe_to_author_production_streaming_path = true`，但
`production_parent_input_qualified = false`、`safe_to_start_production_prefreeze = false`、
`safe_to_start_large_replay = false`及`safe_to_start_large_proving_run = false`。仍需
production streaming/checkpoint materialization、operator resource reservation、
independent review、明確authorization及identity-frozen launch manifest。

Path-free v2.37 evidence為
`artifacts/metadata/cap_unified_statement_parent_abi_v2_37/pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json`
（5,188 bytes，SHA-256
`672c27f8ed0bfc567d3080c9645c079d9009ce7ff815957c9384dc0246b3c8b7`）。
完整codec、mapping、external identities與exact commands見
[`../artifacts/PQ_RBBC_v2_37_UNIFIED_STATEMENT_PARENT_ABI_zh-TW.md`](../artifacts/PQ_RBBC_v2_37_UNIFIED_STATEMENT_PARENT_ABI_zh-TW.md)。

## V2.38 unified-tree streaming checkpoint與launch preflight

V2.38已實作profile-bound binary chunk codec、external-only checkpoint chain及精確
identity resume。Bounded qualification把v2.36 tree state與v2.37 parent input依
`nodes → commitments → tapes → vector hashes → c_r → parent input`固定順序寫成
179 records／15 chunks；在第7個chunk中斷後以精確checkpoint SHA恢復，所有prefix、
chunk、chain及final index驗證成立。

Production layout凍結為未執行的163,859-record／163-chunk plan，raw serialized payload
16,631,418 bytes。這不包含589,054,075-row lower bound的relation、assignment、BR1CS
或兩次replay，也不是runtime／stream-size observation。Production records、leaves、
relation rows及proofs全部為0。

唯讀launch preflight確認目前host的12 cores、約29.7 GB available memory及約664 GB
free disk超過planning minimum；但容量不是授權。V2.38 resource reservation、
independent review及launch manifest均缺少且identity未凍結，production stream尚未
materialize，runner亦未做scale qualification。因此只有
`safe_to_request_resource_reservation = true`與
`safe_to_request_independent_review = true`；production pre-freeze、large replay及
large proving gates全部為false。

Path-free v2.38 evidence為
`artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json`
（7,390 bytes，SHA-256
`7f846858350deefa6a6d4df2dec43a852f8e6deb9c55c99e289c2062f822979e`）。
完整stream grammar、resource estimate、external blockers與exact commands見
[`../artifacts/PQ_RBBC_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE_zh-TW.md`](../artifacts/PQ_RBBC_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE_zh-TW.md)。

## V2.39 unified-tree launch identity-set preflight

V2.39已升版並凍結operator resource reservation、independent review及launch manifest
三份closed-world schemas，實作strict validators、刻意不合法的draft templates、
launch-manifest generator及唯讀identity-set preflight。所有contract均綁定v2.38
portable seal、unified production profile、prospective production command、external
output、fresh-cache／overwrite規則及最小資源。

Qualification確認三份draft都不能冒充attestation；synthetic valid candidates可生成
互相綁定的launch candidate，且只能使`safe_to_freeze_launch_identity_set=true`，不會
使production gate成立。目前沒有真實operator reservation、independent review或launch
manifest，三份identity均未凍結。Production stream/checkpoint、scale qualification及
execution authorization亦未成立，因此production pre-freeze、large replay、large
proving及全部security claims維持false。

Path-free v2.39 evidence為
`artifacts/metadata/cap_unified_tree_launch_preflight_v2_39/pq_rbbc_cap_unified_tree_launch_preflight_portable_evidence_v2_39.json`
（6,792 bytes，SHA-256
`a4d1f8e2d7f206a070a820a801ceded5edd0f0c4250498124354d9453aa3c978`）。
完整schema、qualification、candidate workflow與exact commands見
[`../artifacts/PQ_RBBC_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT_zh-TW.md)。

## Git 與發布規範

- 只提交source、tests、frozen manifests、documentation、checksums與path-free
  portable evidence。
- 建立commit前檢查沒有`.f193assign`、`.br1cs`、pickle、cache、resume、checkpoint
  或logs進入index。
- 不直接push `main`；只有使用者明確授權後才可整合與發布。
- `cap_security_qualified`、`fork_security_proof_revalidated`與
  `production_closed`維持false。
