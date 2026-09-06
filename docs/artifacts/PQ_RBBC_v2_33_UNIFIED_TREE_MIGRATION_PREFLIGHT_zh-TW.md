# PQ-RBBC v2.33 unified-tree CAP migration 唯讀 preflight

日期：2026 年 9 月 4 日

## 結果

本 checkpoint 已依明確授權，保留既有 18-tree profile，並為 unified-tree CAP
保留獨立 candidate namespace/profile；沒有覆寫既有 evidence，也沒有啟動大型
profile build、assignment generation、relation replay或proving run。

- `v2_33_read_only_migration_preflight_closed = true`
- `unified_tree_namespace_reserved = true`
- `migration_impact_contract_frozen = true`
- `safe_to_author_unified_tree_specification = true`
- `safe_to_implement_reduced_prototype = true`
- `exact_unified_tree_specification_authored = true`
- `reduced_unified_tree_implemented_and_verified = true`
- `reduced_runner_qualified = true`
- `safe_to_start_production_prefreeze = false`
- `safe_to_start_large_replay = false`
- `safe_to_start_large_proving_run = false`
- `cap_security_qualified = false`
- `production_closed = false`

目前硬體容量通過最低planning envelope，但capacity check不是執行授權。大型命令在
manifest中只作為未來的exact command contract保留，全部標成
`executable_now = false`與`authorized_now = false`。

## Namespace 與 topology reservation

既有profile保持不變：

- name：`PQ-RBBC-CAP-TCitH-III/Anemoi-193-336-v1`；
- fingerprint：
  `2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`；
- topology：18個獨立roots，其中2 × 4,096 leaves、16 × 2,048 leaves。

新candidate只保留namespace，尚未實作或凍結profile fingerprint：

- name：
  `PQ-RBBC-CAP-TCitH-III/Anemoi-193-336-Unified-GGM-CANDIDATE-v1`；
- relation ID：
  `pq-rbbc/cap/tcith-iii/anemoi-193-336/unified-ggm/candidate/v1`；
- CAP domain prefix：`PQ-RBBC/v2.33/CAP-UGGM/`；
- commitment magic：`PQRBBC-CAP-UGGM-COMMIT-V1`；
- proof magic：`PQRBBC-CAP-UGGM-PROOF-V1`；
- one root、40,960 leaves、40,959 internal nodes；
- non-power-of-two heap為81,919個nodes，leaf indices 40,959–81,918。

保留的position-major interleaving為：positions 0–2,047依序放入全部18個
repetitions，positions 2,048–4,095只放入repetitions 0與1。Checker對全部40,960
logical leaves驗證forward/inverse mapping為bijection。這只是preflight mapping
contract；challenge bit slicing、counter transcript position、`pi_2` grammar與最終
profile fingerprint仍未凍結。

## 影響範圍

保留且不得修改：legacy profile及v2.19–v2.32 historical evidence、ticket
lifecycle、`pq_sat_auth`與頂層system architecture。

GF(2^193)、Anemoi-193/336、未消費CAP commitment bytes的ticket semantics、raw
1,472-bit append delta概念與v2.32 logical statement fields，只能在新profile下重新
驗證後使用。

必須取得新namespace與新evidence的部分包括unified seed expansion、leaf/tape
domains、h1/h2/h3 transcripts、commitment/proof serialization、opening frontier、
`T_open=174`、counter grinding、Protocol-11 Prove/Verify、extractor及unique-mask
reduction。

必須重建或重播：

1. 全部CAP tree producer row streams與assignments；
2. CAP output relocation plan；
3. CAP aggregate relation與assignment；
4. 因`c_r` bytes/profile變更而受影響的parent-bound H_RBBC global tail；
5. parent CAP-to-H_RBBC joined relation；
6. incremental BR1CS與完整relation identity。

Tree 0–17既有observed `stream_bytes`、row-stream digests、assignment identities、
v2.29的589,030,555-row transcript及v2.31 extractor transcript，均不得升格為新
profile的observed evidence。

## External artifacts

下列7份來源已逐byte驗證：Blind-UOV revision、ePrint 2024/490、ePrint
2024/541，以及v2.32 specification、serialization、PoW disposition與partial
implementation evidence。它們只提供migration輸入，不等於新profile evidence。

Initial preflight執行時缺少：

1. `pq_rbbc_cap_unified_tree_spec_v2_33.pdf`；
2. `pq_rbbc_cap_unified_tree_reduced_evidence_v2_33.json`；
3. `pq_rbbc_cap_unified_tree_runner_qualification_v2_33.json`；
4. `pq_rbbc_cap_unified_tree_resource_reservation_v2_33.json`；
5. `pq_rbbc_cap_unified_tree_independent_review_v2_33.json`。

後續bounded authoring已提供並sealed前3份。Resource reservation仍須由operator
明確批准；第5份必須由合格且獨立的reviewer提供，不得由專案自行補造。

## 資源估算

Preflight本身的envelope為1 core、256 MiB peak memory、60秒內、0 replay rows、0
proofs。實際觀察到12 cores、29,214,531,584 bytes available memory與
664,069,861,376 bytes free disk。

未來production執行的保守最低envelope為4 cores、16 GiB available memory、80
GiB free disk。既有18-tree assignments合計9,739,068,204 bytes；單一materialized
result baseline約10,940,023,525 bytes。

若其他topology成本完全不變，單一root展開40,960-leaf tree會比18-tree baseline
多35次seed-derive calls，對應至少23,520 rows：

- projected minimum producer rows：513,335,856；
- projected minimum combined rows：589,054,075；
- 兩次完整replay至少檢查1,178,108,150 rows。

這些是planning lower bounds，不是frozen row/wire counts。後續雖已取得reduced
benchmark與exact opening grammar，但它們不足以安全外推589M-row production
pipeline，因此仍不提供大型執行的elapsed-time估算。Grinding本身的期望值約
15,287 trials，p95/p99 trial upper quantile約45,794／70,397。

## Exact commands

已安全執行的唯讀preflight：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_migration_preflight.py \
  --report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration/pq_rbbc_cap_unified_tree_environment_v2_33.json \
  --blind-uov-paper /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/blind_uov_eprint_2025_895_revision_2025_10_31.pdf \
  --optimized-bavc-paper /tmp/eprint_2024_490.pdf \
  --dsd-explanatory-paper /tmp/eprint_2024_541.pdf \
  --v2-32-specification /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_prove_verify_spec_v2_32.pdf \
  --v2-32-serialization /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_proof_serialization_v2_32.json \
  --v2-32-pow-disposition /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_pow_security_profile_disposition_v2_32.json \
  --v2-32-implementation-evidence /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_prove_verify_implementation_evidence_v2_32.json
```

使用者另行授權後，已執行的bounded reduced phase：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_runner.py \
  --profile-manifest manifests/pq_rbbc_cap_unified_tree_migration_manifest_v2_33.json \
  --phase reduced \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration/reduced \
  --fresh-cache
```

Initial preflight manifest在runner尚未實作時將此命令記為
`executable_now = false`；後續明確授權只開放spec authoring與reduced execution，
並未開放production。Production pre-freeze、frozen replay及aggregate/parent replay
的exact commands仍不可執行。

## Exact specification 與 reduced completion

Exact specification已把下列先前未凍結的candidate details明確化：

- 單一root `k[0]`，heap internal nodes 0–L−2、leaves L−1–2L−2；
- 每個internal node都做一次PRG，因此production為40,959次seed derivation；
- `π(α,i)=Σβ min(i,Nβ)+|{β&lt;α:i&lt;Nβ}|`；
- 6個全新CAP-UGGM domains及其tuple-injective inputs；
- commitment與opening的strict canonical byte grammar；
- h3使用LSB-first vector slices，接著檢查9 explicit bits；
- minimal canonical frontier、`T_open=174`與完整Verify順序。

Reduced executable profile使用logical counts `(4,4,2,2)`、L=12、11個internal
derivations、32-bit tapes、`T_open=4`及2 explicit bits。全部64種hidden-index
tuples的frontier distribution為`{1:1,2:1,3:6,4:20,5:16,6:20}`，其中28種先通過
`T_open`。

Deterministic fresh run在counter 11（第12次trial）取得hidden positions
`(0,0,1,1)`與frontier nodes `(4,6,7)`；158-byte commitment及425-byte opening通過
重建，8個nonhidden tapes均在root equality後才輸出。9/9 mutations全部拒絕，
包含challenge prefix、magic、trailing bytes、h3、hidden position、explicit bits、
oversized frontier、frontier seed及hidden commitment。

Runner qualification另外實際完成fresh-cache、commit後中斷、identity-bound resume、
fresh/resumed result equality與existing-output overwrite refusal。State為external
canonical JSON，不是pickle。Main reduced run耗時36.222秒、peak RSS 20,709,376
bytes；production leaves expanded、relation rows replayed與proofs generated均為0。

External candidate identities：

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Exact specification PDF | 140,010 | `2b8f0c241baa4fd509c2e5e7b0c6f2b6c3108f4f44bc55836825b68a150ee1b0` |
| Reduced evidence | 6,491 | `9074659af8db46cc78c224a9562a4c257214ac3a128062782f898d1b307a65dc` |
| Runner qualification | 1,210 | `e7bb68fd9c5caea8afbbc6ef133e64ae77b67a68fdf5f7d09850a3980ba9a050` |
| Post-reduced preflight | 8,265 | `d517b5c092fb61b79f362b849d91dd119f1166d9aff64a8c3b5b16479e6b6c39` |

Post-reduced preflight將前三份確認為schema-valid candidates；其exact identities另由
path-free reduced portable seal凍結。仍缺operator-approved resource reservation與
independent design/cryptographic review，並需要後續read-only pre-freeze checker綁定
本seal。因此large-run flags仍全部false。

## Evidence identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| checker | 33,644 | `c9fa10e48936d4a4f2b9d7fed2f2a62ad644f91524ff9092b63c0461cc2e1d0e` |
| frozen manifest | 13,990 | `8686d49f59655f09135d91fc79e236c59bc8d6b582c86a55799a0c13acfad9f5` |
| initial external environment report | 7,981 | `c4711956c076cbec96d6d686c5a40c77e303f93bf155566cfb856b2aba876855` |
| initial portable preflight evidence | 7,293 | `624a5c723403a8273d427e40f9160e40463c22dc06a88ce9f448a836d72e4ef7` |
| exact unified-tree implementation | 32,068 | `6be95221ab178704e1257c41ec42066807b5e59acd89a59458dcfd613d4ce1e4` |
| reduced runner | 23,858 | `6f126e42420634c2464a6ee8ba3418e2976c8d83c4003bd3db5b5e43a298470e` |
| specification HTML source | 10,648 | `4e197e6cc4cfe7848af2168a3104fd959621637950a4c2091b3a2834e1e407d9` |
| reduced portable evidence | 5,894 | `758f101d9e825da2d4315d69d46a48b6c5ef563c49d05633cb3b68cde4fbcdd3` |

Portable evidence位於
`artifacts/metadata/cap_unified_tree_migration_v2_33/pq_rbbc_cap_unified_tree_migration_preflight_evidence_v2_33.json`；external report不加入Git。
Reduced completion evidence位於同directory的
`pq_rbbc_cap_unified_tree_reduced_portable_evidence_v2_33.json`。

Evidence verification command：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_migration_preflight_evidence.py \
  --environment-report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration/pq_rbbc_cap_unified_tree_environment_v2_33.json
```

沒有新增或提交assignment、BR1CS、pickle/cache、checkpoint/resume state或logs。
