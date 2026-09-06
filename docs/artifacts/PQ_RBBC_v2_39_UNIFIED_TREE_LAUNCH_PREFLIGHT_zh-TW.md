# PQ-RBBC v2.39 unified-tree launch identity-set preflight

## 結論

V2.39已建立三份closed-world JSON Schema、刻意不合法的draft templates、launch
manifest generator及唯讀identity-set preflight。它逐byte綁定v2.38 portable seal，並
將operator reservation、independent review、production profile、prospective command、
external output與claim boundary放進同一個可驗證launch contract。

本次沒有真實operator reservation或independent review，因此沒有生成真實launch
manifest，也沒有凍結任何external attestation identity。Qualification結果為：

- `attestation_schemas_qualified = true`；
- `real_operator_reservation_present = false`；
- `real_independent_review_present = false`；
- `launch_manifest_authored = false`；
- `launch_identity_set_frozen = false`；
- `safe_to_start_production_prefreeze = false`；
- `safe_to_start_large_replay = false`；
- `safe_to_start_large_proving_run = false`。

沒有展開production leaves、materialize production stream/checkpoint、replay relation
rows、建立assignment／BR1CS或產生proof。

## Protocol位置

V2.38已證明bounded fixture可依固定stage order形成profile-bound chunks，並用外部
checkpoint identity安全中斷／resume。V2.39處理的是下一層控制面：誰保留資源、誰獨立
審查、兩份attestation究竟核准哪一條command，以及launch manifest是否精確綁定它們。

其關係為：

```text
v2.38 portable seal
  + operator resource reservation
  + independent review
  + production profile / exact command / external output policy
  -> launch manifest candidate
  -> identity-set preflight
```

Schema-valid只表示文件形狀與binding正確，不證明簽署人真實、也不自動授權執行。
V2.39的preflight即使收到三份完全合法的candidate，也只回報
`safe_to_freeze_launch_identity_set=true`；production pre-freeze仍固定為false，因為
production-scale stream尚未materialize、runner尚未scale qualification，且本checkpoint
沒有execution authorization。

## Frozen schemas與invalid templates

三份schema為：

- `pq_rbbc_cap_unified_tree_resource_reservation_v2_39.schema.json`：綁定operator、
  reservation window、至少4 cores／16 GiB available memory／80 GiB free disk、
  external output、fresh cache、禁止覆寫及精確command digest；
- `pq_rbbc_cap_unified_tree_independent_review_v2_39.schema.json`：要求reviewer identity、
  affiliation、independence、attestation reference、七個review scopes及
  `approved_for_production_prefreeze_only` disposition；
- `pq_rbbc_cap_unified_tree_launch_manifest_v2_39.schema.json`：綁定前兩份artifact的
  bytes／SHA-256、v2.38 seal、production profile、command與authorization boundary。

Qualification輸出的三份template刻意使用`approved=false`、
`independent_of_implementation=false`、pending disposition、零時窗或未凍結identity，
因此三者都不能通過validator。它們只能供operator/reviewer填寫，不是attestation。

## Qualification與negative properties

External qualification目錄：
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_39_unified_tree_launch_preflight/qualification`。

13個focused tests及qualification共同確認：

- v2.38 predecessor、v2.39 manifest與三份schema exact；
- 三份draft template都被拒絕；
- resource scope變更為可重用其他tree observations時拒絕；
- review嘗試授予security claim時拒絕；
- launch manifest嘗試授權large replay時拒絕；
- synthetic valid candidates只能準備identity freeze，不會啟動production；
- production branch在建立output前拒絕。

本次preflight觀察到12 cores、29,642,174,464 available-memory bytes及
664,062,353,408 free-disk bytes。容量超過planning minimum，但
`capacity_is_reservation=false`且`capacity_is_execution_authorization=false`。

## Exact commands

已執行的bounded qualification：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_launch_preflight.py \
  --phase qualification \
  --v2-38-portable artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_39_unified_tree_launch_preflight/qualification \
  --fresh-output
```

Command SHA-256：
`0a4f29156d7e80b22503f4455ccf3ea8306624ed9928ab714c8dd41572229ae9`。

真實candidate到齊後的唯讀preflight command SHA-256為
`d866f04df626f9865f4b0eaa57fbb8ca0c871e0da4febc264d1fb87a5911eb66`；除了external
report外不修改任何輸入。Launch-manifest authoring command SHA-256為
`60a07edaad4165f8982b503e65d1914227f8310c846aa2706a64aa0d86508707`，目前
`executable_now=false`。Prospective production command仍沿用v2.38 frozen digest
`79da988d8cb17fe23a5e9f263da9bc0f11514f0a36280918278d485176b45c57`
作為predecessor binding；引用v2.39 artifact filenames的candidate production command
SHA-256為`6759ed5ebd1d113365a1a1cc0aed77d0f2bdae989d5aa38540e1af1d09cbd911`，
且`executable_now=false`、`authorized_now=false`。

## Evidence identities

| External artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| resource draft | 1,624 | `6dabdc0f8af032de269788cfb1508d93934550e34a7037f725990651d28a6cea` |
| review draft | 1,750 | `c47c5242ea467397ec0b4734c18c1b666b80a62798d4c740ccfabc07d201c70d` |
| launch draft | 2,148 | `544044f8a5480e9bbb01ca23ef5664a30fa957687c1607fe39b40f0ba0c2d155` |
| read-only preflight | 3,116 | `33ae0c6163ab5806170b7d82d38c8bc80f3f5515638dc1d143bbbeadd6c23f62` |
| qualification | 3,171 | `551da81cd0ac971ecef7fdd5c7304bd12285f96129de1e718b14d49c3488045a` |

Path-free portable evidence：
`artifacts/metadata/cap_unified_tree_launch_preflight_v2_39/pq_rbbc_cap_unified_tree_launch_preflight_portable_evidence_v2_39.json`
（6,792 bytes，SHA-256
`a4d1f8e2d7f206a070a820a801ceded5edd0f0c4250498124354d9453aa3c978`）。

## Remaining blockers

仍缺少三份真實external artifacts：

1. `pq_rbbc_cap_unified_tree_resource_reservation_v2_39.json`；
2. `pq_rbbc_cap_unified_tree_independent_review_v2_39.json`；
3. 由前兩者生成的`pq_rbbc_cap_unified_tree_launch_manifest_v2_39.json`。

取得前兩份後可產生launch candidate並重新執行唯讀preflight；之後仍需要新的
checkpoint凍結三份identity與明確授權production pre-freeze。不得僅修改manifest中的
boolean來解除gate。

沒有沿用tree 0–17 observed `stream_bytes`、digests或assignments，沒有把v2.29
transcript當成unified-profile observation，沒有修改system architecture、ticket
lifecycle或`pq_sat_auth`。External attestation不得由本工具偽造；assignment、BR1CS、
pickle、cache、logs、resume/checkpoint state及production outputs不得加入Git。
