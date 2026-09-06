# PQ-RBBC v2.38 unified-tree streaming checkpoint與launch preflight

## 結論

V2.38已實作profile-bound binary chunk codec、external-only checkpoint chain及精確
identity resume，並以v2.36／v2.37的bounded artifacts完成qualification。179個bounded
records依固定stage order寫成15個chunks；runner在第7個chunk後中斷，再使用中斷
checkpoint的精確SHA-256恢復並完成相同stream。

同時已執行唯讀production launch preflight。目前host容量超過planning minimum，但
operator resource reservation、independent review及identity-frozen launch manifest均
不存在，production stream亦未materialize、runner未做scale qualification。因此：

- `bounded_stream_materializer_qualified = true`；
- `external_checkpoint_resume_qualified = true`；
- `safe_to_request_resource_reservation = true`；
- `safe_to_request_independent_review = true`；
- `safe_to_freeze_launch_manifest = false`；
- `safe_to_start_production_prefreeze = false`；
- `safe_to_start_large_replay = false`；
- `safe_to_start_large_proving_run = false`。

## Protocol位置

V2.37固定了parent要收到的`statement + c_r + ticket_message`。V2.38處理的是在不把
整份production state長期留在記憶體的情況下，如何把unified CAP tree的資料逐段寫到
repo外，並讓中斷後的執行只能從精確的已驗證prefix恢復：

```text
tree nodes
  → leaf commitments
  → leaf tapes
  → 18 logical-vector hashes
  → unified commitment c_r
  → v2.37 parent input
```

每個chunk都綁定profile fingerprint、stage、chunk ordinal、第一個item index、record
count及固定寬度payload。Checkpoint的每筆record綁定chunk filename／bytes／SHA-256及
前一chain digest；resume還必須由呼叫者提供預期checkpoint SHA-256，不能只信任
checkpoint內的self-reported chain。

最後一個stream record是v2.37 bounded parent input，確認streaming boundary確實接到
parent ABI。這仍只是40-leaf fixture；沒有建立production `c_r`或production parent
input。

## Bounded qualification

Bounded layout為：

| Stage | Records | Payload bytes/record | Chunks |
| --- | ---: | ---: | ---: |
| tree nodes | 79 | 25 | 5 |
| leaf commitments | 40 | 49 | 3 |
| leaf tapes | 40 | 8 | 3 |
| logical-vector hashes | 18 | 49 | 2 |
| unified commitment | 1 | 158 | 1 |
| parent input | 1 | 643 | 1 |
| **Total** | **179** | — | **15** |

Raw payload為5,938 bytes；包含chunk headers後的15個binary files合計7,899 bytes。
Chunk-identity stream SHA-256為
`b3ee7d5659380d629b1baece4dedf8aa3342beba16d0c5cae765e842161c5c11`；
跨resume deterministic result identity為
`87edb3d69ca6bba3dbcedb553db7dc3ce8c98be4954df5315a6dd1d57b3479c8`。

中斷checkpoint為5,041 bytes，SHA-256
`dd30629ce8a9b64e9d4e8175dffe9421d33173fd321d2a7e6fc9019e737eb517`；
完成checkpoint為8,495 bytes，SHA-256
`b5ef245fb1af0a08e983f6ab49b3353f0cbbe708c808db90661f9fdec079f805`。
Checkpoint／chunk mutation、overwrite、缺少resume identity及production branch均
fail closed。

## Production layout與資源估算

Production layout只是一份未執行的plan：163,859 records、163 chunks、raw payload
16,631,418 bytes。其分組為81,919個tree nodes、40,960個leaf commitments、40,960個
2,450-bit tapes、18個vector hashes、1個commitment及1個parent input。

這16.6 MB只計算tree stream的raw serialized payload，不包含relation rows、assignment、
BR1CS、checkpoint overhead或兩次完整replay。完整relation仍以至少589,054,075 rows及
至少1,178,108,150次two-pass row checks規劃；它們不是v2.38 observation。

沿用保守minimum：4 CPU cores、16 GiB available memory及80 GiB free disk；wall-clock
仍未凍結，不能由40-leaf benchmark線性外推。本次preflight觀察到12 cores、
29,676,052,480 available-memory bytes及664,067,985,408 free-disk bytes。容量合格不等於
execution authorization。

## Exact commands

已執行的bounded qualification：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_streaming_prefreeze.py \
  --manifest manifests/pq_rbbc_cap_unified_tree_streaming_prefreeze_manifest_v2_38.json \
  --phase qualification \
  --checkpoint-payload /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/qualification/pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json \
  --bounded-parent-vector /tmp/pq_rbbc_external_artifacts_rebuilt/v2_37_unified_statement_parent_abi/qualification/pq_rbbc_cap_unified_parent_input_bounded_vector_v2_37.json \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_38_unified_tree_streaming/qualification \
  --fresh-output
```

Command SHA-256：
`7cf117bc50f8608e92a31279a20107c3cf01f114296b37e4e1882a3226cdc819`。

唯讀launch preflight的exact command已凍結，SHA-256
`33454b8588fdba8160497ccabd6ca3c57d7f496bd7df500076485b1052002419`。
該command即使取得schema-shaped candidates，也只產生report；v2.38不凍結外部
attestation identities。

Prospective production command SHA-256為
`79da988d8cb17fe23a5e9f263da9bc0f11514f0a36280918278d485176b45c57`。
程式目前固定在建立production output前拒絕，`executable_now=false`及
`authorized_now=false`。

## Evidence identities

External qualification目錄：
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_38_unified_tree_streaming/qualification`。

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| completed checkpoint | 8,495 | `b5ef245fb1af0a08e983f6ab49b3353f0cbbe708c808db90661f9fdec079f805` |
| stream index | 3,505 | `22814bb97f94a89f6283b7aa4722260201364c01f7600b70577a334ab61d7b88` |
| run evidence | 2,530 | `e7e27f8e03717a98691352b6a676075ece08955338fff5760749a025381a15cc` |
| qualification | 3,527 | `812d49a04b86a3311db743678604e3c00a5b80cd48f9c524243cc83a78baf185` |
| launch preflight | 4,555 | `e88bfc3d3512ded3f6559cc90525eec1ed4f79b0d52959a5f04a3c6b82750e8c` |

Path-free portable evidence：
`artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json`
（7,390 bytes，SHA-256
`7f846858350deefa6a6d4df2dec43a852f8e6deb9c55c99e289c2062f822979e`）。

Binary chunks可能包含seed與tape material，因此必須保持external；checkpoint、index、
run evidence、qualification及preflight report也不加入Git。兩次fail-closed開發audit
保留在另外的external directories，沒有升格為final evidence。

## Remaining blockers

目前缺少三份v2.38 external artifacts：

1. operator resource reservation；
2. independent design／cryptographic review；
3. 綁定前兩者、v2.37 seal、v2.38 implementation及exact command的launch manifest。

此外production stream／checkpoint尚未materialize，production runner尚未scale
qualification。下一步應先取得前兩份attestation，再建立identity-frozen launch
manifest checkpoint；未完成前不得執行production pre-freeze。

沒有沿用tree 0–17 observed `stream_bytes`、digests或assignments；沒有把v2.29
transcript當成新profile observation；沒有建立assignment、BR1CS、pickle、cache、log
或proof；system architecture、ticket lifecycle及`pq_sat_auth`均未修改。
