# PQ-RBBC v2.37 unified statement serialization與parent-input ABI

## 結論

V2.37已在獨立unified-tree namespace凍結canonical public statement serialization及
parent-input ABI，並以v2.36的40-leaf bounded checkpoint完成qualification。Production
profile只產生314-byte deterministic statement test vector；沒有production `c_r`，所以
沒有產生或宣稱production parent envelope，也沒有啟動production tree、relation、
replay或proving。

Qualification結果為：

- `production_profile_statement_serialization_qualified = true`；
- `bounded_parent_input_abi_qualified = true`；
- `ticket_mapping_qualified_on_bounded_fixture = true`；
- `safe_to_author_production_streaming_path = true`；
- `production_parent_input_qualified = false`；
- `safe_to_start_production_prefreeze = false`；
- `safe_to_start_large_replay = false`；
- `safe_to_start_large_proving_run = false`。

## Protocol位置

以protocol來看，v2.36已能重播「ticket relation → unified root」的bounded relation，
但parent仍只看到未凍結的candidate digest。V2.37把這個接點拆成兩層：

1. `UnifiedCAPStatement`固定public input欄位
   `(common_parameters_digest, ctx, sid, rid, y)`的順序、寬度、profile及bytes；
2. `UnifiedParentInput`固定parent取得的
   `(statement, c_r, ticket_message, binding_digest)`，並要求statement與`c_r`使用同一
   unified-tree profile。

`ctx`直接對應既有`IssueStatement.common_ctx`，`rid`對應
`IssueStatement.rid`，`y`對應`blind_request.masked_target`；`ticket_message`仍是
`SHAKE256("PQ-RBBC/TICKET" || payload)[0:32]`。`sid`是由既有ticket serial經新domain
導出的session identifier，不會重新定義ticket serial。Statement是public input；
private witness沒有進入這兩個codec或portable evidence。

這只凍結新的unified-tree parent ABI。V2.32的legacy statement profile fingerprint
`2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`及18-tree
evidence完全保留，沒有被覆寫或重新標記。

## Canonical encoding

Statement magic為`PQRBBC-CAP-UGGM-STATEMENT-V1`，version為u16le `1`，接續32-byte
profile fingerprint及五個依ID遞增的length-prefixed fields：

| ID | Field | Bytes |
| ---: | --- | ---: |
| 1 | `common_parameters_digest` | 32 |
| 2 | `ctx` | 32 |
| 3 | `sid` | 32 |
| 4 | `rid` | 32 |
| 5 | `y` | 72 |

PPUarent-input magic為`PQRBBC-CAP-UGGM-PARENT-INT-V1`，同樣使用u16le version、
32-byte profile及canonical section order：statement、`c_r`、ticket message、32-byte
binding digest。Binding使用domain-separated SHA-256並對三個變長值加入u64le長度。
Wrong magic/version/profile/order/length、cross-profile decode、trailing bytes、stale
binding及ticket/checkpoint mapping mutation均fail closed。

## Bounded observation

V2.36 completed checkpoint identity為21,530 bytes、SHA-256
`a605d18efa8f23eec3c89da1e4497ddff2c29790c0ea3cb0b7017808cfa39a17`。
由其中unified-tree stage取出的bounded `c_r`為158 bytes、SHA-256
`3efd0855f2c0b9d066dbc672b3e1e6bfef268700d11d7071260f9d8fdc55079e`。

本次輸出：

| Observation | Bytes | SHA-256 |
| --- | ---: | --- |
| production-profile statement bytes | 314 | `7774101a4ef656dc3c68f06420d04db85a6bb1f9625a9ac81154ed9619568db5` |
| bounded-profile statement bytes | 314 | `70d6b51374c74e739a6c7df0e61261b47c22b06b28b11ed70d47584ee5bb64bc` |
| bounded parent-input bytes | 643 | `f94f9b369143a28808fa2ef47f43a7e7615b99d7aa824217ad924a45045d0500` |

16/16 mutation probes均拒絕。Production statement只是codec test vector；production
parent envelopes、production leaves、relation rows、BR1CS rows及proofs全部為0。

## Exact commands

已執行的bounded qualification：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_statement_parent_abi.py \
  --manifest manifests/pq_rbbc_cap_unified_statement_parent_abi_manifest_v2_37.json \
  --phase qualification \
  --checkpoint-payload /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/qualification/pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_37_unified_statement_parent_abi/qualification \
  --fresh-output
```

Command SHA-256為
`7689540d0fd686bf4e8b8b3746abb4bb9e46d212aa02b82a72b5f8bfaad1fec0`。

Portable sealer：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_statement_parent_abi_evidence.py \
  --checkpoint-payload /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/qualification/pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json \
  --production-vector /tmp/pq_rbbc_external_artifacts_rebuilt/v2_37_unified_statement_parent_abi/qualification/pq_rbbc_cap_unified_statement_production_vector_v2_37.json \
  --bounded-vector /tmp/pq_rbbc_external_artifacts_rebuilt/v2_37_unified_statement_parent_abi/qualification/pq_rbbc_cap_unified_parent_input_bounded_vector_v2_37.json \
  --run-evidence /tmp/pq_rbbc_external_artifacts_rebuilt/v2_37_unified_statement_parent_abi/qualification/pq_rbbc_cap_unified_statement_parent_abi_evidence_v2_37.json \
  --qualification /tmp/pq_rbbc_external_artifacts_rebuilt/v2_37_unified_statement_parent_abi/qualification/pq_rbbc_cap_unified_statement_parent_abi_qualification_v2_37.json \
  --output artifacts/metadata/cap_unified_statement_parent_abi_v2_37/pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json
```

Prospective production command只供review，程式目前固定在建立output前拒絕；command
SHA-256為
`7e378a8014f0cdbee2cfb45be349ae0a6a05b855c387334f373e932fd4fa4458`。

## External與portable evidence

External qualification目錄為
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_37_unified_statement_parent_abi/qualification`：

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| production statement vector | 1,569 | `23f811f1eba9686d8f3fcea20a9d871160ec636c2f462073cf7064a0821c08e6` |
| bounded parent-input vector | 3,062 | `655e3969695b8015a83b1dad29f98c98b15c2f59d41c3890901bd23da62365ff` |
| run evidence | 2,279 | `77f5c9c175c245233707f7c0f16377047f630633f46d2cd0a167ffb938112a78` |
| qualification | 3,163 | `e87d3cf29429ba5b60b1f1bd85e35c386275e7edd7902f779b910282ad840dce` |

Path-free portable evidence為
`artifacts/metadata/cap_unified_statement_parent_abi_v2_37/pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json`
（5,188 bytes，SHA-256
`672c27f8ed0bfc567d3080c9645c079d9009ce7ff815957c9384dc0246b3c8b7`）。

External vectors與qualification不加入Git。早期mapping audit保留在獨立external
directory，未被升格為final evidence。

## 下一個安全步驟

V2.37只解除「final unified statement encoding」這個blocker。下一步可撰寫
production streaming／checkpoint materialization path及唯讀launch preflight，但在
operator resource reservation、independent review、explicit authorization及
identity-frozen launch manifest齊備前，仍不可執行production pre-freeze。

沒有沿用tree 0–17 observed `stream_bytes`、digests或assignments；沒有把v2.29
transcript當成新profile observation；沒有建立或提交assignment、BR1CS、pickle、
cache、log、resume/checkpoint state或proof；system architecture、ticket lifecycle及
`pq_sat_auth`均未修改。
