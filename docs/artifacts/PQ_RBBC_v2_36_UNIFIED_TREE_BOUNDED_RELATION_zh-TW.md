# PQ-RBBC v2.36 unified-tree bounded checkpoint payload與relation generator

## 結論

V2.36已實作production-shaped checkpoint payload格式及bounded unified-tree relation
generator，並在40-leaf、18-vector、test-only profile上完成實際qualification。Runner先
在`unified-tree`階段中斷，將完整中間值寫入repo外的canonical JSON payload；resume
必須提供該payload的精確SHA-256，之後relation generator獨立重算並驗證144條
contract-IR equality rows。

本checkpoint關閉的是bounded implementation與control-flow qualification，不是
production-scale relation：

- `checkpoint_payload_format_qualified_on_bounded_fixture = true`；
- `bounded_relation_generator_qualified = true`；
- `production_checkpoint_payload_materialized = false`；
- `production_relation_generator_scale_qualified = false`；
- `safe_to_start_production_prefreeze = false`；
- `safe_to_start_large_replay = false`；
- `safe_to_start_large_proving_run = false`。

## Protocol位置

以protocol來看，v2.35只證明單一unified root producer的控制流程可以運作；v2.36
再加入兩個接點：

1. checkpoint payload保存plan、明確分離的public statement/private witness、
   unified-tree中間值與bounded relation結果；每個stage都綁定前一chain及canonical
   stage data；
2. relation generator從checkpoint重新驗證seed expansion、position-major mapping、
   leaf commitment/tape、18個logical vector hashes、unified root、commitment codec、
   opening及downstream parent-input candidate binding。

Bounded fixture同時呼叫既有reference ticket relation，確認原有ticket statement與
witness仍接受；沒有改動ticket payload或lifecycle。Downstream parent-input row目前只
定義「public statement bytes + unified commitment」的candidate digest，沒有重播
v2.29 parent relation，也沒有將它升格為production parent join。

## Checkpoint payload

Payload格式為`PQRBBC-CAP-UNIFIED-TREE-CHECKPOINT-PAYLOAD-1`，stage order固定為：

1. `plan`；
2. `inputs`；
3. `unified-tree`；
4. `bounded-relation`。

每一stage record都包含prior chain、canonical data digest及新的chain digest；stage
必須是contiguous prefix。Resume除了重新驗證source contract外，還必須由operator
提供預期checkpoint SHA-256，不能只信任payload自帶的chain。Private witness只存在
repo外payload；portable evidence不包含witness bytes。Pickle、隱式cache與overwrite
均被禁止。

本次中斷payload為20,959 bytes，SHA-256
`88ef0b5584a090ffcc18e36d58333742027545c34e1d4261172f9d1e1df85024`；完成payload為
21,530 bytes，SHA-256
`a605d18efa8f23eec3c89da1e4497ddff2c29790c0ea3cb0b7017808cfa39a17`。
Payload identity包含本次runtime observation，故只用於該次resume授權；跨run的
deterministic result identity另行排除elapsed time與RSS。

## Bounded relation observation

144條equality rows的分組為：

| Stage | Rows |
| --- | ---: |
| public statement binding | 1 |
| private witness binding | 1 |
| unchanged reference ticket relation | 1 |
| seed expansion | 39 |
| position-major mapping | 40 |
| leaf commitment and tape | 40 |
| logical vector hashes | 18 |
| unified root hash | 1 |
| commitment codec | 1 |
| opening verification | 1 |
| downstream parent-input candidate binding | 1 |

結果為144/144 satisfied、0 failures。Relation document為40,542 bytes，SHA-256
`38798e22796af846206e8234fbb15e0ed243c3e0722e363980bf655df9a375cc`；canonical
row stream為39,620 bytes，SHA-256
`d59afc7818dd945150206e33ded77e39851876227035bbdb59e2ce23697e80c9`。
跨runtime deterministic result identity為
`10331098958ad60c3433ff0be8c81a22d1d4575a7840eecb924d70cf4bfd8226`。

這144條是checkpoint-contract IR，不是BR1CS、R1CS或production relation rows。
同一row grammar套到40,960-leaf形狀時會有122,904條contract rows，但這只是shape
projection，不是execution observation，更不能取代589,054,075-row planning lower
bound或v2.29的589,030,555-row歷史transcript。

## Resource observation

正式qualification的bounded observations為：

- tree generation：34.715秒；
- relation獨立重算：51.955秒；
- peak RSS：32,579,584 bytes；
- bounded leaves：40；production leaves：0；
- production relation／BR1CS／proof rows：0。

這些數字只適用於Python test-only fixture，不能線性外推production。Production
reservation仍須至少符合v2.34的4 cores、16 GiB available memory、80 GiB free disk，
並由operator明確核准wall-clock window。

## Exact commands

已執行的bounded qualification：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_bounded_relation.py \
  --manifest manifests/pq_rbbc_cap_unified_tree_bounded_relation_manifest_v2_36.json \
  --phase qualification \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/qualification \
  --fresh-cache
```

Portable sealer：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_bounded_relation_evidence.py \
  --checkpoint-payload /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/qualification/pq_rbbc_cap_unified_tree_checkpoint_payload_v2_36.json \
  --bounded-relation /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/qualification/pq_rbbc_cap_unified_tree_bounded_relation_v2_36.json \
  --run-evidence /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/qualification/pq_rbbc_cap_unified_tree_bounded_relation_evidence_v2_36.json \
  --qualification /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/qualification/pq_rbbc_cap_unified_tree_bounded_relation_qualification_v2_36.json \
  --output artifacts/metadata/cap_unified_tree_bounded_relation_v2_36/pq_rbbc_cap_unified_tree_bounded_relation_portable_evidence_v2_36.json
```

Prospective production command只供review，目前固定fail closed：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_bounded_relation.py \
  --manifest manifests/pq_rbbc_cap_unified_tree_bounded_relation_manifest_v2_36.json \
  --phase production-prefreeze \
  --authorization-manifest /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/pq_rbbc_cap_unified_tree_launch_authorization_v2_36.json \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_36_unified_tree_relation/production-prefreeze \
  --fresh-cache --allow-large
```

Command SHA-256為
`69c2c59fbb414299789987ff1522d13d57e20ea07b906a9e6a0c79f38e239e1c`；
`executable_now=false`且`authorized_now=false`。

## Evidence identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| bounded relation implementation | 48,372 | `c69bce3063045f6f468993e7b940d7d3c1277859e75ca546a13325d497a374a7` |
| frozen manifest | 4,283 | `5cc01d28b5cc4ed4c4520b8257d0dc0e159777242c85d24f42325e2f68bb72f4` |
| implementation tests | 8,172 | `e173c71292babd7dd527bb817d41c9b85fdf3a5f62c76c3cac21686e166a9947` |
| sealer tests | 3,359 | `9b58f9705f364cb0683e91d9dfacf11ad24165e1d4967234f2bb98b1778dae86` |
| completed external checkpoint | 21,530 | `a605d18efa8f23eec3c89da1e4497ddff2c29790c0ea3cb0b7017808cfa39a17` |
| external bounded relation | 40,542 | `38798e22796af846206e8234fbb15e0ed243c3e0722e363980bf655df9a375cc` |
| external run evidence | 3,042 | `2347a9b02f8a55f7b1a4880093bc2f0974df47a828e7b429af7b7c8e75069dc3` |
| external qualification | 2,534 | `d97cc7543d2c917ad83073fc621bc056f6d06650184e3ae97fcec1040989b280` |
| portable evidence | 5,719 | `660d4c0d9cf36bbb5ecf02dc66d65721e077171de5b1e9c6b010d19871235fad` |

Portable evidence位於
`artifacts/metadata/cap_unified_tree_bounded_relation_v2_36/pq_rbbc_cap_unified_tree_bounded_relation_portable_evidence_v2_36.json`。
Checkpoint、relation document、run evidence與qualification保持external，不加入Git。

## Remaining blockers與claim boundary

Production仍缺：production-scale payload materialization、scale qualification、final
unified-profile statement encoding、operator resource reservation、independent review、
明確execution authorization及identity-frozen launch manifest。Production observations、
pre-freeze、large replay/proving、CAP／fork security與production closure全部維持false。

沒有沿用tree 0–17的observed `stream_bytes`、digests或assignments；沒有把v2.29
transcript當成新profile observation；沒有建立assignment、BR1CS、pickle或proof；
system architecture、ticket lifecycle與`pq_sat_auth`均未修改。
