# PQ-RBBC v2.28 aggregate replay preflight

日期：2026 年 9 月 3 日

本 checkpoint只建立完整18-tree aggregate replay的唯讀、fail-closed preflight。
它不啟動大型replay，也不把individually sealed tree assignments誤當成aggregate
assignment evidence。

## Frozen preflight

Manifest：`manifests/pq_rbbc_cap_aggregate_preflight_manifest_v2_28.json`

SHA-256：
`c82b435527efe1d343cc6499b408e53f570bcfa47905597afcae890c6125b915`

Frozen namespace固定18棵tree、586,057,567 planned composition rows、
513,312,336 producer rows、15,938,520 output-relocation rows及max wire ID
429,757,232。18份tree assignments合計9,739,068,204 bytes；加入global tail後
為10,743,933,232 bytes。

## Current environment result

本機report：`/tmp/pq_rbbc_aggregate_environment_preflight_v2_28.json`

完整 runner 已實作並以 frozen SHA-256 綁定；本機重建的 tree 0–17、global-tail、
incremental BR1CS 與 prior evidence 均可供唯讀 environment preflight 核對。
Report只寫入`/tmp`，不納入Git；大型 replay 不會由 preflight 自動啟動。

本機實測結果為`safe_to_start_large_replay = true`。檢查時可用記憶體
29,716,008,960 bytes、`/tmp`可用磁碟666,135,166,976 bytes，均高於frozen floor。

## Exact execution command

以下是全部18份archive通過preflight後的精確CLI contract。

```bash
PYTHONPATH=src python src/pq_rbbc_cap_aggregate_replay.py \
  --namespace-manifest manifests/pq_rbbc_cap_production_namespace_manifest_v2_16.json \
  --prior-evidence artifacts/metadata/tree11_17_bounded_recovery_v2_27/pq_rbbc_cap_tree11_17_bounded_recovery_evidence_v2_27.json \
  --global-archive /external/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign \
  --trusted-composer-execution-cache /external/local-recovery/pq_rbbc_cap_composition_execution_v2_8.pkl \
  --incremental-br1cs /external/pq_rbbc_incremental_v2_25.br1cs \
  --tree-archive 0=/external/tree0.f193assign \
  --tree-archive 1=/external/tree1.f193assign \
  --tree-archive 2=/external/tree2.f193assign \
  --tree-archive 3=/external/tree3.f193assign \
  --tree-archive 4=/external/tree4.f193assign \
  --tree-archive 5=/external/tree5.f193assign \
  --tree-archive 6=/external/tree6.f193assign \
  --tree-archive 7=/external/tree7.f193assign \
  --tree-archive 8=/external/tree8.f193assign \
  --tree-archive 9=/external/tree9.f193assign \
  --tree-archive 10=/external/tree10.f193assign \
  --tree-archive 11=/external/tree11.f193assign \
  --tree-archive 12=/external/tree12.f193assign \
  --tree-archive 13=/external/tree13.f193assign \
  --tree-archive 14=/external/tree14.f193assign \
  --tree-archive 15=/external/tree15.f193assign \
  --tree-archive 16=/external/tree16.f193assign \
  --tree-archive 17=/external/tree17.f193assign \
  --checkpoint-directory /external/v2_28_aggregate/checkpoints \
  --manifest /external/v2_28_aggregate/pq_rbbc_cap_aggregate_replay_manifest_v2_28.json \
  --workers 8 \
  --full-row-replay
```

Runner必須stream全部18份planned assignments、只讀取一份global tail、驗證72個
relocated output values與wire IDs、point與segment-boundary identity，並完整replay
586,057,567 rows且零failure。Checkpoint不得接受下載或不可信pickle。

在aggregate replay完成前，`complete_18_tree_assignment_replayed`、
`cross_segment_wire_identity_closed`、parent join、fork-security及production closure
均維持false。
