# PQ-RBBC v2.26 tree 8–10 bounded preflight

日期：2026 年 8 月 30 日

本 checkpoint 只固定 tree 8、9、10 的初始 contract 與執行前置條件；不代表
assignment 已 materialize、完整 replay 已完成或 evidence 已 seal。三個 target 的
`stream_bytes` 均為 `null`，不得引用其他 tree 的 observed byte count。

## Frozen preflight identity

Tracked manifest：
`manifests/pq_rbbc_cap_tree8_10_preflight_manifest_v2_26.json`

SHA-256：
`e74bbed37b385ae584e2c77a0a395ee31661093453526243eb4704d0397b70e5`

驗證命令：

```bash
PYTHONPATH=src python src/pq_rbbc_cap_tree8_10_preflight.py \
  --verify-frozen \
  manifests/pq_rbbc_cap_tree8_10_preflight_manifest_v2_26.json
```

## External artifact preflight

不得載入下載或其他不可信來源的 pickle。以下命令只讀取 non-pickle artifact、
驗證 exact size／SHA-256 並產生環境報告，不會啟動 replay：

```bash
PYTHONPATH=src python src/pq_rbbc_cap_tree8_10_preflight.py \
  --report /tmp/pq_rbbc_tree8_10_environment_preflight_v2_26.json \
  --global-archive /workspace/pq_rbbc_external_artifacts_v2_20/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign \
  --batch-root /workspace/pq_rbbc_external_artifacts_v2_25 \
  --incremental-br1cs /workspace/pq_rbbc_external_artifacts_v2_25/pq_rbbc_incremental_v2_25.br1cs
```

只有報告中的 `safe_to_start_large_replay` 為 `true` 才能準備第一棵 tree。

## Initial replay commands

每棵 tree 必須使用不同 external directory、artifact tag 與 trusted local cache。
以下命令僅適用於 external preflight 成功後的 tree 8 pre-freeze replay：

```bash
PYTHONPATH=src python src/pq_rbbc_cap_planned_tree_producer.py \
  --tree-index 8 \
  --manifest /workspace/pq_rbbc_external_artifacts_v2_26/tree8/prefreeze_manifest.json \
  --output-directory /workspace/pq_rbbc_external_artifacts_v2_26/tree8 \
  --global-archive /workspace/pq_rbbc_external_artifacts_v2_20/pq_rbbc_cap_global_tail_assignment_v2_9.f193assign \
  --global-manifest manifests/pq_rbbc_cap_global_tail_manifest_v2_9.json \
  --execution-cache /workspace/pq_rbbc_external_artifacts_v2_26/tree8/tree8_prefreeze_cache.pkl \
  --artifact-tag v2_26_tree8_prefreeze \
  --workers 8
```

Tree 9 與 tree 10 必須依序執行，並分別使用 `tree9`／`tree10` directory、
cache 與 artifact tag。第一次完整 replay 只建立 `prefreeze_complete` evidence。
觀測值必須逐 tree 凍結到新的 final contract，之後使用 fresh local cache、以
read-only assignment archive 再完整 replay。第二次 replay 完成前，所有 target
formal claims 必須維持 false。

## Prohibited artifacts

不得 commit assignment、BR1CS、pickle、execution cache、checkpoint、resume state
或 logs。Portable evidence 不得包含 absolute local paths。
