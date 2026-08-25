# PQ-RBBC v2.14 — Production tree index 2 checkpoint

## 本 checkpoint 完成的事情

本版完成第二種 production producer shape：tree index 2、2,048 leaves、extension degree 12。它直接引用 frozen global-tail 的兩個 consistency points，wire ranges 為 `39,945,673..39,945,865` 與 `39,945,866..39,946,058`；不配置 local point copies。獨立 local namespace 從 frozen global tail 後的 `40,194,597` 開始。

完整 assignment 先生成並封存，再以 global-tail + local archive 做獨立逐列 replay。結果為 25,666,386 rows、19,478,436 local wires、最大 wire ID 59,673,032、0 verification failures、0 external assertions。六個 stale-witness probes 與三個 imported-point mutation probes 全部 fail-closed；四個 producer outputs 全部與 frozen tail value digest 相符。

## Frozen identities

- Row stream SHA-256: `ad31a74cdf00ee96c646a9142da459069655e528aca3cb58cad07dc2b3b26fb8`
- Assignment SHA-256: `63ee82b2421cbb9b4c5346c72dbdb15e26f0ef8e0d2938357fb75228ef8c9a8b`
- Assignment bytes: `486,961,028`
- Tree component SHA-256: `0f1436bae35d6ad66e09375cffc4609efd62eea7f0c6253454f2657a922b3115`
- Output wire starts: `58,805,397`, `59,595,925`, `59,597,973`, `59,668,401`

## Resume contract

Execution cache 綁定 relation ID、CAP profile fingerprint、randomness label、serialized randomness digest、tree index、source assignment digest 與 imported-point value digest。每個 GGM level 與每 128 leaves 原子寫入 checkpoint。Assignment writer 保留中斷 prefix，重播 canonical values 並逐 byte 核對舊 prefix，只 append 新尾端。Assignment generation 與 full replay 是兩個獨立 stage。

## Claim boundary

目前正式關閉 index 0 與 index 2 各自的 producer-native、point-wire identity、output-value match。以下仍明確未關閉：output wire relocations、完整 18-tree materialization/replay、parent CAP-to-H_RBBC join、fork security proof revalidation，以及總 production closure。

## 重現

```bash
python pq_rbbc_cap_production_tree2_producer.py \
  --output-directory production_tree2_v2_14 \
  --global-archive pq_rbbc_cap_global_tail_assignment_v2_9.f193assign \
  --global-manifest pq_rbbc_cap_global_tail_manifest_v2_9.json \
  --manifest production_tree2_v2_14/pq_rbbc_cap_production_tree2_manifest_v2_14.json \
  --workers 8

python -m unittest -v \
  test_pq_rbbc_cap_production_tree2_checkpoint.py \
  test_pq_rbbc_cap_production_tree2_producer.py
```

## 下一個實作點

把 sealed index-2 manifest evidence 傳入 `pq_rbbc_native_profile.py`、Blind-UOV ABI、reference model 與 BR1CS manifest；驗證 parent BR1CS bytes 保持不變，同時只提升 index-2 checkpoint claims，不提升 18-tree 或 production closure。
