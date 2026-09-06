# PQ-RBBC v2.40 Trace KDF source-identity transition

## 目的

Commit `6b3d54bcf4918d9706e6f067eedb8aa552c09b96` 已修正 Trace KDF 的
canonical split，但其內容在後續 merge 後沒有留在 `main` effective tree。Corrective
commit `13c0524618b1036063f4cb51f8d3b1147fcf595e` 從
`main@7769a2e1c9c5aba625d32bb1f9849a81ef111e31` 重新套用相同三檔內容。

V2.40 不改寫 v2.29／v2.30 manifests、portable evidence 或 checksum inventories；
它另以
`manifests/pq_rbbc_trace_kdf_source_transition_manifest_v2_40.json` 記錄舊 identity
及唯一允許的 corrective successor identity。歷史 checkout 可依原 identity
驗證；目前 checkout 若不符合歷史 identity，必須完整符合 v2.40 manifest
所列三個 source/test identities，不能只放寬其中一個 hash。

## Canonical contract

Trace KDF 固定輸出 80 bytes，byte indexing 為 zero-based、half-open：

```text
Z = P || K_mac
P     = Z[0:48]
K_mac = Z[48:80]
```

Direct reference 使用 `split_trace_kdf_output`，constraint circuit 使用
`split_trace_kdf_wires`。79／81-byte 與 639／641-bit 輸入必須拒絕；reverse-order
instance 必須同時被 direct relation 與 constraint circuit 拒絕。

## Claim boundary

- frozen pad、MAC key、masked identity、tag、ticket payload 及 ticket digest
  vectors 未改變；
- v2.29 parent-join execution evidence 與 v2.30 fork-security evidence 保持歷史、
  read-only；
- `production_opening_implemented = false`；
- PQ simulation-extractable backend、fork-security proof 與 production closure
  仍為 false。

## 驗證

```bash
PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_reference \
  tests.test_pq_rbbc_trace_kdf_source_transition \
  tests.test_pq_rbbc_parent_join_preflight \
  tests.test_pq_rbbc_fork_security_preflight -v

PYTHONPATH=src python -m unittest discover -s tests -v
```
