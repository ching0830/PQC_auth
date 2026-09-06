# PQ-RBBC v2.28 aggregate recovery evidence

日期：2026 年 9 月 3 日

## 結果

V2.28 runner依frozen namespace順序，以唯讀方式重放18份planned tree
assignments、逐wire核對72個relocation ranges，最後重放同一份global-tail
assignment。完成的row accounting如下：

| Segment | Rows | Failures |
| --- | ---: | ---: |
| Tree producers 0–17 | 513,312,336 | 0 |
| 72 output relocations | 15,938,520 | 0 |
| Global tail | 56,806,711 | 0 |
| Aggregate total | 586,057,567 | 0 |

External aggregate replay manifest SHA-256：
`495e528901f8f79247861d9da24bc5019a6b938880c5ea6172cda323339c8804`

Ordered replay transcript SHA-256：
`4cc7215db0d009c26bf3bc8576a984f3bb884528855a8084305ffd0499b7e134`

## Portable evidence

Path-free evidence：
`artifacts/metadata/aggregate_recovery_v2_28/pq_rbbc_cap_aggregate_recovery_evidence_v2_28.json`

SHA-256：
`820bc4e7b9e6e4e9c41153b48088089a6f15181a5bc3f99c60e37fe242d4f2a1`

Sealer不讀取aggregate checkpoint，也不載入任何pickle。它重新核對18份tree
archives、global-tail assignment、incremental BR1CS、namespace manifest、v2.27
prior evidence、frozen preflight manifest、aggregate runner和external replay
manifest的exact byte/SHA identities。Aggregate input identity另由archive set、
runner SHA與本機recovery所得composer semantic execution digest重新計算。

## Claim boundary

本證據只關閉`complete_18_tree_assignment_replayed`與
`cross_segment_wire_identity_closed`，並保留archive identity及72-link precheck
closure。`parent_cap_to_h_rbbc_join_closed`、`fork_security_proof_revalidated`與
`production_closed`全部維持false。

所有assignments、BR1CS、pickle/cache、checkpoint/resume state與logs均保留在
Git之外。
