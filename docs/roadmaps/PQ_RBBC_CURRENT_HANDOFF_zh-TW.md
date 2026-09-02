[English](PQ_RBBC_CURRENT_HANDOFF.md)

# PQ-RBBC 目前交接 — v2.26 tree 8–10 bounded recovery

> **模組範圍：**這是 PQ-RBBC 的操作交接，不是整篇論文 roadmap。專案級背景請先讀 [../../ARCHITECTURE_zh-TW.md](../../ARCHITECTURE_zh-TW.md)、[../../RESEARCH_STATUS_zh-TW.md](../../RESEARCH_STATUS_zh-TW.md) 與 [../../ROADMAP_zh-TW.md](../../ROADMAP_zh-TW.md)。

日期：2026 年 9 月 2 日

新工作階段請先讀本文件、[v2.26 fresh rebuild 進度](../artifacts/PQ_RBBC_v2_26_FRESH_REBUILD_PROGRESS_zh-TW.md)、[tree 8–10 preflight](../artifacts/PQ_RBBC_v2_26_TREE8_10_PREFLIGHT.md) 與 `docs/ARTIFACT_POLICY.md`。開始前必須確認 local／remote `main` 的精確 commit，不可推測尚未整合的 branch 已生效。

## 基底與已封閉邊界

v2.26 bounded recovery 已整合至 local `main` commit `b9c09f1266d269164fd9bded996e8cc38deb91c6`。Planned producer indices 0–10 已 materialize 並依各自 frozen contract 獨立 replay，共 11／18。

Tree 8、9、10 均採兩階段流程：先以 tree-specific directory／artifact tag／cache 完成 pre-freeze replay，再凍結該 tree 自身觀測的 row-stream identity，最後以另一個 fresh cache 完成 frozen replay。沒有跨 tree 沿用 observed stream identity。

已 evidence-sealed 的 bounded components 包含：

- v2.8 composer recovery 與 v2.9 global tail；
- tree 2 rebased replay；
- tree 1、3、4 planned replay；
- tree 5–7 bounded batch；
- tree 8–10 bounded recovery。

這不代表全部 72 relocations、完整 18-tree replay、cross-segment identity、parent join、fork-security proof、production proof backend、signature benchmark 或 production closure 已完成。

## v2.26 portable evidence

Path-free bounded evidence：

`artifacts/metadata/tree8_10_bounded_recovery_v2_26/pq_rbbc_cap_tree8_10_bounded_recovery_evidence_v2_26.json`

SHA-256：

`9a8ad3b2b5af242ef6ee6b33d99035505c1b8a5764d84766ce6d44f9cd00895f`

其 claim boundary 僅推進：

- `materialized_planned_tree_indices = [0, ..., 10]`；
- `materialized_planned_tree_count = 11`。

`remaining_planned_tree_producers_materialized`、`all_72_output_relocations_closed`、`complete_18_tree_assignment_replayed`、`cross_segment_wire_identity_closed`、`parent_cap_to_h_rbbc_join_closed`、`fork_security_proof_revalidated` 與 `production_closed` 全部維持 `false`。

## 必要 identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| v2.9 global-tail assignment | 1,004,865,028 | `946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1` |
| incremental BR1CS | 49,227,687 | `77577df2e8284284c5501b1a68f3009399cebef85512a4dfb094dd0cc32bc799` |
| tree-8 assignment | 486,961,028 | `bf3c1f6ef1fa34b3d5cb9e11d85e65b33a3dbe80c926cf2cd86be291d19c884c` |
| tree-8 frozen manifest | 7,685 | `6e7f4df14772370727940b9367430a8ad37d3eaa4e29a97f174133922c8e69cc` |
| tree-9 assignment | 486,961,028 | `6233e0639bfd09b93bfb1967f5a696fad09eadc7ca5e4f2c9df4fc804a015f19` |
| tree-9 frozen manifest | 7,686 | `f82ce1c1733d30e9c49e69551eeee80698230f01f4857b868764ff51d8f8b806` |
| tree-10 assignment | 486,961,028 | `23ad60862f387387aba139a8465891f7ada0fe4da5be8a318177217094c39bd8` |
| tree-10 frozen manifest | 7,699 | `8c56f7c426ad1f632af36c0d4e40536ff5726a5875734d7014d0b9c429fb067d` |

Tree-specific frozen identities：

| Tree | Final contract SHA-256 | Row-stream bytes | Row-stream SHA-256 | Component SHA-256 |
| ---: | --- | ---: | --- | --- |
| 8 | `15277b5065ef5b97dc7919306c3c1044826b98adee3a92f12be9cde5f9623c99` | 8,961,160,824 | `c6f593afc2afe6393800c26f27203cbc4e1bb3e83cfe57c2ac6cc812553285af` | `c0037cfb5a06379b463d8430e4b8ffbd114db452814283d2330a3cd57357075b` |
| 9 | `cd9c33b29af5472856219bde2541d4029cc747692202463012bae9000f622e34` | 8,961,160,824 | `b8e22f80732b78d8b0a0b02957b91c1b746cb26efe10a4e9d5302e0c8d8960fd` | `fab97914348c255bed04debc578cd8c9d27ab73d92744c0d5f24aaf5ec4409b0` |
| 10 | `011d3c249a7d60232074a7f0eb78b34618b097ffcd1c852040fd888263f6e554` | 8,986,785,870 | `44cf5ff0cdf222d58f1522e06afadccf3ad377ce4893575d1ef8f8317a2f3ba2` | `0378694c05c5236207cdb5d9c148e75f4d9ab5245787523d9de8739577bc8d89` |

Tree 10 的 row-stream bytes 與 tree 8／9 不同，證明後續 tree 不得沿用其他 tree 的 observed byte count。

## Replay 驗證狀態

Tree 8、9、10 每棵均具備：

- 25,666,386 rows replayed at planned offset；
- 4／4 output ports exact match；
- 0 verification failures；
- 0 external assertions；
- 6／6 stale-witness probes rejected；
- 3／3 point-mutation probes rejected；
- frozen replay 使用 fresh cache，沒有 resume。

A／B 整合驗證：

- system access／replay 加 v2.26 targeted validators：45 tests passed，0 skipped；
- tree 8–10 preflight frozen manifest accepted；
- 三份 frozen manifests 可精確重建 tracked portable evidence；
- 完整 repository regression：295 tests passed，12 個既有 optional external-artifact tests skipped，0 failures／errors，575.086 秒。

Tracked checksum inventories：

- `checksums/SHA256SUMS_v2_26_PREFLIGHT.txt`；
- `checksums/SHA256SUMS_v2_26_TREE8_10_RECOVERY.txt`。

大型 assignment、BR1CS、pickle、cache、resume state 與 logs 仍只存在 Git 外部。不得反序列化下載或其他不可信 pickle；identity-bound cache 必須在可信本機重建。

## 下一個 bounded checkpoint

下一個候選 batch 是 tree 11–13，但尚未 preflight、materialize 或 replay：

| Tree | Planned interval | Initial contract SHA-256 |
| ---: | --- | --- |
| 11 | 293,408,181–312,886,616 | `9ecdb58979432dcbbcfd1b02d6b2d32ae104884bf9bde3a54f7b7d645fb02bc7` |
| 12 | 312,886,617–332,365,052 | `76f20f61ed29b2cf7b6ea203ed95a0c54f210c1b5124385c074451cd2a9e4db8` |
| 13 | 332,365,053–351,843,488 | `f67865f9af8a2bede8184987ca6921e3ba880e52565705a8822611b8b84249d7` |

三個 initial contracts 的 `stream_bytes` 都是 `null`。開始大型 replay 前必須先新增並 review tree 11–13 專屬 preflight manifest／tests，驗證 external prerequisites，並保持所有 target formal claims 為 `false`。流程仍須逐 tree 執行 pre-freeze、凍結自身觀測值、fresh-cache frozen replay 與 portable evidence seal。

## Git 與 artifact 規範

- 寫入前重新讀取最新 `main`，並以該精確 base tree 建置。
- 不得 commit `.f193assign`、`.br1cs`、pickle、cache、resume、checkpoint 或 log files。
- 只提交 path-free portable metadata、code、tests、documents、manifests 與 checksum inventories。
- Tree closure 不等於 relocation、18-tree composition、parent join、proof 或 production closure。
- Checkpoint branch 的 merge／push 仍需使用者明確授權。
