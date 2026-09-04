[English](PQ_RBBC_CURRENT_HANDOFF.md)

# PQ-RBBC 目前交接 — v2.30 fork-security proof audit

> **模組範圍：**這是 PQ-RBBC 的操作交接，不是整篇論文 roadmap。專案級背景請先讀 [../../ARCHITECTURE_zh-TW.md](../../ARCHITECTURE_zh-TW.md)、[../../RESEARCH_STATUS_zh-TW.md](../../RESEARCH_STATUS_zh-TW.md) 與 [../../ROADMAP_zh-TW.md](../../ROADMAP_zh-TW.md)。

日期：2026 年 9 月 4 日

新工作階段先讀本文件、v2.29 recovery note、v2.30 fork-security preflight、
v2.30 proof-audit evidence與
`docs/ARTIFACT_POLICY.md`。本 handoff 記錄目前工作 branch 的bounded evidence；
不得推測它已合併至`main`。

## 已封閉邊界

V2.29已依frozen namespace重放18份planned tree assignments、逐wire核對72個
relocations、重放parent-bound global tail，並在GF(2^193)中驗證joined parent
relation。Row accounting：

| Segment | Rows | Failures |
| --- | ---: | ---: |
| Tree producers | 513,312,336 | 0 |
| Relocations | 15,938,520 | 0 |
| Parent-bound global tail | 56,806,711 | 0 |
| Aggregate | 586,057,567 | 0 |
| Joined parent | 2,972,988 | 0 |
| Combined | 589,030,555 | 0 |

因此`complete_18_tree_assignment_replayed`、
`cross_segment_wire_identity_closed`、`parent_bound_global_tail_replayed`、
`gf193_parent_lift_replayed`與`parent_cap_to_h_rbbc_join_closed`均已由本次exact
execution封閉。這不封閉fork-security proof或production。

## Portable evidence identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Frozen preflight manifest | 5,731 | `4e83d260121df7bc9f73f03a3c427f494577cdcabb8808a9e67a2987d137ab78` |
| External preparation manifest | 4,539 | `32f246e13f06e956bb4b39262f41b53d83c2874a646b1f9671381520f1ceb852` |
| External full-replay manifest | 5,685 | `055790dffe51781cff2f2f7893931da5550b9d730bec7ae72927a93f9e352a2a` |
| Portable recovery evidence | 5,695 | `1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e` |

Frozen input identity：
`b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a`

Ordered replay transcript：
`1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514`

Path-free Git evidence位於
`artifacts/metadata/parent_join_recovery_v2_29/pq_rbbc_parent_join_recovery_evidence_v2_29.json`。
完整external identities由該JSON與v2.29 checksum inventory綁定。

## External artifacts

執行產物位於獨立的
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_29_parent_join/`，包含：

- 1,004,865,028-byte parent-bound global-tail assignment；
- 72,354,912-byte joined parent relation archive；
- 74,507,694-byte joined parent assignment；
- full-replay manifest、local checkpoints與tree execution caches。

Tree 0–17 assignments仍分別留在v2.28 recovery、v2.25 batch、v2.26 batch與
v2.27 batch external directories。不得將任何assignment、BR1CS、pickle、cache、
checkpoint/resume state或log加入Git，也不得以其他tree的observed stream bytes
替代目標tree identity。

## V2.30 proof audit

V2.30已將fork-specific proof scope綁定至v2.29 final semantics。官方
ePrint 2025/895之2025-10-31 revision、proof-audit packet、CAP／QROM／
blindness-one-more internal gap reviews、independent-review request與audit manifest
均已凍結。Path-free evidence為
`artifacts/metadata/fork_security_audit_v2_30/pq_rbbc_fork_security_audit_evidence_v2_30.json`
（4,491 bytes，SHA-256
`ab82fe91e2e71cbfdf90bc171b0e62f6be6021365f0870e5878edd8a8496de60`）。

Internal audit結論為fail-closed：paper reductions需要的fork CAP extractor／ZK、
request-proof extractor、concrete QROM boundary、完整fork signer/finalizer、PQ
SE-NIZK backend及independent review均未由functional replay建立。因此目前只關閉
`v2_30_internal_proof_audit_closed`與`v2_30_independent_review_ready`；
`fork_security_proof_revalidated`仍為false。

Initial candidate inventory command及檔名見
[`../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_PREFLIGHT_zh-TW.md)。Candidate artifacts必須放在獨立
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/`。Audit結果與全部frozen
identities見
[`../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_AUDIT_zh-TW.md`](../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_AUDIT_zh-TW.md)。下一個gate是由合格的獨立
cryptographic reviewer出具綁定全部digests的attestation；專案不得自行補造。
不得把v2.29 parent-join execution evidence擴張解讀成security-proof或production
closure。

System architecture、ticket lifecycle與`pq_sat_auth`在v2.29均未修改。

## Git 與發布規範

- 只提交source、tests、frozen manifests、documentation、checksums與path-free
  portable evidence。
- 建立commit前檢查沒有`.f193assign`、`.br1cs`、pickle、cache、resume、checkpoint
  或logs進入index。
- 不直接push `main`；是否commit或push工作branch由使用者另行指示。
- `fork_security_proof_revalidated`與`production_closed`維持false。
