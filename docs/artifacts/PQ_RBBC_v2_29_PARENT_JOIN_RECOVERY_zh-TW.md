# PQ-RBBC v2.29 parent CAP-to-H-RBBC recovery evidence

日期：2026 年 9 月 4 日

## 結果

V2.29 runner 使用同一份 production CAP parent source，保留 ticket payload、
context、RID、serial、holder witness 與 error witness，並以 circuit-produced
ticket digest 建立 fresh parent-bound global tail。完整執行依 frozen namespace
順序重放 18 份 tree assignments、72 個 relocation ranges、parent-bound global
tail，以及 lifted GF(2^193) parent relation。

| Segment | Rows | Failures |
| --- | ---: | ---: |
| Tree producers 0–17 | 513,312,336 | 0 |
| 72 output relocations | 15,938,520 | 0 |
| Parent-bound global tail | 56,806,711 | 0 |
| Aggregate subtotal | 586,057,567 | 0 |
| Joined parent relation | 2,972,988 | 0 |
| Combined total | 589,030,555 | 0 |

Joined parent包含2,971,580個legacy internal rows與1,408個native equality
rows；legacy external assertion已被取代，最終`external_assertions = 0`。

External full-replay manifest：

- bytes：5,685
- SHA-256：`055790dffe51781cff2f2f7893931da5550b9d730bec7ae72927a93f9e352a2a`
- input identity：`b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a`
- ordered transcript：`1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514`

## Parent binding 與 negative gates

Parent-bound values由同一執行確定性產生：

- ticket message：`d270d93873c40df5d4d7fcf651dad7e9653697507bc1a2e70d2651e58f412b78`
- CAP commitment：`12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62`
- derived mask：`cd2a8146346df7460e08e63dbf3841e5e89f1de235e2778c3f885fd60459c2ae`
- H-RBBC image：`d072c963cb46e3c382b843068525726e90b749e997e598c673a0a41635dcf855`
- public y：`e9b075b1e4990134c535f00db9842c45cd508408859e3d00bbaf3f98784fef68`

Message、commitment、mask、hash image、public y、wrong interval、mixed-field
alias與archive corruption mutations全部被拒絕。

## Portable evidence

Path-free evidence：
`artifacts/metadata/parent_join_recovery_v2_29/pq_rbbc_parent_join_recovery_evidence_v2_29.json`

- bytes：5,695
- SHA-256：`1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e`

Fail-closed sealer重新核對full-replay manifest、frozen preflight、preparation
manifest、parent-bound global-tail manifest與assignment、joined parent archive與
assignment、namespace、runner及18份tree assignments的exact bytes／SHA-256。
Portable JSON不含external artifact路徑。

## Claim boundary

本證據關閉以下 exact bounded gates：

- `complete_18_tree_assignment_replayed = true`
- `cross_segment_wire_identity_closed = true`
- `parent_bound_global_tail_replayed = true`
- `gf193_parent_lift_replayed = true`
- `parent_cap_to_h_rbbc_join_closed = true`

它不重驗fork-security proof，也不建立production closure；兩者仍為false。
System architecture、ticket lifecycle與`pq_sat_auth`均未修改。Assignments、
BR1CS、pickle/cache、checkpoint/resume state與logs均保留在Git之外。
