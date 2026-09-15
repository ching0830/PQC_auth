# PQ-RBBC issuance Global-B aggregate CandidateSet 唯讀 preflight v1

日期：2026-09-15。Branch：
`codex/pq-rbbc-issuance-global-b-candidateset-preflight-v1`；直接基線為 Global-A serial gate
`278cdf4682b08b18afe83f63fcd51d660a5785b7`。本 checkpoint 不修改 `main`、system
architecture、ticket lifecycle、`pq_sat_auth`、legacy 18-tree profile 或歷史 evidence。

## 結論

本 gate 定義並實作 bounded two-tree／four-leaf `INSECURE-TEST-ONLY` Global-B aggregate
CandidateSet validator。它把已 capture 的 Global-A complete、scheduler complete、兩份 ordered
tree-post result、兩份 continuation、相同 points identity、adapter receipt prefix/suffix，以及八筆
Global-B relocation candidates 綁在同一份 versioned canonical handoff。

這是 **read-only preflight**：Global-B 的 35,494 條 constraints 未產生、未重播；八組 native
equality rowsets 尚未執行；Global-B consumer、private publication、durable restart與production API
皆未實作。`full_execution_receipt_chain_verified=false`、`Proof-closed=false`、
`Production-closed=false`。

## Protocol 位置

```text
tree-pre results ───────────────┐
                               ├─> eight Global-B relocation candidates ─┐
Global-A complete + points ─────┤                                         │
                               ├─> aggregate CandidateSet ─> Global-B（下一 gate）
tree-post[0] complete ──────────┤                                         │
tree-post[1] complete ──────────┘                                         │
shared salt/message ───────────────────────────────────────────────────────┘
```

Protocol 上，Global-B 消費：

- shared `salt`、ticket `message`；
- tree 0／1 的 `p_plain`、`mhat_plain`；
- tree 0／1 的 `xi_masks`；
- Global-A 已配置的 `H1`、consistency points 與其他 Phase-A owned values。

本 gate 只確認這些來源都屬同一 `invocation_sha256`、`profile_fingerprint` 與 `plan_sha256`，且
future consumer 必須直接使用 CandidateSet 內相同的 immutable raw。它沒有把 host-level value
binding 當成 native constraint replay。

## Snapshot inventory

CandidateSet 共固定 32 個 snapshot identity roles：

1. aggregate handoff、shared-input snapshot與8份relocation candidate；
2. tree-pre handoff、2份tree-pre results及3份ordinal 0→2 receipt raws；
3. Global-A private result、points、fragment receipt及complete checkpoint；
4. 2份tree-post continuations；
5. scheduler ordinal 2→3 receipt suffix；
6. scheduler plan／complete，以及tree 0、1各自的private result／receipt／complete。

Ordinal 2 在 Global-A prefix 中名為 `adapter-receipt-0002.private.json`，在 scheduler suffix 中名為
`tree-pre-1.private-receipt.json`。兩者 filename 不同，但 raw bytes、byte count與SHA-256必須完全
相同；validator 不以 filename 相等取代 raw overlap。

## 八筆 relocation candidates

| Ordinal | Port | Source | Target | Bits |
| ---: | --- | ---: | ---: | ---: |
| 0 | `shared.salt` | canonical shared field | 1 | 386 |
| 1 | `shared.message` | canonical shared field | 387 | 256 |
| 2 | `tree[0].p-plain` | 78,265 | 2,187 | 2,048 |
| 3 | `tree[0].mhat-plain` | 80,313 | 4,235 | 386 |
| 4 | `tree[0].xi-masks` | 81,953 | 4,621 | 1,158 |
| 5 | `tree[1].p-plain` | 117,539 | 7,323 | 2,048 |
| 6 | `tree[1].mhat-plain` | 119,587 | 9,371 | 386 |
| 7 | `tree[1].xi-masks` | 121,227 | 9,757 | 1,158 |

每筆 record 固定 source snapshot identity、source locator、target interval、canonical packed bits、
packed SHA-256及domain-separated value binding。總計7,826個target bits。所有 records 都固定：

```text
host_value_binding_checked = true
native_equality_required = true
native_equality_executed = false
production = false
```

因此這些 records 是下一步 native equality 的候選輸入，不是已完成的 relocation constraint
receipts。

## Receipt graph 與 claim boundary

目前 receipt 結構是分支圖，不是單一線性 execution chain：

```text
ordinal 0 -> ordinal 1 -> ordinal 2
                              ├─> adapter Global-A ordinal 3 -> tree-post[0] receipt
                              │                             └-> tree-post[1] receipt
                              └─> independent Global-A fragment receipt
```

本 CandidateSet 驗證：

- ordinal 0→1→2 raws與links；
- ordinal 2 prefix/suffix raw overlap；
- ordinal 2→3 adapter link；
- independent Global-A receipt與adapter ordinal 3具有相同invocation、phase rows及points binding；
- 兩份tree-post receipts各自link到ordinal 3，且結果順序固定為`[0,1]`。

這仍不建立單一完整 receipt chain，也不代表 Global-B output 已存在。因此 manifest、evidence、
source、tests與handoff均保持`full_execution_receipt_chain_verified=false`。

## Immutable snapshot contract

Validator 不接受 pathname，只接受 frozen dataclass 中的 snapshots。Identity、strict canonical JSON
parsing、version/domain/order、binding與future consumption皆使用相同 `Snapshot.raw`；驗證時不重開
candidate pathname，也不重建monolithic reference或發出relation rows。

本 checkpoint 尚未實作跨兩個published roots的unified filesystem capture API。Future capture
layer必須single-open、single bounded read，並把已驗證的同一批snapshots交給executor；executor
不得重新開啟pathname。

這不代表普通filesystem能證明讀取期間沒有writer。inode／size／mtime／ctime僅能作best-effort
signals。Trusted producer handoff、writer quiescence、owner/mode/ACL、既有writable FD、mount
namespace、filesystem/fsync semantics及private-state confidentiality仍是部署前提。

## Frozen bounded identities

- CandidateSet handoff：5,656 bytes；SHA-256
  `ba284499e8f704840c33ed9b9aaadb86c17e3b4524e02266b4055201ba8b0df3`。
- Shared inputs：1,083 bytes；SHA-256
  `b169c3ab2417e5d8b70fbce10d44a902ae4a852c2ea8acdd011168af9b1be1da`。
- 八份relocation candidate identities逐項封存在manifest與portable evidence；private raw、salt、
  assignment values及published checkpoints皆未進Git。

## Resources 與 exact commands

Default checker只驗證tracked predecessor identities及static contract，規劃上限10秒／128 MiB；
Global-B rows executed為0。這不是production或legacy18 resource estimate。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python \
  src/pq_rbbc_issuance_global_b_candidateset_preflight_v1.py

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_global_b_candidateset_preflight_v1 -v

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

Bounded Global-B、production、large replay與large proving commands全部為`null`。

## Validation

- Targeted：16 passed、0 failed/errors/skipped，28.454秒。
- 六模組continuation／restart／scheduler／Global-A／CandidateSet integration：103 passed、
  0 failed/errors/skipped，195.823秒。
- 完整unittest baseline：1,005 tests；993 passed、12個既有optional-artifact skips、
  0 failed/errors，1502.584秒（wall 1506.38秒）。
- Controlled external probe：8/8 checks通過，25.23秒；涵蓋re-pinned false native-equality
  claim、capture後pathname mutation、ordinal 2 raw overlap與production pre-I/O refusal。
- 每一筆relocation的re-pinned target mutation、swap、gap、wrong version/domain/claim、duplicate及
  trailing bytes均fail closed。
- Wrong/stale handoff digest在dependency validation前拒絕；Global-A value、points、scheduler
  order與receipt overlap/link mutations皆拒絕。
- Capture後pathname改寫不會取代CandidateSet內raw；validation不重開pathname、不產生constraints、
  不建立output。

## Claim matrix

| 狀態 | 本 checkpoint |
| --- | --- |
| Defined | same-invocation aggregate inventory、8 relocation candidates、receipt graph |
| Instantiated | two-tree／four-leaf／degree-3 `INSECURE-TEST-ONLY` |
| Implemented | immutable aggregate CandidateSet builder／validator |
| Tested | bounded positive、negative、mutation、precompute/no-output |
| Evidence-sealed | metadata-only；不含private raws或values |
| Proof-closed | false |
| Production-closed | false |

## 下一個 serial gate

通過獨立re-review後，下一步是 **bounded independently invocable Global-B consumer preflight／
implementation**：只消費本CandidateSet，發出並驗證八組native equality rows與35,494條Phase-B
constraints，產生bounded private result與fragment receipt，再建立append-only publication／restart。

該 gate 完成前不能宣稱完整global-tail continuation、mixed degree-12/13、legacy18 production
provider、fresh parent I1--I5 join、正式`pi_issue`、Proof-closed或Production-closed。
