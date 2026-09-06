# PQ-RBBC v2.29 parent CAP-to-H-RBBC join preflight

日期：2026 年 9 月 4 日

本 checkpoint 建立 parent CAP-to-H-RBBC join 的唯讀、fail-closed preflight，
並在 runner、parent-bound fixture、GF(2^193) lift、row/wire accounting、archive
round-trip 與 mutation gates 全部凍結後才允許大型 replay。

## Frozen preflight

Manifest：`manifests/pq_rbbc_parent_join_preflight_manifest_v2_29.json`

SHA-256：
`4e83d260121df7bc9f73f03a3c427f494577cdcabb8808a9e67a2987d137ab78`

V2.28 aggregate portable evidence、tracked namespace/tail/ABI/parent contracts，
以及既有 49,227,687-byte incremental parent BR1CS 均通過 exact identity。
Legacy BR1CS 是 F2、2,971,580 rows、2,980,304 wires 且含一個 external
assertion；v2.29 不直接拼接它，而是由同一份 parent source 確定性重建 lifted
relation。

## Parent-bound contract

Parent ticket payload、context、RID、serial、holder witness與error witness完全不變。
其 circuit-produced ticket digest 作為新 global-tail 的 32-byte message；production
CAP commitment 提供 576-bit derived mask，再由 native `H_RBBC(message,
commitment)` 產生 576-bit hash image與 public `y = mask XOR hash-image`。

| Port | Wire start | Bits |
| --- | ---: | ---: |
| `shared.message` | 387 | 256 |
| `global.phase-b.commitment` | 40,084,506 | 43,128 |
| `global.phase-b.derived-mask` | 40,127,634 | 576 |
| `global.phase-b.request-hash` | 40,194,018 | 576 |

Boolean parent rows在GF(2^193)中保留bitness與characteristic-two semantics；local
constant 0/1以inline constants表示，2,980,302個non-constant parent wires重編至
`429,757,233..432,737,534`，不與aggregate namespace混用。

唯一 legacy external assertion 由 1,408 個 native equality rows取代：ticket
digest 256、derived mask 576、H-RBBC image 576。Joined parent共2,972,988 rows；
與aggregate合計589,030,555 rows，external assertions為0。

## Structural and mutation gates

External pre-freeze manifest：
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_29_parent_join_prefreeze/pq_rbbc_parent_join_prefreeze_manifest_v2_29.json`

- bytes：3,514
- SHA-256：`b6097f9bf795a4084e9bbc3ca2236f63c50aa00080ec007f8af623fcdc34cd37`
- parent archive round-trip：2,972,988 rows，0 failures
- external assertions：0
- message、commitment、mask、hash-image、public-y、wrong interval、mixed-field
  alias與archive corruption mutations：全部拒絕

此 pre-freeze 的 72,354,912-byte relation archive與74,507,694-byte parent
assignment均為external artifacts，不進Git。

## Ready environment result

Report：`/tmp/pq_rbbc_parent_join_environment_preflight_v2_29_ready.json`

- SHA-256：`9ec475f2f12226a0242199a4d6da37c4ededc19bd88d273665725baf84628f95`
- `blockers = []`
- `safe_to_start_large_replay = true`
- available memory：29,217,288,192 bytes
- free disk：664,929,751,040 bytes
- workers：8

Report中的exact command先生成parent-bound global-tail、joined parent archive與
assignment；所有輸出均位於獨立
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_29_parent_join/`。完成後才能凍結這些
external identities並啟動18-tree full replay。

## Preflight 後續結果

Preflight 允許的 exact execution 已完成；結果與 portable evidence 記錄於
[`PQ_RBBC_v2_29_PARENT_JOIN_RECOVERY_zh-TW.md`](PQ_RBBC_v2_29_PARENT_JOIN_RECOVERY_zh-TW.md)。
本次只關閉 exact parent CAP-to-H-RBBC join；
`fork_security_proof_revalidated`與`production_closed`仍維持false。System
architecture、ticket lifecycle與`pq_sat_auth`均未修改。
