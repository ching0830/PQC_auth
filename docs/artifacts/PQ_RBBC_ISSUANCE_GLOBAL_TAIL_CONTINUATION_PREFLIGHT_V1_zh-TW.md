# PQ-RBBC issuance global-tail continuation preflight v1

日期：2026-09-14；receipt/scheduler successor：2026-09-15

## 結論

本 checkpoint 已用唯讀、witness-independent 的 layout calculation 固定 bounded
two-tree／four-leaf issuance global tail 的 Phase A／Phase B 工程邊界。它沒有執行 CAP
relation、沒有重播 constraints，也沒有建立 assignment、BR1CS、cache、checkpoint、resume
state、log 或 proof。

本 preflight 的 `implementation_version=1.1` 已改以 finding-free scheduler exact commit
`2f1b674cf7afafebd1bdb4778ce456093a6c9005` 為有效 predecessor，並移除模糊的
`receipt_chain_required` claim。它可以安全進入 bounded consumer gate，但不能直接執行完整
global-tail continuation：本 serial-gate branch 的 companion Global-A 1.1 已另行實作；
Phase-B consumer，以及將 Global-A complete 與兩份 tree-post complete 合併到同一 invocation
的 fan-in 尚未實作。因此本 preflight 自身仍報告：

- `safe_to_implement_next_bounded_gate = true`；
- `safe_to_execute_bounded_continuation = false`；
- `safe_to_start_large_replay = false`；
- `safe_to_start_large_proving_run = false`；
- `Proof-closed = false`、`Production-closed = false`。

## Protocol 位置

Issuance CAP child 的依賴序列為：

```text
tree-pre[0..n-1]
  -> global Phase A: H1、consistency points
  -> tree-post[0..n-1]: xi masks
  -> global Phase B: H2、c_r、r、append base、request hash
  -> parent I1--I5 join
```

Phase A 必須同時看到所有 tree-pre 的 leaf commitments、`p_plain` 與 `mhat_plain`，因為
`H1` 會綁定每棵樹及跨樹 correction。Phase B 必須看到 Phase A 的相同 H1／points、所有
tree-post 的 `xi_masks`、salt、message、`p_plain` 與 `mhat_plain`，才能建立 H2 和 canonical
commitment `c_r`。這就是不能讓各 tree 任意獨立前進、也不能用 hash-only metadata 取代
native equality binding 的原因。

本 gate 不改 ticket statement、ticket lifecycle、system architecture 或 `pq_sat_auth`，也
沒有把 relation replay 說成正式 `pi_issue`。

## Frozen bounded layout

所有 interval 都是 half-open `[start, end)`；row interval 是 tail-local row numbering，wire
ID 則是 bounded adapter 使用的 absolute wire numbering。

| 區段 | Row interval | Rows | Wire interval | Wires |
|---|---:|---:|---:|---:|
| input prelude | `[0, 10914)` | 10,914 | `[1, 10915)` | 10,914 |
| global Phase A | `[10914, 30585)` | 19,671 | `[10915, 23094)` | 12,179 |
| global Phase B | `[30585, 66079)` | 35,494 | `[23094, 43837)` | 20,743 |

Phase A boundary ports：

| Port | Wire interval | Bits | Consumer |
|---|---:|---:|---|
| `global.phase-a.h1` | `[20655, 21041)` | 386 | Phase B |
| `global.phase-a.consistency-points` | `[22705, 23091)` | 386 | tree-post 0/1、Phase B |

Phase B output ports：

| Port | Wire interval | Bits | Consumer |
|---|---:|---:|---|
| `global.phase-b.commitment` | `[29982, 34070)` | 4,088 | parent |
| `global.phase-b.derived-mask` | `[34070, 34646)` | 576 | parent |
| `global.phase-b.append-base` | `[34646, 36118)` | 1,472 | issuance signature flow |
| `global.phase-b.request-hash` | `[43258, 43834)` | 576 | parent |

兩個 consistency-point element 的 starts 固定為 `22705`、`22898`。Adapter 的 frozen plan
identity 為：

```text
plan SHA-256:
729418cf1f9400b729ea02798547d260bf508bb775819456193a4e9270087c84

bounded fixture invocation SHA-256:
ff4936ffb4e2de756ceeb9812101ec8f37f354f547f5303cbb73407e70cf5765
```

## Continuation snapshot contract

Future executor 不得嘗試序列化或復原 Python generator frame、allocator mutable object、
full assignment、hash object internal state、sponge witness pool、file descriptor 或 lock。
應改以新的 fragment consumer 從 canonical private snapshots 開始，並固定：

1. version、relation/domain、profile、plan、invocation 與 previous receipt identity；
2. exact absolute wire interval，以及 `F193-LE25` canonical field encoding；
3. ordered group identities、row-semantics digest，以及每份實際宣稱 receipt snapshot 的 raw
   validation；
4. tree output source wire 到 tail prelude target wire 的 native equality receipts；
5. Phase-A result 包含完整 `[10915,23094)` 的12,179個owned values；
6. Phase-B consumer 使用同一 CandidateSet 中的 tail prelude `[1,10915)`、Phase-A
   `[10915,23094)` 及兩份已完成 tree-post results；
7. Phase-B result 包含完整 `[23094,43837)` 的20,743個owned values。

Global-A CandidateSet 攜帶並驗證 ordinal `[0,1,2]` 的完整 raw prefix；scheduler 1.2 攜帶並
驗證 ordinal `[2,3]` raw suffix。兩者以 ordinal 2 的相同 bytes／SHA-256 交會，但 pathname
名稱可以不同。這只定義 future Global-B fan-in 的 overlap contract；目前沒有同時消費兩個
completed roots，因此 `full_execution_receipt_chain_verified=false`，不得宣稱完整 execution
receipt chain。

每份 pathname 只能 single-open、single bounded read。Identity、strict JSON parsing、binding
及 consumer 必須使用同一份 immutable `Snapshot.raw`；capture 後不得重新開啟 pathname 取代
已驗證 bytes。inode／size／mtime／ctime 只能是 best-effort mutation signals，不能證明 writer
在讀取期間完全不存在。Trusted producer handoff、writer quiescence、owner/mode/ACL、既有
writable FD 與 mount namespace 是外部部署前提。

## 現有 evidence 能做與不能做的事

已存在：

- bounded two-tree adapter 的 exact plan、8個 relocation ports 及same-wire point identity；
- tree-post independent continuation contract；
- one-tree private append-only tree-post result publication與process restart；
- finding-free two-tree scheduler 1.2、verified ordinal 2→3 suffix 與 immutable snapshot
  validation grammar；
- 本 serial-gate companion 的 independent Global-A 1.1 consumer／restart。

仍缺：

- 同一 invocation 下 Global-A complete 與兩份 tree-post completed results 的 aggregate
  CandidateSet；
- tail-prelude relocation snapshot與native equality receipt；
- independently invocable Phase-B consumer及Phase-B private result publisher；
- production 18-tree provider、72個relocations的fresh qualification、parent join、PQ-SE backend、
  external artifacts、independent review、resource reservation及large-run authorization。

因此本次 portable evidence 只封存 layout／contract／preflight metadata，不含private values、
assignment或其他 tree 的 observed `stream_bytes`。

## External artifacts

Production 仍需要五份外部輸入，而本 checkpoint 沒有收到已 provision 的 artifact root：

1. `pq_rbbc_trace_public_key_v1.bin`
2. `pq_rbbc_trace_public_key_certification_v1.json`
3. `pq_rbbc_authenticated_system_initialization_v1.bin`
4. `pq_rbbc_issuance_common_parameters_v1.bin`
5. `pq_rbbc_issuance_production_inputs_independent_review_v1.json`

缺少它們不阻止本次 static contract preflight，但會阻止 production execution、large replay
與正式 proving。

## Resource boundary 與 exact commands

唯讀 checker 的上限是10秒／64 MiB；下一個 bounded Phase-A＋Phase-B implementation gate 的
規劃上限是55,165 rows、180秒／512 MiB。這不是 production 估算，也不是執行授權。

唯讀 preflight：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python \
  src/pq_rbbc_issuance_global_tail_continuation_preflight_v1.py
```

Targeted tests：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_global_tail_continuation_preflight_v1 -v
```

本 gate 刻意不提供 bounded continuation、production、large replay 或 large proving command。

## Validation

- Successor preflight targeted：11 passed、0 failed/errors/skipped（0.777秒）。
- 與 Global-A 1.1 combined targeted：27 passed、0 failed/errors/skipped（47.059秒）。
- 完整 unittest baseline 見同 branch 的 Global-A artifact note；沒有啟動large replay、large
  proving或production entrypoint。

## Claim matrix

| 狀態 | 本 checkpoint |
|---|---|
| Defined | Phase A／B layout、ports、snapshot contract |
| Instantiated | false |
| Implemented | read-only checker only |
| Tested | static positive／negative／mutation |
| Evidence-sealed | metadata-only |
| Proof-closed | false |
| Production-closed | false |

## 下一個 critical-path gate

Companion Global-A consumer／restart 已完成。下一步是建立 Global-B same-invocation
aggregate CandidateSet 唯讀 preflight：它必須同時消費 Global-A complete 與 scheduler
complete snapshots，驗證 ordinal 2 raw overlap、相同 invocation/profile/plan、相同 points raw
及 tree `[0,1]` ordered results。通過後才能實作 Phase B；不能直接跳到18-tree replay。
