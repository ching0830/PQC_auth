# Issuance production 42-stage producer ABI 唯讀 pre-freeze v1

日期：2026-09-14。基線為 `c8bcdb2d6676c7c0eed383fc5c4fc062f00f8fb2`，獨立 branch
`codex/pq-rbbc-issuance-production-abi-prefreeze-v1`；沒有修改 main、其他 worktree、
system architecture、ticket lifecycle 或 `pq_sat_auth`。

## Protocol 意義與本次成果

本 gate 仍位於 offline issuance 的 I3：`CAP.Commit` 的輸出必須在同一 relation 內
接到 `H_RBBC(m,c_r)`，再約束 public request `beta = r XOR H_RBBC(m,c_r)`。
不是新增 protocol 階段，也沒有改變 statement、witness、ticket 或線上訊息。

上一 gate 證明五個 **one-tree / four-leaf / insecure-test-only** producers 可獨立呼叫。
本次把它們如何接到 production 18-tree 拓樸的工程契約固定下來，建立唯讀 checker、
closed-world canonical plan、prospective wire reservations、import/export contracts 與 blockers。
本 checker 不執行 CAP computation、row emission、assignment、replay 或 proving；驗證時的
完整 baseline 仍照常執行既有 bounded regressions，不是新的 production execution。

新 ABI namespace：

```text
pq-rbbc/issuance/cap576-native/production-producer-abi/candidate/v1
```

保留 production CAP fingerprint
`2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`；這是 18-root legacy
CAP 的 fresh issuance **工程 ABI candidate**，不是 unified-tree profile，也沒有重新選擇
或資格化 cryptographic backend。新 namespace 不覆寫 predecessor evidence。

## 42-stage mapping

| Ordinal | Stage | Bounded analogue 與 production 差異 |
| --- | --- | --- |
| 0 | validate-snapshots | 使用同一 CandidateSet；不重開 pathname |
| 1 | bind-invocation | `produce_input_binding`；production 須綁定完整 statement/witness/rho 與 input slots |
| 2–19 | tree-pre[0–17] | `produce_tree_pre`；每棵樹自己的 roots、wire cursor、spool，另須輸出 p-plain/mhat-plain |
| 20 | global-tail-phase-a | `produce_global_a`；依 tree index 收齊 18 組 pre ports，計算 17 組 corrections 與共同 points |
| 21–38 | tree-post[0–17] | `produce_tree_post`；各自恢復 pre cursor，全部消費相同的 386-bit point wires |
| 39 | global-tail-phase-b | `produce_global_b`；收齊 18 組 post ports，重用相同 pre bindings，計算 shared alpha、commitment/mask/append/request |
| 40 | parent-native-join | 完整 I1–I5 fresh composition；native equality widths 為 256/576/576 |
| 41 | final-seal | 全部 stage receipts 的有序完整 prefix；不是 production publisher implementation |

每段分開記錄 `previous_receipt_stage` 與 `data_dependencies`。例如 global-A 不只是等
tree-pre[17] 的 receipt，還必須取得全部 18 個 pre results；global-B 同時保留 pre 與 post
imports。Bounded function 名稱只表示 analogue，所有
`bounded_function_directly_production_usable` 均為 false。

## Prospective wire intervals，不是新的 execution observations

採用 positive uint64 wire ID、half-open `[start,end_exclusive)`；wire 0 是 constant one。
直接核對 50 份 pinned prerequisites（合計 1,365,395 bytes），只從 captured child manifest
取用 topology、interval、width、rho offsets 與 historical accounting，不啟動舊 manifest builders。
歷史 pretty-JSON manifests 只作 exact-byte identity leaves；不改寫或冒充新的 canonical inputs。

| Owner／片段 | Planned interval |
| --- | --- |
| tail input reservation | `[1,15939163)` |
| global-A | `[15939163,39946062)` |
| global-B | `[39946062,40194597)` |
| tree 0 pre | `[40194597,79003159)` |
| tree 0 post | `[79003159,79148427)` |
| tree 1 pre | `[79148427,117956989)` |
| tree 1 post | `[117956989,118102257)` |
| 所有 tree reservations 結束 | `429757233`，exclusive |
| fresh parent interval | `null`，lower bound 為 `429757233` |

完整 18 棵樹區間見 machine manifest。Pre/post split 由 frozen producer code 的順序導出：
最後一個 `mhat-plain` output wire 之後開始 `tree-post-horner`。這是 **layout-derived
reservation**，尚未由 production split adapter emission 驗證；fresh pre/post rows、stream bytes、
stream digests、assignments 全為 `null`。

Production 不能使用 bounded 單一 `next_wire`：global-A 的 wire IDs 比各棵樹小，tree-post
必須回到該 tree 的 pre-end，而非從 global-A 的 end 接續。Tail input slots 也只是 reservation，
不得以尚未 binding 的 placeholders 作為可執行 witness。72 個 port relocations 的 target
完整且不重疊地覆蓋 `[643,15939163)`，總共 15,938,520 bits，未來須逐 bit 以 ordinary
equality rows 綁定，不是只比 host digest。各 tree 的 salt/root/message binding 與其他新增 rows
仍須 qualification，不能假定沿用 589,030,555 即代表 fresh I1–I5 已封閉。

Global-A points 固定 reservation 為 `[39945673,39945866)` 與 `[39945866,39946059)`。
每棵 tree-post 與 global-B 必須引用相同 wires，不得複製值後換成新 input wires。

## Multi-tree 與 private state blockers

Production profile 是兩棵 4,096-leaf／degree-13 加十六棵 2,048-leaf／degree-12 trees。
`rho.raw` 維持 1,036 bytes：shared salt byte interval `[84,134)`，18 組 root pairs
位於 `[136,1036)`；中間 framing bytes 仍受既有 rho codec 約束。

Bounded one-tree case 沒有 17 組 corrections；production 必須導出
`delta_p[i] = p[0] XOR p[i]` 與 `delta_mhat[i] = mhat[0] XOR mhat[i]`，分別為
2,048 與 386 bits。現有 bounded global-B 直接從 private spool 形成 wire forms，不能當作
legacy 72-port layout 的 drop-in producer。Parent 仍需 fresh 256/576/576 native equality
bindings，且不能以 mask 不一致的 bounded fixture 宣稱完整 I3 成功。

Bounded cumulative JSON 內的四個 tape records 也不能直接放大。僅以未封閉的 uint64 wire-ID
spool body 規劃就有 `40960 × 2434 × 8 = 797,573,120 bytes`，尚不含 headers、tape values、
assignments 或 rows；不是 observed bytes。本 gate 保持每份 metadata capture <= 1 MiB，
private spool 的 streaming codec、trusted handoff、exact identity 與 recovery 仍是 blocker。
不能藉提高 JSON limit 把大量 private state 塞入 manifest／portable evidence。

## Canonical encoding、snapshot 與部署 contract

Plan 使用 strict canonical JSON（ASCII、sorted keys、compact separators、單一結尾 LF）。
Unknown version/domain/fields、bool 取代 integer、alternate encoding、float、duplicate key、
trailing bytes、wrong tree/port/interval/rho binding 全部拒絕。Plan digest 為
`SHA256(DOMAIN || canonical_plan_raw)`；domain 是
`PQ-RBBC/ISSUANCE-PRODUCTION-PRODUCER-ABI/PLAN/V1`。

Runtime envelope **只有 requirements，尚無 accepting codec／publisher**。它必須另行綁定
full statement.raw、full witness.raw、rho.raw、CandidateSet identities、plan、stage、ordered
imports/exports、per-owner cursor 與 previous receipt；invocation/port/receipt 使用互異 domain
和 length-prefixed digest framing。Fresh output/cache namespace、exact external latest receipt
與 contiguous prefix 都是必要條件，不能沿用 bounded state 或過去的 production values。

讀檔採 single-open、single bounded read；identity、strict parse、binding、validation 都只使用
同一 immutable `Snapshot.raw`。Inode/size/mtime/ctime 僅為 best-effort signals，不能證明讀取
期間沒有 writer。受控 regression 在舊 bytes 完整 capture 後，以同 inode／同長度原地改寫，
並模擬 metadata 保持相同：舊 snapshot 可以接受，但 digest、parse、plan binding 必須全部
對應舊 raw；後續 pathname bytes 不能替代它，新的 wrong-version raw 仍拒絕。

Future executor 必須消費同一已驗證 CandidateSet 與 Invocation snapshots，不能重開 candidate
pathname。Trusted producer handoff、writer quiescence、owner/mode/ACL、既有 writable FD、
mount namespace、filesystem/fsync semantics 仍是外部部署前提。沒有用額外 stat、sleep、
advisory lock 或第二次內容讀取宣稱 filesystem 強不可變性。

## External inventory、資源與 exact commands

本 gate 沒有 provision production artifact root。預設報告的 `not provisioned`／五份 missing
表示 **沒有供本 invocation 驗證的輸入**，不是掃描整台機器後斷言任何地方都不存在檔案：

- `pq_rbbc_trace_public_key_v1.bin`
- `pq_rbbc_trace_public_key_certification_v1.json`
- `pq_rbbc_authenticated_system_initialization_v1.bin`
- `pq_rbbc_issuance_common_parameters_v1.bin`
- `pq_rbbc_issuance_production_inputs_independent_review_v1.json`

指定 external root 後，只 capture 該 root 的同一 CandidateSet 並驗證。Synthetic complete
candidate 即使 structural validation 通過，仍不能解除 producer authenticity、federation
authentication、independent review、CAP/fork security 或 production gates。

本 checker 的工作量只有小型 metadata hash/parse，0 rows、0 proofs、0 writes。Historical
16 GB memory／64 GB free disk／8,000–12,000 秒只供背景，不是本次 fresh production estimate
或已取得的 reservation。Fresh production 資源估算、operator reservation、execution
authorization 與 exact production/replay/proving commands 均維持 `null` 或 false。

單次 metadata CLI 量測（未 warm-up、完整 baseline 同時在跑）為 0.22 秒、peak RSS
32,064 KiB、exit 0；環境 Linux 6.8.0-138-generic x86_64、AMD Ryzen 5 7600X
6-core/12-thread、Python 3.12.9。這是單次 checker observation，不是 production benchmark。
Exact measurement command：

```bash
/usr/bin/time -f 'read_only_check elapsed_seconds=%e max_rss_kib=%M exit=%x' env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_production_abi_prefreeze_v1.py > /dev/null
```

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_production_abi_prefreeze_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_production_abi_prefreeze_v1.py --plan
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_production_abi_prefreeze_v1.py --artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_production_abi_prefreeze_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

前兩個 CLI commands 只印 stdout；第三個 root 必須由 operator 真實 provision，不能把
placeholder 當成 attestation。Exit 0 只表示 metadata checker 成功，不是 production 可執行；
必須讀取各項 false gates。`execute_production` 無條件在 input/output access 前拒絕。

## 驗證、identities 與成熟度

Targeted：17 passed、0 failed/errors/skipped，1.116 秒。包含 19 組 semantic mutations、
canonical rejection、dependency/interval checks、same-capture deterministic regression、
synthetic external input fail-closed、單一 capture 計數及 preflight 不呼叫 builders/publishers 的
guards。完整 baseline 共 878 tests，866 passed、12 skipped、0 failures、0 errors，
1,231.595 秒，exit 0。Skips 為既有 optional v2.13–v2.25 external assignments、execution
caches 或 recovery artifacts 未安裝；本 gate 沒有新增 skip。驗證期間僅本 gate 新檔案與
handoff 尚未 commit，implementation/test bytes 在本次完整 suite 期間保持不變。
`git diff --check` 與 staged diff check 均通過；六份提交檔案沒有大型或 private artifacts。

另依 `pq_rbbc_cap_unified_tree_launch_validation_v2_41.HISTORICAL_IDENTITIES` 核對 19 份
v2.38/v2.39 files，exact size/SHA-256 全部相符。對基線 `c8bcdb2` 的 tracked source/tests/
manifests/artifacts/proof/release diff 為空；新增的本 gate files 與 handoff 不覆寫 predecessor。

Plan SHA-256：`8ab365ec9d3324ef2a669c177914f5f5dbebb4747e1b059d3906d2ff3dc370c4`。
Manifest：120,443 bytes，SHA-256
`4e4757187d3ada9610f8e7d17f96b628d96ac8fefd0537042771a3ba3bacca34`。
Portable evidence：2,590 bytes，SHA-256
`c416ae175f15c2e6080263a51959025698c306100e5effbc3f0164479fcc72f7`。

Defined／Implemented／Tested／Evidence-sealed 僅適用於本 read-only contract 與 metadata。
Production backend Instantiated、production adapter Implemented、production Tested、
Proof-closed、Production-closed、formal `pi_issue`、large replay/proving 全為 false。
沒有把 historical replay、bounded backend 或 file identity 宣稱為密碼學 proof。

依 lane ownership，本次設計理由與命令結果保存在本 artifact note，供 integration lane
之後同步 methodology/experiments/status；未改寫 integration-owned canonical documents。

下一 gate：**bounded multi-tree adapter 與 per-owner allocator qualification**，先以多棵小樹
驗證 corrections、fan-in、pre/post cursor、72-port-style binding 與跨 tree mutation，再規劃
private spool streaming/recovery。這個 bounded authoring gate 可前進；production 大型
materialization／replay／proving 仍不得啟動。
