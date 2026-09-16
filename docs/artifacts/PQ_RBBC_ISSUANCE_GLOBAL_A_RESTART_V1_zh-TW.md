# PQ-RBBC issuance Global Phase A 獨立 consumer／restart v1

日期：2026-09-14；receipt/scheduler successor：2026-09-15。原工作 branch 為
`codex/pq-rbbc-issuance-global-a-restart-v1`；目前 successor branch 為
`codex/pq-rbbc-issuance-global-tail-serial-gate-v1`，直接基線是 finding-free scheduler＋
SRR-01 integration `2f1b674cf7afafebd1bdb4778ce456093a6c9005`。本 gate 不修改 `main`、system
architecture、ticket lifecycle、`pq_sat_auth`、legacy 18-tree profile 或既有 evidence。

## 結論

本 checkpoint 已為 two-tree／four-leaf `INSECURE-TEST-ONLY` fixture 實作可獨立呼叫的
Global Phase A consumer，以及 private、exclusive、append-only result publication／process
restart。Consumer 只使用同一個 immutable `TreePreCandidateSetInsecureTestOnly` 內已 capture
的 snapshots；不重跑 `tree-pre`，也不復原 Python generator、hash object 或 allocator state。

Bounded qualification 已重播 Phase A 的 19,671 條 native constraints；12,179 個 owned wires
及兩個 consistency points 與原本 live adapter 的相同 Phase A 完全一致。這是 bounded
implementation evidence，不是正式 `pi_issue`、cryptographic proof 或 production 18-tree
qualification。Global Phase B 尚未實作，所以完整 global-tail continuation 仍為 false。

Successor `implementation_version=1.1` 明確把 Global-A 的 receipt contract 縮限為實際攜帶且
逐份驗證的 ordinal 0→2 raw prefix；它與 scheduler 1.2 的 ordinal 2→3 raw suffix共享 ordinal
2 bytes／SHA-256。Global-B aggregate CandidateSet 尚未實作，因此
`full_execution_receipt_chain_verified=false`。

## Protocol 位置

這一步位於 offline issuance 的 CAP child：

```text
tree-pre[0] outputs ─┐
                     ├─> Global Phase A ─> H1 + consistency points
tree-pre[1] outputs ─┘                           │
                                                ├─> tree-post[0..1]
                                                └─> Global Phase B（尚未完成）
```

Phase A 的 `H1` 必須同時綁定每棵樹的 leaf commitments，以及跨樹 `p_plain`／
`mhat_plain` corrections；consistency points 再由相同 `H1` 與 profile 導出。因此六個
tree-pre output ports 不能由其他 tree 的 observed `stream_bytes` 代替，也不能只靠名稱或
未驗證 hash metadata 宣稱已完成 relation binding。

## Tree-pre CandidateSet

Authoring helper 只在 bounded fixture 中把既有 session 推進到 `tree-pre[1]`，然後 capture
六份 immutable snapshots：

1. 一份 tree-pre handoff；
2. tree 0、tree 1 各一份 private result；
3. `bind-inputs`、`tree-pre[0]`、`tree-pre[1]` 三份 adapter receipt raws。

兩份 result 共同攜帶下列六個 source-to-tail target ports；所有 intervals 均為 half-open：

| Port | Producer source | Tail target | Bits |
| --- | ---: | ---: | ---: |
| `tree[0].leaf-commitments` | `[76721,78265)` | `[643,2187)` | 1,544 |
| `tree[0].p-plain` | `[78265,80313)` | `[2187,4235)` | 2,048 |
| `tree[0].mhat-plain` | `[80313,80699)` | `[4235,4621)` | 386 |
| `tree[1].leaf-commitments` | `[115995,117539)` | `[5779,7323)` | 1,544 |
| `tree[1].p-plain` | `[117539,119587)` | `[7323,9371)` | 2,048 |
| `tree[1].mhat-plain` | `[119587,119973)` | `[9371,9757)` | 386 |

Consumer 逐一固定 version、relation/domain、profile、plan、invocation、source/target interval、
packed bit encoding、producer value digest、spool identity、ordinal/stage及0→1→2
`previous_receipt_sha256` links。Identity、strict parsing與link validation均使用相同
`Snapshot.raw`；總計 7,956 個 import
wires 必須全部被 Phase A rows 實際引用。

這個 CandidateSet 不是數位簽署或 self-authenticating proof。Trusted producer handoff 是外部
前提；若 caller 能任意重寫 payload、所有 identities 與 receipts，本 gate 不會憑 checksum
推導出 cryptographic provenance。

## Phase A frozen result

| 項目 | 值 |
| --- | ---: |
| Row interval | `[10914,30585)` |
| Rows | 19,671 |
| Wire interval | `[10915,23094)` |
| Owned values | 12,179 |
| `H1` port | `[20655,21041)` |
| Point starts | 22,705、22,898 |
| Fragment stream bytes | 5,376,571 |
| Fragment stream SHA-256 | `66f5d7c5222e5c8c1fb302bdecbe63731a99e7241c023d0ee273042b47e3a275` |
| Row semantics SHA-256 | `eb2f198f93fb8c0ec2b9a6aebfa0be82db608276031736fd57477dbd454432ac` |
| Private assignment SHA-256 | `48168659e921b1625cde9e4a12209a4d422ecd32cc8dca82ac88fa357f2ff2bd` |
| Point snapshot SHA-256 | `43eceeec2f4b9cda18bc96014bebbaed319e0e7a8a8c04a710a6950828826009` |

Private result 使用 `12179xf193-little-endian-hex`：每個 F193 element 固定 25 bytes、小端序且
必須小於 `2^193`。Bounded fixture 的 result 是 610,153 bytes；它包含 secret witness-derived
state，只能存在 caller-provisioned private artifact root，不能提交 Git。Portable evidence
只記錄 identity 與 qualification metadata。

## Append-only publication 與 restart

```text
output/
├── inputs/
│   ├── tree-pre-handoff.private.json
│   ├── tree-0.pre-result.private.json
│   ├── tree-1.pre-result.private.json
│   └── adapter-receipt-0000..0002.private.json
├── results/
│   ├── global-a-result.private.json
│   ├── points.private.json
│   └── global-a-fragment-receipt.private.json
└── journal/
    ├── 0000-publication-plan.private.json
    ├── 0001-inputs-committed.private.json
    ├── 0002-result-committed.private.json
    └── complete.private.json
```

可恢復邊界是 `0001-inputs-committed.private.json` 完成 exclusive publication 與 durability
barrier 之後。Resume caller 必須提供最新 checkpoint 的 exact lowercase SHA-256。Publisher
沿用 v2.42 primitive，不會 truncate、replace 或覆寫既有檔案；合法 orphan prefix 會先驗證
相同 bytes 後採用，未知檔案、gap、wrong/stale digest、wrong version/domain、mutation及trailing
bytes 會 fail closed。

每個 pathname 採 single-open、single bounded read。Identity、strict JSON parsing、binding 與
consumer 都使用同一份 immutable `Snapshot.raw`；capture 後 pathname 的內容不能取代已 capture
snapshot。這不表示程式能證明讀取期間完全沒有 writer：inode／size／mtime／ctime 只可能是
best-effort signals。Trusted producer handoff、writer quiescence、owner/mode/ACL、既有 writable
FD、mount namespace、filesystem/fsync semantics與private-state confidentiality仍是部署前提。

## Resources 與 exact commands

Bounded 規劃上限是 180 秒／512 MiB，private result hard limit 為 1 MiB。這不是 production
估算，也不能外推到 18 trees 或 589,030,555 constraints。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python \
  src/pq_rbbc_issuance_global_a_restart_v1.py

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python \
  src/pq_rbbc_issuance_global_a_restart_v1.py --self-check

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_global_a_restart_v1 -v

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

Production、large replay 與 large proving 沒有 command。五份 production external artifacts 仍
未 provision；正式 common parameters、certified trace key、authenticated initialization、
independent review及PQ simulation-extractable backend亦未因此完成。

## Successor identities

- Tree-pre handoff：1,813 bytes；SHA-256
  `61592d73c78e25f010e2e771687d7e13dac02903c84b93008de7b20e7a09baf8`。
- Tree 0／1 pre-results：SHA-256
  `cd89d9b530b7d698e25f4b847fd3e88b6880e8604d1a8ad51b474495aed59cd4`／
  `bd71797c230119453dd95162eb693085de26ba0ccf971eb16f720d91ae6b4f9b`。
- Phase-A fragment receipt：3,435 bytes；SHA-256
  `33a8813edcecf71c0e67bb3b5cb4579dc2a4269f2c6ede8b2392a91a475d6fdc`。
- Private result：610,153 bytes；SHA-256
  `38c66f6e14daeda8eeecc708d03a49e54312e665187cdbd9635e50b2247cb623`。
- Complete checkpoint：2,001 bytes；SHA-256
  `c5ab55bf862c276db732ad4cb0ff0785d8898d9e142d7fc54d5ef48539974b96`。

## Validation

- Global-A successor targeted：16 passed、0 failed/errors/skipped。
- Preflight＋Global-A combined targeted：27 passed、0 failed/errors/skipped，47.059秒。
- 五模組continuation／restart／scheduler／preflight／Global-A integration：87 passed、
  0 failed/errors/skipped，185.462秒。
- 完整unittest baseline：989 tests；977 passed、12個既有optional-artifact skips、
  0 failed/errors，1492.078秒（wall 1495.86秒）。
- 0／1／2每個receipt raw在依賴identity全部re-pin後的wrong-stage mutation仍拒絕；另有
  re-pinned broken-link rejection。
- v2.38／v2.39 的19份historical identities已逐檔核對不變；`git diff --check`通過，
  prohibited-artifact inventory未發現禁入產物。

## Claim matrix

| 狀態 | 本 checkpoint |
| --- | --- |
| Defined | tree-pre CandidateSet、Phase A fragment/result、publication/restart ABI |
| Instantiated | two-tree／four-leaf／degree-3 `INSECURE-TEST-ONLY` |
| Implemented | independent Phase A consumer、private append-only publisher與restart |
| Tested | bounded positive／negative／mutation／restart（驗證完成後封存） |
| Evidence-sealed | metadata-only；不含private values或assignment |
| Proof-closed | false |
| Production-closed | false |

## 下一個 critical-path gate

下一步是建立 **Global Phase B same-invocation aggregate CandidateSet 與唯讀 preflight**：明確
綁定本 gate 的 completed Phase A result、兩份 completed tree-post results、相同 invocation 的
salt／message／`p_plain`／`mhat_plain` tail inputs，以及 eight relocation receipts。確認 fan-in
完整、安全且不重播前序 fragment 後，才能實作 independently invocable Phase B consumer。

Phase B 尚未通過之前，不能宣稱 global-tail continuation、legacy18 provider、fresh parent
I1--I5 join、正式 `pi_issue`、Proof-closed 或 Production-closed 已完成。
