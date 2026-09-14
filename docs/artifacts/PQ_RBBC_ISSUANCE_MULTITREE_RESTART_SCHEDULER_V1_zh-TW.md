# PQ-RBBC issuance bounded multi-tree restart scheduler v1

日期：2026-09-14。基線為
`ca6d4a43d7b2ebf728c660b4df0abaf526714544`；獨立 branch 為
`codex/pq-rbbc-issuance-multitree-restart-scheduler-v1`。本 checkpoint 只新增名稱含
`multitree_restart_scheduler_v1` 的 source、tests、manifest、metadata-only portable
evidence 與本文件；未修改 one-tree predecessor、root canonical documents、system
architecture、ticket lifecycle 或 `pq_sat_auth`。

初始 commit `2d20829e3f09588e9aed7caf9508bef9b221c6d4` 的 bounded AI security
rereview 找到兩項 P2 與一項 P3：completed-child adoption 缺少 dependency-ordered
directory durability barriers、非 adoption 路徑可在 child root 含未知 component 時發布
不可再次 capture 的 complete、以及 parent output root 未採 closed-world inventory。
Corrective branch
`codex/pq-rbbc-issuance-multitree-restart-scheduler-corrective-v1` 以
`implementation_version=1.1` 建立新 parent plan／checkpoint identities；舊 1.0 scheduler
outputs 不得宣稱已由本 corrective qualification 涵蓋。

## Protocol 位置與 bounded 範圍

本工作仍只位於 offline issuance I3 的 bounded `CAP.Commit` tree-post child：

```text
既有 global-A handoff
        │
        ├── tree 0 continuation ── one-tree restart API ── tree[0].xi-masks
        └── tree 1 continuation ── one-tree restart API ── tree[1].xi-masks
```

Scheduler 只消費既有 one-tree API：

- `run_bounded_tree_post(...)`；
- `latest_checkpoint(...)`；
- `capture_completed_result(...)`。

Scheduler 不複製或改寫 tree-post relation，不呼叫 standalone relation evaluator，不恢復
Python generator frame，不序列化 allocator／`hashlib` state，也不在 capture 後重新開啟
CandidateSet pathname 取代已驗證 snapshots。所有 tree relation、private-result 與 one-tree
journal 驗證仍由 predecessor API 負責。

本 gate 不建立 global-tail phase A/B continuation、不收集 global-tail input set、不建立
global-tail output 或 parent output。它不是完整 CAP provider、legacy18 provider、正式
`Pi_issue.Prove`／`Verify` 或 production proof。

## Canonical execution plan

Execution plan format 為
`PQRBBC-ISSUANCE-MULTITREE-RESTART-SCHEDULER-1-EXECUTION-PLAN`，plan version 為 `1`、
implementation version 為 `1.1`，
relation namespace 為
`pq-rbbc/issuance/multitree-restart-scheduler/tree0-tree1-4leaf-insecure-test-only/v1`。
Domain separation 為 ASCII
`PQ-RBBC/ISSUANCE/MULTITREE-RESTART-SCHEDULER/PLAN/V1`；所有 JSON 使用既有 strict
canonical JSON，unknown／duplicate field、wrong version、noncanonical 或 trailing bytes 均拒絕。

Plan 固定：

- ordered tree indices：`[0,1]`；
- 每棵 tree 的 exact continuation 與 handoff identity；
- domain-separated private input/result root identity；
- 每棵 tree 的 xi-mask output port；
- one-tree plan → inputs → result → complete dependency/checkpoint chain；
- scheduler plan → all inputs → tree 0 result → tree 1 result → complete chain；
- allowed modes：`sequential`、`bounded-parallel`；
- concurrency limit：2；
- per-tree 與 parallel aggregate resource ceiling。

Execution plan identity 為 6,156 bytes，SHA-256
`5153d3f07f5b14413db93826b7bb901b9eb3ca64827c5746ec397847760f17fd`。

### Per-tree identity 與 output port

| Tree | Continuation SHA-256 | Private input root | Private result root | Fresh cache identity | Output port |
| ---: | --- | --- | --- | --- | --- |
| 0 | `86ebf3cd87445b105764966859e7255514bd5e5a09ac0e9071435173a2133c09` | `7e24047f8d08ab08e625ea8f1bdc6f17996755465048486aac8aec724e4befcf` | `3e4aa43c70810343f2f8305e5f8b597b3edf8c63ec540ec958b0aad273cdaf87` | `4b851e6dabf81dc2cb89a09270a28a8ef206e492ffb4de1c2ed2c95f343944b0` | `tree[0].xi-masks`，wire 81,953，1,158 bits |
| 1 | `210365f8a96ba8b435a05af3e9e2a2f3ffb4731e2d7853f508738e55b5fb48ce` | `faea6601e4ae124e74e16769fdb0a29c715788e56dcfb128d74c70758b18153d` | `6e75eb9afbc4e79a32b561ff58973383b0165ecd8c9efa3ff59fb65813b78721` | `baefc17ecb496bf7b2c30fb2988fbb580a03a46cf93b39c526660153b8b3166c` | `tree[1].xi-masks`，wire 121,227，1,158 bits |

Input root 綁定 scheduler relation、tree index、handoff 與 continuation identity；result root
再綁定 input root、private result、receipt、child complete checkpoint 與 output port。Fresh
cache identity 由獨立 domain、tree index、input root 與 continuation 導出。兩個 identity
互異，且 runtime 不建立或共用 writable cache。

## Private output／journal isolation

One-tree API 要求 output 為 trusted artifact root 的 direct child，因此 scheduler 使用三個
互斥 sibling roots；若 scheduler output 名稱為 `scheduler`，runtime layout 為：

```text
private-artifact-root/
├── scheduler/
│   └── scheduler-journal/
├── scheduler.tree-0/
│   ├── inputs/
│   ├── results/
│   └── journal/
└── scheduler.tree-1/
    ├── inputs/
    ├── results/
    └── journal/
```

每棵 tree 的 input snapshots、private result、receipt、journal 與 resume state 均只存在於
自己的 output root。兩棵 tree 不共用 writable cache、journal、resume state 或 observed
`stream_bytes`；plan 中 `observed_stream_bytes` 固定為 `null`。Runtime tree roots 與
scheduler journal 都是 private external artifacts，不進 Git。

Scheduler fresh start 先透過 one-tree API 把兩棵 tree 各自推進至 exact
`inputs-committed`，再發布 scheduler 的 all-inputs checkpoint。只有此 checkpoint 完成後
才構成 scheduler restartable boundary；若 input publication 未完成，必須使用新的 trusted
scheduler root，不猜測缺失 private bytes。

## Scheduling 與 result identity

兩棵 fixture 各實際執行 3,576 rows、配置 2,412 post wires，output identities 為：

| Tree | Private result identity | Complete checkpoint | Output value SHA-256 |
| ---: | --- | --- | --- |
| 0 | 121,721 bytes；`86b8b9e55e8b31f2dc85674521e47e42208d4a525f77bc8ca934c12ae04b65f3` | `b8af8825ee8969a1e498e66e65d0ddc50dd8160b68c80d281dfa00676069406c` | `656b0e3b5581173be60d6c4ac9708305e62d042ebbd498931db5c738fc6a4bb1` |
| 1 | 121,724 bytes；`25555d550b8baaa580bc50ea3acd8e7c589bfa8bda98e9f75e07eaeebfd4e9aa` | `ae942f40258c8746258736e7a068bab0c190115aa630a2aaef9d02eaae89a0f7` | `6b08050b295a420c497ccaa0dacc5da2a4b220331fe804170ec9e9df524fdb32` |

Sequential 與 bounded-parallel 產出的 scheduler journal、兩份完整 one-tree roots、private
results、receipts 與 child checkpoints 全部 byte-identical。測試刻意延遲 tree 0，使 worker
completion order 為 `[1,0]`；scheduler 仍只按 plan 發布 `[0,1]`，final result order 不受
completion order 影響。Scheduler complete checkpoint 為 1,359 bytes，SHA-256
`5afe06b8eefad0d5383653114ab7747fc30699514d9e6a2aa4825dc243e0b625`。

## Crash／restart contract

Tests 覆蓋：

- sequential tree 0 完成並發布 parent checkpoint，而 tree 1 仍停在自己的
  `inputs-committed`；resume 可完成 tree 1；
- tree 0 已完整發布 child output、但 parent tree-result checkpoint 尚未發布的 orphan；
  resume 只在 child complete identity 與 plan pin 完全相符時採用，且不重算 tree 0；
- adopted 或新完成的 child 都必須先通過 closed-world inventory，再依
  `inputs → results → journal → child output → artifact root` 順序完成 directory fsync，
  才能發布 parent tree-result checkpoint；任一 `EIO` 保留原 parent checkpoint並可exact retry；
- scheduler parent必須是trusted artifact root的direct child，parent只允許
  `scheduler-journal`；child root只允許`inputs`、`results`及`journal`；
- parent output lock 下的 competing scheduler 拒絕；
- wrong／stale parent checkpoint 在任何 child input、journal 或 relation work 前拒絕；
- wrong child checkpoint、missing tree root、missing/unknown child result、unknown tree、
  scheduler journal gap 及 reordered final result 拒絕且不修補既有 bytes；
- repeated resume 對 complete scheduler 只 capture 已完成結果，不再執行 tree-post，全部
  files 保持不變。

Parent scheduler journal 與 child journals 都採 exclusive append-only publication。既有 entry
只會以 exact expected bytes 採用，不會 truncate、replace 或 overwrite。Corrective
durability barriers封閉的是受控publication dependency order；這仍是 bounded
cooperative-writer／controlled failure contract，不證明 hostile same-credential writer
exclusion、實體斷電、kernel crash、remount 或跨主機 durability。

## Resource boundary

| 項目 | Bound |
| --- | ---: |
| concurrency limit | 2 workers |
| per-tree max rows | 300,000 |
| per-tree max wires | 200,000 |
| per-tree private result | 262,144 bytes |
| per-tree planned memory | 512 MiB |
| parallel memory ceiling | 1,024 MiB |
| per-tree planned time | 240 seconds |
| scheduler checkpoint | 65,536 bytes |

這些是 bounded fixture ceiling，不是 OS reservation，也不得線性外推為 mixed degree-12/13、
18-tree、589,030,555-row relation 或 proving 的 production estimate。

## Tests、evidence 與 historical identity

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_multitree_restart_scheduler_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_multitree_restart_scheduler_v1.py --self-check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_multitree_restart_scheduler_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

Corrective targeted 最終結果為 20 passed、0 failed/errors/skipped，42.376 秒。完整
corrective baseline 最終結果為 953 tests：941 passed、0 failed/errors、12 skipped，
1436.253 秒。Skipped 案例仍是缺少精確 external artifacts 的既有 optional tests；不得把
skip 解讀為相關 production evidence 已完成。

Metadata-only tracked identities：

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| source | 52,593 | `8b22015ce6a94cc0c11a6c000896f285804fea10f363ea71108623f5940d0cd2` |
| tests | 29,496 | `3d5e55198c451e8b943b0424146f65917a487d902733eb611893bddf2f8e4564` |
| manifest | 15,475 | `fa59af42eedb86e95e709e17d6fcc61d4cb8fd0c89282ec31cc8b4291d146364` |
| portable evidence | 4,081 | `546fdf247aca3b21d3a6fd6b6e6f82e7f65abff0d59e61afff86f8603640138d` |

Portable evidence 不含 continuation、spool、private result、assignment、receipt、scheduler
checkpoint 或 tree resume-state raw。V2.38／v2.39 的 19 份 historical identities 已由
targeted test 逐檔核對不變。

## Claim boundary 與 global-tail dependency

| 層級 | 本 gate 可宣稱範圍 |
| --- | --- |
| Defined | canonical/versioned/domain-separated two-tree plan、root／cache identities、checkpoint chain 與 resource budget |
| Instantiated | tree 0＋1、four-leaf、degree-3 insecure-test-only fixture |
| Implemented | sequential／bounded-parallel scheduler、ordered parent journal、exact orphan adoption、completed capture |
| Tested | identity、order、crash/restart、competing writer、mutation、inventory、idempotence |
| Evidence-sealed | metadata-only bounded evidence |
| Proof-closed | false |
| Production-closed | false |

下列 claims 全部維持 false：

- `global_tail_continuation_implemented`；
- `production_legacy18_provider_implemented`；
- `production_durable_resume_implemented`；
- `qualified_pq_se_backend_integrated`；
- `formal_pi_issue_generated`；
- `Proof-closed`；
- `Production-closed`；
- `safe_to_start_large_replay`；
- `safe_to_start_large_proving_run`。

完整 legacy18 provider 的 serial dependency 仍是 global-tail phase A/B：後續必須先定義
跨 tree result 的 exact ordered input set、wire ownership、global-A/global-B continuation、
receipt chain，以及不可序列化 generator／hash state 的替代 contract；再實作獨立 tail
consumer、mixed degree-12/13 scheduler、fresh I1--I5 parent composition 與 production-scale
qualification。此 checkpoint 不提供 global-tail 或 large-run command。
