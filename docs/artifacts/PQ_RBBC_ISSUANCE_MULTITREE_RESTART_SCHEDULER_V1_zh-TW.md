# PQ-RBBC issuance bounded multi-tree restart scheduler v1

日期：2026-09-14；SRR-01 integration：2026-09-15。原始基線為
`ca6d4a43d7b2ebf728c660b4df0abaf526714544`；獨立 branch 為
`codex/pq-rbbc-issuance-multitree-restart-scheduler-v1`。原始 scheduler checkpoint 只新增名稱含
`multitree_restart_scheduler_v1` 的 source、tests、manifest、metadata-only portable
evidence 與本文件；當時未修改 one-tree predecessor、root canonical documents、system
architecture、ticket lifecycle 或 `pq_sat_auth`。

初始 commit `2d20829e3f09588e9aed7caf9508bef9b221c6d4` 的 bounded AI security
rereview 找到兩項 P2 與一項 P3：completed-child adoption 缺少 dependency-ordered
directory durability barriers、非 adoption 路徑可在 child root 含未知 component 時發布
不可再次 capture 的 complete、以及 parent output root 未採 closed-world inventory。
Corrective branch
`codex/pq-rbbc-issuance-multitree-restart-scheduler-corrective-v1` 以
`implementation_version=1.1` 建立新 parent plan／checkpoint identities；舊 1.0 scheduler
outputs 不得宣稱已由本 corrective qualification 涵蓋。

SRR-01 integration 以 finding-free scheduler commit
`13a75945a075630c1dc366615856239972efa6c6` 為直接基準，在獨立 branch
`codex/pq-rbbc-multitree-srr01-integration` 移植 tree-post receipt-suffix corrective
`64d0947dada2dafb5eb8636f09ea868366e8ef49`，並將 scheduler
`implementation_version` 提升為 `1.2`。先前對 `13a75945` 的 final security re-review
不涵蓋這個 combined tree；1.2 必須另行綁定 exact integration commit 重審。

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
implementation version 為 `1.2`，
relation namespace 為
`pq-rbbc/issuance/multitree-restart-scheduler/tree0-tree1-4leaf-insecure-test-only/v1`。
Domain separation 為 ASCII
`PQ-RBBC/ISSUANCE/MULTITREE-RESTART-SCHEDULER/PLAN/V1`；所有 JSON 使用既有 strict
canonical JSON，unknown／duplicate field、wrong version、noncanonical 或 trailing bytes 均拒絕。

Plan 固定：

- ordered tree indices：`[0,1]`；
- 每棵 tree 的 exact continuation 與 handoff identity；
- ordinal 2 `tree-pre[1]` 與 ordinal 3 `global-a` 的 verified receipt snapshot suffix；
- domain-separated private input/result root identity；
- 每棵 tree 的 xi-mask output port；
- one-tree plan → inputs → result → complete dependency/checkpoint chain；
- scheduler plan → all inputs → tree 0 result → tree 1 result → complete chain；
- allowed modes：`sequential`、`bounded-parallel`；
- concurrency limit：2；
- per-tree 與 parallel aggregate resource ceiling。

Execution plan identity 為 7,249 bytes，SHA-256
`8c29fff552b2ac8027dc99f592f99f4f31fb5fc195665fbc279fe61a71959100`。

Scheduler 1.2 不宣稱完整 receipt chain。兩棵 invocation 都攜帶相同 frozen identity 的
ordinal 2／3 snapshots；`_validate_invocations` 在取得 scheduler output lock、發布 plan 或
建立 child outputs 前，以每份 immutable `Snapshot.raw` 執行 continuation 的 strict schema、
ordinal、stage、invocation、cursor、relocation 與 2→3 link 驗證。Ordinal 0／1 raw 未攜帶，
故 `full_receipt_chain_verified=false`。

### Per-tree identity 與 output port

| Tree | Continuation SHA-256 | Private input root | Private result root | Fresh cache identity | Output port |
| ---: | --- | --- | --- | --- | --- |
| 0 | `d68382b393f66e6fcd1374985aa2f70d9d39c7a092756ac9bd954810bbba2bc9` | `f16e19d67ab502aee80860efaff63e8c2b565e131d8ebb01d7bc0675b2a72344` | `0f6a03dd2764937e73344ea6b70bc61a5f9d9f5f3c3e64cd1ac028452ca802c6` | `b4947f5c2de9a12c0900f6dc24b29f13ccb2cf0a106bd8440dd645da2ac27e8b` | `tree[0].xi-masks`，wire 81,953，1,158 bits |
| 1 | `d2f6bcaad813ae59ebd200512d37fbaae8afcdc604b534009f8d84949c6bdc72` | `89fc6928ce3d1672e5e296c55608e6f3c8f56555d8eeafc12935e2e7553299b8` | `12ac3efe1ddd2b7d11a316c68e83b752d5143cc626fece9b093a358b3825c708` | `38800563e099256dc1bc6e6cfa5b723823fe00d6db425a551bdde2e5946088c1` | `tree[1].xi-masks`，wire 121,227，1,158 bits |

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
| 0 | 121,721 bytes；`c250a462e1202c90a52fbf879270bd1a9d18592cfe1903be36a66f9b352a507c` | `fe2ebf511ad1c6c21a7d823c7b8990de41df1a08e93a6eed40ad3b226b11e1fb` | `656b0e3b5581173be60d6c4ac9708305e62d042ebbd498931db5c738fc6a4bb1` |
| 1 | 121,724 bytes；`613a8516075fc38582d0d197832d980ed65a552f3b02bbdbe602c040f3c892ff` | `9c227c3628a36b1175984b108c19d5c66d873c9ddbf3f6b52b7d9981b92dfd1a` | `6b08050b295a420c497ccaa0dacc5da2a4b220331fe804170ec9e9df524fdb32` |

Sequential 與 bounded-parallel 產出的 scheduler journal、兩份完整 one-tree roots、private
results、receipts 與 child checkpoints 全部 byte-identical。測試刻意延遲 tree 0，使 worker
completion order 為 `[1,0]`；scheduler 仍只按 plan 發布 `[0,1]`，final result order 不受
completion order 影響。Scheduler complete checkpoint 為 1,359 bytes，SHA-256
`ec6fbd094286066d90ef610776ac055dd3afab3a6ac20015aaa303ea3a334b4b`。

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

Integration scheduler targeted 最終結果為22 passed、0 failed/errors/skipped，42.356秒；
continuation＋one-tree restart＋scheduler combined targeted為60 passed、0
failed/errors/skipped，156.497秒。完整integration baseline為962 tests：950 passed、0
failed/errors、12 skipped，1501.625秒。Skipped案例仍是缺少精確external artifacts的既有
optional tests；不得把skip解讀為相關production evidence已完成。

另行執行不依賴test module的controlled integration probe：非法receipt suffix在scheduler
publication／`_PostSink`前拒絕且不建立output；兩個child input sets各恰為7份；sequential／
parallel逐檔byte-identical並固定`[0,1]`；completed capture及complete後repeated resume都未
重算。這是bounded engineering regression，不是獨立security review。

Metadata-only tracked identities：

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| source | 54,862 | `3bb999b414f810dd799e8b84c88fd83e2a7d14ee5ff687eb13b56a1aba01f50b` |
| tests | 32,850 | `df4ec76604e757cc4960da5e93fa885ab11e77725475f0ecefc45493287e652b` |
| manifest | 17,155 | `98de9e5ecfe99cd9592d870504c2e4d05cf3f4648b856a873c4b5e2c0c7b8045` |
| portable evidence | 4,529 | `67235d27db2f0b19fac60f89ecb7d0b406613737344a01cf7a32e0750d5f5dd6` |

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
目前可驗證的 ordinal 2→3 receipt suffix、若要擴張 chain claim 所需的 earlier receipt raws，
以及不可序列化 generator／hash state 的替代 contract；再實作獨立 tail
consumer、mixed degree-12/13 scheduler、fresh I1--I5 parent composition 與 production-scale
qualification。此 checkpoint 不提供 global-tail 或 large-run command。
