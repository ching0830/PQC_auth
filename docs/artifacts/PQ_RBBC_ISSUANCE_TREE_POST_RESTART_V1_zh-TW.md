# Issuance private tree-post publication／restart v1

日期：2026-09-14。基線為
`e2fd55bdecab06bda4a3424a7d47564d36950869`；獨立 branch
`codex/pq-rbbc-issuance-tree-post-restart-v1`。本 gate 不修改 `main`、system
architecture、ticket lifecycle、`pq_sat_auth`、legacy 18-tree profile 或歷史 evidence。

## Protocol 位置

本工作仍在 offline issuance I3 的 `CAP.Commit` child 內：

```text
tree-pre/private spool + global-A points
                  │
                  ▼
       inputs-committed checkpoint
                  │ process 可終止／重啟
                  ▼
       independent tree-post consumer
                  │
                  ├── private post-owned values
                  ├── xi-mask output port
                  └── tree-post receipt
```

上一 gate 已使 tree-post 不依賴 live Python generator。本 gate 再把 continuation、五份
CandidateSet snapshots 與 tree-post result 放入 private append-only publication contract，
使另一個程序能從 `inputs-committed` 邊界執行同一棵 bounded tree。

這不是新的 protocol message，也不是完整 CAP provider、global-tail continuation、parent
join、正式 `Pi_issue.Prove`／`Verify` 或 production proof。

## Private publication layout

Caller 必須先 provision 一個 owner-only trusted artifact root；每次執行使用新的 direct-child
output directory：

```text
output/
├── inputs/
│   ├── handoff、tree-0/tree-1 spools
│   ├── global-A points、global-A receipt
│   └── selected tree continuation
├── results/
│   ├── tree-N.post-result.private.json
│   └── tree-N.post-receipt.private.json
└── journal/
    ├── 0000-publication-plan.private.json
    ├── 0001-inputs-committed.private.json
    ├── 0002-result-committed.private.json
    └── complete.private.json
```

Publisher 沿用 v2.42 Linux/POSIX primitive：private directory flock 只序列化合作 writer；
每個檔案使用 `O_TMPFILE`、完整 write／file fsync、exclusive `linkat` 與 directory fsync。
既有 destination 不會 truncate、replace 或覆寫；symlink／競爭 writer 導致 fail closed。

Journal 以 `previous_checkpoint_sha256` 串接 plan、inputs、result 與 complete。Resume caller
必須從可信 handoff 提供最新 checkpoint 的 exact lowercase SHA-256；程式先核對同一份
immutable checkpoint raw，通過後才讀 private inputs 或重播 tree-post。

## Restart boundary

本 gate 的可恢復邊界明確定義為：

```text
0001-inputs-committed.private.json 已 exclusive publish 且完成 durability barrier
```

通過該邊界後，另一個程序不需要原 session、allocator、generator frame 或 in-memory
assignment，即可從已發布 snapshots 產生 result。受控 process-death regression 涵蓋：

- result payload 發布後；
- receipt 發布後；
- result checkpoint 發布後；
- complete checkpoint 發布後。

重啟會驗證並採用 exact orphan bytes，不會覆寫；wrong／stale external checkpoint digest、
unknown file、journal gap、缺少 committed result、變造 orphan、wrong version/domain/claim、
duplicate key 與 trailing bytes 均拒絕。

若 writer 在 private inputs 尚未完整發布時死亡，只有 plan 或不完整 input subset 不構成
可恢復 handoff。程式不猜測或重新產生缺失 private bytes，必須由 trusted producer 使用新的
publication root 重來。因此：

```text
incomplete_input_publication_recoverable = false
```

## Private result contract

`PQRBBC-ISSUANCE-TREE-POST-PRIVATE-RESULT-1` 固定包含該 tree post interval 的 2,412
個 F193 assignment values，使用 `2412xf193-little-endian-hex`：每個 field element固定
25 bytes、小端序、值域小於 `2^193`。Validator 同時核對：

- result 與 checkpoint exact identity；
- continuation、handoff、tree index、post interval 與 domain；
- 2,412 個 values 的 domain-separated assignment digest；
- xi output slice 為 1,158 個 canonical bits；
- output value SHA-256、receipt summary 與 receipt identity。

Result 是 plaintext secret state，只能留在 private artifact root；沒有 encryption、secure
erase 或 zeroization 保證。Git 的 portable evidence 只記錄 bytes／SHA-256 metadata，不嵌入
continuation、spool、assignment、result 或 receipt raw。

`capture_completed_result(...)` 使用 externally pinned complete checkpoint，對每個 pathname
single-open、single bounded read；identity、strict parsing、binding 與傳給下一 consumer 的值
都來自同一份 immutable `Snapshot.raw`。Capture 後 pathname 改變不會取代已 capture bytes。

這不證明 capture 期間沒有 writer。inode／size／mtime／ctime 只是 best-effort mutation
signals；flock 也不是 hostile-writer exclusion。Trusted producer handoff、writer quiescence、
owner/mode/ACL、既有 writable FD、mount namespace、filesystem/fsync semantics、backup 與
confidentiality 均為部署前提。

## Bounded qualification

唯一執行 profile 是 tree 0、4 leaves、degree 3、security bits 0；production widths 保留但
未執行。

| 項目 | 結果 |
| --- | ---: |
| tree-post rows | 3,576 |
| tree-post allocated wires | 2,412 |
| private input artifacts | 6 |
| private result bytes | 121,721 |
| private result SHA-256 | `86b8b9e55e8b31f2dc85674521e47e42208d4a525f77bc8ca934c12ae04b65f3` |
| receipt bytes | 2,804 |
| receipt SHA-256 | `7161cbfbe1701ca09b8c9348cfb71b42857acc5011e633312642e1eab5a2457d` |

Journal identities：

| Stage | Bytes | SHA-256 |
| --- | ---: | --- |
| publication plan | 1,573 | `044acd1595355e1d4d43c7f1eeda782a08650bcb6914c4f72fa745cdca1f3cf5` |
| inputs committed | 1,398 | `ce0d7f9b824f7a921cba58bc3eaa7aeb16329ac7ebc5d90ccd314d933b5537da` |
| result committed | 1,076 | `335067a3ac69572d379c8967ca71edebc255566c80bd0ff4e3e2bfbc3973d08d` |
| complete | 1,218 | `b8af8825ee8969a1e498e66e65d0ddc50dd8160b68c80d281dfa00676069406c` |

Fresh execution 與 inputs-committed 後 process restart 產生的所有 private files 完全相同。
Completed-result consumer 不重播 tree-post 即可還原相同 2,412 values 與 xi output port。

## Resources 與 exact commands

Bounded limits 維持 200,000 wires、300,000 rows；private result 上限 262,144 bytes、
checkpoint 上限 32,768 bytes；規劃值為 512 MiB 與 240 秒。這不是 OS reservation，不能
外推至 18 trees、589,030,555 rows 或 proving。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_tree_post_restart_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_tree_post_restart_v1.py --self-check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_tree_post_restart_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

Production、large replay 與 large proving 沒有 command。

Targeted regression：16 passed、0 failures/errors/skips，35.929 秒。完整 baseline 共 933
tests，921 passed、12 個既有 optional external-artifact skips、0 failures/errors，
1,364.046 秒，exit 0。V2.38／v2.39 的 19 份 historical bytes／SHA-256 已逐檔核對不變；
`git diff --check` 與 prohibited-artifact inventory 另於 commit 前執行。

## Claim boundary

| 層級 | 本 gate 可宣稱範圍 |
| --- | --- |
| Defined | private publication layout、journal chain、restart/result ABI |
| Instantiated | one-tree／four-leaf／degree-3 insecure-test-only fixture |
| Implemented | exclusive append-only publisher、restart executor、completed-result consumer |
| Tested | fresh/restart identity、real process death、mutation、stale digest、inventory、writer race |
| Evidence-sealed | bounded metadata-only evidence，不含 private payload |
| Proof-closed | false |
| Production-closed | false |

`full_session_restore`、`global_tail_continuation`、production durable resume、legacy18 provider、
72 relocations、fresh I1--I5／parent composition、PQ-SE backend、正式 `pi_issue` 及大型 replay
均未完成；五份 production artifacts、independent review、resource reservation 與明確大型
執行授權仍缺少。

## 後續與平行化邊界

此 gate 完成後，tree-post 的 bounded input/result ABI 已足以讓下列工作使用不同 worktree
與互斥檔案集平行開始：

1. global-tail phase A/B 的 explicit continuation 與 independent consumer；
2. tree restart publisher 從 one-tree fixture 泛化為 bounded multi-tree scheduler，但仍不得
   宣稱 production legacy18；
3. 對 publication、crash model 與 private-state operations 做獨立 security re-review。

真正的完整 legacy18 provider 仍依賴第 1 項 global-tail contract，因此 production profile
freeze、18-tree fresh replay 與 parent I1--I5 composition 必須等待這個 serial dependency。下一
個 critical-path gate 應先建立 **global-tail phase A/B read-only continuation preflight**，固定
跨 tree results 的輸入集合、wire ownership、receipt chain 與不可序列化 hash/generator state。
