# PQ-RBBC issuance Global-A serial gate 唯讀 re-review prompt

請在新的獨立、乾淨 worktree，唯讀審查呼叫者提供的完整 exact serial-gate commit SHA。該
commit 的 parent 必須是 finding-free multitree scheduler＋SRR-01 integration：

```text
2f1b674cf7afafebd1bdb4778ce456093a6c9005
```

Target branch 應為 `codex/pq-rbbc-issuance-global-tail-serial-gate-v1`。較早 prototypes
`c9c8e1184f493e053e8ae11f323130e26cee9d29` 與
`b0863c4b111f52f5183d20bca221f6df1ec506b9` 只可作來源比較；不得以其舊 identities 或
`ca6d4a43...` claim boundary 取代新 successor。不要修改 repository、commit、merge、push，
也不要啟動 production、large replay 或 proving。

## 必查 contract

1. Global-tail preflight `implementation_version=1.1` 必須 pin scheduler 1.2 exact source、tests、
   manifest與portable evidence，以及SRR-01 continuation/restart successors。
2. Preflight不得保留模糊的`receipt_chain_required=true`。Global-A只宣稱raw-verified ordinal
   `[0,1,2]` prefix；scheduler只宣稱`[2,3]` suffix；兩者以ordinal 2相同bytes/SHA-256交會，
   pathname名稱不同不得造成假陰性或假等同。
3. `full_execution_receipt_chain_verified=false`與
   `global_b_same_invocation_candidate_set_implemented=false`必須在source、manifest、evidence、
   artifact note與handoff一致。
4. Global-A 1.1必須對每一份宣稱的receipt snapshot使用single-open、single bounded read；
   identity、strict parse、ordinal/stage/invocation及0→1→2 links均消費同一份immutable raw。
5. Consumer只能消費同一`TreePreCandidateSetInsecureTestOnly`，不得重跑tree-pre、重開candidate
   pathname、恢復Python generator/hash/allocator state或借用其他tree observed stream bytes。
6. 19,671 rows、12,179 owned wires、H1、points、stream／row-semantics及private assignment
   digests必須與unchanged live bounded Phase-A一致。
7. Fresh、inputs-committed restart、real new-process resume、各result publication boundary、
   completed capture與repeated resume必須維持append-only、exact-checkpoint、no-overwrite及
   same-snapshot contract。
8. Production API必須在I/O前拒絕；Global-B、完整global-tail、mixed degree-12/13、legacy18
   production provider、production durable resume、formal `pi_issue`、PQ-SE、large-run、
   Proof-closed與Production-closed全部維持false。

## Independent probes

不要只重跑作者tests。至少在`/tmp`建立新probe：

- 對ordinal 0／1／2各做wrong ordinal、stage、invocation與broken-link mutation；重新pin所有
  直接／間接identity後仍須在Phase-A compute及output建立前拒絕。
- 加入duplicate key、trailing bytes、swap、gap與foreign inventory；不得建立或修補output。
- Capture合法CandidateSet後改寫pathname，確認後續只使用已capture raw。
- Fresh後在每個result／checkpoint publication boundary注入中斷或EIO，確認既有bytes不變且
  exact resume可完成；completed capture/repeated resume不得重算Phase-A。
- 核對ordinal 2 prefix與scheduler suffix的bytes/SHA-256 overlap，並證明這不等於Global-B
  same-invocation fan-in或完整execution receipt chain。

## Commands與交付

至少執行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_global_tail_continuation_preflight_v1 \
  tests.test_pq_rbbc_issuance_global_a_restart_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
git diff <exact-parent> <exact-target> --check
```

逐檔核對19份v2.38/v2.39 historical identities，並執行prohibited-artifact inventory。交付繁體
中文report、`findings.json`、independent probe source/results、commands/results及SHA-256
inventory；finding-free結論也必須綁定exact commit並列出尚未驗證範圍。
