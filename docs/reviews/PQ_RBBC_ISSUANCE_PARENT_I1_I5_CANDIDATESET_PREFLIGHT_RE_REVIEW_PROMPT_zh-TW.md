# PQ-RBBC fresh parent I1–I5 CandidateSet preflight v1 唯讀 AI technical/security re-review prompt

請對指定exact target commit執行唯讀、finding-oriented technical/security re-review。不要修改
repository、不要建立commit、不要merge或push；審查必須鎖定explicit commit object。

## Lineage

- Required base：`12be68c199f108c0141e613b7e70cba251183168`
- Target：由交付方填入本checkpoint exact commit SHA-1。
- Branch：`codex/pq-rbbc-issuance-parent-i1-i5-candidateset-preflight-v1`
- Target必須是required base的直接單一後繼；否則停止並回報。

## 主要審查目標

1. Predecessor pins須精確對應finding-free completion sealer及正式I1–I5定義／codec／bounded CAP
   semantics；不得接受branch移動或同名替代檔案。
2. External parent handoff digest必須在prerequisite、completion CandidateSet或CAP host computation前驗證。
   所有identity、parse、binding與future consumption只使用同一批immutable `Snapshot.raw`，不得
   pathname reopen。
3. 固定40-entry role order必須獨立於handoff內容：completion handoff＋既有36 roles＋parameters／
   statement／witness。完整descriptor permutation、ordinal重算、inventory/handoff re-pin及bool-as-int
   必須拒絕。
4. Parameters、statement、witness binary codecs須拒絕wrong magic/version/profile/domain、section reorder、
   duplicate/unknown section、wrong length、truncation與trailing bytes；`pp`必須綁定exact parameters raw。
5. Host reference I1–I5必須全部對應同一fixture：M/ctx、ticket message、two-tree rho、derived mask r、
   511-byte c_r、72-byte H_RBBC、beta、holder key、rid/sn/error/trace payload。不可把host computation說成
   constraint replay或cryptographic proof。
6. Wire plan應精確得到1,600 public bits、11,622 secret bits、parent-local input/import end 18,143；
   join plan應精確為6,654 bits。Computed與absolute intervals必須保持null，rows upper bound須標為
   unobserved planning value。
7. `sid`只可宣稱canonical/nonzero candidate；不得宣稱freshness、linearizable reservation或consumption。
8. Production及parent execution entrypoints必須在任何I/O、validation、CAP compute或output前拒絕。
9. Manifest、portable evidence、artifact note與handoff須維持parent constraints/native joins replay=0、
   formal pi_issue／PQ-SE／legacy18／Proof-closed／Production-closed=false。
10. Diff不得包含private statement/witness raws、assignment、BR1CS、pickle、cache、checkpoint、resume、
    logs、archives或proving output；v2.38/v2.39 historical identities不得改變。

## 必要 independent probes

- 對40個inventory descriptors逐一做wrong ordinal／role／identity，並做全部pair swaps；重算inventory與
  handoff digest後仍須fail closed。
- Parameters／statement／witness逐section做wrong id、length、version、truncation、trailing及field
  mutation；M、r、rho、k_hold、e、ctx、rid、beta、pp均須有rejection coverage。
- Completion c_r、request hash、ticket message及completion handoff identity做re-pinned mutation。
- Guard pathname reopen、fresh lowerer、native row sink、parent replay及publication；validator只能執行
  declared bounded host reference checks，改寫pathname不得替換已capture raw。
- Production refusal guard確認零I/O、零host CAP compute、零parent compute、零output。
- 檢查portable evidence沒有private raw、absolute path或prohibited artifacts。

## Commands

```bash
git show --no-ext-diff --stat <TARGET>
git diff --check 12be68c199f108c0141e613b7e70cba251183168 <TARGET>
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_tail_completion_sealer_v1 tests.test_pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

另以detached exact-target temporary checkout執行independent probe。最後執行`git diff --check`、19份
historical identity核對、prohibited-artifact inventory與clean status檢查。

## 回報格式

- Findings依P0→P3排列；每項含file/line、重現、impact與最小修正。
- 若無finding，明確寫`No findings`，列targeted/full/probe counts與耗時。
- 明列exact target、parent、tree、branch、環境、未測assumptions與claim boundary。
- Finding-free只支持bounded engineering preflight，不是human cryptographic review、formal proof或
  production approval。
