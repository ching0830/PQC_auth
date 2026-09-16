# PQ-RBBC Global-tail completion sealer v1 唯讀 AI technical/security re-review prompt

請對指定 exact target commit 執行唯讀、finding-oriented technical/security re-review。不要修改
repository、不要建立commit、不要merge或push；判定必須鎖定explicit commit object，不得因branch
後續移動而改變target。

## Lineage

- Required base：`6b27800a2be000b3dd1c67ce25112a0fbba2e495`
- Target：由交付方填入本checkpoint exact commit SHA-1。
- Branch：`codex/pq-rbbc-issuance-global-tail-completion-sealer-v1`
- Target必須是required base的直接單一後繼；否則停止並回報。

## 主要審查目標

1. Predecessor pins是否精確對應finding-free Global-B corrective；不得默默接受branch移動或替代
   source/test/manifest/evidence/artifact note。
2. External completion-handoff digest是否在存取dependent snapshots前先驗證。Validator是否只消費
   CandidateSet中相同immutable raws，沒有重開predecessor pathname、重跑Global-B或重建monolithic
   reference。
3. 固定36-entry `SNAPSHOT_ROLE_ORDER`是否獨立於handoff輸入，並唯一綁定ordinal 0–35；完整
   descriptor permutation、ordinal重算與inventory/handoff re-pin必須拒絕。所有numeric欄位與arrays
   須要求exact `int`且拒絕Python `bool`。
4. 前32 roles是否精確沿用finding-free Global-B CandidateSet；result、receipt與terminal complete
   checkpoint是否驗證exact identity、strict canonical JSON、domain/version/profile/plan/invocation、
   ordinal/stage、input/output inventory及declared previous/publication links。
5. Parent input是否唯一綁定同一Global-B publication的511-byte canonical `c_r`及72-byte request hash，
   並拒絕wrong source digest、version/domain、length、hex case/encoding、digest、unknown field、duplicate
   key及trailing bytes。Future parent必須消費同一captured parent snapshot，不得pathname reopen。
6. Receipt contract是否只宣稱branch graph，維持
   `full_execution_receipt_chain_verified=false`；不得把digest graph說成單一完整execution chain。
7. Row accounting是否清楚區分predecessor已檢查70,143 rows、sealer replay 0與parent replay 0；不得
   冒充589,030,555 constraints replay、proof或production qualification。
8. Production API是否在任何I/O、validation、CAP compute或output建立前拒絕；test-only naming與
   configuration不得跨越production boundary。
9. 文件、manifest、portable evidence及handoff是否精確區分Defined／Instantiated／Implemented／
   Tested／Evidence-sealed／Proof-closed／Production-closed。Legacy18、formal `pi_issue`、qualified
   PQ-SE、large-run、FAC authentication與production claims必須保持false。
10. Portable evidence與Git diff不得包含private raws、parent input、assignment、BR1CS、pickle、
    cache、checkpoint/resume state、logs、archives或proving output；v2.38/v2.39的19份historical
    identities必須不變。

## 必要 independent probes

- 對36個inventory descriptors逐一做wrong ordinal／role／identity，並做所有descriptor pair swap；
  重算inventory與handoff digests後仍須fail closed。
- Handoff wrong version/domain/profile/plan/invocation/stage/graph、bool ordinals/row counts、unknown／
  duplicate/trailing mutation。
- Parent input的四個source digests、`c_r`與request hash之hex／length／digest／encoding、wrong version／
  domain、bool numeric、unknown／duplicate/trailing mutation；每次重建completion handoff後仍須拒絕。
- Global-B CandidateSet、result、receipt、complete的re-pinned raw mutations；complete的ordinal/stage、
  previous/publication link、input/output inventory mutation。
- Guard pathname reopen、Global-B compute、monolithic reference rebuild與parent compute，確認validator仍
  只使用captured raws；改寫外部pathname不得取代已capture snapshot。
- Production refusal guard必須證明無I/O、CAP computation、parent replay或output。
- 核對portable evidence未嵌入任何private raw或absolute path。

## Commands

```bash
git show --no-ext-diff --stat <TARGET>
git diff --check 6b27800a2be000b3dd1c67ce25112a0fbba2e495 <TARGET>
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_tail_completion_sealer_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_b_candidateset_preflight_v1 tests.test_pq_rbbc_issuance_global_b_restart_v1 tests.test_pq_rbbc_issuance_global_tail_completion_sealer_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

另以detached exact-target temporary checkout執行獨立probe。最後執行`git diff --check`、19份
historical identity核對、prohibited-artifact inventory與clean status檢查。

## 回報格式

- Findings依P0→P3排列；每項含file/line、重現步驟、impact與最小修正。
- 若無finding，明確寫`No findings`，分別列targeted/full/probe counts與耗時。
- 明列exact target、parent、tree、branch、環境、未測assumptions與claim boundary。
- Finding-free只支持本bounded engineering checkpoint，不是human cryptographic review或production
  approval。
