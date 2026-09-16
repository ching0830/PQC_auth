# PQ-RBBC Issuance Global-B restart v1 唯讀 AI technical/security re-review prompt

請對指定 exact target commit 執行唯讀、finding-oriented technical/security re-review。不要修改
repository、不要建立commit、不要merge或push。所有判定必須鎖定explicit commit object，不得因
branch之後移動而改變受審target。

## Lineage

- Required base：`4fdb3e3ffb391c3da65f05c98aef8269853c68e6`
- Target：由交付方填入本checkpoint的exact commit SHA-1。
- Branch：`codex/pq-rbbc-issuance-global-b-consumer-v1`
- Target必須是required base的直接單一後繼；否則停止並回報。

## 主要審查目標

1. CandidateSet consumer是否只消費同一批32-role immutable snapshot raws；identity、strict
   canonical JSON、closed schema、receipt graph、binding與execution不得改用重開後的原
   predecessor pathnames。
2. 8組relocation是否逐bit產生7,826條真正native equality rows；source/target locator、順序、
   width與value mutation均須fail closed。特別檢查所有numeric JSON欄位拒絕Python `bool`。
3. Phase-B是否只配置`[23,094,43,837)`，精確執行35,494 constraints；7,826 equalities不得
   混入此數。所有rows須由相同captured values驗證，沒有external assertions。
4. H1/points、p/mhat/xi、shared alpha、H2、canonical commitment及request binding的domain、
   field order、padding與serialization是否和unchanged native relation一致；不得只比較名稱。
5. Fresh publication是否在output建立前完成全部CandidateSet validation。32-role private input
   inventory、journal prefix、externally pinned resume、exact orphan adoption、completed capture及
   repeated resume是否closed-world、append-only、fail closed。程式內獨立固定的
   `INPUT_ROLE_ORDER` 是否唯一綁定ordinal 0–31；不得從plan本身推導可交換順序。
6. Publication/capture validators是否拒絕unknown fields、wrong version/domain/invocation/profile/
   plan、wrong role/ordinal/storage name/original identity、bool-as-int、trailing bytes、output port
   mutation、assignment/commitment/request mismatch及re-pinned checkpoint chain。
7. Production API是否在任何I/O或CAP computation前拒絕；test-only naming与configuration不得
   跨越production boundary。
8. 文件、manifest、portable evidence與handoff是否精確區分Defined／Instantiated／Implemented／
   Tested／Evidence-sealed／Proof-closed／Production-closed；不得宣稱full linear receipt chain、
   production legacy18、formal `pi_issue`、PQ-SE或large-run closure。
9. Portable evidence及Git diff不得含private raws、assignment、BR1CS、pickle、cache、checkpoint、
   resume state、logs或proving output；v2.38/v2.39的19份historical identities必須不變。

## 必要 independent probes

- 對8個rowsets的首／中／尾source與target逐側re-pin mutation；wrong order、swap、gap、duplicate、
  width、source locator、target locator及bool-as-int。
- Candidate handoff、任一32-role raw、role ordinal/name/storage filename/original identity mutation；
  所有非法fresh input須在output建立前拒絕。
- 將ordinal 0/1完整descriptor交換，重算ordinal與storage filename、重新命名input files，並重算
  plan及ordinal 1/2/3 checkpoints；resume與completed capture都必須在compute／publication前拒絕。
- Phase-B input、owned assignment、commitment、request hash、output port start/width、receipt summary
  digest及trailing bytes mutation。
- Fresh→inputs stop→new call resume；result payload／receipt orphan；stale checkpoint；completed
  capture；repeated completed resume；unknown input/result/journal file與journal gap。
- Guard原predecessor pathname reopen、monolithic reference rebuild、tree-pre/Global-A/tree-post rerun，
  確認consumer仍可由既有immutable CandidateSet完成。
- Production refusal guard必須證明沒有output、I/O或CAP computation。

## Commands

```bash
git show --no-ext-diff --stat <TARGET>
git diff --check 2779e845b53e5bd8c60a4cd45b932c69d0173529 <TARGET>
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_b_restart_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_b_candidateset_preflight_v1 tests.test_pq_rbbc_issuance_global_b_restart_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
```

另執行獨立temporary-copy probe；不得修改target checkout。最後執行`git diff --check`、19份
historical identity核對、prohibited-artifact inventory及clean status檢查。

## 回報格式

- Findings依P0→P3排列；每項含file/line、可重現步驟、impact與最小修正。
- 若無finding，明確寫`No findings`，並分別列targeted/full/probe counts與耗時。
- 明列exact target、parent、tree、branch、環境、未測assumptions及claim boundary。
- finding-free只代表本bounded engineering checkpoint；不是human cryptographic review或production approval。
