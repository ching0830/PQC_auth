[English](RESEARCH_STATUS.md)

# 研究狀態

依目前工作 branch 的 PQ-RBBC v2.36 unified-tree bounded relation checkpoint 更新；尚未宣稱已合併至
`main`。

## 整篇論文狀態

| 項目 | Specification | Implementation | Evidence／proof |
| --- | --- | --- | --- |
| 整體架構 | 初版頂層定義 | 不適用 | 待 review |
| FAC issuer authorization | requirements 已知 | 未開始 | 未開始 |
| PQ-RBBC issuance 與 ticket | formal core 已定義 | research relation 與大量 circuit implementation | conditional reductions；production closure false |
| Opening authorization | abstract verifier interface 已定義 | 未開始 | 假設 authorization unforgeability |
| Threshold trace opening | abstract construction 已定義 | 具體完整 protocol 未封閉 | robust transcript 與 real key 未完成 |
| Satellite access 與 PQ AKE | 只有 requirements | 未開始 | 未宣稱 |
| Anti-replay 與 revocation | 只有 requirements | 未開始 | 未宣稱 |
| Handover | 只有 requirements | 未開始 | 未宣稱 |
| End-to-end evaluation | 已辨識 metrics | 未開始 | 無 system benchmark |

## RBBC checkpoint

截至 v2.29 已完成：

- production composer cache recovery；
- parent-bound global-tail regeneration 與 replay；
- planned producer positions 0–17 materialized，且18個位置均依適用的frozen
  contracts完成獨立及aggregate replay；
- 全部72個output relocations逐wire核對；
- complete 18-tree assignment replay與cross-segment wire identity；
- legacy F2 parent relation確定性lift至GF(2^193)，以1,408個native equality
  rows取代唯一external assertion；
- exact parent CAP-to-H-RBBC join，合計589,030,555 rows、0 failures、0 external
  assertions；
- 上述bounded checkpoints的portable path-free evidence。
- v2.30 fork-security唯讀preflight已綁定v2.29 final semantics；authoritative
  Blind-UOV 2025-10-31 revision、fork-specific proof-audit packet、CAP／QROM／
  blindness-one-more internal gap reviews與independent-review request均已凍結並由
  path-free evidence封存。Internal audit已完成且可交付獨立review；由於review
  明確找到CAP extractor、concrete QROM、fork proof、PQ SE-NIZK與獨立attestation
  等blockers，沒有提升任何security claim，也沒有啟動large replay。
- v2.31已進一步凍結CAP的六個oracle domains與full-value transcript、canonical
  admissible commitment、Definition-10 straight-line extractor interface、mixed
  degree-12／13 tree coverage及unique committed mask game。Contract checkpoint已由
  path-free evidence封存。Straight-line extractor specification、unique-mask
  reduction與122,847-record contract-bound candidate evidence已完成並凍結，10／10
  negative vectors均拒絕；目前external inventory只缺independent attestation。
  Numeric accounting同時顯示未含PoW的raw degree term為`2^-182`，低於192-bit
  target，因此CAP security、fork security與production claims全部維持false。
- v2.32已綁定v2.31與589,030,555-row relation identities，凍結Prove／Verify API、
  production proof outer envelope requirements及PoW／security-profile disposition
  schema。Preflight確認public statement只作為public input、Verify不得取得witness，
  並明確禁止把252-byte candidate `c_2`升格為production `c_x`。後續已直接開始
  bounded implementation：strict candidate statement與outer-envelope codec已實作，
  specification、serialization、PoW disposition與partial implementation evidence
  四份external candidates已產生；independent review仍缺少。Paper-compatible PoW
  需要單一interleaved unified GGM tree，但目前fork為18個獨立roots，所以未變更
  architecture/profile、未實作accepting prover/verifier或PoW，也未執行large
  proving run。所有production/security claims維持false。
- v2.33已依明確授權為unified-tree CAP保留獨立candidate namespace/profile，現有
  18-tree profile與全部既有evidence保持不變。唯讀preflight已凍結40,960-leaf
  position-major mapping、migration impact、資源lower bound及future exact command
  contracts；7份既有來源均逐byte驗證，故可進入algorithm specification與reduced
  prototype。由於specification、reduced evidence、runner qualification、resource
  reservation與independent design review尚缺，production pre-freeze、large replay
  與large proving run仍全部禁止。沒有把tree 0–17 observed `stream_bytes`或v2.29
  transcript升格為新profile evidence。
  後續已完成exact specification及12-leaf reduced implementation：單root展開、
  40,960-entry production mapping bijection、strict commitment/opening codec、h3
  counter grinding、explicit-bit與minimal-frontier/T_open驗證均有實作。Deterministic
  positive vector接受，9/9 mutations拒絕；fresh-cache、中斷/resume identity及
  overwrite refusal均通過。這些結果由path-free reduced seal綁定，但不代表
  production profile、CAP security或large replay已完成。
- v2.34已建立read-only production pre-freeze checker與closed-world operator
  resource-reservation schema。它綁定v2.33 reduced seal、凍結production descriptor
  fingerprint及future command digest，並逐byte驗證四份v2.33 external outputs。
  當前host容量通過4 cores／16 GiB／80 GiB minimum，但resource reservation與
  independent review尚未提供；現有runner亦只支援reduced phase，production runner、
  relation contract與execution authorization皆未成立。故production leaves、replayed
  rows與proofs仍為0，所有large-run及security flags維持false。
- v2.35已建立獨立production runner skeleton及relation-stage contract，並以
  `(4,4,2×16)`、40-leaf、18-vector test-only fixture完成fresh/resume deterministic
  identity、overwrite refusal與production branch pre-output rejection qualification。
  這只關閉runner skeleton控制流程；production checkpoint payload與relation generator
  尚未實作，production observations仍全為空，且resource reservation、independent
  review、execution authorization及identity-frozen launch manifest仍缺少。因此
  `production_runner_qualified`、pre-freeze、large replay/proving及security claims
  全部維持false。
- v2.36已實作canonical checkpoint payload與bounded relation generator。40-leaf、
  18-vector fixture在unified-tree後中斷，使用精確payload identity resume，再獨立
  重算144條contract-IR equality rows，結果144/144成立；checkpoint mutation、缺少
  resume identity、overwrite、ticket witness mutation及production branch均fail
  closed。這些不是BR1CS或production constraints；production-scale payload與relation
  qualification、final unified statement encoding及launch external artifacts仍未完成，
  所有production/security flags維持false。
- v2.37已在獨立unified-tree namespace凍結canonical public statement serialization與
  parent-input ABI。Production profile只建立314-byte statement test vector；bounded
  qualification使用v2.36 checkpoint的158-byte `c_r`建立643-byte parent envelope，
  並使16/16 codec、cross-profile、binding及ticket-mapping mutations全部拒絕。這解除
  final statement encoding blocker並允許撰寫production streaming path，但沒有
  production `c_r`、parent envelope或join observation；production pre-freeze、large
  replay/proving及security flags仍全部為false。Legacy 18-tree profile與evidence保持
  read-only，且未沿用其observed stream identities。
- v2.38已實作external-only streaming chunks與checkpoint chain。Bounded fixture將
  v2.36 state及v2.37 parent input寫成179 records／15 chunks，第7個chunk後中斷並以
  精確checkpoint identity resume；checkpoint/chunk mutation、overwrite、缺少resume
  identity及production branch均拒絕。Production 163,859-record／163-chunk／
  16,631,418-byte raw payload僅是layout plan，不是execution observation。目前host
  capacity通過minimum，但resource reservation、independent review及launch manifest
  均缺少，production stream與scale qualification亦未完成，故所有production與
  security gates維持false。
- v2.39已建立resource reservation、independent review與launch manifest三份
  closed-world schemas、刻意不合法的draft templates、strict validators及唯讀
  identity-set preflight。Synthetic valid candidates證明launch binding可建立，但只
  能進入later identity freeze，不能啟動production。目前三份真實external artifacts
  均缺少且未凍結，production stream/checkpoint、scale qualification及execution
  authorization亦未成立；因此production pre-freeze、large replay/proving與全部
  security claims維持false。Portable evidence只封存schema與負向qualification，沒有
  偽造operator或independent-review attestation。

仍未完成：

- 完整CAP Prove／Verify、production `c_x` serialization、PoW／192-bit profile
  disposition、concrete Anemoi ROM／QROM justification及CAP獨立review；
- unified-tree production-scale checkpoint payload materialization／relation
  qualification、production streaming materialization、operator resource reservation、independent
  design/cryptographic review、production runner qualification、外部identity freeze與
  launch manifest，
  以及全新profile pre-freeze與兩次完整replay；
- fork-specific QROM、blindness與one-more proof及其獨立review；
- 合格 PQ zero-knowledge／simulation-extractable backend；
- real trace-encryption key 與 robust threshold transcript；
- 新的 size、time、memory benchmarks；
- production closure。

RBBC 操作上的 authoritative handoff 仍為 [docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md](docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md)。

## 狀態詞彙

- **Defined：**已有文字或 formal interface。
- **Instantiated：**已有具體 primitive 或 protocol choice。
- **Implemented：**已有 executable code。
- **Tested：**已有 positive 與 negative tests。
- **Evidence-sealed：**portable evidence 已綁定宣稱的 execution。
- **Proof-closed：**所需 theorem assumptions 與 reductions 已 review。
- **Production-closed：**implementation、integration、proof 與 benchmark gates 全部封閉。

上述詞彙不可互換使用。
