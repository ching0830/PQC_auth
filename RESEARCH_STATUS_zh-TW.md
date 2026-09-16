[English](RESEARCH_STATUS.md)

# 研究狀態

依 2026 年 9 月 16 日 project-reorganization integration candidate 更新。此 tree 集中
PQ-RBBC v2.43、bounded issuance chain、system governance S0–S2、satellite access v0.2、
D1–D4b access prototypes、opening integration及threshold research checkpoints；不表示這些
研究線已成為同一個 production protocol。精確 identity 由 Git commits、manifests 與 tests
約束。

## 整篇論文狀態

| 項目 | Specification | Implementation | Evidence／proof |
| --- | --- | --- | --- |
| 整體架構 | 頂層角色、階段、claim vocabulary與module ownership已定義 | canonical configuration／public initialization codecs；新增可測模組registry | 導覽與registry不取代security proof；production key ceremony未完成 |
| FAC issuer authorization | v0.1 epoch／policy／quota-bound grant；S2 ML-DSA staging boundary | bounded control plane、單主機多程序SQLite quota、non-threshold ML-DSA staging adapter | schema／auth／quota／restart tests；FAC threshold signature、DKG及跨主機store未完成 |
| PQ-RBBC CAP／ticket core | legacy relation evidence與unified-tree candidate contracts已定義 | v2.43 reservation-binding validator；owner-controlled reservation已建立 | corrective AI review通過；具名獨立human review、launch manifest、scale execution與production closure未完成 |
| Offline issuance `R_issue` | I1–I5、production inputs、split／multi-tree／global phases與parent CandidateSet contracts | bounded two-tree／four-leaf execution chain至fresh-parent read-only preflight | portable bounded evidence；parent constraint consumer、qualified PQ-SE backend與正式`pi_issue`未完成 |
| Opening authorization | v0.1 request、authorization statement、replay與share gate | bounded fail-closed `OpenShareService`及stable `VerifyTicket` integration | deterministic／negative integration tests；production signature／share proof未完成 |
| Threshold trace opening | abstract share／combiner boundary；GF candidate ABI為研究線 | test-only combine及`pq_threshold_candidates` bounded evaluators | 非threshold reference／research tests不構成OA production backend、DKG或privacy proof |
| Satellite access 與 PQ AKE | V1四訊息保留；V2 exact `R_access` NIZK profile已定義；V3 holder-signature仍是候選 | V2 codecs、pure-check、grant、activation、UE accept與application pipeline；D4 ML-DSA／D4b FAEST隔離prototypes | 真實wire／timing prototype evidence；shared production ticket fork、PQ suite與composition proof未完成 |
| Anti-replay／revocation | V2 pending-confirm／active、exact retry、early-burn、wallet及reconciliation semantics | 單主機SQLite replay／wallet／delivery／inbox／revocation／reconciliation／audit／resume／lease | restart、race、mutation tests；跨主機linearizability、實體斷電與production deployment未完成 |
| Handover | requirements與ticket不重用邊界 | 未完成正式protocol | 未宣稱 |
| End-to-end evaluation | metrics與50,000-byte research gate已定義 | exact `R_access`、ML-DSA與FAEST prototype benchmarks | ticket仍含provisional fixture；不是production system benchmark |

## 本次整合來源

整合來源 identities 固定在
[`manifests/project_module_registry_v0_1.json`](manifests/project_module_registry_v0_1.json)。
這只說明哪些完成的 branch checkpoint 被集中；沒有把不同 profile 的 evidence 混成共同
proof，也沒有改寫任何 historical artifact identity。

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
- v2.41已針對v2.39 technical pre-review的八項findings建立獨立successor：候選輸入
  採single-open／single bounded-read snapshots，identity、strict canonical JSON parse、
  binding與validation共用同一immutable raw；exact paths/commands、strict bool/int、
  trusted time、reservation-bound review、exclusive publication及authoring predecessor
  gates均有positive／negative／mutation／race regressions。初次重審發現metadata不能
  證明同長度原地改寫不存在，corrective commit已將契約精確縮限為captured-byte
  consistency，並把filesystem強不可變性列為部署前提。Effective-tree AI technical
  re-review未發現新問題；本機integration regression為641 tests，629 passed、12既有
  optional skips、0 failures/errors。其後建立的v2.41 operator reservation屬被拒流程的
  歷史，不能授權v2.42；external human review、launch identity freeze、execution
  authorization與production仍未成立。
- v2.42已以不改寫sealed v2.33／v2.38／v2.41 evidence的successor修正兩個原始
  interruption-recovery窗口及Blind-UOV參數引用錯置。Corrective commit進一步要求
  existing orphan／checkpoint／complete／index／evidence在採用前補足dependency-ordered
  directory durability barriers，並在output lock內先比對external checkpoint digest，
  再以同一captured bytes完成bounded重算後的canonical／semantic validation。Exact
  corrective AI technical re-review對RR242-01／02、CR-01／02及78份sealed predecessors
  均無新blocking findings；targeted 128 passed，完整suite 676 passed、12既有optional
  skips、0 failures/errors。這只封閉bounded recovery／provenance technical-review範圍；
  未做實體斷電或production-scale qualification，也不是具名human review。
- v2.43已建立綁定v2.42 effective implementation、source identities、exact command、
  trusted roots、batch、window與resource的closed-world reservation contract；三項P2
  technical-review findings經corrective後關閉，passed status已整合，owner-controlled
  approval／reservation已建立。它只允許提交具名獨立human review；目前沒有human review、
  launch manifest、production execution authorization或production observation。

## Issuance checkpoint

獨立 issuance chain 已從 formal I1–I5 relation 推進至 bounded CAP child、split／lowering、
fragment producers、multi-tree adapter、private spool、tree-post、restart scheduler、
Global-A／Global-B／Global-tail completion與fresh-parent CandidateSet preflight。Latest
`b877189` 仍只做同一captured-byte set上的identity／parse／binding與direct host checks；
parent constraints及native join rows為0，3,100,000 rows只是不具 observation 身分的planning
upper bound。Current handoff 見
[`docs/roadmaps/PQ_RBBC_ISSUANCE_CURRENT_HANDOFF_zh-TW.md`](docs/roadmaps/PQ_RBBC_ISSUANCE_CURRENT_HANDOFF_zh-TW.md)。

仍未完成：

- 完整CAP Prove／Verify、production `c_x` serialization、PoW／192-bit profile
  disposition、concrete Anemoi ROM／QROM justification及CAP獨立review；
- unified-tree production-scale checkpoint payload materialization／relation
  qualification、production streaming materialization、v2.43 named external human
  design／cryptographic review、production runner scale qualification、可信producer
  handoff／writer quiescence、外部identity freeze與launch manifest，
  以及全新profile pre-freeze與兩次完整replay；
- fork-specific QROM、blindness與one-more proof及其獨立review；
- 合格 PQ zero-knowledge／simulation-extractable backend；
- real trace-encryption key 與 robust threshold transcript；
- 新的 size、time、memory benchmarks；
- 新access版本的shared ticket／`VerifyTicket` fork、`R_key`與`R_issue,new` circuit、
  concrete production PQ AKE／holder-authentication backend、安全composition及真實ticket
  satellite-path benchmark；
- distributed replay／revocation store、跨主機linearizability、實體斷電qualification與
  handover；
- production closure。

CAP／unified-tree與issuance各自使用兩份current handoff；入口見
[`docs/README_zh-TW.md`](docs/README_zh-TW.md)。

## 狀態詞彙

- **Defined：**已有文字或 formal interface。
- **Instantiated：**已有具體 primitive 或 protocol choice。
- **Implemented：**已有 executable code。
- **Tested：**已有 positive 與 negative tests。
- **Evidence-sealed：**portable evidence 已綁定宣稱的 execution。
- **Proof-closed：**所需 theorem assumptions 與 reductions 已 review。
- **Production-closed：**implementation、integration、proof 與 benchmark gates 全部封閉。

上述詞彙不可互換使用。
