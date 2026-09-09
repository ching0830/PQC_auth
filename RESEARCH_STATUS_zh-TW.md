[English](RESEARCH_STATUS.md)

# 研究狀態

依 2026 年 9 月 9 日整合 checkpoint 更新，包含 system vertical slice、system
initialization／issuer authorization／conditional opening control plane，以及 PQ-RBBC
v2.27–v2.41。精確發布位置仍以 Git commit 與 branch 為準。

## 整篇論文狀態

| 項目 | Specification | Implementation | Evidence／proof |
| --- | --- | --- | --- |
| 整體架構 | 初版頂層定義與 system profile v0.1 contracts | canonical configuration／public initialization bundle codecs | deterministic vectors與negative tests；production key ceremony未完成 |
| FAC issuer authorization | v0.1 epoch／policy／quota-bound grant contract | bounded control-plane與單程序atomic quota reference store | canonical vectors與quota／replay tests；FAC PQ signature及distributed store未完成 |
| PQ-RBBC issuance 與 ticket | formal core 已定義 | research relation 與大量 circuit implementation | conditional reductions；production closure false |
| Opening authorization | v0.1 canonical request、authorization statement、replay與share gate | bounded fail-closed `OpenShareService` control flow | deterministic codecs與gate tests；production signature／share proof未完成 |
| Threshold trace opening | abstract construction與v0.1 share／combiner boundary已定義 | test-only backend下的share consistency、threshold combine及serial check | robust threshold decoder、OA DKG、real keys與production transcript未完成 |
| Satellite access 與 PQ AKE | v0.1 access object layouts、transcript／attempt identities與test-only suite profile；PQ AKE尚未選定 | ServingContext與AccessInit／Challenge／Finish／Accept codecs已實作；無holder authenticator或AKE | object／binding tests；未宣稱authentication security或production closure |
| Anti-replay 與 revocation | v0.1 one-time state、原子消耗、retry／crash semantics與framing已有draft；G1尚未freeze | canonical frame／opaque parser、use identity與test-only process-local linearizable replay model已實作 | replay／framing tests；尚非durable／distributed store，未宣稱production closure |
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
- v2.41已針對v2.39 technical pre-review的八項findings建立獨立successor：候選輸入
  採single-open／single bounded-read snapshots，identity、strict canonical JSON parse、
  binding與validation共用同一immutable raw；exact paths/commands、strict bool/int、
  trusted time、reservation-bound review、exclusive publication及authoring predecessor
  gates均有positive／negative／mutation／race regressions。初次重審發現metadata不能
  證明同長度原地改寫不存在，corrective commit已將契約精確縮限為captured-byte
  consistency，並把filesystem強不可變性列為部署前提。Effective-tree AI technical
  re-review未發現新問題；本機integration regression為641 tests，629 passed、12既有
  optional skips、0 failures/errors。這不是external human cryptographic review；真實
  reservation/review、launch identity freeze、execution authorization與production仍未成立。

仍未完成：

- 完整CAP Prove／Verify、production `c_x` serialization、PoW／192-bit profile
  disposition、concrete Anemoi ROM／QROM justification及CAP獨立review；
- unified-tree production-scale checkpoint payload materialization／relation
  qualification、production streaming materialization、真實operator resource reservation、external
  human design/cryptographic review、production runner scale qualification、可信producer
  handoff／writer quiescence、外部identity freeze與launch manifest，
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
