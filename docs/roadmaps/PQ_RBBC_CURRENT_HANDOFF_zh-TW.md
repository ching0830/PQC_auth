[English](PQ_RBBC_CURRENT_HANDOFF.md)

# PQ-RBBC 目前交接 — v2.42 recovery／provenance successor（已整合）

> **模組範圍：**這是 PQ-RBBC 的操作交接，不是整篇論文 roadmap。專案級背景請先讀 [../../ARCHITECTURE_zh-TW.md](../../ARCHITECTURE_zh-TW.md)、[../../RESEARCH_STATUS_zh-TW.md](../../RESEARCH_STATUS_zh-TW.md) 與 [../../ROADMAP_zh-TW.md](../../ROADMAP_zh-TW.md)。

日期：2026 年 9 月 13 日

## Issuance CAP child staged-executor checkpoint v1（獨立 branch）

2026-09-13從CAP576 native preflight commit `7898697`建立獨立branch
`codex/pq-rbbc-issuance-cap-child-executor-v1`。本checkpoint建立fresh production relation
namespace `pq-rbbc/issuance/cap576-native/production-child/candidate/v1`，並固定42-stage
dependency order：snapshot validation、invocation binding、18個`tree-pre`、global phase A、
18個`tree-post`、global phase B、parent native join及final seal。沒有啟動18-tree replay、
589,030,555-row replay或formal proving。

18棵tree各有fresh child ID、planned intervals、`rho` root byte ranges與四個output ports。
所有fresh output digest、observed `stream_bytes`及assignment identity均為`null`；只重用
historical topology／interval／accounting，沒有沿用其他tree或v2.29的observed values、
assignment、private witness或stream identity。舊monolithic runner不能直接處理global phase A
位於tree pre/post之間的dependency，所以`fresh_split_pre_post_executor_required=true`。

Future production preflight必須消費caller已capture的同一`CandidateSet`與
`InvocationSnapshotV1`；statement、witness及1,036-byte `RhoSnapshotV1.raw`的identity、strict
parse與binding不得重開pathname。Cache/resume採closed-world canonical JSON、exact cache
identity、contiguous stage prefix與domain-separated result chain；per-stage output identity綁定
relation/profile/plan/invocation/stage、rows/wires/stream及ordered port digests。Production atomic
publisher與durable resume仍未實作，state不得提交Git。

Bounded wrapper
`pq-rbbc/issuance/cap576-native/staged-4leaf-insecure-test-only/v1`已執行fresh及中斷後resume：
73,049 rows、53,032 wires、0 external assertions、0 verification failures、未物化assignment；
state mutation、trailing bytes、wrong invocation及wrong execution domain均拒絕。Formal fixture
mask不等於4-leaf child derived mask，因此`full_i3_relation_claimed=false`，不能升格為完整I3、
production relation或`pi_issue`。

Production plan SHA-256為
`ececfbf8421dc6593498bf0da8d5b1f9aed61ceee041ca7af0ebf19f594c0943`。Targeted 17 tests
全部通過；完整baseline共812 tests，800 passed、12個既有optional external-artifact skips、
0 failures/errors（900.813秒）。Manifest為35,544 bytes／SHA-256
`72ca9390f78c03d31bf4e45e25da3a5cf821d31259782df95e54a3e7c2d4d5e4`；portable evidence為
3,163 bytes／SHA-256
`96c6c6732a11126435c2b6dd94a2e5788a1177a60e4754ff76c1d3187f3787c3`。

五份external artifacts、trusted handoff、independent review、fresh production runner、atomic
publisher/resume qualification、PQ-SE backend、resource reservation及large-run authorization
仍未關閉。Production execution、large replay/proving commands為`null`；Defined及bounded
Instantiated／Implemented／Tested／Evidence-sealed為true，production Instantiated／
Implemented、Proof-closed與Production-closed皆為false。沒有修改system architecture、ticket
lifecycle或`pq_sat_auth`。詳細contract、resource estimate與exact bounded commands見
[artifact note](../artifacts/PQ_RBBC_ISSUANCE_CAP_CHILD_EXECUTOR_V1_zh-TW.md)。

下一個gate是fresh split `tree-pre`／`tree-post` runner與atomic stage-output publisher的bounded
crash-safe qualification；external artifacts與review到齊前仍不得啟動production replay。

## Issuance CAP576／1472 native-lowering preflight v1（獨立 branch）

2026-09-13 從reduced issuance constraint commit `d3c08a9`建立獨立branch
`codex/pq-rbbc-issuance-cap576-native-preflight-v1`。本checkpoint固定production child
ports與formal 1,036-byte `rho` same-bytes handoff，並執行production-width／4-leaf／
one-tree insecure test-only native shard；沒有啟動18-tree重建、589,030,555-row replay或
formal proving。

Production profile維持576-bit mask、1,472-bit appended signature、2,048-bit witness、
2,450-bit tape及2 × 4,096／16 × 2,048 leaves。Frozen child ports包括256-bit message、
43,128-bit commitment、576-bit derived mask、1,472-bit append base及576-bit request hash；
parent native equality仍為`256 + 576 + 576 = 1,408` rows。Fresh issuance必須產生fresh
port values。

`rho` canonical serialization固定為magic、production profile、兩個salt、18組root pairs，
共1,036 bytes。Future executor的identity、strict parsing及全部child inputs必須只消費同一
immutable `RhoSnapshotV1.raw`，不得重開pathname。`rho`是per-issuance private witness，
不是global external artifact，也不進入portable evidence。

V2.29 historical evidence（5,695 bytes，SHA-256
`1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e`）只能重用
topology、wire intervals、row accounting、source identity及implementation semantics；
assignment、witness、private `rho`、commitment/mask/request values與其他tree的observed
`stream_bytes`全部禁止重用。589,030,555 rows仍只是historical fixture evidence，不是fresh
issuance或`pi_issue`。

Bounded shard為73,049 rows、53,032 wires、0 external assertions、0 verification failures，
未物化assignment。不同`rho`維持相同row/spool topology digests但改變bound outputs。
Historical shard selector對4-leaf shape錯落至既有2,048-leaf relation ID，因此本gate使用
新test-only wrapper namespace並保持`engine_namespace_production_eligible=false`；正式
implementation必須先建立fresh production relation identity，不能升格舊名稱。

五份production external artifacts仍全部缺少：trace public key、certification、authenticated
system initialization、canonical common parameters及independent review。Production entry
在decode／CAP trace construction前fail closed；large replay及large proving exact command皆為
`null`。Historical resource baseline為16 GB memory、64 GB free disk及8,000--12,000秒，
必須重新reservation，不能視為目前授權。

Targeted 17 tests全部通過；完整baseline共795 tests，783 passed、12個既有optional
external-artifact skips、0 failures/errors（879.409秒）。Portable evidence位於
`artifacts/metadata/issuance_cap576_native_preflight_v1/pq_rbbc_issuance_cap576_native_preflight_portable_evidence_v1.json`
（1,747 bytes，SHA-256
`c4d6b83b7bc9bd893617761c2424f5551acdcfa6229e778175a03304740caf9f`）；
manifest為11,704 bytes／SHA-256
`719dafa600716f53cd81b410c28b40e0d50c6921397dad4dbe7699f5f9480394`。

Defined與bounded Instantiated／Implemented／Tested／Evidence-sealed為true；production
Instantiated／Implemented、qualified PQ-SE backend、formal `pi_issue`、Proof-closed、
Production-closed及large-run gates皆為false。沒有修改system architecture、ticket
lifecycle或`pq_sat_auth`。詳細port表、`rho` byte layout、resource boundary與exact commands見
[artifact note](../artifacts/PQ_RBBC_ISSUANCE_CAP576_NATIVE_PREFLIGHT_V1_zh-TW.md)。

下一個gate是fresh production issuance CAP child namespace與staged executor contract：消除
historical selector alias，固定CandidateSet／RhoSnapshot consumption、fresh cache/resume及
per-tree output identities。External artifacts與獨立review未到齊前仍不得啟動18-tree replay。

## Issuance I1--I5 reduced constraint prototype v1（獨立 branch）

2026-09-13 從production-input qualification commit `e7af82e`建立獨立branch
`codex/pq-rbbc-issuance-reduced-constraint-v1`。本checkpoint固定新test-only namespace
`pq-rbbc/issuance/reduced-constraint/test-only/v1`，沒有啟動589,030,555-row replay或
large proving。

Public statement保持`(pp,ctx,sid,rid,beta)` production shape；private witness保持
`(M,r,rho,k_hold,e)` partition。I1／I2／I4／I5使用既有characteristic-two helpers逐wire
執行；I3改用既有88,282-row reduced CAP／`H_RBBC` native child，而非formal relation
checkpoint的shape-only SHAKE adapter。`message`、`rho`、`derived_mask_prefix`與
`request_hash`四組ports以2,022個in-memory `GF(2^193)` equality rows接合，honest
fixture為0 failed rows及0 external assertions。

本gate刻意使用32-bit insecure/test-only CAP mask，並要求72-byte `r`剩餘544 bits為0。
因此它只驗證composition、field-lift及port ABI，不能替代production 576-bit mask／
1472-bit appended-signature／18-tree relation。完整trace-key structural container已成為
canonical reduced parameters input，並由`statement.pp`綁定exact bytes；fixture仍是
deterministic matrix，不是certified Goppa key。

Bounded accounting為1,600 public bits、11,622 private witness bits、576 internal bridge
bits、2,969,180 parent rows、88,282 child rows、2,022 join rows，合計3,059,484 rows。
Parent shape SHA-256為
`1903f27ab2b6c2f5033aef51e8292cc12a48d8dfeaa10896418a66af8f44c773`。
這些rows只在記憶體生成／驗證；沒有寫出或提交row stream、assignment或BR1CS。

Targeted 18 tests全部通過，涵蓋canonical codecs、partition、positive relation、
`beta`／error／mask-tail mutation、stale child port／assignment、wrong domain／profile／
trace-key identity及production-before-decode refusal。完整baseline共778 tests，766 passed、
12個既有optional external-artifact skips、0 failures/errors（861.258秒）。Manifest與
portable evidence分別為4,517 bytes／SHA-256
`15fd88aceadc138b43737b1a5bb665598f406f8377c5a539011a09e23ed78820`及
2,200 bytes／SHA-256
`d0c3d6a235dbe13ca8667f79bd434720e2eb9dcf0352e17d82be3d47ef6fd3fc`。

Defined、reduced Instantiated／Implemented／Tested為true；production Instantiated、
qualified PQ simulation-extractable backend、formal `pi_issue`、Proof-closed、
Production-closed、large replay/proving authorization全部為false。沒有修改system
architecture、ticket lifecycle或`pq_sat_auth`。

下一個gate是production CAP576／1472 native-lowering preflight與bounded shard：先固定
production child port intervals、formal 1,036-byte `rho` handoff、reuse v2.29 historical
relation的方法、資源估算與exact commands；external production inputs及獨立review未
到齊前不得直接啟動18-tree重建。詳細contract見
[artifact note](../artifacts/PQ_RBBC_ISSUANCE_REDUCED_CONSTRAINT_V1_zh-TW.md)。

## Issuance production-input qualification v1（獨立 branch）

2026-09-13 從 formal issuance relation commit `ff4341b` 建立獨立 branch
`codex/pq-rbbc-issuance-production-inputs-v1`。本 checkpoint 固定
`pq-rbbc/issuance/production-inputs/preflight/v1`，不啟動589M replay或large proving。

新contract定義6,688/5,024/128 trace profile的canonical systematic
`H=(I_R|T)` public-key container。`T`以1,664列、每列628 bytes、byte內LSB-first編碼；
完整container為1,045,216 bytes。Strict parser拒絕wrong magic/version/order/length、
truncation、trailing bytes與錯誤profile。Parser只驗證shape及bytes，不能證明任意矩陣來自
binary Goppa key generation；既有deterministic `SystematicParityCheck`仍是test fixture。

Production issuance common-parameter encoding綁定formal relation manifest、statement
ABI、legacy 18-tree CAP relation/profile、`H_RBBC` relation/profile、trace profile、trace
key/certification identities及issuer verification public-key digest。Authenticated system
initialization再綁定exact common-parameter SHA-256，避免只靠名稱或未驗證JSON升格。

新增`CAPToHRBBCAdapterV1` strict decode一般canonical salt/root `rho`、呼叫既有
`execute_cap_commit`，要求formal `r`等於CAP-derived mask，再直接計算
`beta = r XOR H_RBBC(m,c_r)`。Bounded qualification使用相同2,048-bit witness width與
實際CAP/H_RBBC code paths，但tiny tree profile明確為insecure/test-only；兩組不同`rho`
均可處理。Production profile在本checkpoint中無條件於18-tree execution前拒絕，不能以
caller boolean啟用。

External inventory確認缺少五份真實輸入：trace public key、trace-key certification、
authenticated system initialization、canonical common parameters及independent review。
即使schema/identity結構完整，trusted producer/reviewer handoff與authentication verifier未
整合前仍回報`safe_to_instantiate_production_relation=false`。Checker沿用single-open、
single bounded-read snapshot contract；future executor必須消費同一snapshots，不得重開
pathname。Filesystem writer quiescence與owner/mode/ACL/writable-FD/mount controls仍為部署
前提。

Targeted為19 passed；完整baseline共760 tests，748 passed、12個既有optional
external-artifact skips、0 failures/errors（779.954秒）。Path-free portable evidence位於
`artifacts/metadata/issuance_production_inputs_v1/pq_rbbc_issuance_production_inputs_portable_evidence_v1.json`
（1,528 bytes，SHA-256
`fe7cffbb0037b6bbbea6a262711bb0d803b625771ae3c23b9e19ef6672371721`）。Frozen manifest為
5,728 bytes，SHA-256
`76272df2d70e2a42d4a7acaf18eea54160f7bb3fb272ffe21d296c7d4bb4e752`。
詳細encoding、external requirements、exact command與claim matrix見
[artifact note](../artifacts/PQ_RBBC_ISSUANCE_PRODUCTION_INPUTS_V1_zh-TW.md)。

本gate的Defined、Implemented、Tested、Evidence-sealed為true；Instantiated、
Proof-closed、Production-closed、certified trace key、production relation、正式
`pi_issue`、large replay/proving authorization全部為false。沒有修改system architecture、
ticket lifecycle或`pq_sat_auth`，也沒有建立或提交assignment、BR1CS、pickle/cache、
checkpoint/resume、log或proof output。

下一個安全gate是把I1--I5及本次general CAP/H_RBBC adapter降低到新namespace的reduced
constraint prototype，固定trace-key input ABI與public/private wire partition；在真實external
inputs與獨立review完成前，該prototype仍須拒絕production configuration。

## Formal issuance relation v1 bounded checkpoint（獨立 branch）

2026-09-11 從 issuance ZK backend preflight commit `fc59ff0` 建立獨立 branch
`codex/pq-rbbc-formal-issuance-relation-v1`。本 checkpoint 建立新的 candidate namespace
`pq-rbbc/issuance/formal-relation/candidate/v1`，把 core proof 的 public statement
`(pp,ctx,sid,rid,beta)`、private witness `(M,r,rho,k_hold,e)` 與 I1--I5 映射成可執行
bounded structural evaluator。Ticket payload `M` 不再是 public statement 欄位。

Relation parameters 使用獨立、versioned、ordered、length-prefixed canonical encoding，並
綁定statement ABI、target production CAP profile、trace profile與test trace-key identity。
Wrong version、reordered sections、truncation、trailing bytes、錯誤profile/key digest均拒絕；
statement的`public_parameters_digest`綁定exact parameter bytes。

Executable I3只使用明確命名的
`INSECURE-TEST-ONLY-CAP-HASH-SHAPE-V1`。它以production-shaped 1,036-byte canonical
`rho`測試partition與binding，但不是`CAP.Commit`或`H_RBBC`。I5使用deterministic
`SystematicParityCheck` test matrix，不是certified Goppa key。因此production relation、
production I3、certified trace key與qualified backend全部保持false，production evaluation
在執行前拒絕。

Fresh `sid` 已分離為issuer orchestration boundary：proof transcript未來必須綁定exact
statement bytes，但global freshness需要issuer-side linearizable reservation。新增的
`validate_issuer_sid_candidate`只做immutable snapshot的read-only check，明確回報
`state_reserved=false`與`freshness_proved_by_relation=false`；production mode在沒有可信
reservation handoff時拒絕。本工作不修改ticket lifecycle或`pq_sat_auth`。

Bounded self-check為I1--I5 positive 1/1、4/4 mutations rejected、SID candidate positive、
SID replay rejected、production entry points 2/2 refused，replay rows與cryptographic proofs
皆為0。Targeted 27 passed；完整baseline共741 tests，729 passed、12個既有optional
external-artifact skips、0 failures/errors（737.136秒）。Portable evidence：
`artifacts/metadata/issuance_relation_v1/pq_rbbc_issuance_relation_portable_evidence_v1.json`
（2,068 bytes，SHA-256
`3830e35cb82c979b72e1760ff122caeb8cd5509abe19f2c61298875536bf3f85`）。完整protocol mapping、
encoding、claim matrix與next gate見
[artifact note](../artifacts/PQ_RBBC_ISSUANCE_RELATION_V1_zh-TW.md)。

下一個gate不是large replay：先固定production common parameters/certified trace key，建立
可消費formal `rho`的一般CAP-to-H_RBBC relation adapter，再把I1--I5降低到新namespace的
reduced constraint prototype。完成該relation closure及獨立review後，才可接Aurora
feasibility backend。`formal_pi_issue_generated`、`safe_to_start_large_replay`、
`safe_to_start_large_proving_run`、`Proof-closed`與`Production-closed`皆維持false。

## Issuance ZK backend interface-only preflight（獨立 branch checkpoint）

2026-09-11 從 local `main` commit `6f6d8c8` 建立獨立 branch
`codex/pq-rbbc-issuance-zk-backend-preflight`；未延續或修改 v2.43
reservation-binding worktree。本 checkpoint 盤點既有 ticket-request relation、
production-shape circuit、v2.25 manifests、v2.29 589,030,555-row replay evidence 與
v2.37 unified statement ABI，並建立新的 issuance backend interface namespace。

主要 finding 是 formal `R_issue` 的 public statement
`(pp,ctx,sid,rid,beta)`／private witness `(M,r,rho,k_hold,e)` 與 legacy circuit 不同：
legacy circuit 把完整payload公開，statement沒有`pp`或`sid`；v2.37雖有接近正式形狀的
statement codec，其`sid` fixture不是fresh issuer-side `sid`，且尚未接入完整relation。
因此v2.29 replay不是正式`pi_issue` relation，後續必須使用新relation/profile namespace，
不得覆寫或升格historical evidence。

新介面固定`Setup`、`ProveIssue`、`VerifyIssue`，以及public parameters、statement、
private witness與proof的不同magic、versioned、ordered、length-prefixed canonical encoding；
wrong version、reordered/unknown section、truncation與trailing bytes均拒絕。Statement綁定
canonical PP digest，proof envelope綁定exact statement digest與
`PQ-RBBC/ISSUE-PROOF/V1` transcript domain。

Formal `rho` 固定採既有production CAP profile的1,036-byte canonical
`CAPRandomness` serialization，不接受legacy test adapter的32-byte nonce；錯誤profile、
tree count或非canonical GF(2^193) elements均拒絕。

Production backend allowlist保持空集合。唯一替身明確命名為
`InsecureTestOnlyIssueBackend`／`INSECURE-TEST-ONLY-PQ-RBBC-ISSUE`，不檢查relation、
不提供PQ、ZK、knowledge extraction或simulation extraction，且只能在明確
`production=False`下使用；三個production entry points皆在建立output前拒絕。

保留完整current protocol claim時，simulation extractability確實是concurrent issuance
與gated-CCA/GCCA hybrid的必要條件；stand-alone decoder safety雖可只用knowledge
soundness，但本checkpoint未授權縮限claim。Aurora/libiop只列為後續reduced engineering
baseline，Brakedown只列為performance comparator；沒有production backend被選定或整合。

Bounded self-check為positive 1/1、negative 5/5 rejected、production entry points
3/3 refused，replay rows與cryptographic proofs皆為0。Targeted 26 passed；完整baseline
共714 tests，702 passed、12個既有optional external-artifact skips、0 failures/errors
（737.706秒）。Path-free portable evidence為
`artifacts/metadata/issuance_zk_backend_preflight_v1/pq_rbbc_issuance_zk_backend_preflight_evidence_v1.json`
（3,164 bytes，SHA-256
`b0939939ea64239e8694d0549b1af7865f140ce14f941f1e0a857ea7a2003294`）。完整候選比較、
security requirements、ABI grammar與next gate見
[artifact note](../artifacts/PQ_RBBC_ISSUANCE_ZK_BACKEND_PREFLIGHT_zh-TW.md)。

目前`qualified_production_backend`、`formal_pi_issue_generated`、
`safe_to_integrate_major_backend`、`safe_to_start_large_replay`、
`safe_to_start_large_proving_run`、`Proof-closed`與`Production-closed`全部為false。
下一個gate是先把formal statement/witness partition與fresh issuer-side `sid`接入新relation
namespace，再對identity-pinned backend及exact PQ simulation-extractability theorem做
reduced integration與獨立cryptographic review；大型proving仍需另行資源安排及授權。

## V2.42 recovery／provenance successor（已整合）

2026-09-10 的 Codex AI-assisted cryptographic review 新增 CR-01（P2：兩個 chunk／
checkpoint crash windows 無法 resume）及 CR-02（P3：Blind-UOV 參數引用錯置）。
因此下方 v2.41「下一個 gate」敘述只保留為歷史；目前仍不具 production 核准條件。

`codex/pq-rbbc-v2-42-recovery-and-provenance` 從 `973deee` 建立獨立 worktree，新增
bounded recovery runner、append-only checkpoint journal、exact orphan 重算驗證與
idempotent finalization，以及固定三份 PDF revisions 的 provenance erratum。
V2.33 sealed spec、v2.38／39／41 historical evidence 與原 v2.41 operator reservation
都保留 exact bytes；v2.41 reservation 不能授權未來 v2.42 effective tree。

詳細變更、targeted／full suite、historical preservation 與 claim boundary 見
[新 artifact note](../artifacts/PQ_RBBC_v2_42_RECOVERY_AND_PROVENANCE_zh-TW.md)。
Initial commit `81374602b5c1e304f396f54ef6f2d5b9bf2f06e9` 與 corrective commit
`d6d349020f8ef22e65115130c335ea6db7e337b4` 已於 2026-09-10 由 integration lane
以 fast-forward 整合至 local `main`；沒有改寫兩次負面 review 的受審 identities。

Final exact corrective commit 的唯讀 AI technical re-review 已通過，RR242-01、
RR242-02、CR-01、CR-02 與歷史保存均符合本次 bounded 範圍，沒有新 blocking
findings。Targeted 128 passed；完整 regression 為676 passed、12既有optional skips、
0 failures／errors。持久摘要與完整外部交付 identities 見
[review integration record](../reviews/PQ_RBBC_v2_42_CORRECTIVE_AI_TECHNICAL_RE_REVIEW_RESULT_zh-TW.md)。
Codex AI-assisted review 不等於具名獨立人員核准。

目前 v2.42 reservation、formal human independent review、launch candidate／identity freeze 都未建立，
production-prefreeze、large replay／proving 與全部 security／production claims 為 false。
Root canonical docs 已由 integration lane 依這份 evidence 更新。

### V2.42 corrective：RR242-01／RR242-02（bounded 重審通過）

Exact `81374602b5c1e304f396f54ef6f2d5b9bf2f06e9` 的 AI technical re-review
確認 CR-02，但新增 RR242-01（P2：orphan／existing entry 的 directory fsync
recovery barrier）與 RR242-02（P3：digest 驗證晚於 bounded 重算）。原報告與
machine findings identities 已固定於 recovery manifest，不能把初次重審稱為通過。

本 corrective 在 output lock 內先 capture／比對 latest externally supplied digest，
再讀取／重算 bounded fixtures，後續驗證只使用該 checkpoint 的原 captured raw。
Existing chunks、prefixes／complete、index／evidence 驗證後，依相依順序同步其
pinned parent directories；orphan 在 successor prefix 前另補同步，EIO 一律傳出，
保留既有 bytes／inodes。Wrong／stale digest 不啟動 fixture read／bounded_chunks。

本次新增 9 個 corrective test methods。Focused 47 passed；targeted 128 passed；
完整 regression 676 passed、12 skipped、0 failures／errors（共 688 tests，735.905 秒）。
另以真實 bounded fixtures 重算 fresh／resume／repeated resume 與四種 link 後 fsync
EIO／retry 窗口；結果及 log identities 已更新至 v2.42 metadata。獨立重審另涵蓋
8個post-link／pre-directory-fsync EIO窗口、34個durable publication boundaries、
32個mutation cases及digest-first／same-capture順序，均符合本次bounded契約。

新 source／manifest identities 要求新的 fresh output；不得將初始 v2.42 outputs
改寫為 corrective journal。CR-02 provenance 的四份 source／manifest／test／erratum
檔案、78 sealed predecessors 與歷史 v2.41 reservation／approval records 均不變。
本次未做實體斷電測試，filesystem／mount／writer／ACL／writable-FD assumptions
維持不變；production／security flags 全部 false。

下一步是建立綁定 v2.42 effective implementation／source identities、exact command、
batch、output 與資源窗口的新 operator reservation；不得沿用 v2.41 reservation。其後由
真正具名且獨立的人員審查 exact reservation 與 implementation identities。只有正式
review 無 blocking findings，才能建立 launch manifest candidate 並跑唯讀 preflight。
目前仍沒有 v2.42 reservation、正式 review、launch candidate 或 identity freeze。

## V2.41 branch checkpoint

`codex/pq-rbbc-v2-41-launch-validation-hardening` 從 local main `3885b01` 建立獨立
worktree，並以 `1b89ebe`、`1a1d576` 兩個 commits 針對 v2.39 AI technical
pre-review 的八項 validation findings 建立 successor；effective tree 已 fast-forward
整合至 local `main`。
新版本採 single-read immutable snapshots、exact command locations、strict canonical JSON 與
bool/int、trusted time、reservation/batch-bound review、exclusive atomic publication，
並讓 authoring 與 builder 都要求 exact contracts/v2.38 predecessor。

Commit `1b89ebe` 的 AI technical re-review 找到一項 P2，corrective contract 已明確
縮限：`read_snapshot` 是 single-open、single bounded read；identity、strict JSON parse、
binding 與所有 validation 只使用同一 immutable `Snapshot.raw`。Inode／size／mtime／ctime
僅為 best-effort mutation signals，不證明 capture 期間完全沒有 writer。同 inode、同長度
原地改寫若發生在舊 bytes 完整 capture 之後，可以接受該舊 snapshot；future executor 必須
消費 `CandidateSet` 中的相同 snapshots，不得重開 pathname。

Trusted producer handoff、writer quiescence、owner／mode／ACL、既有 writable FD 及 mount
namespace 均為部署前提／外部 blocker；本 branch 不以重複 stat、sleep、advisory lock 或
重讀 pathname 宣稱一般 filesystem 強不可變性。

V2.38/v2.39 source、tests、schemas、manifests、portable evidence、artifact notes 與
checksums 的 19 份 historical identities 均未變動。下方 v2.39 freeze-ready 敘述
屬歷史 checkpoint；不得用其舊 validator 的結果取代 v2.41 驗證。V2.41 不自動升級
attestations，也沒有正式 launch identity freeze。

新 portable evidence 只保存缺少真實候選的 negative observation。原 13 項及新增
56 項 targeted tests 全部通過；完整 suite 為 629 passed、12 既有 optional skips、
0 failures/errors（共 641 tests）。結果與每個 finding 的 regression 對照見
[`../artifacts/PQ_RBBC_v2_41_LAUNCH_VALIDATION_HARDENING_zh-TW.md`](../artifacts/PQ_RBBC_v2_41_LAUNCH_VALIDATION_HARDENING_zh-TW.md)。
Effective tree 的唯讀 AI technical re-review 未發現新 findings：69 項 targeted、17 組
八項獨立 probes、4 組 corrective probes與17項額外cases全部通過；完整 regression 為
629 passed、12既有optional skips、0 failures/errors（共641 tests）。審查摘要與暫存
report identities 見
[`../reviews/PQ_RBBC_v2_41_AI_TECHNICAL_RE_REVIEW_RESULT_zh-TW.md`](../reviews/PQ_RBBC_v2_41_AI_TECHNICAL_RE_REVIEW_RESULT_zh-TW.md)。

V2.41 checksum inventory 中本 handoff 的 entry 是 `1a1d576:<path>` 的歷史 identity
（24,839 bytes、SHA-256 `689f330692cc3110a422902ce451c116bf0640f13ce71a01bbbb41deab11c3cf`）；
本文件作為 integration-owned current handoff 已繼續前進。驗證 inventory 時須對該一項
使用上述 Git object，其餘15項直接核對current tree；不得回寫歷史checksum掩蓋差異。

下一個 bounded gate 是先 provision repository 外的 trusted artifact root，再由真實
operator 建立 exact v2.41 resource reservation，並由合格且獨立的 human reviewer 對
exact commit、reservation bytes、batch 與 command binding 出具 review。兩者到齊後才
author launch manifest candidate 並重跑唯讀 preflight；這仍不構成 production 授權。

沒有真實 reservation、偽造 review、production-prefreeze、large replay/proving 或
新的 production observation；所有 production/security claims 維持 false。

新工作階段先讀本文件、v2.29 recovery note、v2.30 fork-security audit、
v2.31 CAP-security qualification evidence、v2.32 CAP Prove/Verify preflight、
v2.33–v2.39 unified-tree checkpoints與`docs/ARTIFACT_POLICY.md`。本 handoff 記錄
已納入整合 checkpoint 的bounded evidence；精確發布位置仍須以 Git commit 與
branch 驗證，不得只由散文推測。

## 已封閉邊界

V2.29已依frozen namespace重放18份planned tree assignments、逐wire核對72個
relocations、重放parent-bound global tail，並在GF(2^193)中驗證joined parent
relation。Row accounting：

| Segment | Rows | Failures |
| --- | ---: | ---: |
| Tree producers | 513,312,336 | 0 |
| Relocations | 15,938,520 | 0 |
| Parent-bound global tail | 56,806,711 | 0 |
| Aggregate | 586,057,567 | 0 |
| Joined parent | 2,972,988 | 0 |
| Combined | 589,030,555 | 0 |

因此`complete_18_tree_assignment_replayed`、
`cross_segment_wire_identity_closed`、`parent_bound_global_tail_replayed`、
`gf193_parent_lift_replayed`與`parent_cap_to_h_rbbc_join_closed`均已由本次exact
execution封閉。這不封閉fork-security proof或production。

## Portable evidence identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Frozen preflight manifest | 5,731 | `4e83d260121df7bc9f73f03a3c427f494577cdcabb8808a9e67a2987d137ab78` |
| External preparation manifest | 4,539 | `32f246e13f06e956bb4b39262f41b53d83c2874a646b1f9671381520f1ceb852` |
| External full-replay manifest | 5,685 | `055790dffe51781cff2f2f7893931da5550b9d730bec7ae72927a93f9e352a2a` |
| Portable recovery evidence | 5,695 | `1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e` |

Frozen input identity：
`b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a`

Ordered replay transcript：
`1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514`

Path-free Git evidence位於
`artifacts/metadata/parent_join_recovery_v2_29/pq_rbbc_parent_join_recovery_evidence_v2_29.json`。
完整external identities由該JSON與v2.29 checksum inventory綁定。

## External artifacts

執行產物位於獨立的
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_29_parent_join/`，包含：

- 1,004,865,028-byte parent-bound global-tail assignment；
- 72,354,912-byte joined parent relation archive；
- 74,507,694-byte joined parent assignment；
- full-replay manifest、local checkpoints與tree execution caches。

Tree 0–17 assignments仍分別留在v2.28 recovery、v2.25 batch、v2.26 batch與
v2.27 batch external directories。不得將任何assignment、BR1CS、pickle、cache、
checkpoint/resume state或log加入Git，也不得以其他tree的observed stream bytes
替代目標tree identity。

## V2.30 proof audit

V2.30已將fork-specific proof scope綁定至v2.29 final semantics。官方
ePrint 2025/895之2025-10-31 revision、proof-audit packet、CAP／QROM／
blindness-one-more internal gap reviews、independent-review request與audit manifest
均已凍結。Path-free evidence為
`artifacts/metadata/fork_security_audit_v2_30/pq_rbbc_fork_security_audit_evidence_v2_30.json`
（4,491 bytes，SHA-256
`ab82fe91e2e71cbfdf90bc171b0e62f6be6021365f0870e5878edd8a8496de60`）。

Internal audit結論為fail-closed：paper reductions需要的fork CAP extractor／ZK、
request-proof extractor、concrete QROM boundary、完整fork signer/finalizer、PQ
SE-NIZK backend及independent review均未由functional replay建立。因此目前只關閉
`v2_30_internal_proof_audit_closed`與`v2_30_independent_review_ready`；
`fork_security_proof_revalidated`仍為false。

Initial candidate inventory command及檔名見
[`../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_PREFLIGHT_zh-TW.md)。Candidate artifacts必須放在獨立
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/`。Audit結果與全部frozen
identities見
[`../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_AUDIT_zh-TW.md`](../artifacts/PQ_RBBC_v2_30_FORK_SECURITY_AUDIT_zh-TW.md)。下一個gate是由合格的獨立
cryptographic reviewer出具綁定全部digests的attestation；專案不得自行補造。
不得把v2.29 parent-join execution evidence擴張解讀成security-proof或production
closure。

System architecture、ticket lifecycle與`pq_sat_auth`在v2.29均未修改。

## V2.31 CAP-security qualification

V2.31已綁定v2.30 audit evidence、v2.29 final semantics與production CAP source，
並凍結CAP oracle transcript、admissible commitment、Definition-10 straight-line
extractor interface及unique committed mask game。Mixed production profile維持
2 × 4,096-leaf degree-13 trees與16 × 2,048-leaf degree-12 trees；不得以其他tree
的observed `stream_bytes`代替任何identity。

Path-free checkpoint evidence為
`artifacts/metadata/cap_security_qualification_v2_31/pq_rbbc_cap_security_qualification_evidence_v2_31.json`
（5,606 bytes，SHA-256
`6a447112809ae999d72a4c6886f353ffa1f38720870364009dc7e8155c29edfd`）。
候選authoring seal為同directory下的
`pq_rbbc_cap_security_artifact_evidence_v2_31.json`（4,720 bytes，SHA-256
`eb5b1c901b7fd55d2092e71caadf797f8ac510ad857c8199c9f77cd5b6c544e8`）。

Straight-line extractor specification、unique-mask reduction與包含122,847筆完整
Q_CAP records的candidate evidence均已撰寫、凍結identity並驗證。10／10 negative
vectors均拒絕，且現在`safe_to_request_independent_review = true`。External
inventory只缺independent-review attestation。

然而numeric accounting得到未含PoW的degree term只有`2^-182`，低於192-bit
target；完整CAP Prove／Verify、paper約13.9-bit PoW、production `c_2`
serialization與concrete Anemoi ROM／QROM justification仍缺。因此
`safe_to_start_cap_security_qualification = false`與
`cap_security_qualified = false`。詳細schema、frozen digests、exact authoring與
inventory commands見
[`../artifacts/PQ_RBBC_v2_31_CAP_SECURITY_QUALIFICATION_zh-TW.md`](../artifacts/PQ_RBBC_v2_31_CAP_SECURITY_QUALIFICATION_zh-TW.md)。
在獨立review與上述profile dispositions完成前，不提供qualification execution
command，也不啟動large replay。

## V2.32 CAP Prove/Verify preflight

V2.32已將下一階段限定為完整CAP Prove／Verify、public-statement encoding、
production proof serialization及PoW／security-profile disposition。它綁定v2.31
exact identities與v2.29的589,030,555 rows、0 failures、0 external assertions，
不重播relation也不產生proof。

Frozen outer envelope使用`PQRBBC-CAP-PROOF-V1`、version 1、profile fingerprint及
canonical `c_r`／`c_x`／`pow_nonce`／`pi_2` sections。只有`c_r`的5,391-byte
payload已知；其餘production payloads與完整statement encoding仍未凍結。V2.31的
252-byte candidate `c_2`明確不得升格為production `c_x`。

PoW disposition保留192-bit target並記錄目前raw degree security只有182 bits；
paper的約13.9 PoW bits不會自動繼承。任何tree/profile變更都會使目前production
shape失效並需要新namespace與replay，本preflight未授權該變更。

Path-free evidence為
`artifacts/metadata/cap_prove_verify_preflight_v2_32/pq_rbbc_cap_prove_verify_preflight_evidence_v2_32.json`
（5,445 bytes，SHA-256
`0fcba15c45dda36df82606a49a197eb85aa20e8ac38f1c31c557eba639258657`）。

Initial inventory缺少Prove／Verify specification、production serialization、PoW
disposition、implementation evidence及independent review五份external artifacts。
現已直接開始bounded v2.32 implementation：strict candidate statement codec與outer
proof envelope已實作並測試，且external directory已有specification PDF、
serialization candidate、PoW disposition及partial implementation evidence四份
schema-valid candidates；preflight checker依使用者要求未調整，故其identities仍為
`identity_not_frozen`。Independent review仍缺少。

Paper cross-check確認13.9-bit PoW依賴單一interleaved unified GGM tree、
`T_open=174` rejection sampling與9-bit explicit condition；目前fork為18個獨立roots。
在不改architecture/profile且不建立新namespace/replay的限制下，不能安全補成
paper-compatible PoW。因此`prove()`明確unavailable，`verify()`strict parse後fail
closed，沒有產生accepting proof。結果仍為
`safe_to_implement_cap_prove_verify = false`、
`safe_to_start_large_proving_run = false`及`cap_security_qualified = false`。
詳細schema、資源估算與exact command見
[`../artifacts/PQ_RBBC_v2_32_CAP_PROVE_VERIFY_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_32_CAP_PROVE_VERIFY_PREFLIGHT_zh-TW.md)。

## V2.33 unified-tree CAP migration preflight

使用者已明確授權建立獨立的unified-tree CAP namespace/profile，條件是保留現有
18-tree profile、不覆寫既有evidence，且大型重建與replay只能在preflight安全後
啟動。V2.33已完成唯讀migration preflight並保留新的candidate namespace：

- profile name：
  `PQ-RBBC-CAP-TCitH-III/Anemoi-193-336-Unified-GGM-CANDIDATE-v1`；
- relation ID：
  `pq-rbbc/cap/tcith-iii/anemoi-193-336/unified-ggm/candidate/v1`；
- domain prefix：`PQ-RBBC/v2.33/CAP-UGGM/`；
- topology：one root、40,960 leaves；
- logical mapping：position-major interleaving，且已驗證40,960-entry bijection。

Legacy fingerprint
`2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`
與全部v2.19–v2.32 evidence保持historical、read-only。新profile不得沿用tree
0–17的observed `stream_bytes`、digests或assignments，也不得把v2.29完整transcript
當成新profile evidence。

七份source artifacts已逐byte驗證，環境容量也超過planning minimum，因此
`safe_to_author_unified_tree_specification = true`及
`safe_to_implement_reduced_prototype = true`。Initial report當時列出algorithm
specification、reduced evidence、runner qualification、operator resource reservation
及independent design review五個blockers，所以`safe_to_start_production_prefreeze = false`、
`safe_to_start_large_replay = false`與`safe_to_start_large_proving_run = false`。

Exact specification與12-leaf reduced prototype已依後續明確授權完成。Specification
凍結單root L−1 derivations、π/inverse、new domains、commitment/opening encoding、
LSB-first challenge slicing、minimal frontier、explicit bits與`T_open`驗證。Reduced
run接受1個deterministic opening，9/9 mutations拒絕，並通過fresh-cache、resume
identity與overwrite-refusal qualification；production leaves、relation rows與proofs
全部為0。Path-free reduced seal為
`artifacts/metadata/cap_unified_tree_migration_v2_33/pq_rbbc_cap_unified_tree_reduced_portable_evidence_v2_33.json`
（5,894 bytes，SHA-256
`758f101d9e825da2d4315d69d46a48b6c5ef563c49d05633cb3b68cde4fbcdd3`）。

保守projection為至少589,054,075 combined rows；兩個完整passes至少
1,178,108,150 row checks。這不是frozen count；reduced benchmark與exact opening
grammar不足以安全外推production elapsed time。後續需取得operator-approved
resource reservation與independent design/cryptographic review，並以綁定新seal的
read-only production pre-freeze checker維持gate。完整影響範圍、external blockers、
資源估算與exact commands見
[`../artifacts/PQ_RBBC_v2_33_UNIFIED_TREE_MIGRATION_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_33_UNIFIED_TREE_MIGRATION_PREFLIGHT_zh-TW.md)。

Path-free evidence為
`artifacts/metadata/cap_unified_tree_migration_v2_33/pq_rbbc_cap_unified_tree_migration_preflight_evidence_v2_33.json`
（7,293 bytes，SHA-256
`624a5c723403a8273d427e40f9160e40463c22dc06a88ce9f448a836d72e4ef7`）。

## V2.34 unified-tree production pre-freeze checkpoint

V2.34已建立綁定v2.33 reduced portable seal的read-only、fail-closed production
pre-freeze checker，並凍結resource-reservation JSON Schema、independent-review
contract、production descriptor fingerprint
`c270e4681f23955667a6c0640317e7beccc666d60a0cffb40bfdccfcee811b7a`
及prospective command digest。四份v2.33 external outputs均逐byte驗證；目前環境12
cores、available memory約29.7 GB、free disk約664 GB，通過4 cores／16 GiB／80 GiB
capacity minimum，但capacity observation本身不是execution authorization。

Initial v2.34 report為`safe_to_run_read_only_checker = true`及
`safe_to_request_independent_review = true`。Resource reservation與independent review
尚未提供；而現有runner只支援reduced phase，production runner尚未實作、production
relation contract尚未凍結、本次亦未授權production execution。因此
`safe_to_start_production_prefreeze = false`、`safe_to_start_large_replay = false`與
`safe_to_start_large_proving_run = false`。

Resource schema要求外部operator只授權fresh、exclusive、no-overwrite的
production-prefreeze，明確禁止重用其他tree observed `stream_bytes`，且不得授權
frozen replay、large proving或security claim。由工具輸出的template故意不通過
approval gate；專案不得替operator或independent reviewer補造attestation。

Path-free v2.34 evidence為
`artifacts/metadata/cap_unified_tree_production_prefreeze_v2_34/pq_rbbc_cap_unified_tree_production_prefreeze_evidence_v2_34.json`
（3,816 bytes，SHA-256
`7778bdad550baa31e530c739e916e14d5e5ce4738846c64f2c0729b663a9e341`）。
完整schema、blockers、resource boundary與exact commands見
[`../artifacts/PQ_RBBC_v2_34_UNIFIED_TREE_PRODUCTION_PREFREEZE_zh-TW.md`](../artifacts/PQ_RBBC_v2_34_UNIFIED_TREE_PRODUCTION_PREFREEZE_zh-TW.md)。

## V2.35 unified-tree production runner authoring checkpoint

V2.35已建立新的production runner skeleton與machine-readable relation-stage contract，
並以保留18個logical vectors及兩大／十六小比例的40-leaf test-only fixture驗證
fresh run、plan後中斷／resume、deterministic identity、overwrite refusal及production
branch在建立output前fail closed。Bounded run接受opening，production leaves、relation
rows、assignment、BR1CS與proofs全部為0。

Relation contract凍結stage ordering及planned counts，但所有production observations
仍為`null`；589,054,075 rows仍只是lower bound。Production checkpoint payload與
relation generator尚未實作，resource reservation及independent-review identities亦未
凍結，且沒有production execution authorization或launch manifest。因此只有
`runner_skeleton_qualified = true`；`production_runner_qualified`及三個large-run gates
均為false。

Path-free v2.35 evidence為
`artifacts/metadata/cap_unified_tree_production_runner_v2_35/pq_rbbc_cap_unified_tree_production_runner_evidence_v2_35.json`
（4,836 bytes，SHA-256
`5284654b909158c18c3f3df50b9de190e50bf06469b1d1f1036bfeb860cf292e`）。
完整protocol位置、bounded observation、blockers與exact commands見
[`../artifacts/PQ_RBBC_v2_35_UNIFIED_TREE_PRODUCTION_RUNNER_AUTHORING_zh-TW.md`](../artifacts/PQ_RBBC_v2_35_UNIFIED_TREE_PRODUCTION_RUNNER_AUTHORING_zh-TW.md)。

## V2.36 unified-tree bounded checkpoint payload與relation generator

V2.36已實作canonical checkpoint payload及bounded relation generator。Qualification
使用與v2.35相同的40-leaf／18-vector test-only profile，先在`unified-tree`stage中斷，
再以精確payload SHA-256授權resume；generator獨立重算seed、mapping、leaf/tape、
vector hashes、root、codec、opening、reference ticket relation及downstream parent-input
candidate binding，共144條contract-IR equality rows，全部成立。

這些rows不是BR1CS或production constraints。Production-shape的122,904 contract-row
數字只是grammar projection；沒有取代589,054,075-row lower bound，也沒有沿用其他
tree的observed `stream_bytes`或v2.29 transcript。Bounded qualification成立，但
production-scale payload、relation qualification、final statement encoding、resource
reservation、independent review、execution authorization及launch manifest仍缺少，故
production pre-freeze與所有large-run gates維持false。

Path-free v2.36 evidence為
`artifacts/metadata/cap_unified_tree_bounded_relation_v2_36/pq_rbbc_cap_unified_tree_bounded_relation_portable_evidence_v2_36.json`
（5,719 bytes，SHA-256
`660d4c0d9cf36bbb5ecf02dc66d65721e077171de5b1e9c6b010d19871235fad`）。
完整payload規則、row accounting、resource observation與exact commands見
[`../artifacts/PQ_RBBC_v2_36_UNIFIED_TREE_BOUNDED_RELATION_zh-TW.md`](../artifacts/PQ_RBBC_v2_36_UNIFIED_TREE_BOUNDED_RELATION_zh-TW.md)。

## V2.37 unified statement serialization與parent-input ABI

V2.37已在新的unified-tree namespace凍結strict canonical statement codec與parent-input
envelope。Statement固定`common_parameters_digest`、`ctx`、`sid`、`rid`及72-byte `y`；
parent envelope固定statement、unified commitment `c_r`、32-byte ticket message及
domain-separated binding digest，且statement與commitment profile必須相同。Ticket
mapping直接沿用既有`IssueStatement`及`PQ-RBBC/TICKET` message derivation，沒有修改
ticket lifecycle。

Qualification產生production-profile statement test vector，但沒有production `c_r`，
所以只以v2.36 completed checkpoint的158-byte bounded commitment建立643-byte bounded
parent envelope。兩種statement均為314 bytes，16/16格式、profile、binding及mapping
mutations全部拒絕。Production leaves、relation rows、BR1CS與proofs全部為0；沒有重播
v2.29 parent join，也沒有沿用legacy tree observations。

因此`safe_to_author_production_streaming_path = true`，但
`production_parent_input_qualified = false`、`safe_to_start_production_prefreeze = false`、
`safe_to_start_large_replay = false`及`safe_to_start_large_proving_run = false`。仍需
production streaming/checkpoint materialization、operator resource reservation、
independent review、明確authorization及identity-frozen launch manifest。

Path-free v2.37 evidence為
`artifacts/metadata/cap_unified_statement_parent_abi_v2_37/pq_rbbc_cap_unified_statement_parent_abi_portable_evidence_v2_37.json`
（5,188 bytes，SHA-256
`672c27f8ed0bfc567d3080c9645c079d9009ce7ff815957c9384dc0246b3c8b7`）。
完整codec、mapping、external identities與exact commands見
[`../artifacts/PQ_RBBC_v2_37_UNIFIED_STATEMENT_PARENT_ABI_zh-TW.md`](../artifacts/PQ_RBBC_v2_37_UNIFIED_STATEMENT_PARENT_ABI_zh-TW.md)。

## V2.38 unified-tree streaming checkpoint與launch preflight

V2.38已實作profile-bound binary chunk codec、external-only checkpoint chain及精確
identity resume。Bounded qualification把v2.36 tree state與v2.37 parent input依
`nodes → commitments → tapes → vector hashes → c_r → parent input`固定順序寫成
179 records／15 chunks；在第7個chunk中斷後以精確checkpoint SHA恢復，所有prefix、
chunk、chain及final index驗證成立。

Production layout凍結為未執行的163,859-record／163-chunk plan，raw serialized payload
16,631,418 bytes。這不包含589,054,075-row lower bound的relation、assignment、BR1CS
或兩次replay，也不是runtime／stream-size observation。Production records、leaves、
relation rows及proofs全部為0。

唯讀launch preflight確認目前host的12 cores、約29.7 GB available memory及約664 GB
free disk超過planning minimum；但容量不是授權。V2.38 resource reservation、
independent review及launch manifest均缺少且identity未凍結，production stream尚未
materialize，runner亦未做scale qualification。因此只有
`safe_to_request_resource_reservation = true`與
`safe_to_request_independent_review = true`；production pre-freeze、large replay及
large proving gates全部為false。

Path-free v2.38 evidence為
`artifacts/metadata/cap_unified_tree_streaming_prefreeze_v2_38/pq_rbbc_cap_unified_tree_streaming_prefreeze_portable_evidence_v2_38.json`
（7,390 bytes，SHA-256
`7f846858350deefa6a6d4df2dec43a852f8e6deb9c55c99e289c2062f822979e`）。
完整stream grammar、resource estimate、external blockers與exact commands見
[`../artifacts/PQ_RBBC_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE_zh-TW.md`](../artifacts/PQ_RBBC_v2_38_UNIFIED_TREE_STREAMING_PREFREEZE_zh-TW.md)。

## V2.39 unified-tree launch identity-set preflight

V2.39已升版並凍結operator resource reservation、independent review及launch manifest
三份closed-world schemas，實作strict validators、刻意不合法的draft templates、
launch-manifest generator及唯讀identity-set preflight。所有contract均綁定v2.38
portable seal、unified production profile、prospective production command、external
output、fresh-cache／overwrite規則及最小資源。

Qualification確認三份draft都不能冒充attestation；synthetic valid candidates可生成
互相綁定的launch candidate，且只能使`safe_to_freeze_launch_identity_set=true`，不會
使production gate成立。目前沒有真實operator reservation、independent review或launch
manifest，三份identity均未凍結。Production stream/checkpoint、scale qualification及
execution authorization亦未成立，因此production pre-freeze、large replay、large
proving及全部security claims維持false。

Path-free v2.39 evidence為
`artifacts/metadata/cap_unified_tree_launch_preflight_v2_39/pq_rbbc_cap_unified_tree_launch_preflight_portable_evidence_v2_39.json`
（6,792 bytes，SHA-256
`a4d1f8e2d7f206a070a820a801ceded5edd0f0c4250498124354d9453aa3c978`）。
完整schema、qualification、candidate workflow與exact commands見
[`../artifacts/PQ_RBBC_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT_zh-TW.md`](../artifacts/PQ_RBBC_v2_39_UNIFIED_TREE_LAUNCH_PREFLIGHT_zh-TW.md)。

## Git 與發布規範

- 只提交source、tests、frozen manifests、documentation、checksums與path-free
  portable evidence。
- 建立commit前檢查沒有`.f193assign`、`.br1cs`、pickle、cache、resume、checkpoint
  或logs進入index。
- 不直接push `main`；只有使用者明確授權後才可整合與發布。
- `cap_security_qualified`、`fork_security_proof_revalidated`與
  `production_closed`維持false。
