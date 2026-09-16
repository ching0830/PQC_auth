# One-Time Access Admission v0.1

## 結論

本 checkpoint 將既有 `pq_sat_auth` access codecs、ticket-use identity 與 replay
state model，接到 PQ-RBBC 的真實 `verify_ticket()` control flow，實作一條 bounded
FGS admission path：只有 canonical access flow、authenticated system initialization、
ticket、serving context、challenge cookie、holder authentication、UE key confirmation
與 pure policy checks 全部通過後，才允許 ticket 進入
`UNSEEN -> RESERVED -> CONSUMED`。

這裡的「真實 `VerifyTicket`」是指使用
`src/pq_rbbc/tickets/verification.py` 的 strict parser、bundle bindings 與抽象 issuer
authentication backend，不是宣稱 Blind-UOV production signature backend 已完成。

本 checkpoint 直接沿用：

- `SystemInitializationBundle`、system `ctx` 與 `KeyRole`；
- `CanonicalTicket` 與既有 368-byte `TicketPayload`；
- `AccessInitV1`、`AccessChallengeV1`、`AccessFinishV1`、`AccessAcceptV1`；
- `TicketUseIdentity` 與 `PQ-SAT/USE-KEY/v1`；
- `InMemoryLinearizableReplayStore` 的既有 one-time state machine。

沒有建立另一套 SystemConfiguration、ctx、ticket encoding 或 access framing。

## Admission control flow

`OneTimeAccessAdmissionService.admit()` 的固定順序是：

```text
strict parse Init / Challenge / Finish
  -> authenticate SystemInitialization with pinned FEDERATION_CONFIGURATION anchor
  -> freeze one trusted time value
  -> bind serving-context epoch / policy / digest and challenge expiry
  -> compute and bind the canonical access transcript
  -> real stateless verify_ticket(ticket)
  -> recover d_M, visible serial and ctx from authenticated payload
  -> derive TicketUseIdentity and use_key
  -> read authoritative revocation generation
  -> verify challenge cookie
  -> verify holder-secret possession boundary
  -> verify UE-side AKE key-confirmation boundary
  -> pure resource/policy admission
  -> atomic Reserve with the same revocation generation
  -> prepare inert session/response material
  -> atomic Commit with a second revocation-generation check
  -> release AccessAccept bytes
```

Initialization 會被驗證兩次：admission service 先保護完整 flow，`verify_ticket()` 再保護
ticket boundary。兩次都使用 caller 提供的同一個 out-of-band pinned
`FEDERATION_CONFIGURATION` key。未來若要消除重複驗證，必須先定義可信的 typed
verified-bundle boundary，不能直接信任未驗證 bundle。

## Ticket-use identity

Consumption 使用 ticket payload identity，而不是 transport identity：

```text
d_M = SHAKE256("PQ-RBBC/TICKET" || Encode(M), 32)

use_key = SHAKE256(
    "PQ-SAT/USE-KEY/v1" || ctx || visible_serial || d_M,
    32
)
```

本 vector：

```text
d_M = 41284b146af4f04412e8e39d4a82d2a76a855014951f05223aa1f000ac0364d5
sn  = 0610e4bfd63f35f49bb94fbdffc2bb48
use_key = 1f450cfed8c4aae648f282d24f5bd9a104ed8c6103cea844c7925854f36c98b9
```

因此 signature bytes 的另一種表示不能被當成另一張可消耗 ticket。Store 同時保留
`(ctx,d_M)` 與 `(ctx,sn)` bindings；相同 serial／不同 digest 或相同 digest／不同
serial 都 fail closed。

Conditional Opening 繼續使用 canonical ticket transport 的 SHA-256 digest；opening
identity 與 access consumption 的 `d_M` 用途不同，沒有互換。

## Atomic state、retry 與 crash boundary

`OneTimeAccessStore` protocol 要求：

- `snapshot_revocation(identity)` 取得 authoritative generation；
- `reserve(..., revocation_generation)` 在同一 state-transition lock／transaction
  內重新檢查 generation 與 revoked predicate；
- `commit(..., revocation_generation)` 再次原子檢查，並一起保存 session ID、response
  digest、exact response、consumption time 與 retention deadline；
- backend exception 或 timeout 一律不得釋出成功 response。

既有 `InMemoryLinearizableReplayStore` 新增 process-local revocation generation model。
它以同一把 lock 排序 revocation、reserve 與 commit，可測試 revocation race；但
`production_ready` 仍固定為 false，沒有 durability、跨程序或跨 FGS consistency，
也沒有 revocation distribution。

同一 authenticated attempt 的語意為：

- `RESERVED`：回傳 `access_pending`，不建立第二個 session worker；
- `CONSUMED`：重新驗證完整 request 後，從 store 回復完全相同的 canonical response；
- commit 已成功但 acknowledgement 遺失：第一次 fail closed，retry 從
  `CONSUMED` 回復同一 response；
- 不同 attempt：統一 `access_rejected`，不取得舊 response。

Session backend 只能 `prepare()` inert material，不得在 store commit 前啟用外部
session。Prepare 或 commit 發生不確定錯誤時，service 不自動 abort；reservation
保持 fail closed，等待尚未實作的 reconciliation／operator recovery。這避免把可能
已有效的 session 猜測成失敗後重新釋放 ticket。

## Authentication backend boundary

下列 production primitives仍維持 `Protocol` 抽象：

- challenge-cookie authentication；
- holder-secret possession authentication；
- UE-side PQ AKE key confirmation；
- resource／policy admission；
- session material preparation與 FGS key confirmation；
- issuer ticket authentication；
- durable／distributed admission store。

測試中的 SHA-256 deterministic adapters 全部只位於
`tests/system/test_pq_sat_auth_admission.py`，不是 signature、MAC、holder proof 或
PQ AKE。Source 沒有提供允許 production caller 誤用的 deterministic authentication
backend。

所有 reject 對外使用 `access_rejected`；同 attempt 尚在 reservation 時使用規格允許
的 `access_pending`。`audit_reason` 是內部診斷欄位，不得直接傳給未授權 client。此
prototype 沒有宣稱已處理 timing／traffic-analysis oracle。

## Frozen vector

Manifest：
`manifests/pq_sat_auth_one_time_access_admission_v0_1.json`

Predecessor：
`ecab1d9919d8627fb96fc986008a961a82a37df8`
（VerifyTicket × Conditional Opening integration v0.1）。

主要 identities：

- AccessInit：632 bytes，digest
  `8186ce1970de829a196740a94c800d844e79cc6d70e730decdfdf31060fa6fe4`；
- AccessChallenge：242 bytes，digest
  `7bb122c368bf6f97196ad55149ce8883ab5c33c0eb842677190d74da7ecbff57`；
- AccessFinish：270 bytes；
- transcript digest：
  `17252060a005db8f09f81510576d064850aa96711863187f887804cda8653115`；
- attempt ID：
  `1c4fdfeb8aafef57666b7aa3fea78e60b408c37069653f705e8a05b2157167da`；
- AccessAccept：158 bytes，response digest
  `8abf2aa68bd6d555801be9c8272d3d2c244e78d7d50f994a2038aa549b08f72c`。

定向測試：

```bash
PYTHONPATH=src python -m unittest \
  tests.system.test_pq_sat_auth_admission -v
```

測試涵蓋 honest admission、payload-vs-transport identity、same-attempt exact retry、
different-attempt rejection、16-way concurrent arbitration、invalid ticket signature、
wrong context／flow／expiry／pinned trust anchor、unknown version／suite、truncation、
trailing bytes、authentication backends回傳非 `True` 或拋出例外、revoked ticket、
reserve／commit revocation races、session preparation failure、lost commit
acknowledgement、store partition，以及 serial／digest binding conflict。

## Claim boundary

目前只可宣稱：

- 現有 stateless `VerifyTicket` 已接入 one-time access control flow；
- consumption 使用 authenticated payload 的 `d_M`、visible serial、ctx 與既有
  domain-separated `use_key`；
- pure validation precedes reservation、atomic reserve／commit、唯一並行 winner、
  same-attempt response recovery與fail-closed crash ordering已由 deterministic tests
  覆蓋；
- process-local memory store可測試 revocation generation與one-time state ordering。

不得宣稱：

- Blind-UOV、CAP、holder authenticator、challenge MAC、PQ AKE、FGS key
  confirmation或session activation primitive已 production implemented／qualified；
- `suite_id=0xffff` 是 production suite；
- durable／distributed／cross-FGS linearizable store、revocation distribution、wallet
  journal、reservation reconciliation或retention cleanup已完成；
- handover、unlinkable multi-show或完整 M5／M6 lifecycle已完成；
- 目前 unit tests構成 cryptographic proof、cross-FGS strictly-one-use proof或
  production access admission closure。

本 checkpoint 不修改 `ARCHITECTURE*`、`RESEARCH_STATUS*`、`ROADMAP*`、
`methodology.md`、`experiments.md`、`thesis-outline.md` 或共用 checksums。
