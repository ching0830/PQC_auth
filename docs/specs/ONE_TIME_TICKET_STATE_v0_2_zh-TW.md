# One-Time Ticket 狀態與 1-RTT Access 邊界規格 v0.2

> 狀態：Defined；process-local reference model 已 Implemented／Tested；尚未 durable／distributed／Production-closed
> 日期：2026-09-14
> Access companion：`docs/specs/SATELLITE_ACCESS_v0_2_zh-TW.md`
> Historical predecessor：`docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md`

## 1. 目的與不變身份

本規格將 v0.2 的 `AccessRequestV2 -> AccessAcceptV2` 降成 authoritative ticket
state machine。它選擇 latency-first final-grant semantics：FGS 在送出 M2 前持久化唯一
access grant 與 ticket consumption；第一個受保護 UE packet只負責 session activation，
不再次消耗 ticket。

Ticket identity 延用 v0.1：

```text
d_M = H_ticket(Encode(M))
sn  = M.sn
ctx = M.ctx

use_key = SHAKE256(
    "PQ-SAT/USE-KEY/v1" || ctx || sn || d_M,
    256
)
```

刻意保留 `/v1` label，因為它識別的是同一張 spendable ticket，而不是 access wire
version。V1、V2及未來所有允許接受同一 ticket family 的 verifier 必須查詢相同
authoritative indexes：

```text
UNIQUE(ctx, d_M)
UNIQUE(ctx, sn)
UNIQUE(use_key)
```

不得使用 `PQ-SAT/USE-KEY/v2` 另建平行 namespace，否則同一 ticket 可能在 V1、V2
各成功一次。

## 2. States

```text
UNSEEN
    尚無 record；若 ticket／policy 仍有效，可以開始一次 attempt。

RESERVED
    唯一已完整驗證的 M1 正在建立可持久化 response；尚未發布 M2，尚可在嚴格
    recovery proof 後 abort。

CONSUMED_PENDING_CONFIRM
    唯一 M2／session identity 已 durable commit，M2 可以送出／重送；ticket 永久
    consumed，但 session 尚未取得 client final-key confirmation。

CONSUMED_ACTIVE
    已驗證 SessionActivateV2／第一個 application AEAD，唯一 session active。

CONSUMED_EXPIRED
    Pending session 未在 activation deadline 前確認，或 active session已到期／終止；
    ticket 仍然 consumed，不得重新使用。
```

`REVOKED` 與 ticket／configuration expiry 仍是 acceptance predicates／registries。
它們不會把任何 consumed state 變回 `UNSEEN`。

## 3. Allowed transitions

```text
UNSEEN
  --Reserve(valid AccessRequestV2)--> RESERVED

RESERVED
  --CommitGrant(session + exact M2)--> CONSUMED_PENDING_CONFIRM

RESERVED
  --Abort(proved no response/session publication)--> UNSEEN

CONSUMED_PENDING_CONFIRM
  --Activate(valid client confirmation)--> CONSUMED_ACTIVE

CONSUMED_PENDING_CONFIRM
  --activation deadline / termination--> CONSUMED_EXPIRED

CONSUMED_ACTIVE
  --session expiry / termination--> CONSUMED_EXPIRED
```

Same-attempt retry在 `RESERVED` 回傳 pending disposition；在所有 consumed states只可
回復已提交的 exact M2／status，不建立第二個 worker、KEM encapsulation或 session。

禁止：

```text
any CONSUMED_* -> UNSEEN
any CONSUMED_* -> RESERVED
any CONSUMED_* -> second session
RESERVED(attempt A) -> RESERVED(attempt B)
CONSUMED_PENDING_CONFIRM(session A) -> CONSUMED_ACTIVE(session B)
cross-version second consumption of the same use_key
```

## 4. Pure validation before reservation

FGS 必須完成 `SATELLITE_ACCESS_v0_2_zh-TW.md` §6 全部 pure checks，包括 exact
`Core.VerifyTicket`、revocation snapshot、context／time、`pi_access`與 UE KEM public
key validation。任何失敗不得建立 record。

```text
Reserve(
    identity=(ctx, sn, d_M),
    attempt_id,
    request_digest,
    serving_context_digest,
    reserved_at,
    lease_deadline,
    revocation_generation
)
```

`Reserve` 必須 linearizable／serializable。不同 FGS ingresses／replicas 對同一
`use_key` 只能產生一個 winner。

## 5. Durable final-grant commit

FGS 只能在成功 reservation 下建立 KEM response。以下資料必須在同一 durability
boundary 內 commit：

```text
CommitGrant(
    identity,
    attempt_id,
    request_digest,
    transcript_digest,
    session_id,
    response_digest,
    exact_response_or_recovery_state,
    sealed_session_state,
    serving_context_digest,
    fgs_id,
    revocation_generation,
    consumed_at,
    activation_deadline,
    session_expiry,
    retention_deadline
)
```

Commit必須把 state 設為 `CONSUMED_PENDING_CONFIRM`。只有 commit 成功後才能發布
`AccessAcceptV2`。如果 storage 無法在同一 transaction 保存 consumption、session
identity及 response recovery state，必須使用 write-ahead／transactional recovery，
使 crash 後只可能得到：

1. 沒有 response／session被發布，可安全 abort reservation；或
2. ticket 已 consumed，且可恢復 byte-identical response與同一 session。

不得出現「M2 已送出但 ticket回到 unused」、「ticket consumed但 retry產生新 KEM
ciphertext」或「相同 response 對應不同 session key」。

## 6. Activation

FGS 收到 `SessionActivateV2` 或攜帶等價 header 的第一個 application AEAD 時：

1. 以 `(use_key, attempt_id, request_digest, session_id, response_digest)` 查找唯一
   pending record；
2. 核對 activation deadline、session expiry與最新 session／FGS-key revocation；
3. 驗證 `client_key_confirmation` 或 suite-defined first-record AEAD；
4. atomic `CONSUMED_PENDING_CONFIRM -> CONSUMED_ACTIVE`；
5. commit 成功後才執行 application side effect。

同一正確 confirmation retry 必須 idempotent。Wrong key、wrong response digest、wrong
session、late confirmation或 competing attempt 均不得 activate。Invalid confirmation
不會產生第二次 consumption，因為 ticket 在 grant commit 時已 consumed。

## 7. Exact replay and retry semantics

| 情境 | 對外結果 | State |
| --- | --- | --- |
| malformed／invalid／expired／revoked M1 | generic reject | 不寫入 |
| invalid `pi_access`／KEM key／context | generic reject | 不寫入 |
| 兩個不同 M1 attempts 同時通過 pure checks | 只有 CAS winner；其他 generic reject | winner `RESERVED` |
| 完整相同 M1 平行送達 | 一個 winner，其餘 same-attempt disposition | 同一 record |
| reserve後、response commit前 crash | recovery證明未發布後才可 abort | `RESERVED`或`UNSEEN` |
| commit後、M2送出前 crash | retry回復 exact M2 | `CONSUMED_PENDING_CONFIRM` |
| M2 遺失 | identical M1 retry取得 exact M2 | `CONSUMED_PENDING_CONFIRM` |
| attacker搶先轉送 M1 | 可觸發同一 grant；不能得到 session key | `CONSUMED_PENDING_CONFIRM` |
| wrong／late client confirmation | generic reject；不得執行 side effect | pending或expired |
| correct confirmation平行重送 | 恰一個 activation；其餘 idempotent | `CONSUMED_ACTIVE` |
| consumed ticket換 version／context／attempt | generic reject | 原 consumed state |

外部 response 不得暴露 invalid、revoked、consumed、wrong proof 或 wrong confirmation
的精細分類 oracle。Internal audit 可保存 fixed reason code，但不得記錄 holder secret、
session keys、NIZK witness或不必要的完整 ticket。

## 8. Early-forwarding DoS boundary

`pi_access` 防止沒有 holder secret 的 attacker自行產生新 M1，卻不能阻止 attacker
複製 holder 已產生的完整 M1。Latency-first profile接受以下限制：

- 搶先轉送可提早永久消耗 ticket；
- attacker沒有 UE ephemeral decapsulation key，不能使用 session；
- legitimate UE 保存 exact wallet journal時，仍可重送同一 M1並取回同一 M2；
- attacker若永久阻斷／jamming所有回應，availability不保證；
- session未收到 client confirmation前不得執行 application side effect。

若 early burn 不可接受，必須定義新 profile，把 M2 改成 provisional grant，並延後
consumption 至 client confirmation。不得在本 v0.2 同時宣稱「M2 final accept」及
「M3前可安全釋放 ticket」。

## 9. UE wallet journal

UE 必須在傳送 M1 前，以 crash-safe方式保存：

```text
use identity／ticket reference
exact AccessRequestV2 bytes
ue_kem_dk 或可安全重建它的 state
request_core_digest／request_digest／attempt_id
creation time／epoch／retry deadline
```

在 M2 verified、session終止或明確不可恢復前，不得丟失這些資料。若 UE 遺失 exact
M1或 ephemeral secret，FGS 已提交的 response無法讓 UE 恢復 session；ticket仍保持
consumed。Journal encryption、rollback protection、secure erasure及 device compromise
不由此 reference spec 宣稱完成。

## 10. Reservation lease and recovery

`RESERVED` lease到期本身不足以 abort。Recovery 必須證明：

1. 沒有 committed grant／response identity；
2. 沒有 response publication可能發生；
3. 沒有下游 session authorization／side effect；
4. 舊 worker受 fencing token阻止，不能在 abort後 commit。

只在四項皆成立時才能回到 `UNSEEN`。一旦進入任何 consumed state，即使未 activate
也不得 rollback；pending timeout只可進 `CONSUMED_EXPIRED`。

## 11. Retention and backhaul

Consumption record 至少保存至：

```text
retention_deadline =
    max(ticket_expiry, session_expiry)
    + maximum_clock_skew
    + replay_grace
```

同一 acceptance domain內的 FGS必須共享 linearizable store或使用不重疊的
single-writer partitions。Store unavailable／timeout／partition時，新的 final grant
必須 fail closed。這表示 authoritative store latency仍在 M1→M2關鍵路徑。

## 12. Machine-test invariants

1. 任一 `use_key` 跨 V1／V2 最多一個 consumed grant。
2. 每個 `(ctx,d_M)` 與 `(ctx,sn)` 最多一個 initial session identity。
3. Pure validation失敗不建立任何 record。
4. Parallel distinct attempts最多一個 reservation／grant winner。
5. Same M1 retries只得到同一 `session_id`、`response_digest`及 response bytes。
6. Retry不重新執行 KEM encapsulation。
7. M2永遠不先於 durable `CONSUMED_PENDING_CONFIRM` publication。
8. Pending session不得執行 application side effect。
9. Correct client confirmation只能產生一次 activation。
10. Wrong／late／cross-session confirmation不得 activate。
11. 所有 consumed states永不回到 `UNSEEN`／`RESERVED`。
12. Crash injection後不會形成第二個 response／session key。
13. Store partition／timeout fail closed。
14. Retention cleanup不會讓仍可能被任何版本 verifier接受的 ticket再用。
15. Exact M1 replay不能使 attacker取得 UE session key。

## 13. Claim boundary

Reference state-model tests只能支持 transition／idempotency／race wiring正確；不證明
distributed linearizability、filesystem durability、wallet security、cryptographic AKE、
access-NIZK soundness或 availability。Production claims必須另外取得 concrete backend、
fault/recovery evidence、security proof、independent review與 satellite-path benchmark。

2026-09-14 checkpoint已在`src/pq_sat_auth/v2/replay.py`建立加鎖的process-local model，
並測試distinct／same-attempt reservation races、competing M2 commit、exact response retry、
activation idempotency、wrong／late／cross-session rejection、expiration、termination、abort
evidence shape與跨版本共用identity namespace。它明確標記`durable = false`、
`distributed = false`及`production_ready = false`；不應被解讀為§5的真實durability
boundary或§11的多FGS authoritative store已完成。
