# One-Time Ticket 狀態與 1-RTT Access 邊界規格 v0.2

> 狀態：Defined；FGS replay／delivery／protected application inbox、unified activation-inbox transaction、atomic grant-query registration、bounded expired-reservation reconciliation、authenticated scoped-revocation ingestion／fanout與UE single-host SQLite references已 Implemented／Tested；尚未 distributed／Production-closed
> 日期：2026-09-16
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
UNIQUE(session_id)  # across all committed grants in one acceptance domain
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

FENCED_RESERVATION_INTERNAL
    SQLite／reference store內部recovery tombstone；對protocol caller呈現為`UNSEEN`，但保留
    單調`fencing_generation`，使舊worker不能對後續reservation執行ABA commit。

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
  --ReconcileExpired(exact evidence + fence rotation)-->
      FENCED_RESERVATION_INTERNAL --public view--> UNSEEN

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
    revocation_generation,
    fencing_generation
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
    fencing_generation,
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

Reference grant processor可在commit前取得較新的non-revoked snapshot，並把reservation
記錄的`revocation_generation`單調提升；commit不得接受較舊generation。即使後續使用
單機SQLite store，此兩步驟仍不是同一serializable transaction，不能取代production
backend在authoritative ordering內執行的revocation recheck＋grant commit。

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

Reference explicit-frame processor使用`session_id` index定位grant，再以record中的
`use_key`及完整commit identity執行atomic transition。不同ticket若嘗試commit相同
`session_id`必須fail closed。Processor必須recover並重新核對exact response與sealed
session state；只有store回覆已完成new activation或同一confirmation的existing active
record後，才能釋放內部session capability。Store commit後若caller收到exception、錯誤
type或identity被改寫，結果為`COMMIT_UNCERTAIN`且不得釋放capability；exact retry可從
authoritative active record恢復。

Activation前的authenticated revocation snapshot必須綁定configuration、acceptance
domain、ticket use key、原grant revocation query、FGS／key、request／response及session。
然而外部snapshot與activate store transition不是同一transaction；production backend仍須
提供authoritative ordering。後續bounded first-record processor已把exact
`SessionActivateV2`放入application AAD，並在application authentication成功後才activate；
其後續delivery claim已有單機SQLite durability，但activation、claim與side-effect仍不在
同一transaction，不得被混稱為production exactly-once ordering。

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

Reference `UEAccessAttemptStateV2`將exact M1、authenticated configuration、
`request_digest`、`attempt_id`、ticket expiry、creation time及ephemeral KEM secret視為
一個protected typed handoff。UE response processor會strictly重新解析M1與ticket、重算
ticket-use identity／request／attempt identities，並要求current authenticated
configuration與journal snapshot完全一致。這是in-memory contract，不是crash-safe wallet
store；同一M2 retry會重新decapsulate並導出相同session output，尚未實作已接受session的
durable／idempotent wallet transition。

## 10. Reservation lease and recovery

`RESERVED` lease到期本身不足以 abort。Recovery 必須證明：

1. 沒有 committed grant／response identity；
2. 沒有 response publication可能發生；
3. 沒有下游 session authorization／side effect；
4. 舊 worker受 fencing token阻止，不能在 abort後 commit。

只在四項皆成立時才能回到 `UNSEEN`。一旦進入任何 consumed state，即使未 activate
也不得 rollback；pending timeout只可進 `CONSUMED_EXPIRED`。

Bounded reference successor以單調`fencing_generation`具體化第4項。第一次reservation使用
generation 1；expired reconciliation在同一write transaction驗證exact reservation、
`observed_at > lease_deadline`與canonical evidence，接著把row改為generation 2的protected
`FENCED_RESERVATION_INTERNAL`。下一次reservation使用generation 3；所有grant commit均必須
攜帶取得reservation時的generation，因此generation 1的stale worker不能對generation 3
執行commit。後續reconcile／reserve依序繼續單調增加，耗盡時fail closed。

`no_grant_digest`、`no_publication_digest`與`fencing_digest`是綁定exact reservation及
observation time的canonical audit identity，不是第三方簽署的publication proof。第2項只在
所有M2 release皆通過「commit成功後才return」的`FGSGrantProcessorV2`邊界時成立；scoped
store另拒絕已具有activation query的reservation recovery。Store提供bounded expired scan，
但`observed_at`仍由caller提供，production recovery clock尚未實例化。Background scheduler、
v1→v2 schema migration、distributed worker fencing及實體斷電驗證仍未實作。

顯式reference coordinator把上述原語組成一次bounded `run_once`。Caller必須提供exact
32-byte `invocation_id`；固定policy提供`batch_limit`與`minimum_stale_seconds`。Coordinator
只取樣一次clock，計算：

```text
scan_cutoff = max(0, observed_at - minimum_stale_seconds)
eligible iff lease_deadline < scan_cutoff
```

Store的scan輸出必須是bounded tuple、無重複、只含符合cutoff的active reservations，否則
整批在任何abort前拒絕。每筆abort後都read-back protected fence：exact回覆為`FENCED`；
abort acknowledgement遺失但exact fence存在為`FENCED_RECOVERED`；另一worker以可重新導出的
evidence先完成為`FENCED_BY_PEER`；reservation已被commit／改變或有scoped dependency則為
`NOT_RECONCILED`，不釋放任何狀態。非預期backend錯誤或read-back不確定會標成`UNRESOLVED`
並立即停止後續項目。

Run result的`accepted=true`只表示這一次bounded pass完整結束，不能解讀成每個candidate
均已fence；caller仍須逐項讀取disposition。`invocation_id`目前只是in-memory result的
correlation identity，沒有被認證或持久化。Reference不提供operator authorization、
production clock、常駐scheduler或persistent run audit log。

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
7. Grant commit的revocation generation不得低於reservation generation。
8. M2永遠不先於 durable `CONSUMED_PENDING_CONFIRM` publication。
9. Pending session不得執行 application side effect。
10. Correct client confirmation只能產生一次 activation transition；exact retry取得同一
    active record。
11. Wrong／late／cross-session confirmation不得 activate。
12. 所有committed grants的`session_id`在acceptance domain內唯一。
13. Store回覆不確定時不得釋放application capability。
14. 所有 consumed states永不回到 `UNSEEN`／`RESERVED`。
15. Crash injection後不會形成第二個 response／session key。
16. Store partition／timeout fail closed。
17. Retention cleanup不會讓仍可能被任何版本 verifier接受的 ticket再用。
18. Exact M1 replay不能使 attacker取得 UE session key。
19. Expired reservation reconciliation與grant commit只有一個linearized winner。
20. Fence後的stale worker不能對新reservation執行ABA commit。
21. Internal fence可跨restart驗證，但不會被public lookup誤當成consumed grant。
22. 每次顯式reconciliation run只取樣一次clock。
23. Scan輸出不符合type、batch、expiry或uniqueness邊界時，任何candidate都不得abort。
24. Abort acknowledgement不確定時，只有exact／equivalent protected fence read-back可恢復成功。
25. 非預期backend或fence read-back錯誤會停止同批剩餘項目。
26. 多個coordinator對同一candidate競爭時，只接受同一fence generation／evidence identity。

## 13. Claim boundary

Reference state-model tests支持transition／idempotency／race wiring；single-host SQLite
checkpoint另支持其明定假設下的cross-process serialization與restart recovery。兩者皆不
證明distributed linearizability、hostile-filesystem／physical-power-loss durability、wallet
security、cryptographic AKE、access-NIZK soundness或availability。Production claims必須
另外取得concrete backend、fault/recovery evidence、security proof、independent review與
satellite-path benchmark。

2026-09-14 checkpoint已在`src/pq_sat_auth/v2/replay.py`建立加鎖的process-local model，
並測試distinct／same-attempt reservation races、competing M2 commit、exact response retry、
activation idempotency、wrong／late／cross-session rejection、expiration、termination、abort
evidence shape與跨版本共用identity namespace。它明確標記`durable = false`、
`distributed = false`及`production_ready = false`；不應被解讀為§5的真實durability
boundary或§11的多FGS authoritative store已完成。

2026-09-15 activation checkpoint另在`src/pq_sat_auth/v2/activation.py`實作explicit
`SessionActivateV2` strict processing、exact recovery、client Finished、activation-time
revocation、process-local atomic activate及post-activate capability release；
`src/pq_sat_auth/v2/replay.py`新增全域`session_id` index與可區分new／existing-active的
transition result。它仍未實作durable／distributed atomic revocation ordering、production
session-state protection或first-record application side effect，`production_ready`維持
false。

2026-09-15 UE acceptance checkpoint在`src/pq_sat_auth/v2/ue.py`實作exact M1／M2及
configuration binding、FGS-key lookup／authentication、KEM decapsulation、server／client
Finished與`SessionActivateV2`產生。Honest output可直接通過FGS activation processor；
但UE wallet仍只是protected in-memory input，沒有durability、rollback protection、
secure erasure或production cryptographic backend，不能據此宣稱crash-safe session recovery
或production PQ AKE。

2026-09-15後續UE wallet checkpoint新增兩個UE-local states：`PREPARED`及
`ACCEPTED_PENDING_ACTIVATION`。`Prepare`必須在M1可能送出前commit exact attempt；M2驗證
成功後，coordinator先原子commit exact response、session keys與activation bytes，再
read-back並核對protected record，最後才把session交給呼叫端。Same-attempt／same-M2 retry
只回復既有record；不同attempt、不同M2、資料mutation或不確定commit回覆不得釋放session。

`SQLiteUEWalletStoreV2`以per-operation connection、WAL、`synchronous=FULL`及
`BEGIN IMMEDIATE`提供單機多程序serialization與restart recovery，並要求外部protection
backend在資料進入SQLite前封裝整份canonical record。已測試commit後突然process exit，
但沒有實體斷電、kernel crash、remount或hostile-filesystem evidence；test-only
XOR／HMAC adapter也不是production cryptography。資料庫rollback protection、secure erasure
及accepted後舊page／WAL中的ephemeral secret清除仍未實作，因此此checkpoint不能被解讀為
production secure wallet或FGS authoritative distributed replay store已完成。

2026-09-15 first protected application checkpoint另固定`FirstApplicationRecordV2`、AAD、
nonce context、`sequence_number = 0`及record digest。UE端獨立SQLite outbox先以
`RESERVED`固定plaintext identity，再以`READY`保存exact wire bytes；commit及read-back
完成前不釋放。FGS先驗證client Finished與application protection，再activate，最後由
process-local claim只釋放一次plaintext capability。它已測試restart、thread／process
race、lost acknowledgement、ciphertext mutation及competing sequence-zero record；該
checkpoint的FGS delivery仍不durable／distributed，activation與external side effect也不是同一
transaction，故不構成crash-safe exactly-once保證。

2026-09-15 FGS replay SQLite checkpoint將同一完整state contract接到單機durable store。
`use_key`、ticket digest／serial與session ID均有唯一index；canonical record經獨立
protection backend後保存exact sealed M2與sealed session state。`BEGIN IMMEDIATE`、WAL、
`synchronous=FULL`及parent-directory fsync提供可信單機假設下的跨程序serialization與
restart recovery；process-local transition suite、跨程序races、突然process exit與實際
grant→restart→activation pipeline均已測試。它不是多FGS authoritative store，也未提供
rollback／hostile-filesystem／實體斷電證據；該checkpoint的revocation snapshot atomicity、
durable delivery及external side-effect transaction仍未完成。

2026-09-15 FGS first-record delivery SQLite checkpoint再將process-local claim替換為單機
durable at-most-once gate。`session_id`只能綁定一個`record_digest`；跨thread／process只有
一個`NEW` winner，exact retry在restart後只取得`EXISTING`且不再釋放plaintext，competing
authenticated sequence-zero record拒絕。Claim commit後突然process exit仍可恢復既有
identity；但若commit acknowledgement或application side effect前crash，工作可能遺失。
Activation、claim及external mutation不是同一transaction，故不支持exactly-once、
distributed、rollback、hostile-filesystem或實體斷電宣稱。

2026-09-15 FGS application inbox checkpoint再把`record_digest` claim與受保護plaintext
work item放入同一單機SQLite enqueue。FGS inbox模式在commit後只回`QUEUED` metadata，
dispatcher從`PENDING`恢復工作，呼叫`apply_once(record_digest, plaintext)`取得stable
receipt後才轉成`COMPLETED`。Application apply acknowledgement或inbox completion
acknowledgement遺失的retry均已測試，test-only idempotent ledger只產生一次effect。

此結果仍有兩個必要邊界：activation與inbox enqueue不是同一transaction，前者完成後
crash仍需UE exact retry；而production external application必須自行證明其`apply_once`
在實際side effect transaction內原子去重。Repository尚未提供該production adapter，
所以external exactly-once、distributed consistency及Production-closed仍為false。

2026-09-15 unified activation-inbox successor以新的單一SQLite schema取代上述兩筆交易
的推薦部署方式。它在同一connection與同一`BEGIN IMMEDIATE`中執行
`CONSUMED_PENDING_CONFIRM -> CONSUMED_ACTIVE`及`PENDING` inbox insert；inbox protection
或insert在commit前失敗時兩者一併rollback。Exact retry、restart與跨process race均只能
得到同一對active grant／inbox identity，且unified store拒絕獨立activation入口。

此successor封閉的是單機reference內的activation-inbox crash gap，不包含activation前的
revocation snapshot atomicity，也不把external application mutation納入SQLite transaction。
Production application仍需實作可驗證的`apply_once`，故external exactly-once、distributed
consistency、physical power-loss及Production-closed維持false。

2026-09-15 authoritative activation-revocation successor再把exact per-session revocation
fence放入同一SQLite database。Processor先讀snapshot做pure validation，最後commit時在
同一`BEGIN IMMEDIATE`內重讀並要求bytes所代表的所有欄位完全相同，再依序完成activation
與inbox insert。Revocation publication與activation因此在可信單機上有唯一順序：publication
先commit則舊activation失敗且不消耗；activation先commit則已接受work item保留並可完成。

2026-09-15 authenticated scoped-revocation successor停用上述未驗證的direct publication，
改用綁定system bundle、`ctx`、epoch、policy、signer key、scope／target、generation及時窗的
canonical authenticated command。四種scope分別匹配configuration digest、FGS authentication
key ID、ticket use key與session ID；command insert與既有registered queries的fence fanout在
同一transaction完成，之後才登錄的query會重播同一`ctx`的歷史commands。

本reference暫以system-initialization的`FEDERATION_CONFIGURATION` key作control-plane
authority，並由out-of-band trust anchor驗證；這只是現有ABI內的provisional選擇。Concrete
PQ authentication、獨立revocation key ceremony、authority rotation／unrevocation、fanout
規模benchmark及跨FGS consensus／linearizable store皆未完成，也沒有實體斷電或rollback
證據。因此「single-host authenticated ingestion與general-scope fanout已測試」仍不得擴張成
「production revocation已完成」。

2026-09-15 atomic grant-query registration successor再移除grant commit後由caller手動補登錄
activation query的操作缺口。Scoped store現在只接受包含exact grant、activation query及
source access-revocation query的composed commit；replay transition、query insert及matching
historical revocation replay在同一`BEGIN IMMEDIATE`內完成。若所得fence已revoked，整筆
transaction rollback，ticket保持`RESERVED`且M2不會釋放。

若grant-query commit已成功但ack遺失，retry只有在existing grant與唯一registered query皆
完整時才取回原M2；missing／corrupt query不會被當成成功。這封閉可信單機SQLite中的
grant-query crash gap，但失敗後reservation仍須依既有bounded recovery evidence處理，並不
代表distributed revocation、automatic abort或Production-closed已完成。
