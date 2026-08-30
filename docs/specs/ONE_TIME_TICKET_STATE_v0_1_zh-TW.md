# One-Time Ticket 狀態與 Access 邊界規格 v0.1

> 狀態：Draft；canonical framing、use identity 與 process-local replay model 已實作／測試
> 日期：2026-08-30
> 所屬模組：M5 Satellite authentication、M6 Anti-replay／revocation／handover
> Canonical architecture：`ARCHITECTURE_zh-TW.md`

## 1. 目的與 claim boundary

本規格將 system profile v0.1 的 short-lived、strictly one-use ticket 決策降成可實作、可測試的狀態機。它定義 FGS 何時可消耗 ticket、並行 replay 如何仲裁、失敗與 crash 如何恢復，以及 handover 如何避免重用已消耗 ticket。

本規格不修改 PQ-RBBC core：

- `VerifyTicket(T)` 仍是 stateless cryptographic verification；
- fresh serial、issuance-side `sid` replay control、opening-authorization replay control、one-more unforgeability，以及 trace DEM 的 one-time privacy，都不等於 access ticket one-use；
- one-use 性質只在本規格的 FGS state transition、holder authentication 與儲存假設下成立；
- 整體 protocol 目前是 Defined；canonical framing／parser、use identity 與 test-only process-local replay model 已達 Implemented／Tested。
- Access object serializers、holder authenticator、PQ AKE、durable／distributed replay store、revocation 與 handover 尚未實作；上述局部測試不代表整個模組、proof 或 production closure。

## 2. v0.1 系統假設

1. FGS 是 online-path verifier 與 session endpoint；LEO／FLEO 不維護 authoritative ticket-consumption state。
2. 同一 acceptance domain 內的 FGS 共享線性一致（linearizable）的 replay store，或使用能提供等價 single-writer／consensus 保證的分片配置。
3. Ground-network partition 時採 fail closed：無法存取 authoritative replay state 的 FGS 不得建立新 session。
4. FGS 具有可信的 epoch 與時間來源；允許的 clock skew 必須由部署 profile 固定。
5. Access protocol 必須證明 UE 持有 ticket 中 `h=H_hold(k_hold)` 所對應的 holder secret，並把證明綁定完整 access transcript。只有看到 ticket bytes 不足以消耗或使用 ticket。
6. PQ AKE、holder authenticator 與 key-confirmation primitive 尚待 D-002 選定；v0.1 先以 suite-bound opaque fields 固定接口，不能把 test adapter 宣稱為 production cryptography。

若未滿足第 2、3 或 5 點，系統不得宣稱跨 FGS strictly one-use。

## 3. 名詞與 identities

### 3.1 RBBC identities

對 spendable ticket `T=(M, sigma)`：

```text
d_M = H_ticket(Encode(M))
sn  = M.sn                    # 16-byte visible serial
ctx = M.ctx                   # 32-byte common context digest
```

本規格延用 proof 中的 `d_M` 作為 canonical ticket digest。它只 digest canonical payload `M`，不把可能具有不同表示的 signature bytes 當成不同可使用票券。

### 3.2 Consumption key

```text
use_key = SHAKE256(
    "PQ-SAT/USE-KEY/v1" || ctx || sn || d_M,
    256
)
```

Replay store 必須同時具有：

- `UNIQUE(ctx, d_M)`；
- `UNIQUE(ctx, sn)`；
- `UNIQUE(use_key)`。

若相同 `(ctx, sn)` 對應不同 `d_M`，或相同 `d_M` 對應不同 visible serial，必須 fail closed 並產生內部 integrity alert；不可選擇其中一份繼續驗證。

### 3.3 Serving context

Serving context 由 operator 固定的 canonical object 編碼後產生：

```text
serving_context_digest = SHAKE256(
    "PQ-SAT/SERVING-CONTEXT/v1" || Encode(ServingContextV1),
    256
)
```

`ServingContextV1` 至少包含共同的 operator、FGS、satellite／relay scope、beam／cell scope、epoch 與 policy identifiers。實際 identifier encoding 在 G1 interface freeze 前仍是 draft；不得使用自由格式或未長度分隔的字串。

## 4. Canonical framing

所有 v0.1 access objects 使用同一 framing：

```text
FrameV1 =
    magic[8]       # ASCII "PQSAT-A1"
 || version_u16be # 0x0001
 || type_u16be
 || body_len_u32be
 || body[body_len]
```

Body fields 依每一 object 的固定順序編碼。Primitive-dependent opaque field 使用：

```text
Opaque = len_u32be || value[len]
```

規則：

- parser 必須先檢查 frame length、version、type、field count 與 suite-specific maximum；
- integer 只用 unsigned big-endian fixed width；
- fixed-width field 不得再加 length；
- opaque field 必須使用最短、唯一且 suite 規定的表示，不接受 alternate encoding；
- unknown version、type、suite、trailing bytes、duplicate field 或 non-canonical encoding 一律拒絕；
- domain labels 是 protocol constants，不在 wire object 中接受 user-supplied 替代值。

此 framing 是 v0.1 draft boundary；在 G1 前可透過版本更新修正，但一旦產生 frozen vectors，不得在同一 version 靜默改義。

## 5. Access objects

### 5.1 `AccessInitV1`（type `0x0001`）

```text
suite_id_u16be
ctx[32]
serving_context_digest[32]
ue_nonce[32]
attempt_nonce[16]
ticket = Opaque
ue_key_share = Opaque
```

- `ue_nonce` 與 `attempt_nonce` 每次新 attempt 必須隨機產生。
- `ticket` 必須是 `T=(M,sigma)` 的唯一 canonical encoding。
- `AccessInitV1` 只觸發 pure validation 與 challenge 產生，不得消耗或 reserve ticket。

### 5.2 `AccessChallengeV1`（type `0x0002`）

```text
suite_id_u16be
ctx[32]
serving_context_digest[32]
ue_nonce[32]
fgs_nonce[32]
attempt_nonce[16]
challenge_expiry_u64be
fgs_key_share = Opaque
challenge_cookie = Opaque
```

`challenge_cookie` 必須讓 FGS 驗證 challenge 是由本 federation／FGS 產生、未過期，且綁定 init digest、suite、nonces、key shares 與 serving context。可以使用 authenticated stateless cookie 或獨立 pending-challenge store；它不是 ticket-consumption record。

### 5.3 `AccessFinishV1`（type `0x0003`）

```text
suite_id_u16be
ctx[32]
serving_context_digest[32]
ue_nonce[32]
fgs_nonce[32]
attempt_nonce[16]
challenge_cookie = Opaque
holder_authenticator = Opaque
ue_key_confirmation = Opaque
```

### 5.4 Transcript 與 attempt identity

```text
init_digest      = SHAKE256("PQ-SAT/ACCESS-INIT/v1" || Encode(AccessInitV1), 256)
challenge_digest = SHAKE256("PQ-SAT/ACCESS-CHALLENGE/v1" || Encode(AccessChallengeV1), 256)
finish_core      = canonical AccessFinishV1 fields excluding authenticators

transcript_digest = SHAKE256(
    "PQ-SAT/ACCESS-TRANSCRIPT/v1"
    || init_digest
    || challenge_digest
    || Encode(finish_core),
    256
)

attempt_id = SHAKE256(
    "PQ-SAT/ACCESS-ATTEMPT/v1"
    || d_M
    || serving_context_digest
    || ue_nonce
    || fgs_nonce
    || attempt_nonce
    || transcript_digest,
    256
)
```

Holder authenticator、AKE keys 與兩端 key confirmation 都必須綁定 `transcript_digest`、`d_M`、`ctx` 與 serving context。不得只簽 nonce 或 ticket digest 的真子集。

### 5.5 `AccessAcceptV1`（type `0x0004`）

```text
suite_id_u16be
attempt_id[32]
session_id[32]
serving_context_digest[32]
session_expiry_u64be
fgs_key_confirmation = Opaque
```

```text
response_digest = SHAKE256(
    "PQ-SAT/ACCESS-ACCEPT/v1" || Encode(AccessAcceptV1),
    256
)
```

`AccessAcceptV1` 必須經 session key 或 suite 規定的 FGS authenticator 保護。Replay store 可保存 sealed response 或足以重建完全相同 response 的受保護 state，以支援同 attempt 的 idempotent retry。

## 6. Authoritative ticket state machine

### 6.1 States

```text
UNSEEN     # replay store 沒有 record；邏輯上可嘗試使用
RESERVED   # 唯一 authenticated attempt 正在原子建立 session
CONSUMED   # 已成功建立唯一 session；不可回復或再次使用
```

`EXPIRED` 與 `REVOKED` 是 acceptance predicates／獨立 registries，不是可從 `CONSUMED` 回復的狀態。任何 state 下若 policy 判斷 expired 或 revoked，都不得建立新 session。

### 6.2 Allowed transitions

```text
UNSEEN  --Reserve(valid AccessFinish)--> RESERVED
RESERVED --Commit(session + response)--> CONSUMED
RESERVED --Abort before commit---------> UNSEEN
CONSUMED --same-attempt retry----------> CONSUMED + idempotent response
```

禁止：

```text
CONSUMED -> RESERVED
CONSUMED -> UNSEEN
CONSUMED -> second session
RESERVED(attempt A) -> RESERVED(attempt B)
```

### 6.3 Pure validation before reservation

FGS 必須依序完成以下檢查，任一失敗都不得寫入 consumption record：

1. strict frame／object parsing；
2. federation configuration、suite、epoch、expiry 與 serving context；
3. `Core.VerifyTicket(T)`；
4. recompute `d_M`、`sn`、`ctx` 與 `use_key`；
5. ticket／serial revocation snapshot；
6. challenge cookie、nonces、deadline 與 transcript digest；
7. holder-secret possession authenticator；
8. UE-side AKE key confirmation；
9. resource／policy admission that does not create an externally visible session。

不得用「先 consume，失敗再 rollback」取代上述順序。

### 6.4 Atomic reserve and commit

完成 pure validation 後：

```text
Reserve(use_key, ctx, d_M, sn, attempt_id, transcript_digest)
```

必須以 linearizable compare-and-set 或 serializable transaction 實作。成功 reserve 的 attempt 是唯一可能建立 session 的 attempt。

Session record、`AccessAcceptV1` response identity 與 `CONSUMED` transition 必須在同一 durability boundary 內 commit：

```text
Commit(
    use_key,
    attempt_id,
    transcript_digest,
    session_id,
    response_digest,
    sealed_response_or_recovery_state,
    consumed_at,
    retention_deadline
)
```

若 storage 無法原子涵蓋 session 與 consumption，必須使用 write-ahead／transactional recovery，使 crash 後只能得到「確定未建立 session」或「確定 CONSUMED 且可回復相同 response」兩種結果，不得形成 session 已有效但 ticket 被重新釋放的狀態。

## 7. Duplicate、retry 與 crash semantics

| 情境 | 對外結果 | Consumption state |
| --- | --- | --- |
| malformed／invalid ticket | generic reject | 不寫入 |
| expired／revoked／wrong context | generic reject | 不寫入；revocation 另記 |
| invalid holder authenticator／key confirmation | generic reject | 不寫入 |
| 兩個不同 attempt 同時通過 pure checks | 只有 CAS winner 可繼續；loser generic reject | winner `RESERVED` |
| 同 attempt 在 `RESERVED` 時重送 | pending／retry response，不建立第二個 worker session | 不變 |
| reserve 後、commit 前 process crash | recovery 證明無 session 後才可 abort／lease release | `RESERVED` 或安全回到 `UNSEEN` |
| commit 後、response 送出前 crash | retry 回復同一 sealed response | `CONSUMED` |
| response 遺失後，同 attempt 重送 | 驗證 retry binding 後回復完全相同 session response | `CONSUMED` |
| consumed 後不同 attempt 使用同 ticket | generic reject | `CONSUMED` |
| consumed 後相同 bytes 跨 serving context | generic reject | `CONSUMED` |

外部錯誤應避免提供「invalid／expired／revoked／consumed」的精細分類 oracle；內部 audit log 可保存穩定 reason code。Timing 與 traffic-analysis leakage 必須在 evaluation 中量測，不能只靠統一錯誤字串宣稱消除。

## 8. Reservation lease

`RESERVED` 可以有短 lease，但 lease 到期本身不足以釋放 ticket。Recovery procedure 必須確認：

1. 沒有 committed session record；
2. 沒有 committed response identity；
3. 沒有下游已生效的 session authorization；
4. 對應 attempt worker 不再可能 commit。

只有四項都成立時才能執行 `Abort`。若結果不確定，保持 `RESERVED` 並 fail closed，交由 reconciliation／operator recovery；不得為 availability 猜測「大概沒有成功」。

## 9. Revocation ordering

Revocation check 必須在 pure validation 時執行，並在 reserve／commit transaction 內再次確認同一或更新的 revocation generation。

- revocation 先 commit：access 必須拒絕；
- consumption 先 commit：已建立 session 是否立即終止由 session-revocation policy 決定，但 ticket 永遠維持 `CONSUMED`；
- 兩者競爭：由 replay store／revocation store 的 serializable order 決定並留下 audit evidence。

## 10. Handover boundary

Initial access 成功後 ticket 已是 `CONSUMED`。Handover 必須使用綁定原 session、target serving context、fresh nonces 與 handover sequence 的 session-derived authorization；不得再次呼叫 ticket consumption，也不得把已消耗 ticket 當作新 access credential。

若無法驗證 session-derived handover，v0.1 必須重新取得一張尚未使用的新 ticket 執行 full access；不可回退重用舊 ticket。

## 11. Persistence 與 retention

Consumption record 至少保留至：

```text
retention_deadline = ticket_expiry + maximum_clock_skew + replay_grace
```

在 federation policy 能證明所有 verifier 已拒絕該 epoch、所有延遲封包已超出 network lifetime，且 audit retention 已滿足前，不得提前刪除。刪除只是 storage lifecycle，不得使 expired ticket 重新可用。

不得在 log 中保存 holder secret、session key、裸 opening share 或不必要的完整 ticket。Audit record 應保存 digest、state transition、時間、FGS identity、revocation generation 與穩定 reason code。

## 12. 必須 machine-test 的 invariants

1. 每個 `use_key` 最多一個 `CONSUMED` record。
2. 每個 `(ctx,d_M)` 最多建立一個 initial session。
3. 每個 `(ctx,sn)` 最多建立一個 initial session。
4. 驗證失敗不建立 reservation 或 session。
5. 兩個並行不同 attempts 恰有零或一個成功，不得有兩個成功。
6. 同 attempt retry 只能取得相同 `session_id` 與 `response_digest`。
7. 不同 attempt 不得取得 consumed ticket 的 response。
8. Crash injection 在每個 durability boundary 後都不會產生第二個 session。
9. `CONSUMED` 永不轉回 `UNSEEN`／`RESERVED`。
10. Wrong epoch、context、nonce、key share、authenticator、confirmation 或 transcript byte 全部拒絕且不消耗。
11. 相同 serial／不同 digest，以及相同 digest／不同 serial 都 fail closed。
12. Handover 不改變 ticket consumption record，也不建立第二個 initial session。
13. Store partition／timeout 時 fail closed。
14. Retention cleanup 不會使仍可被 verifier 接受的 ticket 再次可用。

## 13. 安全性與 availability 限制

- One-time acceptance 依賴 holder authentication；若 bearer ticket 本身即可使用，passive observer 可先行消耗造成 impersonation／DoS。
- One-time acceptance 依賴 linearizable state；eventual-consistency replicas 可能同時接受同一 ticket。
- Fail-closed partition 會降低 availability，是 v0.1 為縮小安全範圍所接受的 trade-off。
- 一次性 ticket 不能隱藏同一 ticket 的失敗重送 linkage；系統只能限制成功使用次數並縮短可觀察窗口。
- FGS、timing、serving context 與 issuance batch size 仍可能產生 metadata linkage，需要獨立 privacy analysis。
- 本規格不提供 unlinkable multi-show。若未來加入 `Show`，必須使用新 protocol version 與新的 security proof，不能在 v0.1 中關閉 consumption check。

## 14. 下一個 implementation gate

進入程式實作前仍須完成：

1. 選定 `ServingContextV1` identifiers 的 exact widths／encodings；
2. 選定 v0.1 `suite_id` registry 與每個 opaque field maximum；
3. 決定 replay store reference backend 與 transaction model；
4. 定義 holder authenticator 與 PQ AKE 的 production／test adapter boundary；
5. 產生正負 canonical byte vectors；
6. 將本文件與 threat-model lane 的 security games 交叉 review。

上述項目完成並 review 後才可宣告 G1 interface freeze。
