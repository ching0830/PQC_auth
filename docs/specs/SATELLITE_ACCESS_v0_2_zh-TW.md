# Satellite Access 與 PQ AKE 規格 v0.2

> 狀態：Defined；bounded reference codecs／relation／processors、UE SQLite wallet、FGS single-host SQLite replay／delivery／protected application inbox、unified activation-inbox transaction、authenticated scoped-revocation ingestion及fanout已 Implemented／Tested；尚未 Instantiated／distributed／Proof-closed／Production-closed
> 日期：2026-09-15
> 所屬模組：M5 Satellite authentication、M6 Anti-replay／revocation／handover
> State companion：`docs/specs/ONE_TIME_TICKET_STATE_v0_2_zh-TW.md`
> Historical predecessor：`docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md`

## 1. 目的與版本邊界

本規格定義一個以 **一趟 UE–FGS 往返**回傳接入結果的候選 access profile：

```text
UE  -> FGS: AccessRequestV2(ticket, freshness, serving context,
                            UE ephemeral KEM key, pi_access)
FGS -> UE : AccessAcceptV2(FGS authentication, KEM ciphertext,
                           server key confirmation, access result)
```

`AccessRequestV2` 不依賴逐次 `fgs_nonce`。FGS 在第二則訊息使用 fresh KEM
encapsulation randomness，並把其 ciphertext、FGS identity 與完整 request 綁入
authentication transcript。UE 在收到並驗證 `AccessAcceptV2` 後，於 1 RTT 得到接入
授權結果及 FGS 對最終 key 的 unilateral key confirmation。

若 FGS 還要求 UE 對最終 session key 的 explicit key confirmation，UE 必須在第一個
受保護 application packet 中攜帶 `SessionActivateV2`。它不是另一輪 access
authorization；FGS 只在驗證它後把 pending session 標為 active。

本規格是新版本，不修改或重新解讀 v0.1 bytes：

- `AccessInitV1`、`AccessChallengeV1`、`AccessFinishV1`、`AccessAcceptV1` 保持原義；
- v0.1 的 `fgs_nonce` 與 challenge cookie 不得被靜默刪除；
- v0.2 使用不同 frame magic、version、message types、domain labels 及 proof relation；
- 同一 ticket 的 consumption identity 跨 v0.1／v0.2 共用，禁止以 protocol version
  差異取得第二次成功 access；
- negotiation／fallback 必須受 authenticated configuration 明確允許。接收端不得因
  v0.2 驗證失敗自動降級至 v0.1。

## 2. Claim boundary

本規格只固定候選 protocol semantics 與 byte contract。它不代表：

- access NIZK backend 已選定或具有 post-quantum simulation extractability；
- production PQ KEM、FGS authentication、KDF 或 MAC suite 已選定；
- FGS authentication key 已加入 production system-initialization ceremony；
- production durable／distributed replay store、secure UE wallet 或 session endpoint 已完成；
- access authentication、session freshness、forward secrecy 或 availability 已證明；
- 減少 message count 已經降低實測 latency、energy 或 communication bytes。

`pi_access` 是新的在線 holder-possession proof，不是離線 issuance 的 `pi_issue`。
兩者不得共用 proof bytes、statement ABI、relation identifier、domain separator 或
claim boundary。未來可以評估共用同一種已 qualification 的 proof-system backend，
但仍須使用獨立 proving／verification parameters identities 與安全組合分析。

## 3. 前置 authenticated configuration

UE 與 FGS 在 access 前必須同意一份 federation-authenticated configuration，至少包含：

```text
access_protocol_version
access_profile_digest
system_config_digest
ctx
epoch
valid_from / valid_until / maximum_clock_skew
acceptance_domain
FGS identity and FGS authentication key identity
access NIZK relation / parameter identity
PQ KEM / FGS authentication / KDF / MAC suite identities
channel-binding mode policy
```

FGS authentication key必須與 FAC、OA、issuer、opening、audit keys 分離。現有 system
profile v0.1 initialization key-role ABI 未包含此角色；production 使用前必須建立
versioned extension，不得把 issuer 或 federation-configuration key 臨時兼作 FGS key。

若 configuration 無法驗證、已過期、遭撤銷或版本／suite 不支援，FGS 必須 fail
closed。UE 亦不得信任未被 configuration 授權的 FGS response key。

## 4. Canonical framing

v0.2 frame：

```text
FrameV2 =
    magic[8]       # ASCII "PQSAT-A2"
 || version_u16be # 0x0002
 || type_u16be
 || body_len_u32be
 || body[body_len]
```

Message types：

```text
0x0101 AccessRequestV2
0x0102 AccessAcceptV2
0x0103 SessionActivateV2
0x0104 FirstApplicationRecordV2
```

Primitive-dependent fields 使用：

```text
Opaque = len_u32be || value[len]
```

所有 integer 使用 unsigned fixed-width big-endian。Parser 必須拒絕 wrong magic、
unknown version／type／suite、overflow、truncation、alternate encoding、trailing bytes
及超出 suite-specific exact／maximum length 的欄位。Domain labels 是 protocol
constants，不接受 wire-supplied substitute。

### 4.1 Test-only suite boundary

在 production primitive freeze 前，implementation 可以保留 `suite_id = 0xffff` 與
`proof_suite_id = 0xffff` 作 test-only profile，但必須明確標記
`production_ready = false`。Test-only upper bounds 不得被誤寫為 production sizes。

## 5. `AccessRequestV2`

Canonical body field order：

```text
suite_id_u16be
proof_suite_id_u16be
system_config_digest[32]
ctx[32]
epoch_u64be
target_fgs_id[32]
fgs_auth_key_id[32]
serving_context_digest[32]
authorization_digest[32]
client_time_u64be
ue_nonce[32]
attempt_nonce[16]
channel_binding_mode_u16be
channel_binding_digest[32]
ticket = Opaque
ue_kem_epk = Opaque
holder_binding_tag[32]
access_nizk = Opaque
```

`ticket` 必須是 `T=(M,sigma)` 的唯一 canonical encoding。FGS 必須執行
`Core.VerifyTicket(T)`，從已驗證 payload 取得：

```text
d_M = H_ticket(Encode(M))
sn  = M.sn
ctx = M.ctx
h   = M.h
```

`authorization_digest` 綁定 canonical service／scope／policy／validity object。若服務
授權是公開 predicate，FGS 在 NIZK 外驗證其真實性；若要證明 hidden attributes 滿足
policy，必須另行擴充 issuance ticket commitment 與 access relation。本 v0.2 不憑空
宣稱已證明未被 ticket 承諾的 hidden attributes。

### 5.1 Request core 與 holder binding

`request_core` 是 `AccessRequestV2` body 從 `suite_id` 起至 `ue_kem_epk` 結束的
canonical bytes，不包含 frame header、`holder_binding_tag` 或 `access_nizk`：

```text
request_core_digest = SHAKE256(
    "PQ-SAT/ACCESS-REQUEST-CORE/v2"
    || Encode(request_core),
    256
)

holder_binding_tag = SHAKE256(
    "PQ-SAT/ACCESS-HOLDER-BIND/v2"
    || k_hold[32]
    || request_core_digest,
    256
)
```

所有 variable-length inputs 已由 canonical `Opaque` encoding 長度分隔；`k_hold` 與
digest 固定為 32 bytes。

### 5.2 Access NIZK statement／witness／relation

```text
x_access = (
    access_profile_digest,
    access_pp_digest,
    h,
    request_core_digest,
    holder_binding_tag
)

w_access = k_hold
```

```text
R_access(x_access; w_access) = 1 iff

    h = H_hold(k_hold)

and holder_binding_tag = SHAKE256(
        "PQ-SAT/ACCESS-HOLDER-BIND/v2"
        || k_hold
        || request_core_digest,
        256
    )
```

FGS 必須從 authenticated configuration 與收到的 exact request 自行建構
`x_access`；不得接受 UE 另傳且未核對的 statement interpretation。Relation／circuit
必須實際約束 `request_core_digest`，不能讓 compiler 將它當 unused public input 移除。

Bounded reference將statement bytes固定為：

```text
Encode(x_access) =
    magic[8]       # ASCII "PQSAT-X2"
 || version_u16be # 0x0002
 || access_profile_digest[32]
 || access_pp_digest[32]
 || h[32]
 || request_core_digest[32]
 || holder_binding_tag[32]
```

Production proof backend若需要不同outer envelope，必須保留上述tuple的唯一canonical
mapping並以versioned profile明定，不得默默重排或省略public inputs。

此 relation 證明 holder secret possession 並授權 `request_core`，但不在 circuit 內
重驗 Blind-UOV signature；ticket validity 由外部 `Core.VerifyTicket(T)` 負責。Proof
backend 的 composition theorem 必須說明這兩個 verifier 如何共同形成 acceptance
predicate。

### 5.3 Full request 與 attempt identity

```text
request_digest = SHAKE256(
    "PQ-SAT/ACCESS-REQUEST/v2"
    || Encode(AccessRequestV2),
    256
)

attempt_id = SHAKE256(
    "PQ-SAT/ACCESS-ATTEMPT/v2"
    || use_key
    || request_digest,
    256
)
```

`request_digest` 包含 `holder_binding_tag` 與 `access_nizk`。只有完整 bytes 相同的
request 才是同 attempt retry；此處`Encode(AccessRequestV2)`包含完整FrameV2 header及
body。UE 不得在 retry 時重抽 nonce、KEM key 或 proof；若
重建成不同 bytes，即為 competing attempt。

### 5.4 Freshness

v0.2 不使用 per-attempt `fgs_nonce`。FGS 必須共同檢查：

1. ticket 尚在有效期且未被撤銷；
2. `epoch` 等於 authenticated current configuration／serving context epoch；
3. `client_time` 位於 profile 固定的 clock-skew／freshness window；
4. `ue_nonce` 與 `attempt_nonce` 具有規定 entropy；
5. `target_fgs_id` 與 `fgs_auth_key_id` 指向本次實際 verifier；
6. authoritative replay store 對 `use_key` 的決策。

時間、epoch 與 nonce 只限制 stale replay window；它們不取代 atomic one-time
consumption。完整複製尚未消耗的 request 仍可能通過 pure cryptographic checks。
第4項是UE生成器及部署要求；FGS從單一request只能檢查exact length並排除全零sentinel，
不能由收到的值本身證明CSPRNG entropy。

### 5.5 Channel binding

```text
channel_binding_mode = 0  => channel_binding_digest = 32 zero bytes
channel_binding_mode = 1  => digest of an authenticated lower-layer exporter
```

Unknown mode 一律拒絕。Mode 1 的 exporter 必須由 UE 與 FGS 獨立取得並比對，不得只
相信 UE supplied metadata。若部署沒有此類 exporter，profile 必須明列 mode 0 並只
宣稱 serving-context binding，不得宣稱 cryptographic channel binding。

## 6. FGS processing order

FGS 對新 request 必須依序完成下列 pure checks，任一失敗不得 reserve／consume：

1. FrameV2、object、field lengths 與 suite registry；
2. authenticated configuration、version、epoch、time、FGS identity 與 key IDs；
3. serving／authorization／channel context；
4. `Core.VerifyTicket(T)` 及 canonical payload extraction；
5. recompute `d_M`、`sn`、`ctx`、`use_key`、request digests 及 attempt ID；
6. ticket／serial／holder／configuration／FGS-key revocation snapshot；
7. `pi_access` verification；
8. UE KEM public-key validation；
9. 不建立外部 session 的 resource／policy admission。

上述 pure checks完成後，FGS 才能呼叫 authoritative state machine 的 `Reserve`。
Revocation generation 必須在 commit 時以 serializable ordering 再檢查。

## 7. `AccessAcceptV2`

成功 reserve 後，FGS 對 `ue_kem_epk` 執行 fresh encapsulation：

```text
(kem_ciphertext_to_ue, ss) <- KEM.Encaps(ue_kem_epk; fresh randomness)
```

Canonical body field order：

```text
suite_id_u16be
system_config_digest[32]
ctx[32]
epoch_u64be
fgs_id[32]
fgs_auth_key_id[32]
request_digest[32]
attempt_id[32]
session_id[32]
serving_context_digest[32]
session_expiry_u64be
activation_deadline_u64be
kem_ciphertext_to_ue = Opaque
fgs_authenticator = Opaque
server_key_confirmation = Opaque
```

`response_core` 是 body 從 `suite_id` 起至 `kem_ciphertext_to_ue` 結束的 canonical
bytes，不包含 frame header、`fgs_authenticator` 或 `server_key_confirmation`。

```text
transcript_digest = SHAKE256(
    "PQ-SAT/ACCESS-TRANSCRIPT/v2"
    || request_digest
    || Encode(response_core),
    256
)
```

KDF 必須以 suite-defined、domain-separated interface 綁定：

```text
K_master = KDF(
    ss,
    protocol/profile || roles || algorithms || ctx || epoch
    || fgs_id || serving_context_digest || transcript_digest
)

K_server_finished
K_client_finished
K_application
K_exporter
    <- ExpandWithDistinctLabels(K_master)
```

FGS authentication 與 key confirmation：

```text
fgs_authenticator = FGS.Auth(
    sk_FGS,
    "PQ-SAT/FGS-AUTH/v2" || transcript_digest
)

server_key_confirmation = MAC(
    K_server_finished,
    "PQ-SAT/SERVER-FINISHED/v2"
    || transcript_digest
    || SHAKE256(fgs_authenticator, 256)
)
```

`FGS.Auth` 可以在後續 suite 中選定 PQ signature 或具等價 security model 的
authenticated construction。單獨能產生相同 KEM secret 的 MAC 不等於 FGS identity
authentication；production suite 必須同時提供兩者。

```text
response_digest = SHAKE256(
    "PQ-SAT/ACCESS-ACCEPT/v2"
    || Encode(AccessAcceptV2),
    256
)
```

此處`Encode(AccessAcceptV2)`包含完整FrameV2 header及body。

FGS 必須在送出 response 前，將 exact response 或足以重建相同 response 的 sealed
state，連同 consumption decision 放入同一 durability boundary。Retry 不得重新執行
KEM encapsulation或產生第二個 session ID。

## 8. UE acceptance 與 `SessionActivateV2`

UE 必須：

1. 核對 response 與原始 M1 的 configuration、FGS、context、request digest 及
   attempt ID；
2. 驗證 FGS key 是 current authenticated configuration 所授權；
3. 驗證 `fgs_authenticator`；
4. 使用原始 ephemeral decapsulation key 解出 `ss`；
5. 重建 transcript／KDF 並驗證 `server_key_confirmation`；
6. 核對 session／activation expiry。

全部通過後，UE 可在 1 RTT 進入 `UE_ACCEPTED`，並產生：

```text
SessionActivateV2 body =
    suite_id_u16be
 || request_digest[32]
 || attempt_id[32]
 || session_id[32]
 || response_digest[32]
 || client_key_confirmation = Opaque

client_key_confirmation = MAC(
    K_client_finished,
    "PQ-SAT/CLIENT-FINISHED/v2" || response_digest
)
```

獨立frame形式的reference identity為：

```text
activation_digest = SHAKE256(
    "PQ-SAT/SESSION-ACTIVATE/v2"
    || Encode(SessionActivateV2),
    256
)
```

其中`Encode(SessionActivateV2)`包含完整FrameV2 header及body。若部署把client Finished
併入第一個application AEAD，必須以suite-defined方式把等價五個fixed fields與
confirmation綁進record header／AAD。

它可以是獨立 frame，也可以作為第一個 application AEAD record 的 authenticated
header。FGS 必須在 atomic activation commit 後才執行該 record 的 application side
effect。重複的正確 confirmation 必須 idempotent；錯誤、過期或跨 session
confirmation 不得啟動 session。

### 8.1 第一個受保護 application record

v0.2 bounded reference 將「把 `SessionActivateV2` 併入第一個 application AEAD」的
exact bytes 固定如下：

```text
FirstApplicationRecordV2 body =
    suite_id_u16be
 || request_digest[32]
 || attempt_id[32]
 || session_id[32]
 || response_digest[32]
 || sequence_number_u64be       # 必須為 0
 || activation = Opaque         # exact canonical SessionActivateV2 frame
 || ciphertext = Opaque
```

其中 `activation` 內的五個 fixed fields 必須與 record header 完全相同。AAD、nonce
context 及 record identity 分別為：

```text
authenticated_header =
    suite_id || request_digest || attempt_id || session_id
 || response_digest || sequence_number || Opaque(activation)

AAD = "PQ-SAT/FIRST-APPLICATION-AAD/v2"
   || authenticated_header

nonce_context = SHAKE256(
    "PQ-SAT/FIRST-APPLICATION-NONCE/v2"
 || suite_id_u16be || session_id || sequence_number_u64be,
    256
)

record_digest = SHAKE256(
    "PQ-SAT/FIRST-APPLICATION-RECORD/v2"
 || Encode(FirstApplicationRecordV2),
    256
)
```

`nonce_context` 是交給 concrete suite 的唯一衍生輸入，不代表直接截取成任一 AEAD 的
nonce；實際 nonce mapping、tag size 與 plaintext limit 必須由 production suite 固定。
同一 `session_id` 的 sequence 0 只能保留一個 plaintext identity。UE 必須先在 durable
outbox 完成 `RESERVED -> READY`、保存 exact record bytes 並 read back，才可把 wire bytes
交給傳輸層；相同 plaintext retry 回傳原 bytes，不得重新選 nonce 或建立另一個 record，
不同 plaintext 則 fail closed。

FGS 的共同處理順序為：strict parse及binding、驗證client Finished、以
`K_application`驗證整個record AEAD，再進入activation commit boundary。AEAD失敗不得
activate；另一個通過AEAD的sequence-0 record必須視為conflict。Processor固定三種互斥
sink profiles：

- legacy direct-delivery compatibility path：取得durable at-most-once claim後釋放一次
  plaintext capability；exact retry只回`ALREADY_DELIVERED`。此path可能在claim後crash時
  永久遺失工作；
- compatibility durable-inbox path：activation後以另一筆enqueue保存claim identity與
  protected plaintext；
- recommended unified activation-inbox path：同一SQLite database／connection／
  `BEGIN IMMEDIATE`內，同時把grant轉成`CONSUMED_ACTIVE`並建立`PENDING` protected
  plaintext，
  processor只回queue metadata；dispatcher以`record_digest`呼叫application `apply_once`，
  再保存stable receipt並標記`COMPLETED`。

Processor必須只配置其中一種sink；unified模式另強制activation processor與atomic inbox
使用同一store object，且store停用獨立`activate_session()`入口。這封閉單機SQLite模型中
activation commit後、inbox enqueue前的crash window。Production external application
仍必須自行在side-effect transaction內實作原子idempotency；因此本規格仍不宣稱任意
external application side effect具有crash-safe exactly-once保證。

## 9. Acceptance terminology

為避免把 1 RTT 說得比實際保證更強，v0.2 固定三個不同事件：

| Event | 時點 | 可宣稱內容 |
| --- | --- | --- |
| `FGS_AUTHORIZED_PENDING` | FGS 完成 M1 驗證且 durable commit 唯一 M2 | ticket 已唯一消耗、FGS 已授權一個尚待 client confirmation 的 session |
| `UE_ACCEPTED` | UE 驗證 M2 authentication／KEM／server Finished | UE 在 1 RTT 知道合法 FGS 已授權且雙方可導出相同 session key |
| `FGS_ACTIVE` | FGS 驗證 client Finished／第一個 application AEAD 並 atomic activate | FGS 具有 UE 對最終 key 的 explicit confirmation，session 可執行 side effects |

不得把 `FGS_AUTHORIZED_PENDING` 寫成已確認 UE liveness；不得在
`FGS_ACTIVE` 前執行不可逆 application side effect。

## 10. Replay、搶先轉送與 DoS 邊界

完整複製／搶先轉送 M1 時：

- proof、ticket、FGS、context、authorization、time 與 UE KEM key仍綁定原 request；
- attacker 沒有 UE ephemeral secret，不能取得 final session key；
- 同一 `request_digest`／`attempt_id` 只能取得原先持久化的同一 M2；
- 不同 attempt 或跨 context／FGS／epoch request 必須拒絕；
- 全 federation 仍只能有一個 successful consumption／session identity。

但是，兩訊息 final-grant profile 無法阻止 attacker 把 holder 已產生的 M1 提早送達並
觸發 `CONSUMED_PENDING_CONFIRM`。Exact retry 可讓 UE 取回 M2，卻不能保證 active
attacker／jamming 下的 availability。若部署要求「client confirmation 前不得永久
消耗」，必須另建 provisional-grant profile：M2 不能稱為 final `AccessAccept`，並在
M3 才 commit consumption。該 profile 不屬於本 v0.2 選定語意。

移除 challenge 也移除 v0.1 cookie 可提供的 return-routability／cheap DoS gate。FGS
必須依序先做 size／version／epoch／target checks、duplicate cache、rate limiting 與
resource admission，再執行昂貴 proof／signature operations；這些只能減緩 resource
exhaustion，不能形成無條件 liveness theorem。

## 11. Latency 與 distributed store

v0.2 將 UE–FGS access authorization 從四訊息縮成兩訊息，但 authoritative
`Reserve + durable CommitGrant` 仍在 M1 與 M2 之間的關鍵路徑：

```text
UE-visible result latency ~= one UE-FGS RTT
                         + FGS verification
                         + authoritative store transaction
                         + FGS KEM/authentication
```

同一 acceptance domain 有多個 FGS 時，無法在未取得 linearizable decision 前安全送出
final accept。若要把 ground backhaul 移出關鍵路徑，必須把 ticket acceptance authority
預先分片／綁定到單一 authoritative FGS domain；這會改變 handover、availability、
privacy 與 ticket semantics，須用新 profile 分析。

## 12. Security requirements and open proof obligations

至少需要：

- PQ access-NIZK completeness、zero knowledge、knowledge soundness；若 reduction
  需要模擬其他 proofs 後抽取新 forgery，則需要 simulation extractability；
- `Core.VerifyTicket` 與 `R_access` 的 composition lemma；
- FGS authentication unforgeability及 key authorization／rotation security；
- PQ KEM active security、KDF key separation、server／client key confirmation；
- session-key freshness、known-key security，以及 long-term／ephemeral reveals 後的
  forward-secrecy範圍；
- exact replay、parallel replay、cross-version replay、context substitution 與 downgrade
  games；
- ticket burn、proof-verification amplification、jamming 與 store partition 的
  availability boundary；
- access proof／ticket／routing metadata 的 linkability analysis。

NIST SP 800-227 §4.4 提供 ephemeral KEM key、ciphertext與 MAC-based key
confirmation 的基礎模型；RFC 8446 §4.4.4／§8 說明 peer Finished 與一致 anti-replay
state 的不同責任；RFC 9180 §8.1／§9.1 說明 context binding 與 unauthenticated base
KEM mode 的限制。這些標準只作設計依據，不等於本 composition 已被證明。

## 13. Implementation gate

依序完成：

1. FrameV2、三個 object codecs 與 canonical digest vectors；
2. `R_access` direct evaluator與 mutation tests；
3. abstract NIZK／KEM／FGS-auth／KDF／MAC interfaces；
4. test-only adapters，且不得跨 production gate；
5. v0.2 replay-state reference model、exact retry、parallel race及 activation tests；
6. cross-version shared `use_key` tests；
7. crash／wallet recovery與 distributed-store model；
8. concrete PQ suite selection、security review及 cross-language vectors；
9. message bytes、prove／verify、store backhaul與 end-to-end latency benchmark。

只有第 1–6 項完成也只能宣稱 bounded reference implementation／tests，不得宣稱
production PQ AKE、proof closure或 production closure。

### 13.1 2026-09-14 bounded implementation checkpoint

目前已完成第1、2、3、5、6項的process-local reference範圍：

- `src/pq_sat_auth/v2/framing.py`：V2 frame／opaque canonical codec；
- `src/pq_sat_auth/v2/access.py`：三個objects、core／full encodings、digests與跨訊息
  binding；
- `src/pq_sat_auth/v2/proof.py`：verifier-owned statement codec與`R_access` direct
  evaluator；
- `src/pq_sat_auth/v2/backends.py`：abstract crypto contracts與test-only suite的
  production拒絕邊界；
- `src/pq_sat_auth/v2/replay.py`：process-local reservation、durable-commit語意模型、
  pending／active／expired、exact retry與race handling。

定向39項與repository-wide 727項tests已通過；後者含12項既有optional skips。這個
checkpoint沒有實作第4項的cryptographic test adapter，也沒有實作FGS完整processing
pipeline、ticket verifier integration、實際NIZK／KEM／FGS-auth／KDF／MAC、wallet、
crash persistence或distributed store。`production_ready`維持false。

### 13.2 FGS pure-check processor checkpoint

後續checkpoint已新增`src/pq_sat_auth/v2/processor.py`，依§6順序完成strict parse、
authenticated configuration provider、single-sample trusted time、freshness／nonce、
channel exporter、stable `VerifyTicket`、`TicketUseIdentity(ctx,sn,d_M)`、query-bound
revocation snapshot、`pi_access`、UE KEM public-key validation及pure admission。成功只
回傳`ValidatedAccessRequestV2`，不呼叫`Reserve`或建立session／M2。

其中`SystemAccessTicketVerifierV2`已接上versioned PQ-RBBC `verify_ticket()` contract，
但issuer authentication仍是abstract backend。System Initialization v0.1尚未包含FGS
authentication key／access suite extension，所以authenticated access configuration仍是
明確provider boundary；test adapters不構成production cryptography。Exact處理順序、
測試及claim boundary見
`docs/artifacts/SATELLITE_ACCESS_v0_2_FGS_PURE_CHECK_PROCESSOR_zh-TW.md`與
`manifests/pq_sat_auth_fgs_pure_check_v0_2.json`。

### 13.3 FGS grant processor checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/grant.py`，把pure-check output接到`Reserve`、
KEM encapsulation、session ID、transcript、KDF、FGS authentication、server Finished、
pre-commit revocation recheck、response／session-state protection及`CommitGrant`。只有
commit成功才回傳exact `AccessAcceptV2`；same-attempt retry回復並重新驗證原M2，不重做
KEM或建立第二個session。

Authenticated configuration snapshot新增pure-check age、reservation lease、activation
window、session lifetime及retention grace policy；stable ticket adapter輸出authenticated
ticket expiry。Reference pre-commit revocation check與process-local commit尚非同一原子
ordering；crypto／sealing backends仍為test-only，activation processor亦未完成。完整
設計、failure semantics及claim boundary見
`docs/artifacts/SATELLITE_ACCESS_v0_2_FGS_GRANT_PROCESSOR_zh-TW.md`與
`manifests/pq_sat_auth_fgs_grant_v0_2.json`。

### 13.4 FGS activation processor checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/activation.py`。FGS先以全域唯一`session_id`
查找committed grant，recover並重新驗證exact `AccessAcceptV2`及sealed pending session
state，再檢查activation binding、deadline／session expiry、query-bound configuration／
FGS-key／ticket／session revocation，以及client Finished。只有process-local store完成
atomic `CONSUMED_PENDING_CONFIRM -> CONSUMED_ACTIVE`後，processor才回傳包含application
key與exporter key的內部capability；exact retry回傳同一active record與capability，平行
重送只有一個transition winner。

此capability不是application side effect本身，也不是network bearer token。於該checkpoint
第一個受保護application record仍未完成；後續§13.7已補上bounded record與delivery
capability，但side-effect exactly-once transaction、production session-state protection及
durable／distributed store仍未完成。Activation revocation snapshot與store
transition亦非同一authoritative transaction，存在明確TOCTOU邊界；concrete PQ AKE／
Finished suite仍待研究線選型與實例化。完整failure semantics、tests與claim boundary見
`docs/artifacts/SATELLITE_ACCESS_v0_2_FGS_ACTIVATION_PROCESSOR_zh-TW.md`及
`manifests/pq_sat_auth_fgs_activation_v0_2.json`。

### 13.5 UE AccessAccept processor checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/ue.py`。UE從protected attempt state載入exact M1、
authenticated configuration、request／attempt identities、ticket expiry及原始ephemeral
KEM secret，strictly parse M2後依§8順序執行：current configuration與response binding、
trusted time／policy期限、query-bound FGS verification key、FGS authentication、KEM
decapsulation、與FGS共用的canonical KDF context、server Finished，最後產生client
Finished及exact `SessionActivateV2`。

FGS authentication刻意先於KEM decapsulation，且任何backend只有明確boolean `True`才算
成功。成功輸出的application／exporter keys及activation bytes已與FGS activation
processor做bounded end-to-end測試。Processor本身不更新wallet；protected journal的
durability／rollback protection、production FGS-key distribution、concrete PQ KEM／
authentication／KDF／Finished suite、secure erasure及first protected application record
仍未完成。詳細設計與claim boundary見
`docs/artifacts/SATELLITE_ACCESS_v0_2_UE_ACCEPT_PROCESSOR_zh-TW.md`及
`manifests/pq_sat_auth_ue_accept_v0_2.json`。

### 13.6 UE durable wallet reference checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/wallet.py`與
`src/pq_sat_auth/v2/storage/sqlite_wallet.py`。UE必須在傳送M1前呼叫`Prepare`，將exact
request、authenticated configuration、request／attempt identities、ticket expiry及
ephemeral KEM secret形成canonical、versioned record，交由獨立record-protection backend
後才寫入SQLite。相同ticket的相同attempt為idempotent；不同attempt不得覆蓋原record。

M2通過既有UE processor後，wallet在單一`BEGIN IMMEDIATE` transaction內執行
`PREPARED -> ACCEPTED_PENDING_ACTIVATION`，保存exact M2、session identities／keys及
`SessionActivateV2`。Coordinator只有在commit回覆、read-back及exact output validation
全部成功後才釋放UE session；commit acknowledgment不確定或store output被改寫時不釋放，
exact retry則從已提交record恢復同一session，不重新處理M2。

SQLite profile固定application ID、schema version、WAL、`synchronous=FULL`、bounded
canonical JSON及以`(use_key,state,revision)`組成的protection AAD。測試涵蓋thread／process
race、restart、commit後突然process exit、corruption、schema／protection identity、lost
ack及deadline recovery。這只支持可信單機filesystem與SQLite假設下的reference durability；
test-only protection adapter不是production encryption。Rollback protection、hardware-backed
key、secure erasure、實體斷電／kernel crash／remount、distributed wallet及first protected
application record於該checkpoint仍未完成；其後續bounded實作見§13.7。詳細evidence與machine claims見
`docs/artifacts/SATELLITE_ACCESS_v0_2_UE_WALLET_SQLITE_zh-TW.md`及
`manifests/pq_sat_auth_ue_wallet_v0_2.json`。

### 13.7 First protected application record checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/application.py`與
`src/pq_sat_auth/v2/storage/sqlite_first_record.py`，實作§8.1的`0x0104`
`FirstApplicationRecordV2`、exact AAD／nonce context／record digest、UE sequence-zero
reservation及SQLite outbox。兩階段`RESERVED -> READY`先固定plaintext digest，避免同一
session在race時用相同sequence／nonce context保護不同plaintext；只有finalize commit與
read-back一致後才釋放wire bytes。Restart、parallel exact retry、competing plaintext、lost
ack、schema identity及corruption均有測試。

FGS透過activation processor的pure pre-activation check先驗證application protection，
成功後才執行既有atomic session activation；process-local delivery store對同一session只
釋放一次plaintext capability，exact retry不重複釋放，第二個authenticated sequence-zero
record拒絕。此ordering使corrupt ciphertext不會把pending session轉成active。

這在該checkpoint仍是test-only protection backend下的bounded reference，當時FGS
delivery state尚不durable；後續單機durable successor見§13.9。即使有successor，activation
與delivery claim仍不是同一transaction，external application side effect也不具crash-safe
exactly-once保證；concrete production AEAD、secure nonce mapping與實體斷電測試仍未完成。
原checkpoint的完整evidence與machine claims見
`docs/artifacts/SATELLITE_ACCESS_v0_2_FIRST_APPLICATION_RECORD_zh-TW.md`及
`manifests/pq_sat_auth_first_application_v0_2.json`。

### 13.8 FGS single-host durable replay store checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/storage/sqlite_replay.py`，將既有
`src/pq_sat_auth/v2/replay.py`的完整state contract接到單機SQLite：

```text
RESERVED
  -> CONSUMED_PENDING_CONFIRM
  -> CONSUMED_ACTIVE
  -> CONSUMED_EXPIRED
```

Store以`use_key`為primary identity，並對`(ctx,ticket_digest)`、`(ctx,serial)`與
`session_id`建立unique indexes。每一列保存canonical、versioned record，包含exact sealed
M2與sealed pending session state；整份record在進入SQLite前交給獨立protection backend，
AAD綁定use identity、state／revision及session identity。所有mutation使用
`BEGIN IMMEDIATE`、WAL及`synchronous=FULL`，資料庫建立後另執行parent-directory fsync。

測試把process-local store的完整transition suite重播到SQLite，另涵蓋thread／process
reservation、competing grant及activation races、restart、commit後突然process exit、
schema／application identity、row metadata／protected bytes mutation，以及實際FGS grant
processor在store restart後回復exact M2再完成activation。

這支持可信單一host與SQLite／filesystem假設下的cross-process serialization及restart
durability，不支持多FGS／多host linearizability。Test-only protector不是production record
protection；rollback、hostile filesystem、kernel crash／remount與實體斷電仍未驗證。
外部revocation snapshot與store transition也尚非同一authoritative transaction；本
checkpoint當時的FGS delivery claim尚未durable，後續單機successor見§13.9。詳細evidence與machine claims見
`docs/artifacts/SATELLITE_ACCESS_v0_2_FGS_REPLAY_SQLITE_zh-TW.md`及
`manifests/pq_sat_auth_fgs_replay_sqlite_v0_2.json`。

### 13.9 FGS single-host durable first-record delivery checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/storage/sqlite_delivery.py`。Store以`session_id`
作primary key，永久綁定唯一`record_digest`；第一次atomic insert回覆`NEW`，exact retry
回覆`EXISTING`，另一個已通過application authentication的sequence-zero record則拒絕。
只有`NEW` claim在commit成功後才可取得plaintext capability。

Store使用獨立application ID／schema、WAL、`synchronous=FULL`、`BEGIN IMMEDIATE`、
database mode `0600`及首次建立後parent-directory fsync。Domain-separated public checksum
可偵測bounded row corruption，但不是MAC，也不支持hostile-filesystem security。測試涵蓋
thread／process exact race、competing digests、restart、commit後突然process exit、schema／
row mutation、processor restart及lost claim acknowledgement。

此checkpoint把process-local claim提升為可信單一host下的durable at-most-once gate，沒有
讓activation與claim成為同一transaction，也沒有納入external application mutation。
因此claim後crash可能造成工作遺失，但retry不得重複釋放plaintext；distributed consistency、
rollback protection、實體斷電與exactly-once side effect仍未完成。完整evidence見
`docs/artifacts/SATELLITE_ACCESS_v0_2_FGS_DELIVERY_SQLITE_zh-TW.md`，machine claims收錄於
`manifests/pq_sat_auth_first_application_v0_2.json`。

### 13.10 FGS protected application inbox與idempotent dispatch checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/storage/sqlite_inbox.py`與
`src/pq_sat_auth/v2/dispatch.py`。推薦的FGS路徑不再於delivery claim後直接把plaintext交給
外部application，而是在同一enqueue transaction中保存受保護的work item：

```text
authenticated first record
  -> activate session
  -> inbox PENDING(session_id, record_digest, protected plaintext)
  -> application.apply_once(record_digest, plaintext) -> stable receipt
  -> inbox COMPLETED(receipt)
```

Inbox processor模式只回覆`QUEUED`／`ALREADY_QUEUED`／`ALREADY_COMPLETED` metadata，
不回傳`FirstApplicationDeliveryV2` plaintext capability。獨立dispatcher可掃描pending
session IDs、驗證並開啟protected item，再要求application adapter以
`record_digest`作idempotency key。Application已commit但ack遺失時，retry必須取得同一
receipt而不得重做side effect；inbox completion ack遺失時，restart必須讀回`COMPLETED`。

這封閉了「delivery claim已commit但plaintext work item未持久化」窗口，並提供enqueue後
的自主restart recovery。不過activation與inbox仍是兩筆交易；activation後、enqueue前
crash仍依賴UE exact retry。外部application的`apply_once`是必要假設，repository只有
test-only SQLite ledger驗證composition，沒有production application adapter或跨服務
distributed transaction。因此external side effect exactly-once仍為false。詳細evidence見
`docs/artifacts/SATELLITE_ACCESS_v0_2_APPLICATION_INBOX_zh-TW.md`，machine claims收錄於
`manifests/pq_sat_auth_first_application_v0_2.json`。

### 13.11 FGS unified activation-inbox transaction checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/storage/sqlite_unified.py`及activation processor的
composed commit hook。Unified store延用replay與inbox的canonical protected records，但以
新的application ID及一個包含兩張表的exact schema建立單一SQLite database。對已完整驗證
的第一筆record，唯一commit順序為：

```text
BEGIN IMMEDIATE
  validate exact CONSUMED_PENDING_CONFIRM grant
  update replay row -> CONSUMED_ACTIVE
  insert inbox row -> PENDING(record_digest, protected plaintext)
COMMIT
```

任一步驟在commit前失敗都rollback兩者；exact retry只能讀回同一active grant與同一
pending／completed inbox identity。Store不使用`ATTACH`，也拒絕透過獨立
`activate_session()`繞過composition。測試涵蓋inbox sealing failure rollback、restart、
跨process exact race、competing authenticated first record、dispatch completion，以及
已接受work item在session之後逾期仍可完成。

這只封閉可信單機SQLite／filesystem假設下的activation-inbox gap。Activation前取得的
revocation snapshot仍未與authoritative state transition放入同一transaction；production
record／plaintext protection、實體斷電、rollback／hostile filesystem、distributed FGS及
production application `apply_once`仍未封閉，external side effect exactly-once仍為false。
詳細evidence見
`docs/artifacts/SATELLITE_ACCESS_v0_2_UNIFIED_ACTIVATION_INBOX_zh-TW.md`，machine claims見
`manifests/pq_sat_auth_fgs_unified_activation_inbox_sqlite_v0_2.json`。

### 13.12 FGS authoritative activation-revocation fence checkpoint

後續checkpoint新增`src/pq_sat_auth/v2/storage/sqlite_authoritative.py`，以新的application
ID及三表exact schema繼承unified profile。Activation processor也把它實際檢查的
`ActivationRevocationQueryV2`與exact `ActivationRevocationSnapshotV2`帶入composed
commit request。建議單機reference的完整順序變成：

```text
read exact local revocation snapshot
BEGIN IMMEDIATE
  re-read and match the exact authoritative fence
  validate grant/query/time/generation/non-revoked bindings
  update replay row -> CONSUMED_ACTIVE
  insert inbox row -> PENDING(record_digest, protected plaintext)
COMMIT
```

`publish_activation_revocation()`與activation都由同一database的`BEGIN IMMEDIATE`
序列化。因此publish先commit時，持有舊snapshot的activation會rollback；activation先commit
時，該筆已接受的inbox work可依既有dispatcher完成。Publication採per-query digest的單調
generation與sticky revocation flags，exact retry不增加revision。

這只封閉可信單機SQLite中的**exact per-query fence publication vs activation**順序。
Repository尚未提供具生產身分驗證的revocation writer，也未把configuration／FGS key／
ticket等general-scope事件fan out到全部session query rows；跨FGS distributed state、
production record／plaintext protection、外部application side effect、hostile filesystem及
實體斷電仍未封閉。因此本checkpoint仍非Production-closed或Proof-closed。詳細evidence見
`docs/artifacts/SATELLITE_ACCESS_v0_2_AUTHORITATIVE_ACTIVATION_REVOCATION_zh-TW.md`，
machine claims見
`manifests/pq_sat_auth_fgs_authoritative_activation_inbox_sqlite_v0_2.json`。

### 13.13 FGS authenticated scoped-revocation ingestion checkpoint

本checkpoint新增`src/pq_sat_auth/v2/storage/sqlite_scoped_revocation.py`，把authenticated
revocation command、registered activation query、materialized fence、replay grant及protected
inbox放入同一單機SQLite database。網路或不可信caller不能直接提交fence；唯一公開管理
入口必須先驗證system-initialization envelope及revocation command authentication。

Canonical command固定以下欄位：

```text
access_protocol_version, ctx, system_bundle_digest, epoch, policy_digest,
signer_key_id, scope, scope_target, generation,
issued_at, authorization_expires_at, command_id, reason_digest
```

Authentication message另綁定versioned domain與`signing_role`。本reference暫時使用既有
system-initialization bundle的`FEDERATION_CONFIGURATION` key作control-plane authority，
並要求caller明確提供同一out-of-band trust anchor。這是避免改動既有bundle ABI的暫時
選擇，不表示production應讓configuration與revocation共用同一私鑰。Concrete PQ
authentication與獨立revocation key role仍待新版initialization ceremony決定。

Scope與exact query欄位的對應固定為：

| Scope | `scope_target`匹配欄位 | Materialized flag |
| --- | --- | --- |
| `ACCESS_CONFIGURATION` | `system_config_digest` | `configuration_revoked` |
| `FGS_AUTHENTICATION_KEY` | `fgs_auth_key_id` | `fgs_key_revoked` |
| `TICKET_USE` | `ticket_use_key` | `ticket_revoked` |
| `SESSION` | `session_id` | `session_revoked` |

Ingestion在一個`BEGIN IMMEDIATE`內保存append-only command，並把它fan out至所有已登錄且
匹配的query fences；之後才登錄的query會重播該`ctx`的歷史commands。Activation與command
ingestion使用同一database write order，所以只能出現「activation先commit」或「revocation
先commit」之一。Command exact replay為idempotent；同一`command_id`改寫、generation不遞增、
第一筆後的bundle／authority key變更、無效時窗或驗證backend錯誤都fail closed。已接受的
revocation為sticky；command authorization expiry只限制何時可ingest，不會自動解除撤銷。

這個successor仍是O(registered queries) ingestion及O(commands in ctx) late-registration replay，
尚未做規模benchmark。Authority rotation／unrevocation、獨立revocation key ceremony、concrete
PQ verifier、多host replication／consensus、rollback／hostile-filesystem防護、實體斷電及
production record／plaintext protection均未完成。Query registration亦是可信FGS內部composition
邊界，不是可直接暴露的網路API。因此只能宣稱bounded single-host authenticated-ingestion
與general-scope fanout已Implemented／Tested，不能宣稱production revocation完成。詳細evidence見
`docs/artifacts/SATELLITE_ACCESS_v0_2_AUTHENTICATED_SCOPED_REVOCATION_zh-TW.md`，machine claims見
`manifests/pq_sat_auth_fgs_scoped_revocation_sqlite_v0_2.json`。
