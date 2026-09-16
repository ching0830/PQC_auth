# `R_access` 50,000-byte發行／存取分工研究：D1–D2 v0.1

日期：2026-09-16

研究分支：`codex/r-access-50k-d1-d3`

基準 commit：`51602fee718f26d30ff025cf50ab88938890fe7a`

## 1. 結論

現行 exact SHAKE-based `R_access` 的 2,151,727-byte proof 無法接近
50,000-byte完整握手目標。可行的研究方向是建立**新版本**：發行時以
`R_issue,new`認證一把每票獨立的holder public key，存取時使用該key對當次
`HolderAuthCore`簽章。這不是舊`R_access`的壓縮或同義替換。

在下列尚未實測的條件成立時，兩個候選都有明顯通訊空間：

- PQ-RBBC fork最終issuer signature仍為11,644 bytes；
- 新ticket payload採本文件的48-byte `q` layout；
- FGS authentication採ML-DSA-65，AKE採ML-KEM-768，Finished各48 bytes；
- FGS verification key已由authenticated configuration預先配置；
- 不把certificate chain、link-layer overhead或重傳算成0，而是標成未知並另計。

依現行codec精確framing公式，使用explicit `SessionActivateV2`時：

| Holder profile | 條件式完整ticket | M1 | M2 | M3 | 條件式完整握手 | 距50,000 bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ML-DSA-65 | 12,126 | 18,897 | 4,755 | 198 | 23,850 | 26,150 |
| FAEST-192s v3 | 12,126 | 23,094 | 4,755 | 198 | 28,047 | 21,953 |

這些是**條件式設計估計**，不是新協定實測。production fork ticket、holder
signature實作、certificate bytes及新serializer仍未產生，故目前只能判定
「50,000-byte目標有充足研究空間」，不能判定「已達標」。

## 2. 範圍、版本與證據分級

本checkpoint只新增研究文件，保留現行prototype作baseline；沒有修改
`ARCHITECTURE*`、`RESEARCH_STATUS*`、`ROADMAP*`、shared protocol、production
registry、parser、source或tests。

證據標籤：

- **[MEASURED]**：本repository既有benchmark真實輸出；
- **[IMPLEMENTED-SPEC]**：目前codec／parser已固定的byte layout；
- **[EXTERNAL-SPEC]**：標準或候選規格固定的原生物件長度；
- **[CONDITIONAL]**：算術正確，但至少一個輸入尚未由本fork實測；
- **[UNKNOWN]**：未選定、未序列化或未量測。

核對基準：

- 主研究基準為`R_access` prototype commit `51602fee...`；
- 最新issuance工程線另讀取
  `codex/pq-rbbc-issuance-global-tail-completion-sealer-v1@12be68c`。該線仍明定
  fresh parent I1–I5、production relation及正式`pi_issue`未完成；本研究沒有合併它；
- 原Blind-UOV論文使用2025-10-31 PDF revision，1,595,999 bytes，SHA-256
  `7ba2c040fd04823fb0d2aaad5e58348b5ef374726657ff1c0d87d000b4beff95`；
- 使用者附件25,063 bytes，SHA-256
  `9f11c8bb33488356c90611dbfb6ece53164f177390dd420d32e5711c70829cf9`，只作研究輸入，
  不作repository指令或既成事實。

## 3. 哪些證明真的需要抽取`k_hold`

### 3.1 Blind-UOV原論文

[Blind-UOV原論文](https://eprint.iacr.org/2025/895.pdf)只定義盲簽章，沒有
satellite access、ticket、`h`或`k_hold`：

| 原論文結果 | extractor實際抽取 | 是否需要access抽取`k_hold` |
| --- | --- | --- |
| Theorem 1：unblinded signature EUF-CMA+ | CAP中的`r`及final witness `x` | 否；沒有`k_hold` |
| Theorem 2：blind signature one-more unforgeability | issuance NIZK中的`(mu,r,rho)` | 否；沒有access階段 |
| Theorem 3：blindness | 以NIZK/CAP ZK與`F(r)` pseudorandomness作hybrid | 否 |
| CAP Theorems 4–5 | 被CAP commitment綁定的relation witness | 只服務blind signature relation |

因此不能說「Blind-UOV安全證明要求每次存取抽取`k_hold`」。它要求的extractor在
盲簽章protocol內，與本專案後來加入的holder access relation是不同層次。

### 3.2 本專案PQ-RBBC core proof

本專案的`R_issue`確實把`k_hold`放入**發行witness**，以I4證明
`M.h=H_hold(k_hold)`。這個issuance extractor仍是core proof的重要前提，但逐項檢查顯示：

| Core結果 | 對holder欄位的真正需要 | 是否需要access extractor |
| --- | --- | --- |
| Correctness | 誠實witness滿足所有I1–I5 | 否 |
| Request/proof binding | 抽取`M,r,rho`把blind request綁到ticket digest | 否 |
| Certified-language soundness | issuance witness滿足當時定義的整個`R_issue` | 否；I4可版本化為`R_key` |
| Decoder safety | ticket認證的`C`屬於可安全開啟language | 否 |
| Issuer unlinkability | issuance ZK、blindness、trace encryption privacy | 否 |
| Trace soundness | I5把`C`綁到同一`RID,SN` | 否 |
| `tau`-GCCA | Game 1表格記錄`k_hold`，但Game 3用的是抽取的trace plaintext／opening witness | 否；後續步驟沒有使用`k_hold` |
| Ticket one-more unforgeability | completed issuance與distinct ticket digest計數 | 否 |

精確結論是：**core proof需要從issuance proof抽取一份滿足holder-binding conjunct的
witness；它不要求從access transcript抽取原本的32-byte `k_hold`。** 若I4改成
`R_key(pk_H; omega_H)`且I5改綁新holder descriptor，core reduction必須按新relation重證，
但不需要額外發明access `k_hold` extractor。

### 3.3 End-to-end access game

目前`G-ACCESS-AUTH`仍是open game。它要求honest FGS接受時存在唯一partnered UE，且UE
持有相應ticket／holder state；文字沒有固定該state必須由knowledge extractor輸出。
因此可以把holder責任改寫為：

> 對誠實ticket中的每票holder public key，除holder授權或signature scheme遭偽造外，
> adversary不能使honest FGS對新的`HolderAuthCore`接受。

這足以支援「防止只複製ticket便建立新request」的目標，但不提供下列性質：

- 從任意accepting transcript恢復原`k_hold`；
- 一般signature等同SE-NIZK；
- deniability或不可轉讓性；
- malicious issuer non-frameability；
- access unlinkability或完整AKE安全。

## 4. D1：新experimental relation delta

以下只定義`experimental/access-holder-auth/v3`候選，不配置production suite ID。

### 4.1 Holder descriptor與ticket payload

固定canonical descriptor：

```text
D_H = (
    holder_suite_id_u16,
    holder_pp_digest[32],
    q[QLEN]
)

q = SHAKE256(
    "PQ-SAT/HOLDER-PUBLIC-KEY-BIND/v3"
    || Encode(holder_suite_id, holder_pp_digest, pk_H),
    8 * QLEN
)
```

`Encode`必須對每個variable field作唯一length separation。`QLEN=48`是本checkpoint的
主帳目，因384-bit輸出提供至多192-bit generic collision bound；`QLEN=64`保留為敏感度
分析，只增加16 bytes。整個系統仍有32-byte`H_ticket`等較低collision ceiling，故兩者都
不能單獨支持Category-3端到端claim。

候選payload：

```text
M_new =
    ticket_profile_version_u16
 || ctx[32]
 || sn[16]
 || holder_suite_id_u16
 || holder_pp_digest[32]
 || q[48]
 || syndrome[208]
 || masked_identity[48]
 || trace_tag[32]
```

故`|M_new|=420` bytes；`QLEN=64`時為436 bytes。這是候選layout，不是現行
`CanonicalTicket`可解析的格式。

trace associated data同步改為：

```text
trace_ad_new = Encode(
    ticket_profile_version,
    ctx,
    sn,
    holder_suite_id,
    holder_pp_digest,
    q
)
```

追蹤plaintext仍為`RID || SN`，syndrome／masked identity／trace tag長度不變。舊
`h[32]`被descriptor取代；trace ciphertext中的32-byte KMAC tag**不刪除**，只是KDF／MAC
輸入必須重版並綁定`trace_ad_new`。

### 4.2 `R_issue,new`

```text
x_iss = (pp_new, ctx, SID_iss, RID, beta)
w_iss = (M_new, r, rho, e, pk_H, omega_H)
```

`R_issue,new(x_iss;w_iss)=1` iff：

```text
I1' TicketShapeNew(M_new, ctx, authorized holder suite/parameters) = 1
I2' m = H_ticket,new(Encode(M_new))
I3' c_r = CAP.Commit(r; rho)
    beta = r + H_RBBC,new(m, c_r)
I4' q = H_bind(Encode(holder_suite_id, holder_pp_digest, pk_H))
    R_key(holder_suite_id, holder_pp_digest, pk_H; omega_H) = 1
I5' R_enc(tpk, M_new.C, trace_ad_new; RID || M_new.sn, e) = 1
```

I2／I3的digest寬度可以保持blind-request ABI固定，但payload與hash domain改版後，fork的
blindness、one-more、cross-message binding及final signature size都要重新驗證；不能因
input最後仍壓成32-byte digest而宣稱proof自動繼承。

### 4.3 ML-DSA-65 `R_key`

最強、最清楚但電路最昂貴的候選是exact seed relation：

```text
omega_H = (xi[32], bounded_keygen_trace)
(pk_H, sk_H) = ML-DSA-65.KeyGen_internal(xi)
EncodePublicKey(pk_H) is the exact 1,952-byte FIPS 204 encoding
```

FIPS 204允許以32-byte seed重新產生key pair，但內部sampling有rejection behavior；
issuance circuit必須固定最大trace、counter encoding、超限拒絕及canonical decoding。
ZK無法證明外部RBG真的uniform，只能證明給定seed依指定演算法導出該key。

若先做較小的`R_key,consistency`，可改驗canonical secret/public key解碼、`tr=H(pk)`、
`t=A*s1+s2`與Power2Round consistency；它證明key一致，不證明KeyGen分布，security game
必須明示這個較弱合約。本checkpoint不把兩者混稱。

Holder authentication使用FIPS 204原生API：

```text
sigma_H = ML-DSA.Sign(sk_H, Encode(HolderAuthCore), ctx_H)
ctx_H = "PQ-SAT-HOLDER-AUTH-V3"
```

public key 1,952 bytes、signature 3,309 bytes，為FIPS 204規格值，不是本機實測。

### 4.4 FAEST-192s v3 `R_key`

依FAEST v3 exact key domain：

```text
omega_H = (k[192], x[128])
require not (k[0] and k[1])
y = AES192_k(x) || AES192_k(x xor LE128(1))
pk_H = x || y                         # 48 bytes
sk_H encoding = x || k                # 40 bytes
```

這個`R_key`與FAEST原生OWF相同，避免在issuance relation內驗整份FAEST signature。
FAEST-192s v3 signature為9,410 bytes。FAEST在2026-09仍是NIST additional signatures
Round-3 candidate，不是FIPS標準；其規格提供EUF-CMA／QROM分析，但不自動提供本專案的
access composition或SE-NIZK定理。

### 4.5 `HolderAuthCore`與訊息流程

新M1先canonical encode下列內容，認證資料本身不在被簽核心中：

```text
HolderAuthCore = (
    protocol_version,
    access_suite_id,
    holder_suite_id,
    system_config_digest,
    exact canonical ticket bytes,
    ctx,
    epoch,
    target_fgs_id,
    fgs_auth_key_id,
    serving_context_digest,
    authorization_digest,
    client_time,
    ue_nonce,
    attempt_nonce,
    channel_binding_mode,
    channel_binding_digest,
    ue_kem_epk,
    pk_H
)
```

FGS執行：

```text
VerifyTicketNew(T_new)
recompute q from (suite, pp digest, pk_H)
compare q with authenticated M_new descriptor
HolderSig.Verify(pk_H, Encode(HolderAuthCore), sigma_H)
```

建議訊息序列保持v0.2 latency-first topology：

```text
M1 UE -> FGS:
   T_new, pk_H, sigma_H, UE ML-KEM-768 epk, context/freshness fields

M2 FGS -> UE:
   ML-KEM-768 ciphertext, FGS ML-DSA-65 authentication,
   server Finished, durable final grant

M3 UE -> FGS:
   client Finished as explicit SessionActivateV2,
   or embedded in first protected application record
```

UE在M2後一個RTT取得並驗證結果；FGS只在M3／首筆protected record後進入`ACTIVE`。
holder signature在M1尚不能綁定未產生的M2 ciphertext，因此M2 authentication、KDF及雙向
Finished仍須綁定M1與M2。

新profile應由`HolderAuthCore`導出stable logical attempt identity，而不是把隨機化
signature bytes當成唯一attempt。否則同一core重簽或signature malleability會製造不同
`request_digest`；若仍以完整wire bytes作attempt identity，就需要strong unforgeability或
額外state rule。Bitwise retry仍應恢復exact已提交M2。

### 4.6 舊欄位的精確差異

| 舊v0.2 | 新候選 | 結果 |
| --- | --- | --- |
| `h=H_hold(k_hold)` | `D_H=(suite,pp_digest,q)` | 改ticket schema與I4 |
| access witness `k_hold[32]` | ML-DSA seed/key或FAEST OWF key | 不再是舊relation |
| `holder_binding_tag[32]` | `holder_authenticator=signature` | 舊tag刪除 |
| `access_nizk` | `pk_H`及原生holder signature | 不得沿用舊proof suite ID |
| trace AD `Encode(ctx,sn,h)` | `trace_ad_new` | I5及trace vectors重版 |
| `request_digest`含舊proof | 新canonical request | retry／attempt identity需重定義 |
| access SE-NIZK假設 | holder signature UF假設 | issuance SE-AoK仍保留 |

## 5. D2：完整byte帳目

### 5.1 現行exact baseline

| 項目 | Bytes／結果 | 證據 |
| --- | ---: | --- |
| exact `R_access` statement | 170 | [MEASURED] |
| exact proof | 2,151,727 | [MEASURED] |
| Boolean AND gates | 76,800 | [MEASURED] |
| UE prover workload proxy median | 605.938 ms | [MEASURED，host-specific] |
| FGS verify workload proxy median | 337.857 ms | [MEASURED，host-specific] |
| M1 | `T_current + 2,153,265` | [MEASURED proof + IMPLEMENTED-SPEC framing] |
| production `T_current` | unknown | [UNKNOWN] |

因此現行baseline即使不計ticket、M2與M3，也已超出50,000 bytes約43倍。

### 5.2 現行codec的精確固定開銷

由`src/pq_sat_auth/v2/access.py`與`framing.py`直接取得：

```text
FrameV2 header                  16
Opaque length prefix            4
AccessRequestV2 fixed prefix   294
AccessAcceptV2 fixed prefix    282
SessionActivateV2 prefix       130
FirstApplicationRecord prefix  138
```

候選新M1有ticket、UE KEM epk、holder pk及holder signature四個`Opaque`欄位，故：

```text
|M1_new| = 16 + 294 + 4*4 + T + 1184 + PK_H + SIG_H
         = T + 1510 + PK_H + SIG_H
```

與附件保守的`T+1538+PK_H+SIG_H`不同；差28 bytes來自刪除32-byte舊tag，再多加一個
4-byte `Opaque` length。這只是候選新serializer公式，現行parser尚未實作它。

AKE／FGS authentication候選：

```text
|M2| = 16 + 282 + 3*4 + 1088 + 3309 + 48 = 4,755
|M3| = 16 + 130 + 4 + 48                  =   198
```

若client Finished嵌入first protected record：

```text
|record_0| = 16 + 138 + 4 + |M3| + 4 + |AEAD ciphertext|
           = 360 + |AEAD ciphertext|
```

production AEAD尚未選定。[CONDITIONAL]若只為尺寸敏感度假設16-byte tag且至少1-byte
application plaintext，則`record_0=377` bytes；application payload本身必須另外列出。

### 5.3 Ticket帳目

現行`CanonicalTicket` envelope在payload與signature以外精確為62 bytes：

```text
magic 16 + schema 2 + protocol 2 + role 2 + issuer key id 32
+ payload length 4 + signature length 4 = 62
```

因此舊12,012-byte數字是`368 + 11,644`的core-level provisional target，**不含**
62-byte transport envelope。若11,644-byte fork signature成立，現行canonical transport
ticket會是12,074 bytes。

新候選：

| `q` | Candidate payload | Ticket公式 | 採11,644-byte issuer signature時 |
| --- | ---: | ---: | ---: |
| 48 bytes | 420 | `482 + SIG_I` | 12,126 |
| 64 bytes | 436 | `498 + SIG_I` | 12,142 |

`SIG_I=11,644`仍只是Blind-UOV論文數值對fork的provisional target；沒有新的final
signature bytes，因此最後一欄全是[CONDITIONAL]。

### 5.4 Holder與AKE原生物件

| 物件 | Bytes | 分類 | 是否在每次握手 |
| --- | ---: | --- | --- |
| ML-DSA-65 holder pk | 1,952 | [EXTERNAL-SPEC] FIPS 204 | M1 |
| ML-DSA-65 holder signature | 3,309 | [EXTERNAL-SPEC] FIPS 204 | M1 |
| FAEST-192s v3 holder pk | 48 | [EXTERNAL-SPEC] | M1 |
| FAEST-192s v3 holder signature | 9,410 | [EXTERNAL-SPEC] | M1 |
| ML-KEM-768 UE epk | 1,184 | [EXTERNAL-SPEC] FIPS 203 | M1 |
| ML-KEM-768 ciphertext | 1,088 | [EXTERNAL-SPEC] FIPS 203 | M2 |
| FGS ML-DSA-65 signature | 3,309 | [EXTERNAL-SPEC] FIPS 204 | M2 |
| server Finished | 48 | [CONDITIONAL] HMAC-SHA384 profile | M2 |
| client Finished | 48 | [CONDITIONAL] HMAC-SHA384 profile | M3 |
| FGS ML-DSA-65 verification key | 1,952 | [EXTERNAL-SPEC] | 預先配置；first-contact另計 |
| certificate／configuration chain | unknown | [UNKNOWN] | 現行M1/M2不攜帶 |
| issuer verification key | paper約189.2 KB | [CONDITIONAL comparator] | 預先配置，不得塞入握手 |
| trace public key | anchor 1,044,992 | [CONDITIONAL parameter anchor] | 不在access wire |

### 5.5 50,000-byte gate

explicit M3時：

```text
ML-DSA total = T + 1510 + 5261 + 4755 + 198 = T + 11,724
FAEST total  = T + 1510 + 9458 + 4755 + 198 = T + 15,921
```

因此不依賴20 kB／10 kB預算的必要且充分條件是：

| Holder profile | 完整ticket上限 |
| --- | ---: |
| ML-DSA-65 | `T <= 38,276` |
| FAEST-192s v3 | `T <= 34,079` |

若額外在first-contact傳送raw FGS ML-DSA-65 public key，兩個上限各減1,952 bytes；若還
攜帶certificate chain，再減其實際serialized bytes。重傳、IP／transport／satellite
link-layer header及雙段路徑承載均未包含在50,000-byte application-layer gate。

### 5.6 選擇判斷

| 面向 | ML-DSA-65 | FAEST-192s v3 |
| --- | --- | --- |
| 完整holder bytes | 5,261 | 9,458 |
| 標準狀態 | FIPS 204 | NIST Round-3 candidate，未標準化 |
| `R_key` issuance成本 | exact keygen／lattice consistency預期較複雜 | AES-192 OWF relation直接且固定 |
| Access verify | 原生signature verify | 原生signature verify |
| 新假設 | module-lattice | AES／symmetric、ROM／QROM proof model |
| 通訊 | 較小 | 多4,197 bytes但仍有空間 |
| 建議角色 | D4主線與標準化基準 | D4對照與relation-friendly候選 |

故D4應先以ML-DSA-65取得可互通、可量測的完整wire baseline，再以FAEST-192s驗證
「較簡單issuance `R_key`是否值得多付4,197 bytes」。不能只按signature bytes決策；
issuance circuit成本、UE時間／能耗、標準成熟度與security composition同樣是門檻。

## 6. 來源

- [Blind-UOV／Blinding Post-Quantum Hash-and-Sign Signatures](https://eprint.iacr.org/2025/895.pdf)
- [FIPS 204：ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [FIPS 203：ML-KEM](https://doi.org/10.6028/NIST.FIPS.203)
- [NIST SP 800-227：KEM與key confirmation](https://doi.org/10.6028/NIST.SP.800-227)
- [FAEST v3 specification](https://faest.info/faest-spec-v3.0.pdf)
- [NIST Round-3 additional signatures status](https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures)

## 7. D1–D2 claim boundary

已完成：proof dependency核對、兩個具體`R_key`候選、`R_issue,new`、holder auth core、
trace delta、訊息位置、current-codec byte公式、完整M1／M2／M3帳目與50,000-byte條件。

未完成：新circuit、new ticket serializer、holder signatures、certificate encoding、完整
production ticket、UE／FGS benchmark、security reduction、shared integration、Proof-closed或
Production-closed。
