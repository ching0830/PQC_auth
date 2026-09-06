# Ticket lifecycle 文獻回顧與設計比較

> 文件性質：研究文獻與設計比較，不是 canonical architecture、protocol specification、implementation evidence 或 proof closure 宣告。
> 範圍：one-time anonymous credentials、bounded-use credentials、unlinkable presentation、offline credential batches、replay prevention 與 crash recovery。
> 專案基準：system profile v0.1 已選擇 short-lived、strictly one-use ticket；本文評估此選擇及替代方案，不改寫該決策。
> 最後核對：2026-08-30。

## 摘要結論

PQ-RBBC core 與 ticket lifecycle 必須分開論證。Core 的 issuer unlinkability、one-more ticket unforgeability、fresh serial、issuance-side `sid` replay control、opening-authorization replay control，以及 trace DEM 的 one-time privacy，皆不表示同一張 access ticket 只能被接受一次。現有 `VerifyTicket` 是 stateless，票券本身亦沒有 rerandomizable／zero-knowledge `Show`；重送同一 `T=(M,σ)` 會產生相同 canonical digest，因而可被 verifier 或觀察者連結。

就 system profile v0.1 而言，文獻支持保留「預發行一批短效、單次 ticket + FGS durable atomic consumption」作為最小且可審核的設計。它把衛星在線密碼成本維持在固定 ticket 驗證與 AKE，但代價是：UE batch storage、FGS consumption-state storage、跨 FGS 一致性延遲，以及 crash 後「已消耗但 UE 未收到回覆」造成的 availability 損失。

不建議把 bounded-use 或 unlinkable `Show` 描述成單純移除 consumption check：兩者都需要新的 presentation relation、security game、domain／counter semantics、encoding、proof backend、revocation model及 benchmark。若未來確實需要一張 credential 支撐多次 handover，優先研究「master credential 離線導出 unlinkable one-use presentations」或 PQ k-TAA，而不是重複出示目前固定 ticket。

## 1. 術語與安全性分層

### 1.1 三種「one-time」不可混稱

| 用語 | 精確意義 | 不保證什麼 |
| --- | --- | --- |
| one-time trace encryption／DEM | 同一加密 randomness／derived pad 不可重用；是 trace ciphertext privacy／integrity 的條件 | 不限制 `T` 被 verifier 接受幾次 |
| one-more unforgeability | 完成 `q` 次 issuance 後，攻擊者不能產生多於 `q` 個不同 verifying ticket digests | 不阻止已合法取得的同一 digest 被 replay |
| strictly one-use access ticket | 對某一 canonical ticket identity，系統至多完成一次成功的 access state transition | 不是 stateless signature verification 可單獨提供的性質 |

NIST SP 800-63B-4 將 replay resistance 定義為記錄舊 authentication message 後仍難以成功重放，並以 verifier nonce／challenge 提供 freshness；對 OTP 類型則明確要求有效期內只接受一次 [S8]。這也說明 freshness 與 credential consumption 是互補控制：fresh transcript 能阻止原封不動重播舊 AKE response，卻不能阻止持有者拿同一個仍有效 bearer ticket 回應新的 nonce。

### 1.2 RBBC core security

依既有 core proof，本文只把下列項目視為 core 層的條件式主張：

- ticket canonical payload 與 blind-signing request／issuance witness 的 binding；
- issuer unlinkability（要求 common metadata，且不涵蓋 timing／traffic analysis）；
- one-more ticket unforgeability；
- certified trace-ciphertext validity、unique opening、trace soundness 與 gated trace privacy；
- issuance `sid` 只控制 issuance replay／quota，且不進入 ticket；
- opening authorization 的 replay control 只控制 opening API。

上述主張不包含 satellite AKE、access replay、revocation distribution、handover、FGS replication、failure recovery 或 availability。尤其 `Core.VerifyTicket(T)=1` 對同一 `T` 可重複得到相同結果；這是正確的 stateless verification 行為，不是 core 缺陷。

### 1.3 System lifecycle security

Lifecycle 層另需定義並驗證：

- ticket identity：依既有 lifecycle draft 使用 payload digest `d_M = H_ticket(Encode(M))`，並與 visible `sn`、`ctx` 形成 domain-separated `use_key`；signature bytes 不另立可消耗身份；
- expiry、epoch、policy、serving context 與 revocation 的判定時點；
- 同一 ticket 的並行、重送、跨 FGS／跨 context 請求如何序列化；
- 驗證失敗、AKE 失敗、timeout、process crash、storage crash、network partition 的 state transition；
- consumption record 的 durability、replication、retention 與 garbage collection；
- UE 不確定前次結果時，重試是取得同一結果，還是無條件拒絕；
- crash recovery 不得把已完成的成功 transition rollback 成可再次使用。

## 2. 正式文獻中的三個 credential 家族

### 2.1 Strictly one-use／one-show

Chaum 的 blind-signature 工作奠定「issuer 不看見最終 token」的基礎 [S1]；Chaum–Fiat–Naor 的 offline e-cash 顯示另一個關鍵界線：離線接受時通常不能即時阻止 double spend，只能在後續存款／對帳時偵測並揭露重複花費者 [S2]。因此 one-show credential 可以有兩種完全不同的 operational semantics：

1. **online prevention**：verifier 查詢共享 spent set，第一個成功者被接受，後續拒絕；
2. **offline detection**：多個 disconnected verifier 可能都先接受，之後才偵測或追責。

System profile v0.1 要求「最多成功建立一個 access session」，屬於第一種。若 FGS 在 partition 中各自接受，語意就已降級成第二種，不能仍稱 strictly one-use。

預先發行多張彼此獨立的 one-use token 是典型 wallet／coupon 思路。Compact e-cash 更進一步讓一次 withdrawal 產生大量可 unlinkably 花費的 coins，壓縮 wallet 與 withdrawal 成本 [S6]。它證明「batch issuance 可攤銷成本」是合理研究方向，但其 pairing／Strong-RSA 假設、double-spend tracing 與 PQ-RBBC 的 trace/opening governance 不同，不能直接當作本專案的 PQ construction。

### 2.2 Bounded-use（k-times anonymous authentication）

Teranishi–Furukawa–Sako 定義 k-TAA：註冊使用者在上限內匿名驗證；超過允許次數時，可由 authentication records 公開追查濫用者 [S4]。Nguyen–Safavi-Naini 的 dynamic k-TAA 再加入 application provider 的 grant、revoke、expiry 控制 [S5]。此家族把「同一 enrollment 至多 k 次」放進密碼協定與 presentation tags，而非只在 verifier 資料庫替固定 credential 計數。

這種設計的優點是 holder 不必儲存 k 張完整 ticket，正常的前 k 次 presentation 可不可連結；代價是新的公開 tag／domain／counter 結構、超額使用的 detectability 或 tracing semantics、較複雜 proof，以及 application-provider scope。早期具體方案依賴 bilinear pairing、Strong Diffie–Hellman 或 DBDH，因此只能作功能模型與比較基準，不能作 PQ 實例。

對衛星情境還要特別區分：

- **prevent-after-k** 需要 verifier 間及時共享已見 tag／counter state；
- **detect-after-k** 可容忍 disconnected acceptance，但可能已建立超額 sessions；
- k 是每 credential、每 epoch、每 provider、每 serving domain 或全 federation 的上限，會直接改變 linkability domain 與同步範圍。

### 2.3 Unlinkable multi-show／`Show`

Camenisch–Lysyanskaya anonymous credentials 明確提供同一 credential 任意多次、unlinkably demonstrate possession，且不必每次聯絡 issuer [S3]。這種 multi-show privacy 依賴每次 presentation 的 randomized proof／signature protocol；它不是「重送同一 signed object」。現代 anonymous-credential 定義也通常把 presentation unlinkability 視為核心安全性：觀察者不能判斷兩次有效 shows 是否來自同一 holder。

Unlinkable `Show` 最適合高頻 reauthentication／handover，因為 UE 不必維護大量完整 tickets，FGS 也不必保存每次固定 ticket digest。但它本身不提供 quota：若政策要求 one-use／k-use，仍須加入 domain-specific nullifier、rate-limited anonymous credential、k-TAA，或 online state。撤銷也較複雜，常需要 accumulator、epoch witness、short-lived credential 或 verifier-local revocation material。

對目前 PQ-RBBC，新增 `Show` 至少需要：

- 對 credential possession、policy、expiry、holder binding 與 trace ciphertext binding 的新 relation；
- presentation randomization／ZK 的 PQ security definition；
- malicious-holder、malicious-verifier、concurrent presentation 與 reset attack games；
- revocation、opening evidence、context binding 與 canonical transcript encoding；
- 衛星在線 proof size、verify time、memory 與 latency benchmark。

## 3. 設計比較

| 面向 | Strictly one-use ticket batch（v0.1） | Bounded-use credential（k-TAA 類） | Unlinkable multi-show credential |
| --- | --- | --- | --- |
| 正常使用 linkability | 不同 tickets 若 issuance 與 metadata 控制得當可 unlinkable；同一 ticket 的 retry 可連結 | 上限內可設計為 unlinkable；超額後依方案 detect／trace | 多次 Show 以 randomization／ZK 達成 unlinkability |
| quota 語意 | 每 ticket 1 次；batch 大小近似 quota | 密碼協定表達每 credential／domain 最多 k 次 | 原生通常無次數上限 |
| replay prevention | durable spent set + fresh access transcript | presentation tags/nullifiers + state；或事後超額偵測 | fresh transcript 防舊 proof replay；若需 quota仍要額外 state/nullifier |
| UE storage | O(B × ticket size) | 通常 O(credential + auxiliary state)，可小於 B 張 ticket | O(credential + revocation witness) |
| FGS storage | O(有效期內 consumed tickets)，可存 digest | O(已見 tags／nullifiers)，依 domain 與 k | 僅 nonce/session state；若 revocation/quota則另計 |
| 在線計算 | 現有 fixed ticket verification + AKE，最簡單 | 新 ZK／tag verification | 新 randomized ZK Show，通常最重 |
| disconnected FGS | 無共享 state 就不能保證 prevention | 可做 detect-after-k；嚴格 prevention 仍需協調 | authentication 可離線驗證；quota／fresh revocation另論 |
| crash ambiguity | 高：commit 後回覆前 crash 會損失一張 ticket | counter/tag commit 也有相同問題 | 無消耗時較低；session/AKE commit 仍可能不確定 |
| revocation | 短效期降低 stale window；可撤 epoch／key／serial | 需 dynamic membership／revocation 設計 | accumulator／epoch witness 或短效 renewal 常見 |
| 對目前 core 的改動 | 無 core theorem 擴張；新增 lifecycle protocol | 新 primitive、relation、games 與 proof | 新 Show protocol、games 與 proof |
| PQ readiness（本專案） | 可沿用 PQ-RBBC 的條件式 core，lifecycle 尚未實作／證明 | 傳統基準多非 PQ；候選需獨立審核 | 需選定合格 PQ ZK／credential backend |

結論不是 one-use 在所有面向都最佳，而是它對 v0.1 的**新增密碼假設最少、online format 最明確**。其複雜度被移到可靠狀態管理與預發行供應；這兩部分仍是 protocol work，不能以「使用資料庫」一句帶過。

## 4. Offline credential batches

### 4.1 Batch 的 privacy 條件

一批 ticket 只有在下列條件成立時，才能合理主張彼此不可由 issuer／observer 輕易關聯：

- 每張 ticket 使用獨立 fresh `sn`、holder-related randomness 與 trace-encryption randomness；
- blind issuance 對 batch/concurrent sessions 的 blindness 假設成立；
- `ctx`、policy、expiry bucket、key identifiers 與 wire length 對足夠大的 anonymity set 相同；
- batch index、issuance `sid`、UE identifier、個人化 expiry 或 quota marker 不進入可見 ticket；
- activation time、排序、路由與使用節奏不直接重現 issuance batch 的順序；
- UE 不因 crash restore 而回復已用 ticket 的本機狀態。

Core proof 已明示 timing、formatting 與個人化 metadata 位於 cryptographic game 之外。實務上，batch size 本身也可能成為 side information；應採少量 federation profiles／bucket，而不是每位 UE 不同的精確數量與 expiry。

### 4.2 Availability sizing

令有效期內預估 full initial access（包括 handover authorization 無法驗證時的 fallback）次數為 `N`，重試或不確定消耗的預留為 `R`，安全餘裕為 `S`，則 batch 下限可先以 `B ≥ N + R + S` 建模。這只是容量模型，不是安全公式；應由實測的 access rate、handover fallback rate、contact gap、issuance outage、clock skew、packet loss 與 crash ambiguity 分布估計。

短 expiry 減少 spent-state retention、stolen-ticket exposure 與 revocation lag，卻提高補發依賴與 batch exhaustion。長 expiry 提升 disconnected availability，但增加 UE/FGS storage、撤銷窗口與 traffic-correlation 時間。建議 benchmark 至少報告 `B`、每張 ticket bytes、UE wallet bytes、每 epoch spent-set entries、耗盡率及 p50/p95/p99 issuance gap。

### 4.3 有效窗口內保存 ticket identity 的可行性結論

在先不考慮跨 FGS／GS 驗證的單一 authoritative acceptance domain 中，保存仍可能被接受之 ticket identity，是達成 strictly one-use 的合理基線。Core 已定義 canonical payload digest：

```text
d_M = H_ticket(Encode(M))
```

FGS 必須先完成 ticket、expiry、context、revocation、holder possession 與 access transcript 驗證，再以 database unique constraint、linearizable compare-and-set 或等價 serializable transaction，原子執行 `check-and-insert(d_M)`；只有插入成功的 request 可以建立 initial session。普通的「先查詢、建立 session、最後寫入」存在並行 race，不能提供 one-use。

Consumption record 不必永久保存。其安全清除下限為：

```text
retention_deadline
  = ticket_expiry
  + maximum_clock_skew
  + maximum_in_flight_time
  + replay_grace
```

清除 spent record 後，FGS 仍須獨立拒絕 expired ticket；record 消失不得使舊 ticket 恢復有效。若 expiry 使用 federation-wide epoch／bucket，可在 grace window 結束後整批刪除對應 partition，降低逐筆 garbage collection 成本，且避免 per-user expiry 成為 issuer watermark。

最低限度只需保存固定長度 digest、serial、context／epoch、state 與 retention timestamp，不需保存完整 ticket、registered identity、holder secret、NIZK witness 或 session key。容量應以實測 record size `s_record`、成功 access rate `r` 與 retention window `W` 估算：

```text
records ≈ r × W
storage ≈ r × W × s_record × replication_factor
```

例如 `r = 1,000 access/s`、`W = 1 hour` 時共有 360 萬筆；32-byte digest 的理論下限約 115 MB，但加入 database row/index、recovery metadata 與 replication 後會更大。這只是容量規劃示例，不是本專案 benchmark。Bloom filter 可作前置加速，但 false positive 會拒絕尚未使用的合法 ticket；若不接受此 availability loss，authoritative decision 仍須使用 exact store。

因此，本階段的設計結論為：

```text
short-lived ticket
+ canonical d_M
+ validation-before-consumption
+ atomic check-and-insert
+ crash-safe session/consumption commit
+ expiry-bounded retention
= 單一 authoritative domain 內的 strictly one-use enforcement
```

此結論尚不涵蓋跨 FGS global one-use；多 verifier 情境仍需 shared linearizable state、single-writer sharding 或明確降級為 later double-spend detection。

### 4.4 UE wallet 的原子狀態

UE 至少需要 `unused → reserved → outcome-known` 的 crash-safe local journal。`reserved` ticket 不應因 app restart 自動回到 `unused`；否則 FGS 可能已成功消耗它。UE 可用同一 request identifier 重查結果，但不得用新的 transcript 把相同 ticket 當新授權再次消耗。備份／多裝置同步亦須避免同一 ticket 被複製到兩個可獨立使用的 wallets；這是 non-transferability／wallet consistency 問題，不由 blind signature 自動解決。

## 5. Replay prevention 與 serving-context binding

建議把下列三層 replay 分別命名與測試：

1. **Transcript replay**：重放舊 nonce／AKE messages。以 verifier fresh nonce、完整 transcript hash、role、protocol version 與 serving context binding 拒絕；NIST 與 FIPS challenge-response guidance 支持此模式 [S8, S9]。
2. **Ticket reuse**：用同一有效 ticket 回應新的 challenge。以 canonical digest／serial 的 atomic check-and-consume 拒絕；nonce 單獨無效。
3. **Cross-context replay**：把一個 FGS／beam／epoch 的 response 轉送至另一 context。ticket policy 與 AKE transcript 必須共同綁定 audience／serving context；NIST federation guidance同樣要求 audience 與 nonce 檢查 [S10]。

IETF DPoP 提供很接近的 operational precedent：server 可保存 `jti` 並拒絕有效窗口內的 duplicate；RFC 同時警告，多 server endpoint 若無共享 state，strict single-use 可能不可行 [S11]。它不是 anonymous credential 標準，但精確展示了本系統的 replication trade-off。

既有 lifecycle draft 以 domain-separated `use_key = H(ctx || sn || d_M)` 作主鍵，並同時要求 `(ctx,d_M)`、`(ctx,sn)` 唯一；此三重檢查可拒絕 serial／digest inconsistency。只保存必要 digest 可降低 raw-ticket exposure，但 access timing、FGS location、serving context 與 consumption record 仍是 linkable operational metadata；應設定最小 retention、access control 與分離的 audit policy。

## 6. Crash-recovery semantics

### 6.1 安全 commit point

一個成功 access 應有單一 linearization point：在所有 ticket/context/expiry/revocation 與 AKE 前置驗證成功後，以 durable transaction 原子寫入：

```text
(use_key, ctx, d_M, sn) : absent
    -- compare-and-insert -->
(use_key, ctx, d_M, sn, attempt_id, response_digest, committed)
```

只有 durable commit 成功的請求能建立 session authorization；唯一鍵／conditional write 解決同一 ticket 的並行競爭。驗證失敗不得建立 consumed record。另一方面，一旦 commit，crash recovery 不得刪除或 rollback 該 record 來「補償」UE，否則攻擊者可利用 crash／timeout 重用 ticket。

ARIES 說明 write-ahead logging 如何在 crash 後維持 atomicity/durability [S12]。RIFL 對 retryable RPC 的 exactly-once 結果列出四個必要部分：RPC identity、completion record durability、retry rendezvous 與 garbage collection [S13]。這些是 lifecycle 設計原則；本文不指定資料庫產品。

### 6.2 四個 failure windows

| Crash 時點 | Recovery 後 ticket 狀態 | 對 UE 的結果 |
| --- | --- | --- |
| durable commit 前 | unused | 可用相同或新 request 重試 |
| commit transaction 中且未形成 durable commit | 由 storage recovery 決定為完整 commit 或 abort，不可出現半筆狀態 | 查詢 authoritative state 後處理 |
| durable commit 後、session response 前 | consumed | 相同 `request_id` 只能取得原 completion record／確定性拒絕；不得建立第二 session |
| response 後 | consumed | duplicate 回傳已完成結果或拒絕，不再執行副作用 |

最難的是第三列：安全性要求 ticket 保持 consumed；availability 則希望 UE 能拿到已購得的 session。若 completion record 能安全保存 session handle／可恢復的 key-confirmation state，相同 request 可 resume；若不能，就必須 fail closed 並消耗 ticket。不能把「UE 沒收到回覆」等同「FGS 沒 commit」。

### 6.3 Retry contract

建議 protocol 明確區分：

- **same-request retry**：相同 ticket、`request_id`、client ephemeral contribution 與 transcript prefix；只能查詢／完成同一 logical operation；
- **new attempt**：新的 request/AKE transcript；若 ticket 已 commit 則拒絕；
- **unknown outcome**：UE 在 retention window 內向 authoritative FGS group 查詢，不把 reserved ticket 放回池中；
- **retention expiry**：completion detail 可先刪，但最晚只能在 ticket 絕對 expiry + 最大 clock skew + 最大 in-flight window 後移除防重用 tombstone。

若 session secret 不應寫入 durable store，可保存 outcome digest 與以 fresh recovery exchange 重新 key-confirm 的 capability；其 security 需要另行定義。切勿為「exactly once」而無限制保存 session keys。

### 6.4 Replication 與 partition

Strict one-use 是 global invariant 時，接受 access 的 FGS 必須對同一 ticket namespace 使用具線性一致性／共識語意的 authoritative store，或把 ticket 預先 shard 到唯一 home verifier。前者增加跨地面站 RTT、quorum availability 與同步流量；後者降低同步延遲，但 home outage／路由切換會降低 availability 並可能洩漏 coarse routing link。

在 network partition 中同時允許多個 FGS 獨立接受，依 CAP 型取捨不可能同時保證立即 availability 與 global strict single-use。設計必須明確選擇：

- fail closed：無 quorum／home state 時拒絕，維持 safety；
- scoped lease／preallocation：某 ticket 只在一個 verifier shard 有效，維持局部單寫者；
- fail open + later detection：提升 availability，但語意降級為 double-use detection，且可能已建立多個 sessions。

## 7. 衛星網路 trade-off

| 維度 | One-use batch 的收益 | 主要成本／風險 | 可評估的控制 |
| --- | --- | --- | --- |
| privacy | 不同 ticket 可避免固定 credential 的直接重複 link；HNCC 不需在線 | batch timing、使用順序、FGS location、expiry bucket、spent logs 仍可關聯 | common metadata、issuance/use decorrelation、digest-only state、retention limits |
| availability | UE 在失聯期間可用預載 tickets；HNCC 不在在線路徑 | batch exhaustion；commit-before-reply 損失；FGS quorum／home outage | capacity margin、overlapping replenishment、same-request recovery、明示 fail-closed policy |
| UE storage | 無複雜 multi-show proof state | 近似 `B × |T|`；目前完整 ticket size仍是 provisional target，不得當 measured value | 報告實際 serialization、encrypted wallet、anti-rollback storage |
| FGS storage | 每筆可只存固定長度 digest/tombstone | entries 隨 access rate × retention window 成長；replication 放大 | epoch partition、expiry GC、bounded identifiers、DoS admission control |
| satellite latency | issuance proof 不進衛星路徑；LEO 可只 relay | ticket bytes、FGS lookup/consensus、AKE RTT；跨站共識可能支配 latency | 將 authoritative state 留地面、single-home routing、量測 p95/p99 而非只報 crypto time |
| handover | initial access 消耗一次 ticket；正常 handover 可用 session-derived authorization | handover authorization 失效時須用新 ticket 做 full access；fallback rate 會消耗 batch | 綁定原 session、target context、freshness 與 sequence；未來 unlinkable Show 仍需獨立 proof |
| revocation | short-lived ticket 可縮短 stale exposure | 大 batch/長 expiry 延長被竊 wallet 可用期；serial revocation list 增長 | epoch/key revocation、short buckets、wallet compromise reporting、量測散布延遲 |

衛星鏈路中，節省 UE storage 而引入更大的 online ZK proof 不一定划算；反之，大 batch 也可能使 UE secure storage 與補發流量成為瓶頸。比較時必須分開量測 offline issuance、UE–satellite transport、FGS verification/state commit、AKE 與 handover，不能以單一「authentication latency」掩蓋地面共識成本。

## 8. 對 system profile v0.1 的具體建議

### 8.1 保留的基線

保留 short-lived、strictly one-use ticket，但把它描述成以下組合，而非 RBBC theorem：

```text
PQ-RBBC validity
+ fresh, context-bound access/AKE transcript
+ durable atomic use-key consumption
+ crash-safe completion/retry contract
+ expiry/revocation/replication policy
= system-level strictly one-use access semantics
```

### 8.2 與 lifecycle draft 的交叉檢查

目前 `docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md` 已定義 payload-based `d_M`、domain-separated `use_key`、`UNSEEN/RESERVED/CONSUMED`、pure validation、atomic reserve/commit、same-attempt idempotent response、fail-closed partition、retention 下限、revocation ordering，以及 session-derived handover boundary。這些選擇與本文的文獻結論一致，且仍明確標為 Defined／Draft，不代表 implementation 或 proof closure。

後續 cross-review 仍應追蹤：

1. `ServingContextV1` 與 suite opaque fields 的 exact encoding／maximum；
2. holder authenticator、PQ AKE 與 key-confirmation 的 production security；
3. replay store backend 是否實際提供規格要求的 atomicity、durability 與 linearizability；
4. UE wallet 的 journal、anti-rollback、備份與多裝置同步；
5. batch profiles 如何避免個人化 metadata／quota watermark；
6. 實測 batch exhaustion、same-attempt recovery、partition rejection 與 retention cleanup；
7. crash injection 是否覆蓋 reserve、session creation、commit、response sealing／delivery 的每一 durability boundary。

### 8.3 未來研究 gate

只有在量測顯示 `B × ticket size`、handover consumption rate、FGS state/consensus latency 或 batch exhaustion 已成主要瓶頸時，才值得升級到 bounded-use／unlinkable Show。候選方案至少以相同 security target 比較：

- presentation bytes 與 round trips；
- UE/FGS compute、memory、persistent storage；
- k 次使用內 unlinkability 與超額後 privacy loss；
- revocation freshness 與 disconnected verifier semantics；
- PQ assumptions、concurrent security、reset/crash security；
- 與 conditional opening、non-frameability、serving context、AKE 的 composition。

## 9. 可驗證來源與 claim mapping

以下只列正式論文、標準、RFC 或作者／出版者的穩定頁面。傳統方案多非 post-quantum；本文引用其 security notion 或 lifecycle pattern，不宣稱可直接部署於 PQ-RBBC。

| ID | 來源 | 本文使用的 claim | 適用限制 |
| --- | --- | --- | --- |
| S1 | David Chaum, “Blind Signatures for Untraceable Payments,” CRYPTO 1982, DOI [10.1007/978-1-4757-0602-4_18](https://doi.org/10.1007/978-1-4757-0602-4_18) | blind issuance 與之後 token 使用不可由 signer 直接配對的基礎 | RSA 時代工作；不是 PQ-RBBC 實例 |
| S2 | David Chaum, Amos Fiat, Moni Naor, “Untraceable Electronic Cash,” CRYPTO 1988, DOI [10.1007/0-387-34799-2_25](https://doi.org/10.1007/0-387-34799-2_25)；[作者摘要](https://www.wisdom.weizmann.ac.il/~naor/PAPERS/untrace_abs.html) | offline acceptance 可事後偵測／揭露 double spender，而非即時 prevention | e-cash threat model 與本專案 opening governance 不同 |
| S3 | Jan Camenisch, Anna Lysyanskaya, “An Efficient System for Non-transferable Anonymous Credentials with Optional Anonymity Revocation,” EUROCRYPT 2001, DOI [10.1007/3-540-44987-6_7](https://doi.org/10.1007/3-540-44987-6_7)；[IACR PDF](https://www.iacr.org/archive/eurocrypt2001/20450093.pdf) | credential 可多次、unlinkably demonstrate possession，且不需每次聯絡 issuer | Strong RSA/DDH；非 PQ |
| S4 | Isamu Teranishi, Jun Furukawa, Kazue Sako, “k-Times Anonymous Authentication,” ASIACRYPT 2004, DOI [10.1007/978-3-540-30539-2_22](https://doi.org/10.1007/978-3-540-30539-2_22)；[IACR PDF](https://iacr.org/archive/asiacrypt2004/33290305/33290305.pdf) | 上限內 anonymous authentication、超額使用的 public tracing/detectability 模型 | 傳統 number-theoretic assumptions；非 PQ |
| S5 | Lan Nguyen, Reihaneh Safavi-Naini, “Dynamic k-Times Anonymous Authentication,” ACNS 2005, DOI [10.1007/11496137_22](https://doi.org/10.1007/11496137_22)；[IACR ePrint 2005/168](https://eprint.iacr.org/2005/168) | k-TAA 加入 provider grant、revoke、expiry | pairing/SDH/DBDH；非 PQ |
| S6 | Jan Camenisch, Susan Hohenberger, Anna Lysyanskaya, “Compact E-Cash,” EUROCRYPT 2005, DOI [10.1007/11426639_18](https://doi.org/10.1007/11426639_18)；[IACR ePrint 2005/060](https://eprint.iacr.org/2005/060) | 一次 withdrawal 形成大量 unlinkable coins，攤銷 issuance/wallet 成本並處理 double spend | random-oracle、Strong RSA/y-DDHI；非 PQ |
| S7 | Stefan Brands, “Restrictive Blinding of Secret-Key Certificates,” 1995，[CWI publication record](https://ir.cwi.nl/pub/5049) | blind issuance 可限制 hidden attributes；offline credential/wallet 的早期設計脈絡 | 非 PQ；本文不採其具體 scheme |
| S8 | NIST SP 800-63B-4, “Digital Identity Guidelines: Authentication and Authenticator Management,” §3.2.7，[official HTML](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/) | replay-resistance 定義；nonce/challenge freshness；OTP 有效期內只接受一次 | 身分驗證標準，不是 anonymous-credential construction |
| S9 | FIPS 196, “Entity Authentication Using Public Key Cryptography,” [NIST record](https://csrc.nist.gov/pubs/fips/196/final) | unique time-variant challenge-response 的 entity-authentication precedent | 已撤回標準；僅作歷史 protocol pattern，不作算法選型 |
| S10 | NIST SP 800-63C-4, “Federation and Assertions,” [official HTML](https://pages.nist.gov/800-63-4/sp800-63c.html) | audience restriction 與 nonce validation 防 cross-RP assertion replay | federation assertion guidance，非本系統完整 AKE proof |
| S11 | IETF RFC 9449, “OAuth 2.0 Demonstrating Proof of Possession (DPoP),” §11.1，[RFC Editor](https://www.rfc-editor.org/rfc/rfc9449.html) | 保存 `jti`、有效窗口內拒絕 duplicate；多 server 無共享 state 時 strict single-use 的可行性限制 | OAuth operational precedent；不提供 anonymity |
| S12 | C. Mohan et al., “ARIES: A Transaction Recovery Method Supporting Fine-Granularity Locking and Partial Rollbacks Using Write-Ahead Logging,” ACM TODS 17(1), 1992, DOI [10.1145/128765.128770](https://doi.org/10.1145/128765.128770)；[IBM record](https://research.ibm.com/publications/aries-a-transaction-recovery-method-supporting-fine-granularity-locking-and-partial-rollbacks-using-write-ahead-logging) | durable transaction 與 crash recovery 的 WAL 基礎 | database recovery pattern，不替本 protocol 定義 state machine |
| S13 | Collin Lee et al., “Implementing Linearizability at Large Scale and Low Latency,” SOSP 2015（RIFL），DOI [10.1145/2815400.2815416](https://doi.org/10.1145/2815400.2815416)；[作者 PDF](https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf) | exactly-once retry 需要 request identity、durable completion、retry rendezvous、GC | 其保證有 client/server assumptions；本文只採設計檢核框架 |

## 10. Claim boundary

- 本文沒有證明或實作 strictly one-use lifecycle，只給出文獻支持的 requirements 與 design alternatives。
- 本文沒有把傳統 CL credential、k-TAA、Brands credential 或 compact e-cash 宣稱為 post-quantum。
- 本文沒有宣稱 nonce、serial、one-more unforgeability 或 one-time DEM 任一項可單獨阻止 ticket reuse。
- 本文沒有把 offline double-spend detection 等同 online double-spend prevention。
- 本文沒有選定資料庫、共識協定、PQ `Show` backend、k-TAA construction 或 handover protocol。
- 本文的 provisional ticket size 引用邊界仍以既有 core proof 為準，不將估算值改寫成 measured production result。
