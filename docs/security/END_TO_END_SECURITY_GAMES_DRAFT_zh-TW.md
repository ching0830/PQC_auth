# 端到端 Threat Model 與 Security Games 草稿

> 狀態：研究草稿；非 canonical architecture、非 proof-closure 或 production-closure 宣告
>
> 適用 profile：system profile v0.1（short-lived、strictly one-use ticket）
>
> 依據：`ARCHITECTURE_zh-TW.md`、`methodology.md`、`research-notes.md`、`docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex` 與 `docs/DOCUMENTATION_POLICY_zh-TW.md`
> 初稿日期：2026-08-30；文獻術語與比較更新：2026-08-31

## 1. 目的、範圍與 claim discipline

本文件建立 PQ-RBBC cryptographic core 與衛星 access、session、handover、revocation、opening lifecycle 之間的端到端威脅模型及 game-based proof obligations。它是後續 protocol specification、形式化 reduction 與 integration test 的工作底稿，不修改或取代 `ARCHITECTURE_zh-TW.md`、`RESEARCH_STATUS_zh-TW.md` 或 `ROADMAP_zh-TW.md`。

本文所有安全敘述分成四類：

| 標記 | 意義 | 可否視為端到端已證明 |
| --- | --- | --- |
| **[CORE-THEOREM]** | RBBC core proof 對其抽象介面與既定 game 給出的 conditional reduction | 否；只能在該 proof 的範圍與 assumptions 內引用 |
| **[PROFILE-ASSUMPTION]** | system profile 為組合 core 與在線協定新增的信任、狀態、網路或營運假設 | 否；assumption 不是 theorem |
| **[OPEN-GAME]** | 尚須定義完整實驗、證明 reduction 或 composition theorem 的性質 | 否 |
| **[IMPLEMENTATION-TEST]** | 可由測試、fault injection、model checking 或 interoperability vectors 驗證的實作不變量 | 否；test evidence 不能取代 cryptographic proof |

除明確標記為 **[CORE-THEOREM]** 的結果外，本文件描述的端到端性質一律不得被解讀為已證明。即使未來某個 **[OPEN-GAME]** 有 proof，也仍須另外確認 concrete primitives、parameters、canonical encodings、backend 與 implementation evidence 符合該 proof 的 assumptions。

## 2. 系統模型與角色

### 2.1 角色與安全責任

| 角色 | 能力與預設信任 | 端到端責任 |
| --- | --- | --- |
| UE／holder | 可為惡意、可複製自己的 ticket／secret、可啟動並行 session、可與 network attacker 串通 | 保護 holder secret 與 session state；產生 access／handover 訊息；不得藉並行或故障重用 one-time ticket |
| HNCC | honest-but-curious issuer；知道 enrollment identity 與 issuance transcript；依共同 policy、quota 與 augmented relation 誠實發行 | 不得個人化 anonymity-set metadata；不得持有 OA threshold；不在正常 access／handover 在線路徑 |
| FAC | federation authorization authorities；可有少於門檻的腐化成員 | 以獨立 `(t_F,n_F)` key／ceremony 授權 configuration 與 issuer operation；不得因此取得 opening 能力 |
| OA | opening authorities；攻擊者可控制少於 `t_O` 個成員 | 只經 signature-gated API 對已授權 request 產生 share；驗證 ticket、case、purpose、evidence、expiry、replay 與 request digest |
| FGS | 地面 verifier、anti-replay state owner 與 session endpoint；本 profile 的安全性依賴其正確執行 | 驗證 access transcript、原子 check-and-consume、session key establishment、revocation 與 handover policy |
| LEO／FLEO | 資源受限且不預設可信；可被腐化、延遲、重排、丟棄、重送或竄改所中繼訊息 | 僅中繼或執行明確指定的輕量檢查；不得持有 issuer、FAC、OA secret keys 或成為 consumption state 的唯一權威 |
| Network attacker | quantum polynomial time；完全控制不受保護網路，可竊聽、插入、刪除、重排、延遲、複製、平行投遞與跨鏈路轉送訊息 | 不被信任；可控制或利用惡意 LEO／FLEO，但不能憑假設直接讀取 honest endpoint 內部 state |

Operator 的 configuration、epoch、domain、policy、expiry bucket、key identifiers、serving-context namespace 與 revocation policy 必須受到 federation authentication；Operator 不因營運角色自動被授予 issuance 或 opening secret。

### 2.2 腐化與串通案例

端到端 theorem 至少須分別處理下列案例，而不能用單一「attacker」籠統涵蓋：

1. 惡意 UE 加上 network attacker／惡意 LEO 或 FLEO。
2. honest-but-curious HNCC 加上 passive／active network observation，但不持有 opening threshold。
3. 少於 `t_O` 個 OA 加上 evidence processor／network attacker。
4. 少於 `t_F` 個 FAC；以及 FAC 與 OA organizations 重疊但 keys、thresholds 與 compromise domains 獨立的情況。
5. FGS crash、rollback、split-brain 或局部 compromise。若 FGS 完全惡意，one-time acceptance、AKE endpoint authentication 與 revocation enforcement 通常無法成立；相關 theorem 必須明列是否只保護 UE、是否只提供可稽核 evidence，或直接排除此案例。
6. HNCC 惡意發行／framing。RBBC core 的 trace soundness 不涵蓋惡意 issuer；除非增加 threshold issuer、可稽核 issuance 或公開 proof，否則列為 trust-boundary failure。

Adaptive corruption、state reveal、session-key reveal、ephemeral randomness reveal、OA/FAC proactive refresh 與 post-compromise recovery 尚未固定，必須在 AKE 與 composition game 中明定。

### 2.3 資產與安全事件

主要資產為 registered identity、holder secret、ticket inventory、未使用 ticket、consumption state、session／handover keys、issuer／FAC／OA secret shares、revocation state、opening evidence 與 audit transcript。主要安全事件包括：未授權 access、同一 ticket 建立多個 session、舊 transcript 建立 fresh session、跨 context 接受、未授權或重複 opening、錯誤 identity opening、revoked object 被接受，以及 metadata／timing 導致超出宣稱範圍的 linkability。

## 3. RBBC core 可引用的既有結果

以下均為 **[CORE-THEOREM]**，且是對 proof 中抽象 interfaces／games 的 conditional reductions，不表示 concrete fork、SE-NIZK backend、robust threshold implementation 或端到端系統已封閉：

| Core 結果 | 提供的性質 | 不提供的性質 |
| --- | --- | --- |
| QROM cross-message request binding | 在 CAP extraction／unique-mask 與 QROM assumptions 下，限制同一 request 對不同 message 的 binding failure | access transcript binding、serving-context binding |
| End-to-end correctness（core 用語） | 誠實 issuance ticket 可驗證；足門檻 honest OA 可重建 `rid || sn` | access、AKE、handover 或 lifecycle 的端到端 correctness |
| Certified-language soundness 與 certified ciphertext validity | verifying ticket 可關聯至 accepted issuance witness，並包含與 issuance identity／serial 綁定的有效 ciphertext | ticket 只使用一次、session key security |
| Signature-gated decoder safety | honest OA 僅經 gated API 時，decoder 接觸非語言 ciphertext 的機率有 reduction bound | opening policy 本身正當、OA service availability |
| Issuer unlinkability | honest-protocol curious HNCC 在共同 visible metadata、honest holders 與無 opening threshold 下，不能把兩張最終 ticket 對回 issuance session | timing、format、radio fingerprint、IP／location anonymity；惡意 issuer security |
| Trace soundness | 惡意 holder 不能讓 accepted issuance ticket 開成不同 `rid` 或不同 serial | 惡意 issuer framing；opening authorization governance |
| `τ`-GCCA trace privacy | 少於 opening threshold 的 attacker，在 certified-ticket gated-opening game 中不能區分 challenge identity | bare ciphertext IND-CCA、challenge ticket opening、traffic-analysis privacy |
| Ticket one-more unforgeability | `q` 次 completed accepted issuance 後，不能產生超過 `q` 個 distinct verifying ticket digests | 每張已簽 ticket 最多成功 access 一次 |
| Concrete trace unique opening／correctness／conditional privacy | exact trace relation 的 unique plaintext、誠實解碼 correctness，以及在 stated QROM、qPRF、fresh-error 與 threshold decoding assumptions 下的 one-time privacy | 可部署參數核准、robust OA transcript、一般多次加密安全 |

Core proof 明確不宣稱：malicious-issuer security、metadata／timing anonymity without system controls、UC composability、side-channel resistance、satellite AKE security、FLEO／handover security、bare ciphertext IND-CCA。Core `VerifyTicket` 是 stateless；fresh issuance serial、issuer-side `sid` replay control、opening-authorization replay control 與 one-more unforgeability，均不等於 access ticket one-use。

## 4. System profile 新增 assumptions

以下皆為 **[PROFILE-ASSUMPTION]**，未被 RBBC core theorem 證明：

- **P-A1 Canonical encoding。** Issuance、ticket verification、ticket digest、access transcript、consumption key、opening 與 audit 對相同物件使用 byte-for-byte 相同且 domain-separated 的 canonical encoding；解析器拒絕 alternate／ambiguous encoding。
- **P-A2 Configuration authenticity。** FAC authentication 唯一綁定 version、epoch、domain、policy、expiry bucket、issuer／OA key identifiers 與 context digest；不同 anonymity-set 使用者不帶個人化 metadata。
- **P-A3 Honest FGS state transition。** 至少一個負責接受決策的 FGS 正確驗證並以 linearizable／serializable transaction 原子執行 check-and-consume；state 不會無偵測 rollback、fork 或遺失。
- **P-A4 Single consumption authority semantics。** 多 FGS／region 間有明確一致性協定或不可重疊的 acceptance authority；partition 期間不得由兩個 authority 各自成功消耗同一 ticket。
- **P-A5 Freshness source。** FGS nonce 不可預測且不重複；epoch／expiry 判斷有明定 clock-skew；counter、nonce cache 或 channel transcript 不會因 restart 靜默重用。
- **P-A6 Access transcript binding。** PQ AKE／authentication transcript 綁定完整 canonical ticket digest、visible serial、FGS identity、serving context、protocol version、roles、fresh nonces、negotiated algorithms 與 relevant channel binding。
- **P-A7 AKE primitive security。** 未來選定的 PQ KEM／signature／KDF／key-confirmation composition 在所選 multi-session、active、quantum attacker 與 reveal model 下安全。
- **P-A8 Revocation authenticity and monotonicity。** Revocation objects 經 federation authentication，帶 version／epoch／effective time；verifier 不接受 stale rollback，並對缺資料採明確 fail-open 或 fail-closed policy。
- **P-A9 Handover authorization。** 舊與新 FGS、source／target context、session identifier、fresh handover nonce、key epoch 與 transcript digest 被完整綁定；handover credential 不等同可再次使用的 access ticket。
- **P-A10 Opening governance。** FAC authorization（或另定 authority）與 OA decryption keys 獨立；authorization 唯一綁定 ticket digest、case ID、evidence digest、purpose、expiry 與 request nonce，且 consumption state 可防重放。
- **P-A11 Key separation。** Issuer、FAC、OA、FGS authentication、AKE 與 audit keys 具有獨立 domain、generation、storage、rotation 與 compromise boundary。
- **P-A12 Endpoint／platform boundary。** Honest UE、FGS、FAC 與 OA 的 secret state 不被 side channel、memory disclosure、malicious RNG、supply-chain compromise 或 endpoint malware 洩漏；若要涵蓋，須另建模型與 evidence。
- **P-A13 Privacy operations。** Ticket fixed-format、issuance batching／activation、common expiry buckets、routing／logging minimization 與足夠 anonymity set 被營運層維持；否則 cryptographic unlinkability 不能推出 traffic unlinkability。

## 5. 共用 game framework

後續 games 應共享一個明確 challenger state，而非各自假設不一致的 lifecycle：

```text
pp, federation configuration, issuer/FAC/OA/FGS keys
IssueLog[dT]       = (rid, sn, ctx, policy, expiry, issuance status)
Consume[dT]        = unused | pending(txid) | consumed(session_id, transcript_hash)
Session[sid]       = (UE role, FGS, context, transcript_hash, key state, status)
Handover[hctx]     = (source sid/context, target context, nonce, status)
Revoke[obj]        = (version, effective_time, reason/status)
OpenAuth[auth_id]  = (dT, case_id, evidence_digest, purpose, expiry, used/status)
Audit[event_id]    = append-only decision/evidence record
```

Oracle 至少應區分 `Issue`、`Deliver／Send`、`AccessStart`、`AccessFinish`、`ConsumeAttempt`、`RevealSessionKey`、`CorruptRole`、`Handover`、`PublishRevocation`、`OpenAuthorize`、`OpenShare`、`CombineOpen` 與 `Crash／Recover`。每個 game 必須定義 session partnering、freshness predicate、allowed corruptions、challenge exclusions、winning event 及 negligible advantage。

## 6. Access authentication 與 session freshness

### 6.1 `G-ACCESS-AUTH`：access mutual authentication

**[OPEN-GAME]** 攻擊者完全控制 network 與 LEO／FLEO relay，並可驅動多個 UE／FGS sessions。若 honest FGS 接受 session，則除 negligible probability 外，必須存在唯一 partnered UE session，該 UE 持有對應 ticket／holder state，雙方同意 ticket digest、FGS identity、serving context、roles、algorithms 與 transcript。若 honest UE 接受，亦須存在唯一 partnered honest／authorized FGS session。未知 key-share、role confusion、identity misbinding 與 downgrade 都計為勝利。

此 game 必須以 RBBC certified-language soundness／one-more unforgeability 作為「ticket 合法來源」的組合 lemma，但仍需 AKE authentication、holder-possession（若 protocol 要求）、transcript binding 與 FAC configuration authenticity 的 reduction。

### 6.2 `G-SESSION-FRESH`：fresh session-key indistinguishability

**[OPEN-GAME]** 對符合 freshness predicate 的 accepted session，attacker 在 real session key 與同長度 random key 間的 distinguishing advantage 應 negligible。Freshness predicate 至少明定：partner 是否被腐化、long-term／ephemeral key reveal 的時點、ticket／holder secret reveal、session-key reveal、KEM decapsulation key compromise，以及 handover key 派生關係。

必須另行定義 key confirmation、key separation、known-key security、forward secrecy、backward／future secrecy 與 post-compromise security；不能僅由「使用 PQ KEM」推出。

### 6.3 `G-CONTEXT-SUB`：context substitution resistance

**[OPEN-GAME]** attacker 從一個有效 access transcript 置換、刪除或重新編碼 `epoch/domain/policy/expiry/kid/FGS/serving-context/role/algorithm/channel` 的任一受保護欄位。若 honest endpoint 在不同 canonical context 下接受，且不存在對該完整 context 的 partnered session，attacker 勝利。

此 game 同時涵蓋 cross-domain、cross-epoch、cross-FGS、cross-role、downgrade 與 alternate-encoding substitution。RBBC 的 `ctx` binding 只涵蓋 ticket common information；它不自動綁定動態 serving context 或 AKE transcript。

### 6.4 可測但不能代替 proof

**[IMPLEMENTATION-TEST]** 建立 positive／negative vectors，逐一 mutation version、epoch、domain、policy、expiry、key IDs、FGS ID、serving context、nonce、role、algorithm 與 channel binding；測試 stale nonce、nonce collision injection、transcript truncation、message reordering、unknown key-share、downgrade 與 key-confirmation failure。跨語言 implementation 必須對 canonical transcript hash 產生相同 bytes。這些測試能抓 wiring／parser／state-machine bug，不能證明所有 QPT adversary 下的 AKE security。

## 7. One-time consumption、replay 與 parallel replay

### 7.1 `G-ONE-CONSUME`：最多一次成功

**[OPEN-GAME]** 對任一 canonical ticket digest `dT`，即使 attacker 複製 ticket、建立任意多平行 connections、選擇不同 LEO／FLEO relay 或不同 FGS ingress，所有 honest acceptance authorities 中最多一個 access session 能進入 `accepted-and-consumed`。Winning event 是兩個不同 session IDs／transcript hashes 對同一 `dT` 都成功接受；單純重送而全部被拒絕不算勝利。

原子操作應具備語意：

```text
Verify all immutable ticket/context/expiry/revocation/AKE preconditions
CAS Consume[dT]: unused -> pending(txid)
Complete key confirmation and durable decision
Commit pending(txid) -> consumed(session_id, transcript_hash)
```

何時 reserve、何時 commit、失敗是否釋放、timeout 後由誰恢復，須在 protocol specification 固定。安全性要求不能與 availability recovery 使用互相矛盾的 rollback 規則。

### 7.2 `G-REPLAY`：sequential／cross-context replay

**[OPEN-GAME]** attacker 記錄一個完整或部分 access transcript，之後在同一或不同 FGS、epoch、serving context、relay path 重送。若沒有 fresh partnered UE execution，honest endpoint 仍建立新 session 或接受舊 key，attacker 勝利。已消耗 ticket 的任何後續 access 均須拒絕；未完成 transcript 的 message replay 亦不得繞過 nonce／transcript checks。

### 7.3 `G-PARALLEL-REPLAY`：racing requests

**[OPEN-GAME]** challenger 允許 attacker 精確控制 interleaving，在多 FGS replicas 上同時送出相同 ticket 與相同／不同 nonces、contexts、AKE shares。安全目標是在所有 admissible schedules、crash points 與 retry paths 中，linearization order 只產生至多一個成功 session。此 game 需要 stateful／distributed-system lemma，不能只歸約到 signature unforgeability。

### 7.4 Failure semantics

**[PROFILE-ASSUMPTION]** 驗證失敗不得消耗 ticket；成功決策 durable 後不得 rollback 重用。對 `pending` 後 crash 的不確定結果，profile 必須選擇安全優先的 fail-closed reconciliation，或提出能證明 exactly-once 的 recovery protocol。允許 UE 因不確定結果換用新 ticket 可改善安全，但會犧牲 availability 與 inventory。

### 7.5 可測但不能代替 proof

**[IMPLEMENTATION-TEST]** 至少包含：相同 ticket 的 2、N 與跨-region barrier-synchronized races；transaction abort；process kill；disk／replica delay；leader failover；stale snapshot；duplicate delivery；不同 context 同票 race；key confirmation 前後 crash；timeout retry；已消耗 state restart 後持久性。測試應斷言 successful session count `<= 1`、失敗不誤消耗，以及 audit／store state 一致。有限 schedules 的通過不能證明所有並行 interleavings 或 Byzantine storage 下的 theorem。

## 8. Handover

### 8.1 `G-HO-AUTH`：handover authentication／context continuity

**[OPEN-GAME]** attacker 控制 source 與 target 間網路及 relay。若 target FGS 接受 handover，必須存在未撤銷、未終止且符合 freshness predicate 的 source session，並有唯一 partnered handover execution；雙方同意 source session／context、target FGS／context、handover nonce、key epoch、transcript digest 與 authorization scope。Cut-and-paste、cross-target replay、old-session resurrection、role swap 或將 access ticket 當 handover token 均為勝利。

### 8.2 `G-HO-KEY`：handover key freshness／separation

**[OPEN-GAME]** target session key 對 attacker 應 pseudorandom，且 source key 或其他 target key 的 reveal 不應自動洩漏它；具體 forward、backward 與 compromise-recovery 性質依 KDF ratchet／fresh KEM composition 定義。Handover 不應重複消耗原 access ticket，也不應使已 consumed ticket 恢復可用；它應以已認證 session continuity 或獨立、單用途 handover authorization 為基礎。

### 8.3 `G-HO-PRIV`：handover privacy boundary

**[OPEN-GAME]** 在不揭露 registered identity 的前提下，定義 observer 能否連結 handover 前後 session。若營運需要 continuity，linkability 可能對 involved FGS 或局部時間窗是刻意允許的；game 必須明示 observer、時間窗與 context，而不能宣稱全域 unlinkability。

### 8.4 可測但不能代替 proof

**[IMPLEMENTATION-TEST]** mutation source／target context、nonce、session ID、key epoch、target identity；重播舊 handover；同一 authorization 平行送往多 targets；source termination／revocation 與 handover race；packet loss、out-of-order、rollback 與 dual-connectivity。測試驗證 state transitions 與 byte binding，不取代 handover AKE／key-indistinguishability proof。

## 9. Revocation

### 9.1 Revocation scope

Revocation object 必須分型：issuer／FAC／OA／FGS key revocation、configuration／epoch revocation、ticket／serial revocation、UE credential or holder-key compromise、active session termination。不同類型不能只用同一 vague blacklist 表示。

### 9.2 `G-REV-AUTH`：authenticity／rollback resistance

**[OPEN-GAME]** attacker 不能偽造、竄改、刪減或 rollback federation-authenticated revocation state，使 honest verifier 接受低於已知 monotonic version 的 view。對 partitioned verifier，game 必須明定 freshness window 與 fail-open／fail-closed outcome。

### 9.3 `G-REV-EFFECT`：revocation effectiveness

**[OPEN-GAME]** 在 revocation 生效時間加上明定 propagation bound 後，受撤銷 ticket、key、configuration 或 session 不得建立新 access／handover session；active session 是否立即終止需另定。短效 one-time ticket 降低 exposure，但不等於 revocation proof。

### 9.4 Privacy and revocation

**[OPEN-GAME]** 若 revocation handle／query 可被 observer、HNCC 或 FGS 用來跨 session 連結 UE，必須量化 leakage。Private revocation、bucketed distribution 或 verifier-local check 各有不同 availability／privacy 成本；尚未選定前不得宣稱 revocation-preserving anonymity。

### 9.5 可測但不能代替 proof

**[IMPLEMENTATION-TEST]** 驗證 signature、version monotonicity、expiry、key rotation、delta gap、stale cache、partition recovery、revocation/access race、revocation/handover race與 clock skew。測試可顯示 dissemination／cache implementation 符合規格，不能證明 authenticity primitive、全網 bounded delivery 或 privacy game。

## 10. Authorized opening

### 10.1 已有 core 基礎

**[CORE-THEOREM]** Certified ciphertext validity、signature-gated decoder safety、trace soundness、unique opening 與 `τ`-GCCA 提供「有效 ticket 中 trace ciphertext 的語言／identity binding」、「不暴露 bare partial-decrypt API 時的 decoder boundary」、「少於 `t_O` shares 的 protocol-specific privacy」等基礎。它們不證明誰有權核發 case authorization、purpose 是否正當、audit log 完整或 service 可用。

### 10.2 `G-OPEN-AUTHZ`：authorization unforgeability／substitution

**[OPEN-GAME]** attacker 可取得其他 tickets、cases、evidence、purposes、expiries 的合法 authorizations，若能讓 honest OA 對未被授權的 tuple `(dT, caseID, evidenceDigest, purpose, expiry, requestNonce)` 產生 share，即勝利。Ticket、case、evidence、purpose、expiry、key ID、OA set 或 encoding 任一 substitution 都必須被涵蓋。

### 10.3 `G-OPEN-ONCE`：authorization replay resistance

**[OPEN-GAME]** 對被標為 one-use 的 opening authorization，任意平行、跨 OA endpoint、retry 或 crash interleaving 最多只能形成一個授權 opening event／audit record。是否允許同一 case 重新簽發新 authorization 必須由治理 policy 明定，不能靠重送舊 object。

### 10.4 `G-OPEN-ROBUST`：robust combine／accountability

**[OPEN-GAME]** 少於 threshold 的惡意 OA 可拒絕服務或提交 malformed／inconsistent shares；combiner 不得輸出錯誤 `rid || sn`，且若輸出成功，shares、request digest 與 OA identities 應可驗證地對應同一 request。是否要求識別 faulty share、公開可驗證 transcript 或 guaranteed output delivery，須分開定義。

### 10.5 `G-OPEN-PRIV`：threshold／purpose boundary

**[OPEN-GAME]** 少於 `t_O` OA、FGS、HNCC、FAC 與 evidence processor 的允許串通集合，在未取得合法 challenge authorization 時不能得知 registered identity，除已宣告 leakage。HNCC 本來在 issuance 知道 identity，因此對 HNCC 的目標是 issuance-to-ticket unlinkability，不是 identity secrecy。達到 `t_O` 的 authorized set 被設計為可開啟，故不在 confidentiality 保護範圍。

### 10.6 可測但不能代替 proof

**[IMPLEMENTATION-TEST]** 確認 production API 不存在 bare partial decrypt；mutation ticket／case／evidence／purpose／expiry／nonce；authorization replay 與 races；混合不同 request 的 shares；invalid share；不足 threshold；serial mismatch；audit append failure；key rotation。這些測試可驗證 fail-closed API 與 wiring，但不能取代 authorization EUF、threshold privacy、unique opening、robustness 或 governance legitimacy proof。

## 11. Privacy game 與明確邊界

### 11.1 可主張的最小 cryptographic privacy

- **[CORE-THEOREM]** 對 honest-protocol curious HNCC 的兩票 issuer unlinkability，前提是 common visible metadata、honest holders 且 HNCC 無 opening threshold。
- **[CORE-THEOREM]** 對 outside observer／evidence processor／少於 `t_O` OA 的 certified-ticket `τ`-GCCA trace privacy，且 challenge digest 不可 opening。
- **[OPEN-GAME]** Access observer unlinkability：在兩個符合相同 public metadata／traffic shape 的 honest UE access executions 間區分 challenge UE 的 advantage。此 game 必須列出 FGS、HNCC、LEO／FLEO、OA 的 corruption／collusion，以及 location、timing、packet length、ticket digest、serial、serving context 與 radio-layer leakage。

### 11.2 不在目前 privacy claim 內

目前不得宣稱：

- 對 malicious HNCC 的 anonymity／non-frameability；
- 對可觀察 issuance 與 access timing、獨特 expiry／policy、routing、IP、location、RF fingerprint 或 packet loss pattern 的 traffic-analysis anonymity；
- 同一 ticket 多次 presentation 的 unlinkability（profile 反而要求 one-use，重複出示同一 fixed ticket 本身可連結）；
- 對 honest FGS 隱藏 ticket digest、serial、serving context 或 session continuity；
- authorized `t_O` opening set 面前的 identity confidentiality；
- endpoint compromise、side channel、logs／telemetry、crash dump 或 operator database 洩漏下的 privacy；
- handover 前後的全域 unlinkability，除非未來 game 明確定義並證明。

Privacy 與 accountability 之間必須以 observer-specific leakage function 表示。為 replay prevention 而由 FGS 看見／儲存 `dT` 與 serial，是明確系統 leakage；其 retention、access control 與跨 FGS sharing 需另定 policy。

## 12. Availability 邊界

Availability 不由 RBBC unforgeability、privacy 或 AKE proof 推出。Network attacker 或惡意 LEO／FLEO 能丟棄、延遲、jam 或 partition 封包；少於 threshold 的 OA 也可能 withholding。沒有同步網路、資源、replication 與 honest-majority／threshold responsiveness assumptions 時，無法保證 access、handover、revocation delivery 或 opening liveness。

可研究但尚未證明的目標包括：

- **[OPEN-GAME] `G-ACCESS-LIVE`：**在明定 bounded-delay、honest FGS、可達路徑、未撤銷且未過期 ticket 與資源上限下，honest UE 最終成功或得到可區分的終止結果。
- **[OPEN-GAME] `G-CONSUME-RECOVER`：**crash／partition 後不產生 double acceptance，且 pending ticket 最終被安全決定；若選擇永久 burn，應把它列為 safety-over-availability outcome。
- **[OPEN-GAME] `G-OPEN-LIVE`：**至少 `t_O` 個 honest／responsive OA 與可達 network 下，合法 request 最終可 combine；robustness 不等同 guaranteed delivery。
- **[OPEN-GAME] `G-REV-FRESH`：**在 bounded dissemination assumption 下，revocation view 於期限內更新；完全 partition 時只能明定 fail-closed 拒絕或承擔 fail-open security risk。

**[IMPLEMENTATION-TEST]** 可用 load、latency、packet-loss、partition、retry、quota exhaustion、storage outage、OA withholding 與 DoS tests 量測 availability envelope。測得的 percentile、throughput 或 recovery time 是特定環境 evidence，不是對任意 network attacker 的可用性 proof。

## 13. 端到端 composition theorem 待辦

### 13.1 建議主 theorem 形式

**[OPEN-GAME]** 在明列全部 component assumptions、profile assumptions 與 corruption restrictions 下，對任意 QPT attacker，端到端壞事件 advantage 應可界為：

```text
Adv_E2E
 <= Adv_Core-CertSound + Adv_Core-1mUF + Adv_Core-Unlink/Trace/GCCA (依事件選用)
  + Adv_FAC-Auth + Adv_OpenAuth
  + Adv_AKE-Auth + Adv_AKE-Key + Adv_KDF/Hash/Encoding
  + Adv_State-OneConsume + Adv_Context/Handover + Adv_Revocation
  + Pr[nonce/serial collision] + Pr[state rollback/split-brain]
  + explicitly stated operational leakage/failure terms.
```

不能把所有 core advantages 無差別相加；每個端到端 winning event 應先建立 event decomposition，再只引用實際需要的 lemmas。State rollback／split-brain 若僅靠 assumption 排除，必須清楚寫成 failure probability 或 trusted-system assumption，而非 negligible cryptographic term。

### 13.2 尚待固定的規格

在正式 proof 前至少要固定：

1. Access／AKE message flow、canonical transcript 與 partnering function。
2. Consumption transaction 的 reserve／commit／abort／crash recovery semantics。
3. Multi-FGS authority、一致性、partition 與 migration model。
4. Serving-context grammar、FAC-authenticated fields 與 downgrade policy。
5. Session freshness／reveal／adaptive-corruption model。
6. Handover token、source／target authorization、key schedule 與 ticket-consumption關係。
7. Revocation object types、effective time、propagation bound 與 privacy leakage。
8. Opening authorization issuer、policy、one-use state、robust share proof 與 audit semantics。
9. Observer-specific privacy leakage 與 availability network assumptions。
10. Concrete primitive selection、PQ parameters、SE-NIZK backend 與 fork-specific proofs。

## 14. Test evidence 對照表

| 性質 | Implementation test 能支持 | 不能由 test 得出 |
| --- | --- | --- |
| Canonical binding | golden vectors、cross-language byte equality、field mutations | collision resistance、所有 parser ambiguity 不存在 |
| One-time consumption | race／crash／restart／replication scenarios 無 double success | 所有 schedules、任意 Byzantine／rollback storage 下 exactly-once |
| Replay／freshness | recorded transcript、stale nonce、reorder、duplicate 被拒 | QPT active attacker 下 AKE security |
| Context substitution | 每個 context field mutation 被拒 | protocol composition／unknown key-share theorem |
| Handover | state-machine、race 與 mutation tests | handover key indistinguishability、全域 unlinkability |
| Revocation | stale／forged fixture、cache、version、propagation measurements | federation signature security、全網 bounded liveness、privacy |
| Authorized opening | gate、threshold、share mixing、serial mismatch、replay tests | threshold privacy、auth unforgeability、robustness theorem |
| Privacy | fixed sizes、logging review、controlled traffic experiment | timing／location anonymity 或 cryptographic indistinguishability proof |
| Availability | benchmark、fault injection、recovery measurements | 對 jamming、unbounded DoS 或 permanent partition 的保證 |

測試結果必須連同 commit、環境、commands、inputs、raw outputs 與限制記錄在適當 evidence／experiment 文件。通過測試只代表 Tested 或相應 evidence maturity；不得自行升級為 Proof-closed 或 Production-closed。

## 15. Review checklist

- [ ] 每個 game 都列出 parties、oracles、corruption、freshness、challenge restriction、winning event 與 advantage。
- [ ] Core theorem 的引用沒有超出 honest-issuer、abstract-interface 與 gated-opening範圍。
- [ ] One-more unforgeability 沒有被誤寫成 one-time consumption。
- [ ] Issuance `sid`、fresh serial、opening replay state 沒有被誤寫成 access anti-replay。
- [ ] `ctx` 與動態 serving context／AKE transcript 的 binding 被分開處理。
- [ ] FGS state consistency、crash recovery 與 partition assumptions 明列。
- [ ] FAC 與 OA keys、thresholds、ceremonies 及 compromise domains 保持獨立。
- [ ] HNCC、FGS、OA、network observer 的 privacy goals 使用不同 games／leakage。
- [ ] Authorized opening 的 confidentiality、authorization、robustness、audit 與 liveness 沒有混為一談。
- [ ] Availability 與 privacy 邊界沒有被 cryptographic safety theorem 掩蓋。
- [ ] Implementation tests 只作 conformance／regression evidence，不取代 reduction。
- [ ] 未來 claim 更新回到 canonical status 文件；本草稿不自行宣告 closure。

## 16. 衛星認證文獻的 security-property 術語對齊

### 16.1 比較來源與閱讀限制

本節以使用者提供的四份論文 PDF 為比較集合：

1. **AnFRA** — *Anonymous and Fast Roaming Authentication for Space Information Network*，IEEE TIFS，2019。
2. **PkT-SIN** — *A Secure Communication Protocol for Space Information Networks With Periodic k-Time Anonymous Authentication*，IEEE TIFS，2024。
3. **N3PA-STIN** — *A Novel Three-Party Authentication Protocol for Multiuser Access in Satellite Terrestrial Integrated Networks*，IEEE IoT Journal，2025。
4. **QPCASIN** — *A Quantum-Defended Privacy-Aware Preemptive Handover-Enabled Continuous Authentication in Space Information Networks*，IEEE TIFS，2025。

比較以所提供 PDF 的正文、表格及其中可見的 proof sketch／tool-verification 敘述為限。PkT-SIN 與其他論文提及但未包含在 PDF 內的 supplementary proofs，不在本次獨立核對範圍。因此「未明確處理」只表示在本次閱讀的 threat model、security requirements、security analysis 或 comparison attributes 中沒有找到相同粒度的定義；不等於已證明該論文的 protocol 不具備該性質。

各論文的 attacker model、primitive、trust boundary 與 proof technique 不同。表中的同名性質只能用來比較研究問題與 claim scope，不能僅因名稱相同就視為同一 security game，也不能把 informal inspection、symbolic verification 與 computational reduction 當成同等證據。

### 16.2 本文採用的顯示名稱

為與上述衛星認證文獻一致，後續論文正文及比較表優先使用下列英文名稱；精確的 game identifier 保留作為括號內限定，防止常見名稱掩蓋 security semantics：

| 建議顯示名稱 | 本草稿對應項目 | 必要限定 |
| --- | --- | --- |
| Mutual Authentication | `G-ACCESS-AUTH` | 本文是 UE–FGS mutual authentication；若 LEO/FLEO 也成為 authenticated party，才稱 Three-Party Mutual Authentication |
| Secure Key Establishment／Key Agreement | `G-SESSION-FRESH` 的 authentication 與 correctness 部分 | 必須另列 session-key indistinguishability，不能只證明雙方算出相同 key |
| Session Key Security／Semantic Security | `G-SESSION-FRESH` | 採 ROR／Test-style game 時須明列 Freshness predicate 與 reveal queries |
| Key Forward Secrecy／Key Backward Secrecy | `G-SESSION-FRESH`、`G-HO-KEY` | 沿用 PkT-SIN、AnFRA、N3PA-STIN 用語；另說明是 session key 還是 domain／handover key |
| Conditional Anonymity | core issuer unlinkability、`τ`-GCCA 與未來 access privacy 的組合目標 | 「conditional」指合法門檻 opening，不代表所有 observer 都看不到 metadata |
| User Anonymity | `G-ACCESS-PRIV`（待正式編號） | 必須列出 observer 與 leakage；不直接沿用「identity 被 hash 即匿名」的弱定義 |
| Unlinkability | core Issuer Unlinkability 與 access／handover unlinkability games | 分開標成 Issuer Unlinkability、Access Unlinkability、Handover Unlinkability |
| Accountability | Trace Soundness、Non-Frameability、Authorized Opening | 不只要求可 reveal；還要求 identity／serial binding 與不能誣陷 honest holder |
| Resistance to Replay Attacks | `G-REPLAY` | 區分 timestamp／nonce transcript replay 與已消耗 ticket replay |
| Resistance to Parallel Replay Attacks | `G-PARALLEL-REPLAY` | 本文刻意新增的細分類；涵蓋 racing、replica 與 distributed state interleavings |
| Resistance to Impersonation Attacks | `G-ACCESS-AUTH` 的 unpartnered acceptance event | UE、FGS、LEO/FLEO impersonation 應分開報告 |
| Resistance to Man-in-the-Middle (MitM) Attacks | `G-ACCESS-AUTH`、`G-CONTEXT-SUB`、AKE key security | 不以「已抵抗 impersonation」單獨推出 MitM resistance |
| Resistance to Modification／Injection Attacks | transcript integrity 與 `G-CONTEXT-SUB` | 涵蓋欄位 mutation、message injection、role／algorithm substitution |
| Resistance to Desynchronization Attacks | `G-CONSUME-RECOVER` 與 handover／revocation state recovery | 須涵蓋 pending consumption、crash 與 rollback，而不只允許重新啟動 protocol |
| Handover Authentication | `G-HO-AUTH` | 另列 Handover Key Security 與 Handover Privacy，不用單一「supports handover」取代 |
| Dynamic Joining and Revocation | `G-REV-AUTH`、`G-REV-EFFECT`、`G-REV-FRESH` | 本文另區分 authenticity、effectiveness、freshness、privacy 與 liveness |
| Resistance to DoS／DDoS Attacks | availability／resource-exhaustion 分析 | 必須區分 prevention、mitigation、detectability；不能把 rate limit 寫成對任意 DDoS 的保證 |
| Resistance to Long-Term Key Leakage | AKE reveal model | 需指定洩漏哪一角色、何種 key 及發生時點 |
| Resistance to Temporary Secret Leakage | AKE reveal model | 需指定 ephemeral reveal 與 freshness 是否仍成立 |
| Resistance to Device Loss／Physical Capture Attacks | endpoint-compromise extension | 不在目前 profile proof scope；不可由 cryptographic core 自動推出 |
| One-More Ticket Unforgeability | RBBC core theorem | 不等同 one-time consumption 或 k-Detectability |
| Authorized Opening | `G-OPEN-AUTHZ`、`G-OPEN-ONCE`、`G-OPEN-ROBUST`、`G-OPEN-PRIV` | 比一般 Accountability／Identity Reveal 更窄且更可稽核 |

文獻中的「Forward/Backward Secrecy」有時只表示 current session-key disclosure 不影響 past／future session keys，與標準 AKE 的 perfect forward secrecy、future secrecy 或 post-compromise security 不必然相同。本研究引用時應保留原作者名稱，並在自己的 game 中使用 reveal timing 精確定義。

### 16.3 四篇論文使用的名稱與證據型態

| 論文 | 原文明確列出的主要 security-property 名稱 | 正文採用的主要分析／驗證形式 |
| --- | --- | --- |
| AnFRA | Mutual Authentication、Anonymity、Unlinkability、Key Establishment、Forward/Backward Secrecy、Resistance of Modification／Replay／Impersonation／Man-in-the-Middle Attacks；另有 User Identity Reveal 與 Dynamic User Enrollment and Revocation | 以 primitive assumptions 與逐項 informal security analysis 為主 |
| PkT-SIN | Secure Key Establishment、Mutual Authentication、Key Forward/Backward Secrecy、Anonymity、Accountability、Unlinkability、Resistance to Replay／Impersonation／MitM／DDoS Attacks；另比較 periodic k-Time Anonymous Authentication、Handover、Revealing Violator's Identity Without TTP、Selective Attribute Disclosure | PkT-KVAC 對 Unforgeability、Anonymity、k-Detectability、Exculpability 提供 theorem／proof sketch，系統屬性多為逐項 analysis；完整 proofs 部分指向 supplementary material |
| N3PA-STIN | Three-Party Mutual Authentication、Key Agreement、Forward and Backward Secrecy、Conditional Anonymity、Conditional Verifiability、Unlinkability、Dynamic Joining and Revocation；Resistance to Replay、Impersonation、MitM、Device Loss、Long-Term Authentication Key Leakage、Temporary Secret Leakage、Denial-of-Service、Physical Attacks；Batch Processing | 對 session-key semantic security 給 sequence-of-games bound，其他多為 informal security analysis |
| QPCASIN | Freshness、Semantic Security、Mutual Authentication、Forward and Backward Secrecy、Replay／Injection／MitM／Desynchronization Attacks、User Anonymity、Unlinkability、Password-Guessing resilience、DoS/DDoS detectability；Preemptive Handover 與 Continuous Authentication | QROM computational game、Scyther（Aliveness、Weak Agreement、Noninjective Agreement、Noninjective Synchronization、Secrecy／SKR）及 ProVerif（含 Injective Agreement／secrecy claims），另有 informal discussion |

QPCASIN 明確把 DoS／DDoS **prevention** 排除於範圍外，只主張 protocol-level detectability。比較時應保留此限定。相對地，PkT-SIN 與 N3PA-STIN 使用「Resistance to DDoS／Denial-of-Service Attacks」名稱，但其論述分別依賴 periodic `k` limit／detection 與將 batch verification 移往 resource-rich GS；這些 claim 的 attacker budget 與 availability definition 不能直接視為相同。

## 17. Security-property 比較

### 17.1 判讀符號

| 符號 | 意義 |
| --- | --- |
| `●` | 提供的 PDF 明確列為 requirement、theorem、analysis item 或 verified claim |
| `◐` | 有相關機制／敘述，但未以本列的精確粒度獨立定義 |
| `—` | 本次閱讀未在主要 threat／requirements／security-analysis／comparison 部分找到明確對應 |
| `C` | 本機制已有 RBBC core conditional theorem，但未組成端到端 theorem |
| `O` | 本機制已在本草稿建立 open game／proof obligation，尚未證明 |
| `A` | 本機制目前只有 profile assumption／design boundary |

`—` 不是「不安全」的判決；`●` 也不是本文件對該論文 proof correctness 的背書。

### 17.2 對齊比較矩陣

| Security property | AnFRA | PkT-SIN | N3PA-STIN | QPCASIN | 本機制目前邊界 |
| --- | :---: | :---: | :---: | :---: | --- |
| Mutual Authentication | ● | ● | ●（three-party） | ● | `O`：`G-ACCESS-AUTH` |
| Secure Key Establishment／Key Agreement | ● | ● | ● | ● | `O`：access AKE 尚未選定 |
| Session Key Semantic Security／Freshness game | ◐ | ◐ | ● | ● | `O`：`G-SESSION-FRESH` |
| Key Forward／Backward Secrecy | ● | ● | ● | ● | `O`：須固定 reveal model |
| Conditional Anonymity／Accountability | ●（group-manager reveal） | ● | ● | ◐（anonymity，未以 opening 治理為重點） | `C+O`：trace core 加 authorized opening games |
| User Anonymity | ● | ● | ● | ● | `C+O+A`：core trace privacy、access privacy open、traffic assumptions |
| Unlinkability | ● | ● | ● | ● | `C+O`：issuer unlinkability 已有 conditional reduction；access／handover 尚待證明 |
| Resistance to Replay Attacks | ●（timestamps） | ●（duplicate TIN/token） | ●（timestamps） | ●（timestamps／injective agreement） | `O`：nonce/transcript replay 加 stateful one-use |
| Atomic One-Time Ticket Consumption | — | ◐（k-time token accounting，但 semantics 不同） | — | ◐（Ticket injective agreement，但未見 distributed consume semantics） | `A+O`：profile v0.1 與 `G-ONE-CONSUME` |
| Resistance to Parallel Replay Attacks | — | — | — | — | `O`：`G-PARALLEL-REPLAY` |
| Context Substitution Resistance | — | ◐（handover/session binding） | ◐（identities/timestamps in key transcript） | ◐（session identifiers／agreement claims） | `A+O`：`G-CONTEXT-SUB` |
| Resistance to Modification／Injection Attacks | ●（modification） | ◐（MitM/integrity） | ◐（MitM／MAC binding） | ●（injection） | `O`：transcript integrity／context mutation |
| Resistance to Impersonation Attacks | ● | ● | ● | ●（masquerading） | `O`：納入 authentication winning event |
| Resistance to MitM Attacks | ● | ● | ● | ● | `O`：以 AKE／partnering game 定義 |
| Handover Authentication | ●（fast roaming） | ●（三種 handover scenarios） | — | ●（preemptive handover） | `O`：`G-HO-AUTH` |
| Handover Key Security／Privacy 分離 | ◐ | ◐ | — | ◐ | `O`：`G-HO-KEY`、`G-HO-PRIV` |
| Dynamic Joining and Revocation | ● | ◐ | ● | ●（user list／service period management） | `A+O`：authenticity、effectiveness、freshness、privacy 分開 |
| Authorized／Purpose-Limited Opening | — | ◐（dishonest-user reveal／exculpability） | ◐（NCC conditional de-anonymization） | — | `C+A+O`：gated core、governance assumption 與四個 opening games |
| Threshold Opening Privacy (`< t_O`) | — | — | — | — | `C+O`：core `τ`-GCCA；robust system composition 未封閉 |
| Non-Frameability／Exculpability | ◐（group signature基礎，但比較段未見獨立 game） | ●（Exculpability） | ◐（conditional anonymity/accountability） | — | `C+O`：honest-issuer Trace Soundness；malicious-issuer 尚未解決 |
| One-More Ticket Unforgeability | — | ◐（credential unforgeability／k-detectability，不是同一 game） | — | — | `C`：RBBC core conditional theorem |
| Resistance to Desynchronization Attacks | — | ◐（handover state update） | ◐（domain-key update） | ● | `O`：consumption／handover／revocation recovery |
| Resistance to Long-Term Key Leakage | — | ◐（session-key independence discussion） | ● | ●（reveal model） | `O`：AKE freshness/reveal model 待固定 |
| Resistance to Temporary Secret Leakage | — | — | ● | ●（reveal-state model） | `O`：AKE freshness/reveal model 待固定 |
| Resistance to Device Loss／Physical Capture | — | ●（physical capture discussion） | ● | ◐（password／state reveal） | 不在目前 core；未來 endpoint-compromise game |
| Resistance／Detectability of DoS／DDoS | — | ●（resistance） | ●（resistance） | ●（detectability；prevention out of scope） | `O+A`：只界定 conditional liveness／resource assumptions |
| Batch Processing | — | — | ● | — | 尚未列為 security claim；可作 performance／DoS mitigation design |
| Post-Quantum／Quantum-Defended Session Mechanism | —（ECC） | —（pairing／DL/DDH） | —（ECC/ECDLP） | ●（Frodo／QROM） | core 與 AKE 均以 PQ 為目標，但 production closure 仍為 false |

### 17.3 不可直接橫向等同的項目

- **Replay resistance。** AnFRA、N3PA-STIN、QPCASIN 主要以 timestamp／freshness checks 論述；PkT-SIN 以重複 token series number 偵測。本文另要求 ticket digest 的 transactional one-time consumption，因此解決的是更 stateful 的 winning event，但尚未證明或實作。
- **Unlinkability。** PkT-SIN 的 randomized Show、N3PA-STIN／QPCASIN 的 changing pseudonym，以及 RBBC 的 issuer unlinkability 對應不同 observer。本文不能用 core Issuer Unlinkability 宣稱已達成 network-wide Access Unlinkability。
- **Accountability。** AnFRA、PkT-SIN、N3PA-STIN 都具 identity reveal／accountability 概念。本文可能的差異不在「首次加入追責」，而在 authorization object、independent threshold OA、purpose/evidence binding、gated share API、serial consistency 與少於門檻 privacy 的組合。
- **Handover。** AnFRA、PkT-SIN 與 QPCASIN 已明確處理 roaming／handover；本文不能把「有 handover」本身列為新貢獻。可主張的研究問題是把 one-time ticket state、serving-context substitution、fresh target key、revocation race 與 observer-specific privacy 放入同一 composition model。
- **Post-quantum security。** QPCASIN 已明確提出 quantum-defended protocol 與 QROM analysis，因此本文不能宣稱是這組比較中唯一 PQ satellite authentication。本文的候選差異是 PQ blind accountable credential core、threshold opening 與 satellite AKE 的組合；但 fork proof、SE-NIZK backend、robust opening、AKE 與端到端 proof 均尚未封閉。
- **Formal proof。** QPCASIN 與 N3PA-STIN 有 session-key computational games，QPCASIN 另有 Scyther／ProVerif，PkT-KVAC 有 credential theorems。本文的 contribution 應以 game scope 與 composition boundary 表述，不能籠統聲稱其他工作「沒有 formal security」。

## 18. 本機制的候選 security contributions

以下是相對於這四份比較文本，值得發展成論文 contribution 的 security-analysis 方向。除標為 core conditional theorem 的部分外，目前都是 **[OPEN-GAME]**、**[PROFILE-ASSUMPTION]** 或設計主張，不是已完成成果。

### 18.1 Certified relation-bound anonymous ticket issuance

**已有 core conditional basis：**Request／Proof／Message Binding、Certified-Language Soundness、Certified Ciphertext Validity、Ticket One-More Unforgeability 與 honest-protocol HNCC 的 Issuer Unlinkability。

**相對差異：**四篇比較文獻使用 group signature、anonymous credential、pseudonym 或 encrypted/hash identity；本機制額外把 exact blind request、canonical ticket payload、holder secret、authenticated registered identity、serial 與 threshold trace ciphertext 放在同一 issuance relation 中。這個 contribution 應命名為 **Certified Relation-Bound Blind Issuance**，而不只是一般 User Anonymity。

**限制：**fork-specific blindness／one-more proof、PQ SE-NIZK backend 與 production composition 尚未封閉；不得寫成 concrete scheme 已完成證明。

### 18.2 Issuer Unlinkability 與 Access Unlinkability 的分離

**已有 core conditional basis：**Issuer Unlinkability 對 honest-but-curious HNCC 隱藏最終 ticket 與 issuance session 的配對。

**候選貢獻：**明確區分：

1. **Issuer Unlinkability**：HNCC 的 issuance view 對 final ticket 的 linkability；
2. **Access Unlinkability**：network／LEO／FLEO／FGS observer 對不同 access sessions 的 linkability；
3. **Handover Unlinkability**：handover continuity 所必要的局部 link 與全域 observer leakage。

這比單一「Unlinkability」欄位更能避免 observer confusion，但後兩者尚無 proof，fixed one-use ticket 也只避免合法重複 presentation，不消除 metadata、timing 或 routing linkability。

### 18.3 Atomic One-Time Consumption 與 Parallel Replay Resistance

**候選貢獻：**將 **Resistance to Replay Attacks** 細分成 transcript replay、consumed-ticket replay 與 parallel racing replay，並把 linearizable check-and-consume、multi-FGS split-brain、pending transaction、crash recovery 及 safety-over-availability decision 放入 game。

這四篇均談 replay resistance；PkT-SIN 甚至有 bounded-use token 與 duplicate detection。因此 contribution 不能寫成「首次 one-time／bounded-use」。較精確的說法是：在本次比較文本中，尚未看到把 distributed atomic consumption 與 parallel replay interleavings 定義成獨立 security game 的做法。

### 18.4 Serving-Context Substitution Resistance

**候選貢獻：**把 ticket `ctx`、FGS identity、dynamic serving context、roles、algorithm negotiation、channel binding、fresh nonces 與 handover source／target context 放入 canonical transcript，以 `G-CONTEXT-SUB` 統一 cross-domain、cross-epoch、cross-FGS、unknown-key-share、role confusion 與 downgrade attacks。

比較論文會把部分 identity、timestamp、satellite／GS parameters 放入 hash、signature 或 session key derivation，但本次閱讀未見以 **Context Substitution Resistance** 命名並獨立定義完整 substitution game。此點仍須在 protocol bytes 固定後才能正式比較。

### 18.5 Authorization-Gated Threshold Opening

**已有 core conditional basis：**Signature-Gated Decoder Safety、Trace Soundness、unique opening 與 `τ`-GCCA Trace Privacy。

**候選貢獻：**相較一般 Conditional Anonymity／Accountability／Dishonest User Revealing，本機制要求：

- FAC governance 與 OA decryption keys／thresholds／compromise domains 獨立；
- authorization 綁定 ticket digest、case ID、evidence digest、purpose、expiry 與 request nonce；
- OA 不暴露 bare partial-decrypt API；
- authorization replay state、robust shares、serial consistency 與 audit transcript；
- 少於 `t_O` OA 下的 certified-ticket chosen-ciphertext privacy。

較適合的 contribution 名稱是 **Authorization-Gated Threshold Opening with Purpose and Evidence Binding**。不能寫成其他論文沒有 accountability；差異在 opening governance、threshold privacy 與 API／transcript boundary 的精細程度。

### 18.6 Safety、Privacy 與 Availability 的顯式邊界

**候選貢獻：**把 anti-replay fail-closed、ticket burn、revocation staleness、OA withholding、network partition 與 DoS 分成 safety、privacy、liveness 三類，明確指出 cryptographic authentication theorem 不保證 jamming／permanent partition 下 availability。

QPCASIN 已明確區分 DoS/DDoS detectability 與 prevention，PkT-SIN／N3PA-STIN 也提出 mitigation。因此本文的差異應表述為 **explicit compositional boundary and failure semantics**，不是聲稱率先考慮 availability。

### 18.7 可用於論文摘要的保守表述

在所有 open games 與 implementation 尚未封閉前，可使用：

> 本研究提出一個端到端 security-game framework，將既有衛星認證文獻常用的 Mutual Authentication、Secure Key Establishment、Conditional Anonymity、Unlinkability、Forward/Backward Secrecy、Replay Resistance、Handover Authentication 與 Revocation，進一步細分為 issuer-versus-access unlinkability、atomic one-time consumption、parallel replay resistance、serving-context substitution resistance，以及 authorization-gated threshold opening。此 framework 明確區分 RBBC core 的 conditional theorems、system assumptions、待證 games 與 implementation evidence。

只有在相關 games、reductions、concrete instantiations 與 evidence 均完成後，才可改寫為「本機制 achieves／proves」。目前不宜使用「首次」、「唯一」、「全面優於」或「其他論文皆未考慮」等無法由四份 PDF 充分支持的措辭。
