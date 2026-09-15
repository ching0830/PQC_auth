# 第二十堂：角色分離、最小權限與共謀邊界

日期：2026-09-15。所屬階段：4／設計取捨。
接續[第十九堂](19_BLIND_VS_ORDINARY_ISSUANCE_zh-TW.md)，本堂分析為什麼發行、接入驗證、
治理授權與身分開啟不交給同一個角色，以及「避免共謀」在安全設計中究竟能做到什麼程度。

## 1. 角色分離不是增加名稱，而是分開敏感能力

系統內最敏感的三種能力是：

1. **知道註冊身分並發行票券。**HNCC 在 enrollment／issuance 時知道 `rid`，並持有 issuer
   signing key。
2. **看到使用活動並建立 session。**FGS 看見 ticket、時間、serving context、session 與
   consumption state。
3. **把特定票券開啟為註冊身分。**OA members 持有 threshold decryption shares。

若同一方同時擁有三種能力，它可以從註冊、發行一路追蹤到每次接入，並直接開啟身分。Blind
issuance、FGS anonymity 和 threshold opening 的分界都會失去意義。

角色分離採用兩個常見安全原則：

- **Least privilege（最小權限）：**每個元件只取得完成工作所需的最少資料、金鑰與操作。
- **Separation of duties（職責分離）：**高風險操作必須跨不同權限完成，不讓單一角色自行批准、
  執行並驗證自己的行為。

這些原則降低單一元件失陷的影響範圍，不能保證所有角色永遠不共謀。

## 2. 每個角色應該知道什麼、不能做什麼

| 角色 | 正常責任與可見資料 | 不應單獨具有的能力 |
| --- | --- | --- |
| UE／holder | 保存 `k_hold`、票券與 session state；提出 issuance／access request | 發行簽章、修改共同 policy、產生 OA shares |
| Operator | 提出共同 epoch、domain、policy、expiry bucket、serving rules | 自己宣稱設定可信、任意為單一 UE 改 metadata、持有全部治理／開啟秘密 |
| FAC／federation governance | 認證共同 configuration 與 HNCC 的 issuer grant／quota | 直接發行票券、看到每次 access、持有 OA decryption threshold |
| HNCC | 驗證 `rid`、issuance policy／quota、`pi_issue`，回傳 blind-signing response | 跟蹤每次 access、持有 OA shares、任意個人化共同 metadata |
| FGS | 驗票、執行 holder authentication／PQ AKE、維護 anti-replay state、建立 session | 取得註冊 `rid`、自行發票、取得 issuer／OA secret keys |
| OA member | 驗 opening request／authorization，產生自己的一份 `OpenShare` | 單獨解密、處理任意裸 ciphertext、看到所有 access logs |
| LEO／FLEO | 中繼或執行協定明確指定的輕量檢查 | 保存 issuer、FAC、OA secrets，或成為 consumption state 唯一權威 |

Operator「提出 policy」與 FAC「認證 policy」不同。如果接收端直接相信 Operator 提供的公鑰和
自簽設定，攻擊者也能產生自己的公鑰及惡意設定。Verifier 必須先持有 out-of-band federation trust
anchor，再驗證 initialization bundle。

## 3. 三條正常資料路徑

### 3.1 治理與發行

```text
Operator 提出共同設定
→ FAC／governance 認證 configuration 與 bounded issuer grant
→ HNCC 只能在指定 ctx、epoch、policy、quota、expiry 內發行
```

FAC 不替 HNCC 產生每張票券，HNCC 也不能自行擴張自己的授權。

### 3.2 日常接入

```text
UE → LEO／FLEO relay → FGS
FGS 驗 ticket、holder、context、freshness、state、PQ AKE
→ 建立 session
```

HNCC 和 OA 不在正常 satellite online path。這同時減少延遲依賴和日常身分資料集中。

### 3.3 例外開啟

```text
特定 ticket + case + evidence + purpose
→ OPENING_AUTHORIZATION key role 驗證案件授權
→ 至少 t_O 個 OA 各自產生有效 share
→ Combiner 重建並核對 rid、sn
```

「案件可開啟」和「具有解密 share」是兩道不同的門。單有授權沒有 shares 不能解密；湊到 shares
卻沒有有效授權，也不應從正常 `OpenShareService` 取得輸出。

## 4. 把角色合併會發生什麼

### HNCC 與 FGS 合併

同一系統同時持有 enrollment／issuance 資料和完整 access metadata，traffic correlation、時間配對
及個人化 policy 的風險提高。Blindness 在 honest-protocol、common-metadata 模型下仍可保護確切
ticket 配對，但無法阻止同一營運域利用位置、時間、路由與裝置資訊做推測。

### FGS 與足夠 OA shares 合併

FGS 本來看見每次出示的 ticket。若它同時控制至少 `t_O` 份 opening secrets，就能對看到的票券
執行開啟，FGS anonymity 的主要邊界失效。

### Opening authorization 與足夠 OA shares 合併

同一控制域既能批准案件，又能完成解密，會讓「先審查目的／證據，再由獨立成員開啟」退化成
自行批准、自行解密。即使 wire format 仍有兩種 key，若人員、管理帳號、HSM 或 root seed 完全
相同，實際 compromise domain 仍可能沒有分開。

### FAC 與 HNCC issuer 合併

同一方可以替自己擴張 issuer grant、quota 或 epoch，削弱 federation authorization 的意義。
Verifier 仍需由外部 trust anchor 驗證 grant，不能把 HNCC 自己宣告的權限當成可信。

### 把高價值 secrets 放到 LEO／FLEO

衛星端暴露、更新困難且可能被捕獲。若保存 issuer 或 opening secrets，單一衛星 compromise 的
影響會從中繼服務擴大為大量偽造或身分開啟。因此目前只允許 relay 或明確的輕量檢查。

## 5. 相同 organization 不等於可以共用同一把 key

Architecture 允許 FAC 與 OA 由相同 organizations 營運，這是部署彈性；但仍要求以下項目獨立：

- key pair／secret shares；
- threshold `t_F` 與 `t_O`；
- DKG／key ceremony；
- storage 與存取帳號；
- rotation／revocation；
- audit log；
- compromise domain。

`Compromise domain` 是「一次入侵或管理失誤可能同時控制的範圍」。例如兩個服務使用不同 key ID，
但 secret keys 都由同一 root seed 推導並放在同一未隔離伺服器，形式上有兩把 key，實際上仍可能
一次全部失陷。

所以要分清三個層次：

```text
Organization：誰營運
Protocol role：協定中允許做什麼
Key role：哪一把 key 只能認證／解密哪一類資料
```

同一 organization 可以承擔多個 protocol roles，但論文必須誠實列出這會讓哪些腐化事件相關。

## 6. 目前程式如何固定 key-role separation

`SystemInitializationBundle` 要求五種 public key roles 各出現一次：

1. `FEDERATION_CONFIGURATION`
2. `ISSUER_AUTHORIZATION`
3. `OPENING_AUTHORIZATION`
4. `ISSUER_VERIFICATION`
5. `OPENING_ENCRYPTION`

目前 contract 要求各角色的 key ID 與 public-key digest 彼此不同，FAC 與 OA 的 member count／
threshold 也分開編碼。後續模組只取得相符 role 的 public reference：

- issuer grant 只能由 `ISSUER_AUTHORIZATION` role 驗證；
- opening case 只能由 `OPENING_AUTHORIZATION` role 驗證；
- ticket 使用 `ISSUER_VERIFICATION` role；
- opening shares 對應 `OPENING_ENCRYPTION` role。

這能阻止「拿一把已知但用途錯誤的 key，去驗證另一種訊息」。Domain-separated message encoding
則進一步阻止相同 bytes 在不同角色間被重新解讀。

不過目前 bundle 只保存 public key identity／digest，相關 production PQ signature、FAC／OA DKG、
真正 secret storage 與 ceremony 仍未完成。Codec 和 wrong-role negative tests 支持介面分離，不能
證明真實組織、硬體或管理權限已隔離。

## 7. 角色分離如何處理共謀

角色分離的目標不是聲稱「無法共謀」，而是把安全結論寫成明確條件：

- 少於 `t_O` 個 OA 被控制時，攻擊者不應能開啟身分。
- 達到或超過 `t_O` 個 OA secrets 被控制時，threshold privacy 假設失效。
- Curious HNCC 與 FGS 分享 ticket contents 時，issuer unlinkability 仍依賴 blind issuance 與共同
  metadata；若再加入 traffic observation，只能在額外網路假設下分析。
- HNCC 若完全惡意，現有 trace soundness／non-frameability 不涵蓋 issuer framing。
- FGS 若完全惡意，one-time acceptance、revocation enforcement 與 AKE endpoint authentication
  通常也不能由現有設計保證。

Threshold 的作用是把「攻陷一個節點」提升成「必須取得至少指定數量的獨立 shares」。如果部署上
所有 shares 都受同一管理員、同一 root account 或同一備份檔控制，數學門檻仍存在，實際獨立性卻
大幅降低。

## 8. 分離帶來的成本

- 系統要管理更多 keys、certificates、key IDs、rotation 和 revocation。
- FAC／OA 需要 DKG、ceremony、成員更換及 threshold availability。
- Opening 要等待授權與足夠 OA members，可能因成員離線而失敗。
- 多個組織間的 audit、incident response 與版本同步更複雜。
- 設定錯誤或 key-role mismatch 必須 fail closed，可能降低 availability。

這些成本大多在 initialization、issuance governance 或 exceptional opening，不必加入每次 satellite
access。正常接入只需要 FGS 已取得並驗證的共同設定、票券資料、撤銷資訊和 state backend。

## 9. 目前實作與宣稱邊界

| 項目 | 目前狀態 |
| --- | --- |
| 五種 public key roles、唯一 key IDs／digests、FAC／OA threshold shape | 已由 canonical contracts 實作／測試 |
| Authenticated initialization 與外部 pinned trust anchor | 介面與 deterministic tests 已有；production PQ authentication 未完成 |
| Bounded issuer grant、role check、quota／replay reference | 已實作／測試單程序 prototype；FAC threshold backend 未完成 |
| Opening request、authorization role check、share gate／combiner control flow | 已實作／測試抽象 backend 邊界；production threshold opening 未完成 |
| 真實 FAC／OA DKG、ceremony、HSM／storage isolation | 尚未完成 |
| 組織共謀與部署 compromise-domain 證據 | 尚未建立 |

正式依據見 [architecture roles](../../ARCHITECTURE_zh-TW.md#角色)、
[system initialization contracts](../../docs/artifacts/SYSTEM_INITIALIZATION_CONTRACTS_v0_1_zh-TW.md)、
[issuer authorization](../../docs/artifacts/ISSUER_AUTHORIZATION_v0_1_zh-TW.md) 與
[conditional opening gate](../../docs/artifacts/CONDITIONAL_OPENING_GATE_v0_1_zh-TW.md)。

## 10. 口試時可以怎麼回答

> 本系統把知道註冊身分並發票的 HNCC、看到日常使用並建立 session 的 FGS，以及持有身分開啟
> shares 的 OA 分開。FAC／governance 另外認證共同設定與 issuer grant，Operator 只能提出 policy，
> LEO／FLEO 不保存高價值秘密。這遵循 least privilege 與 separation of duties，使單一 compromise
> 不會同時取得身分、使用紀錄和開啟能力。角色分離不會消滅共謀；安全主張必須明列少於 `t_O`
> OA、honest-protocol HNCC、正確 FGS 等假設。即使同一組織營運多個角色，其 keys、thresholds、
> ceremonies、storage、rotation 和 compromise domains 仍須獨立。目前程式已固定 public key-role
> separation 與 fail-closed control flow，但 production PQ backends、DKG、真實 key isolation 及部署
> 共謀證據尚未完成。

下一堂分析地面站與衛星的工作分配：為什麼 LEO／FLEO 主要中繼，而較重的驗證、state 與 session
工作放在 FGS，以及這個選擇如何影響 latency、backhaul、信任與可用性。
