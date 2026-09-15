# 第二十堂：組織拓撲、角色分離與跨域關聯風險

日期：2026-09-15。所屬階段：4／設計取捨。
接續[第十九堂](19_BLIND_VS_ORDINARY_ISSUANCE_zh-TW.md)，本堂先修正一個重要觀念：
**行政組織、協定角色與密碼金鑰角色是三種不同的分類。**

前一版把 HNCC、FGS、FAC、OA 和 satellite operator 畫成彼此獨立的組織，並討論
「HNCC 與 FGS 合併」。這不符合作者確認的實際部署。正確的組織模型是：

- FAC 與 OA 是最高治理組織內的兩種功能，該組織負責管理整個系統；
- HGS 隸屬 HNCC；
- FGS 隸屬另一個 NCC；
- NCC 與 satellite operator 是合作關係；
- 衛星由 satellite operator 營運。

所以 HNCC 擁有自己的 HGS、其他 NCC 擁有自己的 FGS，都是正常的行政隸屬，不是安全分析中
臨時發生的「角色合併」。

## 1. 先分清三張地圖

### 1.1 行政組織圖：誰管理誰

最高層是同一個 federation governance organization，內含 FAC 與 OA 功能。營運層則有 home NCC
（HNCC）、其他／受訪 NCC，以及 satellite operator。HNCC 管理 HGS，其他 NCC 管理 FGS，
satellite operator 管理 LEO／FLEO；各 NCC 與 satellite operator 透過合作提供服務。

這一層回答的是：

- 員工、設備與預算屬於哪個組織？
- 哪個組織可以制定或執行管理政策？
- 發生事故時由誰負責？

### 1.2 協定角色圖：每個元件在流程中做什麼

目前研究文件已明確賦予的主要工作是：

| 協定角色 | 目前明確的工作 |
| --- | --- |
| FAC function | 認證共同設定與有界的 issuer authorization |
| OA function／members | 在案件授權與門檻條件成立後，提供 opening shares |
| HNCC | 認證註冊身分、檢查發行資格／quota／`pi_issue`，參與 blind issuance |
| FGS | 驗證 ticket、holder、serving context、freshness 與狀態，建立 session |
| LEO／FLEO | 中繼，或執行日後明確指定的輕量工作 |
| UE | 保存 `k_hold` 與票券，建立發行／接入證明並參與 session establishment |

HGS 的**行政歸屬**已由作者確認為 HNCC，但現有 canonical architecture 尚未定義 HGS 在協定中的
確切訊息、驗證、狀態或中繼責任。因此本堂只固定它「屬於 HNCC」，不猜測它一定執行哪一步。

### 1.3 金鑰角色圖：哪一把 key 能批准什麼

同一組織可以執行多個協定功能，但不同用途仍應使用不同 key roles。現在
`SystemInitializationBundle` 分開五種 public key roles：

1. `FEDERATION_CONFIGURATION`
2. `ISSUER_AUTHORIZATION`
3. `OPENING_AUTHORIZATION`
4. `ISSUER_VERIFICATION`
5. `OPENING_ENCRYPTION`

這一層回答的是：某把 key 可以驗哪一類訊息、某份 secret share 能做哪一種運算，以及一個
管理帳號失陷時會同時得到哪些能力。

## 2. FAC 與 OA 同組織，為什麼仍分成兩種功能

作者的系統把 FAC 與 OA 放在同一個最高治理組織，這是組織事實。把它們分成兩個名稱，目的不是
假裝它們來自互不相關的公司，而是區分兩種敏感操作：

- **FAC function：**認證 federation configuration 與 HNCC 的發行權限；
- **OA function：**對特定 opening case 執行身分開啟。

即使同一組織負責兩者，仍可用不同 key pairs、OA threshold shares、HSM policy、操作人員、案件
核准流程與 audit logs 限制日常誤用。例如「設定可接受」不能直接當成「准許開啟某張票券」，
`OPENING_AUTHORIZATION` 也不能代替 `OPENING_ENCRYPTION` shares。

但論文不能把這種**組織內分權**寫成「抵抗整個最高治理組織惡意」。如果同一治理組織的最高權限
可以控制 opening authorization 和至少 `t_O` 份 opening secrets，完整治理域失陷時，匿名性便不在
原本的門檻假設內。這裡能主張的強度，取決於實際的人員、設備與管理隔離，而不只 key role 名稱。

## 3. NCC、地面站與衛星營運商的正確關係

### Home domain

HNCC 與 HGS 屬於同一個 home administrative domain。HNCC 在 enrollment／issuance 時知道 `rid`、
發行資格、`sid` 與 quota。HGS 未來若會看到網路 metadata 或執行部分接入工作，這些可見資料必須
在正式協定中列出；現有文件還不能替它下結論。

### Visited／other-NCC domain

FGS 隸屬另一個 NCC。依目前 access 草稿，FGS 是驗票、holder authentication、anti-replay／
consumption state 和 session establishment 的端點。它會看到 ticket、serving context、時間與
session 資料，但正常接入不應直接取得註冊 `rid`。

### Satellite-operator domain

Satellite operator 與各 NCC 合作並營運 LEO／FLEO。衛星路徑可看到的 routing、時間、cell 或流量
metadata，不能因為 payload 使用密碼學保護就當成消失。高價值 issuer、FAC 或 OA secrets 也不應
因營運合作而自然下放到衛星。

目前程式的 `ServingContextV1` 已包含 `operator_id_digest`、`fgs_id_digest`、relay scope、cell scope、
epoch 與 policy digest，能綁定一次接入的部分服務環境。不過它沒有 HGS、home NCC 或 visited NCC
的明確欄位，也沒有編碼 FGS 與某 NCC 的行政隸屬；程式中的 digest 不能取代組織拓撲規格。

## 4. 應分析「跨域分享資料」，不是「HNCC 與 FGS 合併」

現在把三個主要資料視角分開：

| 行政域 | 可能直接看見的核心資料 | 論文要問的問題 |
| --- | --- | --- |
| Home NCC／HNCC＋HGS | 註冊與發行資料；HGS 的額外 metadata 尚待定義 | 能否把 issuance session 配到日後票券？ |
| Other NCC＋FGS | 最終 ticket、接入時間、serving context、session／consumption state | 能否得知 `rid`，或連結不同票券？ |
| Satellite operator＋LEO／FLEO | relay、cell、routing、時間與流量 metadata | 能否透過網路觀察推測使用者或行程？ |
| Federation governance organization（FAC＋OA） | configuration／authorization 與受控 opening 能力 | 哪些條件允許開啟，誰能批准與湊足 shares？ |

真正需要分析的情境是：**home-domain issuance records 與 visited-domain access records 被共同分析
時，還能推出什麼？** 這可以是兩個 NCC 合作交換資料、事件調查、資料外洩或惡意分享，不需要把
HNCC 和 FGS 描述成同一組織。

在 honest-protocol、common-metadata、HNCC 沒有 opening threshold 等條件下，blind issuance 的核心
目標仍是：即使 home domain 後來取得 visited FGS 看見的 ticket contents，也不能只靠 issuance
transcript 與 ticket 可靠配對。但是它不自動隱藏：

- 發行與接入時間；
- 位置、relay path、cell 與封包大小；
- 每位使用者不同的 policy、expiry bucket 或其他 watermark；
- HGS 未來可能觀察、但尚未被規格限制的 metadata。

所以這裡應寫成「在限定觀察資料下的 issuer unlinkability」，而不是無條件的「HNCC 與 FGS 無法
共謀」。

## 5. 正常隸屬與高風險權力集中要分開

### 正常且預期的隸屬

- HNCC 管理 HGS；
- 其他 NCC 管理 FGS；
- satellite operator 管理衛星；
- FAC 與 OA 位於同一最高治理組織。

這些關係本身不是協定漏洞。安全模型應把每個行政域原本能看到的資料算入攻擊者 view。

### 需要明列的失陷或濫用情境

- **跨 NCC 資料共享：**home issuance records 與 visited access logs 結合後，可能產生 timing／
  location correlation；blindness 只涵蓋其安全遊戲定義的密碼配對問題。
- **治理域取得完整 opening 能力：**若 opening authorization 與至少 `t_O` 份 shares 都受同一個
  可被完整控制的管理域支配，未授權開啟的風險由實際內部分權與稽核決定。
- **Visited NCC／FGS 與 opening threshold 合作：**FGS 已看見特定 ticket；取得合法 opening 或控制
  足夠 shares 時便可恢復其追責身分。兩種情況要分別記錄為授權追責與門檻失陷。
- **NCC 與 satellite operator 交換 metadata：**即使沒有 `rid`，時間、位置與路由仍可能支援統計
  關聯。
- **衛星保存高價值 secrets：**單一衛星失陷可能擴大成偽造、治理冒充或任意 opening，因此是否
  下放任何密碼功能必須另外論證。

`Collusion` 在這裡最好翻成「原本分屬不同控制邊界的參與者共同使用各自資料或秘密」。它不等於
兩個組織正式合併，也不適合用來描述 HNCC 與自己的 HGS 這種既有隸屬。

## 6. Least privilege 與 separation of duties 應套在哪裡

- **Least privilege（最小權限）：**HGS、FGS、LEO、後端服務與人員只取得其工作所需的資料和 key。
- **Separation of duties（職責分離）：**同一治理組織內，設定認證、案件批准、opening share 產生
  與結果稽核可由不同 key roles、帳號或多人門檻完成。
- **Compromise domain（共同失陷範圍）：**一次帳號、HSM、root seed、備份或管理層失陷可以同時
  控制哪些功能。

因此同一 organization 內仍能做有意義的分權，但這種分權有多強要靠部署證據支持。兩個服務即使
有不同 key ID，若 secrets 都從同一 root seed 推導並存於同一台未隔離主機，實際 compromise
domain 仍可能相同。

## 7. 目前實作與正式文件的邊界

| 項目 | 目前狀態 |
| --- | --- |
| 五種 public key roles、不同 key identities、FAC／OA threshold shape | 已由 canonical contracts 實作／測試 |
| HNCC issuance、FGS access endpoint 與 LEO／FLEO relay 的抽象流程 | 已有規格與 reference control flow；production PQ backends 未完成 |
| `ServingContextV1` 對 operator、FGS、relay／cell scope 的綁定 | 已有 test-only reference codec；deployment identifier mapping 未固定 |
| FAC 與 OA 同屬最高治理組織 | 作者已確認的預定部署；canonical 文件目前只說可由相同 organizations 營運，尚未完整畫出層級 |
| HGS 隸屬 HNCC、FGS 隸屬其他 NCC、NCC 與 satellite operator 合作 | 作者已確認的預定拓撲；尚未寫入 canonical architecture 或程式資料模型 |
| HGS 的確切協定責任與資料可見性 | 尚未定義，不能由本堂自行補造 |
| 真實 key ceremony、HSM／帳號隔離、跨組織資料治理證據 | 尚未完成 |

這個差距很重要：本堂記錄的是作者對預定系統拓撲的更正，尚不能說成 canonical architecture 已完成
該定義。正式研究文件之後需要由 integration lane 同步，並解決現有 `Operator` 名稱究竟指
satellite operator、service-policy role，或另一個治理功能，避免同名角色造成誤解。

正式現況依據見 [architecture roles](../../ARCHITECTURE_zh-TW.md#角色)、
[system initialization contracts](../../docs/artifacts/SYSTEM_INITIALIZATION_CONTRACTS_v0_1_zh-TW.md) 與
[one-time ticket state](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md)。

## 8. 口試時可以怎麼回答

> 我的組織架構有兩個層次。最高層是同一個 federation governance organization，其中包含 FAC 與
> OA 功能並管理整體系統；營運層的 HGS 隸屬 HNCC，FGS 隸屬另一個 NCC，各 NCC 與 satellite
> operator 合作，而衛星由 satellite operator 營運。這些行政關係不等於密碼功能可以共用同一把
> key。系統仍將 configuration、issuer authorization、opening authorization、issuer verification
> 與 opening encryption 分成不同 key roles，OA opening 還受案件授權與 threshold 控制。因此我不把
> HNCC 與自己的 HGS 描述成共謀，也不把 HNCC 和 FGS 寫成組織合併；我要分析的是 home-domain
> issuance data、visited-domain access data 與 satellite metadata 被跨域分享後，密碼學與流量分析
> 各能連結到什麼。目前程式已表達部分 key-role separation、HNCC／FGS 協定角色及 serving context，
> 但 HGS 的協定責任和完整組織拓撲仍待正式規格化。

下一堂分析地面站與衛星的工作分配。屆時會以這個修正後的組織拓撲為前提，分開討論 HGS、FGS
與 LEO／FLEO 的行政歸屬、協定工作、在線延遲及資料可見性；不會先替尚未定義的 HGS 工作下結論。
