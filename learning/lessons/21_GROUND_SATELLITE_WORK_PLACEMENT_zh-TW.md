# 第二十一堂：地面站與衛星的工作分配——延遲、狀態與信任

日期：2026-09-15。所屬階段：4／設計取捨。
接續[第二十堂](20_ROLE_SEPARATION_AND_COLLUSION_zh-TW.md)，本堂以作者確認的組織拓撲為前提，
回答兩個不同問題：

1. HGS、FGS 與 LEO／FLEO 分別屬於哪個組織？
2. 票券驗證、持票者認證、Replay state 與 session establishment 實際在哪裡執行？

第一題是行政隸屬，上一堂已經固定。第二題是 **work／computation placement**，會直接影響延遲、
backhaul、可用性與失陷後果。本堂不把兩者混成同一張圖。

## 1. 目前可以確定的工作配置

| 元件 | 行政歸屬 | 目前 access 草稿中的工作 |
| --- | --- | --- |
| UE | 使用者端 | 保存 ticket／`k_hold`，產生 holder authenticator、UE freshness 與 key-agreement data，核驗 FGS 回應 |
| HGS | HNCC | 行政歸屬已確認；canonical protocol 尚未指定 access／issuance 的確切工作 |
| HNCC | Home NCC | 在接入前完成註冊與 blind issuance；不參與每次 visited access |
| LEO／FLEO | Satellite operator | 中繼 access messages，或執行日後明確指定的輕量檢查；不維護權威 ticket-consumption state |
| FGS | 其他／受訪 NCC | 驗 ticket、policy、context、holder、freshness、revocation 與 access transcript，作為 PQ AKE／session endpoint |
| Replay backend | FGS acceptance domain 的地面後端 | 原子執行 `Reserve`／`Commit`，確保一張票券最多建立一個 initial session |

FAC／OA 位於最高治理組織，但不加入每次正常 access。它們負責共同設定、發行授權與例外 opening，
不是為每次連線即時回答身分查詢的後端。

## 2. 為什麼目前把較重工作放在 FGS

### 2.1 FGS 比衛星更適合更新與擴充驗證程式

後量子 signature、holder authenticator、PQ AKE、policy 和 revocation 都可能需要較多計算、記憶體
與較大的資料。地面機房通常較容易：

- 增加 CPU／記憶體或水平擴充服務；
- 更新 suite、public keys、revocation snapshot 與安全修補；
- 保存 audit、session 和 failure-recovery state；
- 連接需要交易語意的資料庫。

這是部署上的工程理由，不是密碼學定理。之後仍要用相同硬體條件的 benchmark 證明實際成本。

### 2.2 Strictly one-use 需要一個共同裁決點

`VerifyTicket(T)` 是 stateless：兩台 verifier 各自驗同一張合法 ticket，都可能得到 `True`。要限制
只建立一個 initial session，還要有權威狀態：

```text
UNSEEN → RESERVED → CONSUMED
```

同一 acceptance domain 的 FGS 必須共享 linearizable replay store，或把每張票券確定地送到唯一
single writer。若把權威狀態分散到快速移動、可能斷線的多顆衛星，兩顆衛星可能在尚未同步時各自
接受同一張票券。此時只有三種誠實選擇：

1. 等待跨節點一致性，承擔額外通訊延遲；
2. 網路分割時 fail closed，犧牲 availability；
3. 允許暫時重複接受，將安全目標降為事後偵測。

v0.1 選擇前兩者的組合：權威狀態在 FGS acceptance domain；無法可靠取得狀態時不建立新 session。

### 2.3 FGS 本來就是 session 的另一端

依目前架構，UE 最後要和 FGS 建立受保護 session。FGS 因而必須核對 access transcript、自己的
身分、key share、key confirmation 與 serving context。若衛星只驗 ticket，FGS 仍需完成 session
authentication 和 state commit；把第一層驗證搬到衛星未必能縮短 UE 收到可用 session 的時間。

## 3. 「衛星只中繼」不表示衛星完全不做密碼學

論文目前談的是**使用者 access authentication 的責任**。真實衛星系統本身還可能需要鏈路層認證、
路由保護、控制訊息驗證與設備管理；這些是 satellite operator 的基礎設施安全，不能和本論文的
ticket／holder verification 混為一件事。

即使只看本論文，未來也可把一個已驗證的輕量子集交給 LEO，例如：

- canonical frame 與最大長度檢查；
- suite／epoch 的快速 allow-list；
- 明顯過期或錯誤 context 的早期拒絕；
- 在成本可接受時，用公開 verification key 做初步 ticket check。

Signature verification 使用 public key，不需要把 issuer secret key 放上衛星。因此「衛星驗簽」的
主要代價不是 issuer key 洩漏，而是：衛星需要可靠取得最新 configuration／revocation data、執行
額外計算，且 FGS 之後仍可能要重新驗證並提交權威狀態。這種 early rejection 可減少惡意流量進入
地面端，卻不一定減少正常使用者的端到端 RTT。

衛星仍不應取得 issuer signing key、OA shares，或成為唯一權威 consumption store。若將來要改變
這一點，必須重新定義 trust model、state consistency、key rotation 與衛星失陷後的復原方式。

## 4. 驗證放在 FGS，仍然可以把兩次 RTT 降成一次

**驗證位置**和**訊息往返數**是兩個獨立設計軸。

### 現有四訊息草稿：約 2 RTT

1. UE 經 LEO／FLEO 傳 `AccessInit` 給 FGS。
2. FGS 回傳含 `fgs_nonce` 的 `AccessChallenge`。
3. UE 依 challenge 產生 holder authenticator，傳 `AccessFinish`。
4. FGS 驗證、提交 state，回傳 `AccessAccept`。

從 UE 第一次送出申請，到 UE 收到接受結果，共經過四段 UE–FGS 單向路徑，也就是約兩個 RTT。

### 首則請求附接入 NIZK 的候選：約 1 RTT

1. UE 預先取得並驗證必要的共同設定、FGS 身分及短期 prekey／時段資料。
2. UE 第一則請求直接帶 ticket、serving context、UE freshness、key-agreement data 與 access NIZK。
3. FGS 核驗 ticket、holder relation、freshness、PQ AKE binding 和 replay state，提交唯一 session。
4. FGS 回傳受認證的接受結果與 key confirmation，UE 核驗後使用 session。

這仍然是 **UE → satellite relay → FGS → satellite relay → UE**。密碼驗證與權威狀態都可留在 FGS，
只是 UE 不必先等一個逐次 `fgs_nonce` 才產生 holder proof。

接入 NIZK 必須是另一個正式定義的 relation；不能把離線發行的 `pi_issue` 原封不動重用。它至少要
綁定 ticket、holder secret relation、目標 FGS／serving context、有效期間、UE request identity 與
key-agreement data。若沒有逐次 challenge，短期 prekey、共同時段值、接受窗口與 one-use state
共同承擔 freshness／Replay 邊界。

這個一往返形狀目前是**候選設計**，尚未進入 canonical architecture；production access NIZK、PQ
AKE、編碼、安全模型與 benchmark 都還沒有完成。

## 5. 三種延遲不能只叫做 backhaul

為了避免量測時把不同網路段混在一起，本論文至少要分開：

| 延遲 | 端點 | 是否仍存在 |
| --- | --- | --- |
| Satellite-path delay | UE ↔ LEO／FLEO ↔ FGS | 一往返候選仍有 1 RTT；四訊息草稿約 2 RTT |
| State-backhaul delay | FGS ↔ authoritative replay／session backend | Strictly one-use 仍需要，除非 backend 與 FGS 共置或採唯一 writer 配置 |
| Home-domain lookup delay | FGS ↔ HNCC／HGS | 目前日常 access 不需要；發行已在接入前完成 |

令 `d_path` 表示一次 UE 到 FGS 的單向傳播，`d_state` 表示一次權威狀態交易等待，`c_UE`、`c_FGS`
表示兩端在線計算。只看成功且不重試的簡化模型：

\[
L_{4msg}\approx4d_{path}+c_{UE}+c_{FGS}+d_{state}
\]

\[
L_{2msg}\approx2d_{path}+c'_{UE}+c'_{FGS}+d_{state}
\]

其中 access NIZK 可能讓 `c'_UE`、`c'_FGS` 和第一則訊息 bytes 變大。它省下的是約
`2d_path`，不會自動把 `d_state` 變成零。因此是否真的更快，要量測 proof generation、verification、
transmission 和 state transaction 的總和。

## 6. 如何另外降低 state-backhaul delay

這一部分不能只靠 NIZK，因為 NIZK 證明關係成立，無法告訴 FGS「另一台 FGS 是否剛剛已經接受
同一張票券」。可評估的工程方法包括：

### 將 state backend 與 FGS 共置

FGS 在本地機房完成資料庫交易，可降低正常延遲。但多個 FGS 共享 acceptance domain 時，replicas
仍需提供 linearizable consistency；只採 eventual consistency 會留下雙重接受窗口。

### 依 ticket identity 分片到唯一 writer

用 canonical `use_key` 決定唯一負責的 shard／FGS，使同一 ticket 不會由兩個 writer 同時裁決。
代價是請求可能需要地面轉送到 owner，故障移轉也必須保證舊、新 writer 不會同時接受。

### 縮小 acceptance domain

票券只允許在特定 FGS／區域使用，可讓狀態局部化。代價是漫遊彈性下降，serving context 也可能
提供更多可連結 metadata。

### 改成 offline double-spend detection

各站先接受，事後合併紀錄找出重複使用，可以降低同步等待，但安全語意已從「阻止第二次成功」
變成「允許後再偵測」。這不符合目前 strictly one-use 的 v0.1 claim，不能只當成資料庫優化。

## 7. HGS 在這張配置圖中的位置

HGS 隸屬 HNCC 已經確定；它是否承擔下列任一工作，仍待正式決策：

- 作為 UE 聯絡 HNCC 進行 enrollment／offline issuance 的網路入口；
- 散布 home-domain configuration 或 ticket inventory；
- 提供衛星鏈路／控制面的營運功能；
- 參與某些 visited access 或 handover 訊息。

這些選項不能當成同一件事。如果每次 visited access 都必須通知 HGS，home domain 會看到接入時間、
路徑或目的地 metadata，也重新加入 latency-critical path，影響對 HNCC 的匿名／不可連結性與
availability。若 HGS 只參與接入前發行，它的成本屬於 offline phase，不直接增加每次 access RTT。

因此正式規格 HGS 時，至少要填四欄：收到什麼、驗證什麼、保存什麼、失聯時是否阻止 access。
在這四欄完成前，只能宣稱它的行政歸屬，不能宣稱其協定安全性或效能。

## 8. 目前實作與宣稱邊界

| 項目 | 目前狀態 |
| --- | --- |
| FGS 作為 verifier／session endpoint；LEO／FLEO 不保存權威 consumption state | canonical architecture／draft state spec 已定義 |
| `AccessInit`、`AccessChallenge`、`AccessFinish`、`AccessAccept` 的 codecs／transcript digest | 已實作並有 object／binding tests |
| 真正 ticket／holder verification、PQ AKE 與 key confirmation | 尚未實作；目前對應欄位仍是 test-only opaque bytes |
| Linearizable replay store | 有 process-local reference model；durable／distributed backend 尚未完成 |
| 首則 access NIZK 的一往返候選 | 已在學習筆記記錄需求，尚未成為 canonical protocol |
| HGS 的 protocol role | 尚未定義／實作 |
| Satellite／state-backhaul 端到端 latency benchmark | 尚未完成 |

正式依據見 [architecture roles／M5／M6](../../ARCHITECTURE_zh-TW.md)、
[one-time ticket state](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md)、
[access latency note](../notes/ACCESS_LATENCY_AND_NIZK_zh-TW.md) 與
[research status](../../RESEARCH_STATUS_zh-TW.md)。

## 9. 口試時可以怎麼回答

> 我的預定部署中，HGS 隸屬 HNCC，FGS 隸屬其他 NCC，NCC 與 satellite operator 合作；這是行政
> 拓撲。協定的工作放置則另行決定。目前 v0.1 讓 LEO／FLEO 中繼，FGS 負責較重的票券、policy、
> holder、revocation、PQ AKE 與 session 驗證，並透過地面權威狀態原子消耗 one-use ticket。這樣較
> 容易更新運算資源和維護跨 FGS 一致性。若要把四訊息草稿的約 2 RTT 降為約 1 RTT，不必把驗證
> 搬到衛星；可以讓 UE 在首則申請附上綁定 serving context、freshness 與 key agreement 的 access
> NIZK，仍由 FGS 驗證及提交 state。這會省下一次衛星 challenge 往返，但不會消除 FGS 到權威
> replay backend 的 state-backhaul delay。後者需要共置、唯一 writer 或縮小 acceptance domain 等
> 工程設計，並各自承擔一致性、可用性或漫遊限制。

下一堂分析 short-lived ticket 的有效期、預先發行數量與補充策略，理解降低在線成本之後，為什麼
UE 端會出現票券庫存、過期浪費、斷線可用性與隱私 metadata 的新取捨。
