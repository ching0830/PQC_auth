# 第十六堂：後量子計算前移——離線發行、在線驗證

日期：2026-09-15。所屬階段：4／設計取捨。
接續 [第十五堂](15_END_TO_END_AND_DATA_VISIBILITY_zh-TW.md) 的完整生命週期，現在開始回答
「為什麼要這樣設計」。本堂依學習者更正，將**主要理由**放回後量子運算成本與接入延遲。

## 1. 先修正「比較基準」的說法

上一版以「每次 FGS 都向 HNCC 查詢」作為比較基準，這個標示不正確。它至多是一個用來思考
模組位置的反事實設計，不是論文實驗或相關研究的 baseline。

論文需要比較的是實際衛星認證論文，而且每篇機制的角色、訊息、信任假設與驗證位置可能不同。
不能先把它們都改畫成「FGS 查 HNCC」，再拿本專案比較。正式比較要逐篇核對原協定後，使用
共同但公平的量測軸；本 repository 的 PQ satellite authentication 文獻整理目前仍列為未開始。

## 2. 本專案的主要動機：把重型 PQ 運算提前完成

後量子 signature、NIZK、blind-signature proof 與相關有限體／多項式計算，通常會帶來較大的
運算量、proof／signature bytes 或記憶體需求。衛星接入又受到長傳播時間、短接觸窗口與資源受限
節點影響，因此每次接入才執行全部重型工作，可能使 latency 與負載過高。

本專案採用的核心想法是：

> 只要某項計算不依賴這次接入才知道的新資料，就盡量在接入前完成；只有必須核對當下端點、
> 時間、服務環境、session key 與使用狀態的工作留在衛星在線路徑。

「離線發行」是 computation placement，也就是運算時點的選擇。它不是宣稱發行過程沒有網路，
也不是把整個驗證都提前算完。

## 3. 哪些工作可以前移

在 UE 還沒有發出本次接入請求前，可以完成：

1. HNCC 對 `rid` 的註冊身分認證。
2. UE 產生 `k_hold`、`sn`、追責密文 `C`、blind randomness 與 hidden ticket `M`。
3. UE 計算發行關係的 `pi_issue`，HNCC 驗證 I1–I5。
4. HNCC 產生 blind-signing response，UE 執行 Finalize 並驗證最終票券 `T`。
5. UE 在有效期與庫存政策內保存多張待用票券。

這些工作主要依賴註冊身分、共同設定與票券本身，不需要知道未來會連到哪一個 FGS、當時的
freshness 或那次 session key。因此可以在網路條件較好、裝置有時間或接入需求尚未發生時完成。

## 4. 哪些工作不能全部前移

接入當下仍需處理：

- 目前要連線的 serving context 與 FGS；
- 這次請求的 freshness，避免把舊認證當成新請求；
- 票券 signature、policy、expiry 與 revocation；
- UE 對 `k_hold` 的持有者認證；
- UE 與 FGS 的 PQ AKE、key confirmation 及 session key；
- authoritative replay state 的 Reserve／Commit。

原因是這些資料在票券發行時尚未確定，或必須反映接入當下的真實狀態。若把未來 FGS、nonce
或 session key 全部預先固定，可能限制可連線端點、增加重用風險，或失去新鮮性與前向安全性。

所以本專案不是「把驗證全部離線化」，而是把**可預先完成的重型 issuance work**移出在線路徑，
保留**必須依賴當下資料的 access work**。

## 5. Replay 是什麼

Replay 中文通常稱為**重放攻擊**：攻擊者把先前網路上曾經有效的訊息完整保存，之後再次送出，
企圖讓驗證者把舊訊息當成一個新的合法請求。

例如：

1. 小明正常傳送接入訊息 `A`，FGS 驗證成功。
2. 攻擊者不需要知道 `k_hold`，只要在網路上複製 `A`。
3. 攻擊者稍後再次傳送完全相同的 `A`。
4. 如果 FGS 只檢查「signature／NIZK 是否有效」，舊的 `A` 仍可能通過，因為它原本就是真的。

Replay 與 forgery 不同。Forgery 是製造一份原本不存在的有效訊息；replay 使用的可能是百分之百
真實、簽章也正確的舊訊息。這正是為什麼「密碼學驗證成功」不等於「這是新的請求」。

### 5.1 為什麼 NIZK 不會自動防 Replay

NIZK 證明的是某個 statement 符合 relation。若 statement 永遠相同，昨天的有效 proof 今天仍會
對同一 statement 驗證成功。要限制重放，statement 必須綁定適當的 freshness、serving context、
key share／session 資料與 ticket；驗證端也需要判斷該票券或請求是否已經使用。

時間戳或 UE 自己產生的 nonce 只能協助區分／限制時間，不能單獨阻止攻擊者在接受窗口內複製
同一份訊息。FGS 必須保存或查詢權威狀態，才能知道「這份有效資料已經成功使用過」。

### 5.2 本專案在哪裡防 Replay

- **Access replay：**以 ticket digest、`sn`、context 與 transcript 形成使用 identity，透過
  `UNSEEN → RESERVED → CONSUMED` 阻止同一張票券建立第二個 initial session。
- **Issuance replay：**發行端使用 `sid` 及授權／quota state，避免同一發行流程被重複接受。
- **Opening replay：**case、nonce、authorization key 等形成 opening replay key，避免相同案件
  請求反覆取得 OA shares。
- **Handover replay：**規格要求綁定原 session、目標 context、新鮮值與單調 sequence。

合法 retry 也會重送資料，所以系統不能把所有重複封包都叫做攻擊。同一 `attempt_id` 的合法重試
應恢復同一結果；另一個 attempt 使用同一張已消耗票券，才應拒絕建立新 session。

### 5.3 Repository 裡還有另一種「replay」用法

本 repository 的 PQ-RBBC 工程文件常出現 `relation replay`、`row replay` 或 `aggregate replay`。
這時通常不是網路攻擊，而是**把已保存的 assignment／中間結果重新代入限制式執行檢查**，確認
同一批計算仍符合 relation。這是一種可重現驗證工作。

閱讀時可用上下文區分：

- `access replay`、`replay attack`、`anti-replay`、`replay store`：在談舊協定訊息被再次使用；
- `relation replay`、`rows replayed`、`aggregate replay`：在談重新執行計算／限制檢查。

兩者英文相同，但安全問題與工程用途完全不同。

## 6. NIZK 與減少衛星往返的正確關係

本專案已有的 `pi_issue` 是**發行 NIZK**。它可能很重，所以正適合移到接入前；它不會直接改變
目前 `AccessInit → Challenge → Finish → Accept` 的四訊息時序。

若要把約兩次衛星 RTT 的草稿改成約一次 RTT，還需要另一個 **access holder authenticator**。
一個候選是讓 UE 在第一則訊息附上 NIZK／Fiat–Shamir 型證明，綁定 ticket、serving context、
UE freshness、key share 與受認證的時段／prekey 資料，使 FGS 不必先回傳逐次 proof challenge。

即使如此，下列工作仍然存在：

- FGS 的 proof／ticket／policy verification time；
- PQ AKE 與 key confirmation 的安全組合；
- 完整複製或搶先轉送第一則訊息的處理；
- replay-store Reserve／Commit；
- 兩訊息回應是否足以完成雙方要求的 authentication 與 key confirmation。

因此，NIZK 可以用更多本機計算與 proof bytes 換取較少的衛星互動。是否真的更快，要比較省下的
一個衛星 RTT 與增加的 proving、transmission、verification 及 state 等待，不能只比較訊息數。

## 7. 延遲應按「離線／在線」分開量測

### 接入前成本

- identity verification；
- ticket／trace ciphertext／blind request 建立；
- `pi_issue` proving 與 verification；
- Blind-UOV response、Finalize 與 ticket storage。

### 衛星在線成本

- message count、online transmitted bytes 與衛星 RTT；
- UE／FGS 的 holder authentication、ticket verification 與 PQ AKE；
- FGS policy／revocation processing；
- authoritative replay-store latency；
- session commit 與接受回應。

這種報告方式才能展示「哪些大型運算被前移，以及在線還剩多少」。若把 offline issuance time 與
online access latency 混成單一數字，就無法驗證本設計的主要主張。

目前四訊息草稿約含兩個 `RTT_sat`，兩訊息候選約含一個 `RTT_sat`；兩者都是由訊息順序推得，
尚不是本專案的端到端 benchmark。

## 8. 計算前移帶來的其他效益與代價

隱私效益是 HNCC 不必加入每次接入，因此不會因在線查詢直接建立 `rid → 每次使用` 的資料表。
FGS 仍能看到票券、`sn`、serving context 與 session，衛星路徑也可能洩漏 timing／位置 metadata。

系統還需承擔：

- UE 預先取得與安全保存短效票券；
- 票券過期、庫存不足與發行高峰的 availability；
- revocation data 預先散布及 freshness；
- distributed replay state 的一致性與 backhaul；
- 裝置遺失或 `k_hold` 外洩後的處理。

因此，主要理由是降低 PQ 在線計算與衛星關鍵路徑負擔；減少 HNCC 在線依賴及改善 issuer
unlinkability 是同一配置帶來的重要效益，而不是用來取代主要運算動機的唯一說法。

## 9. 與其他衛星驗證論文應如何比較

真正的 related-work／evaluation baseline 必須來自已核對的實際論文。每篇機制即使流程不同，
仍可在共同維度上比較：

1. 角色、信任假設與認證發生位置；
2. 是否後量子，以及使用哪些 primitive／security level；
3. 是否允許 precomputation，預先計算了哪些項目；
4. 接入訊息數、online bytes 與衛星 RTT；
5. UE、衛星、FGS／地面端各自的 online computation；
6. 是否需要 ground backhaul，以及位於哪個協定時點；
7. identity privacy、unlinkability、traceability 與 replay protection；
8. storage、state、revocation、handover 與 failure assumptions；
9. benchmark 硬體、網路模型、資料集與計時範圍是否可比。

流程不同不代表不能比較；它表示不能只比一個總時間或把對方重畫成本專案的角色。文獻沒有報告
的數值應標成未報告，不能自行補值。尚未核對實際衛星論文前，本堂不列出虛構 baseline 名稱或結果。

## 10. 目前正式設計與實作邊界

| 項目 | 目前可說的狀態 |
| --- | --- |
| 將 high-cost identity verification／issuance relation 移出衛星在線路徑 | 已是 methodology 與 architecture 的設計原則 |
| 發行關係與 PQ-RBBC 工程 | 有 executable relation、circuit／producer checkpoints 與局部證據；不等於完整 production issuance |
| 發行 NIZK `pi_issue` | 正式 relation 已定義；合格 PQ SE-NIZK backend 尚未封閉 |
| Satellite access | canonical framing 與四種 draft codecs 已實作／測試；holder authenticator、PQ AKE 尚未選定 |
| Replay state | 單程序 reference 已測試；durable／distributed backend 尚未完成 |
| 低 RTT access 候選 | 已記錄需求與必要條件，尚未成為 canonical protocol，沒有端到端 benchmark |
| 衛星論文比較 | 文獻追蹤仍待建立，尚無可宣稱的正式 baseline 結果 |

本堂修正學習教材，不新增 D-編號決策，也不改寫 integration lane 管理的 canonical 文件。
正式依據見 [methodology](../../methodology.md)、[architecture M2／M5／M6](../../ARCHITECTURE_zh-TW.md)、
[一次性票券規格](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md) 與
[接入延遲補充](../notes/ACCESS_LATENCY_AND_NIZK_zh-TW.md)；完成程度仍以
[研究狀態](../../RESEARCH_STATUS_zh-TW.md) 為準。

## 11. 口試時可以怎麼回答

> 後量子密碼學元件通常具有較高的運算、通訊或記憶體成本，所以本機制把不依賴當次接入的
> 身分認證、票券建構、發行 NIZK 與盲簽署提前完成。衛星在線階段只保留必須綁定當下 FGS、
> serving context、freshness、PQ AKE 與 replay state 的工作。這項配置也讓 HNCC 不必參與每次
> 接入，有助於 issuer unlinkability；代價是票券庫存、撤銷散布與一致消耗狀態。正式效能比較
> 會使用實際衛星驗證論文，依相同 security level、online computation、bytes、RTT、backhaul、
> precomputation 與硬體範圍比較，不假設其他論文都採用 HNCC 在線查詢。

下一堂先建立「如何公平比較流程不同的衛星認證論文」的方法，再回到 one-use ticket 與 reusable
anonymous `Show` 的設計取捨。
