# 第十六堂：為什麼採用離線發行、在線驗證

日期：2026-09-15。所屬階段：4／設計取捨。
接續 [第十五堂](15_END_TO_END_AND_DATA_VISIBILITY_zh-TW.md) 的完整生命週期，現在開始回答
「為什麼要這樣設計」。第一個取捨是：為什麼不在每次衛星接入時都向 HNCC 查詢使用者資格，
而要先發行票券，日後由 FGS 驗證。

## 1. 真正比較的是「哪些工作留在接入關鍵路徑」

本堂比較兩種架構位置，不是比較電腦有沒有連上網路：

| 方案 | 接入前 | 每次接入時 |
| --- | --- | --- |
| 每次在線查 HNCC（比較基準） | 不一定預先取得匿名票券 | FGS 需把接入相關資料送往 HNCC，等待身分／資格結果，再決定是否建立 session |
| 本專案：離線發行、在線驗證 | UE 先與 HNCC 完成身分認證、發行 NIZK 與盲簽署 | UE 出示票券；FGS 驗票、驗持票者、服務條件與 AKE，再處理一次性狀態 |

第一列是用來分析取捨的 hypothetical baseline，不是本 repository 已定義或實作的另一套正式協定。
「離線發行」也不是完全不通訊，而是把發行移出每次 access 的 latency-critical path。

## 2. 為什麼每次查 HNCC 看起來很簡單

若每次接入都查 HNCC，直覺流程是：FGS 收到請求後，把使用者帳號或可辨識憑證送給 HNCC；
HNCC 查詢註冊、付款、撤銷或服務資格，再回覆允許／拒絕。

它的優點是集中：

- HNCC 可使用最新的帳戶與資格資料；
- 不需要 UE 預先保存多張票券；
- 許多政策可以集中修改，不必等待票券到期。

但這種簡單把代價放進每一次接入，而且讓 HNCC 更容易知道哪位註冊使用者在什麼時間使用服務。

## 3. 為什麼本專案把發行移到接入前

### 3.1 減少接入時的 HNCC backhaul dependency

若 FGS 必須等待 HNCC 回覆，接入時間會多出 FGS–HNCC 的網路往返、HNCC 查詢與排隊時間。
HNCC 無法連線或壅塞時，合法使用者也可能不能接入。

預先發行票券後，FGS 可利用已認證的共同設定與 issuer verification key 驗票，不需要在線詢問
HNCC「這是不是小明」。這把註冊身分驗證、發行 NIZK 與盲簽署的成本移到接入前。

但這不表示接入完全沒有 backhaul。嚴格一次性票券仍需要權威 replay state；多個 FGS 若共享
線性一致 store，Reserve／Commit 可能仍要等待地面網路。離線發行移除的是 **HNCC 身分／資格查詢**，
不是自動移除所有後端狀態存取。

### 3.2 避免 HNCC 直接觀察每次使用

HNCC 在註冊與發行時知道 `rid`，這是它的責任。若每次接入又回到 HNCC 查詢，它便能直接累積
「這個 `rid` 在何時、向哪個服務環境接入」的紀錄，issuer unlinkability 很難成立。

盲發行將這兩段分開：HNCC 認證 `rid` 並核准一份隱藏票券關係；日後 FGS 只收到最終票券。
在相應 blindness、NIZK、共同 metadata 與 timing assumptions 下，HNCC 不應能把發行 session
對應到最終票券及其使用。

這不是保證所有參與者都看不見使用紀錄。FGS 仍看到票券、`sn`、serving context 與 session；
衛星與網路觀察者仍可能看到 timing、位置、流量及路徑 metadata。

### 3.3 把重型工作留在地面與非即時階段

發行關係需要綁定 hidden ticket、blind request、holder secret、已認證 `rid`、`sn` 與 trace
ciphertext。相關 NIZK／Blind-UOV 工作可能很重，不適合讓資源受限且不預設可信的 LEO／FLEO
在每次接入時處理。

本架構讓 HNCC 與 UE 在接入前完成發行；接入時較重的 policy verification、anti-replay 與
session endpoint 工作原則上放在 FGS。衛星只中繼，或執行未來協定明確指定且可驗證的輕量子集。

## 4. NIZK 在兩個階段扮演不同角色

這裡最容易產生誤解：本專案已有的 `pi_issue` 是 **發行 NIZK**。它讓 HNCC 在看不到隱藏票券
與秘密見證時，驗證 I1–I5。因為它位於離線發行，所以不會直接減少目前 access draft 的訊息數。

若要減少衛星接入往返，需要另外定義 **access holder authenticator**。一個候選是讓 UE 在第一則
訊息中附上 NIZK／Fiat–Shamir 型證明，證明掌握 `k_hold`，並綁定 ticket、serving context、UE
freshness、key share 及可接受的時段或預先認證資料。這可能讓 FGS 不必先回傳逐次 challenge。

然而，首則證明仍需處理：

- 如何判定 freshness，以及接受窗口多大；
- 舊證明被完整複製時，如何由一次性狀態拒絕；
- 攻擊者搶先轉送合法首則訊息時，session key 與端點如何綁定；
- FGS prekey／時段資料如何認證、更新與避免重用；
- 成功 session 與 ticket consumption 如何原子提交。

所以「NIZK 非互動」能移除證明內的即時 challenge 往返，不能單獨提供完整的 access freshness、
anti-replay、AKE 或 distributed state consistency。

## 5. 把接入延遲拆開，才知道優化了哪裡

先用符號分解，不代入尚未量測的數字：

- `RTT_sat`：UE 經衛星與 FGS 完成一次請求／回應的往返時間；
- `T_verify`：FGS 的 parsing、ticket、holder authenticator、policy 與 AKE 驗證時間；
- `T_state`：權威 replay store 執行 Reserve／Commit 的等待；
- `T_HNCC`：若每次在線查 HNCC，額外的地面 backhaul、排隊與查詢時間。

概念上可以這樣比較：

```text
每次查 HNCC
  = satellite message schedule + T_verify + T_HNCC + T_state

離線發行、在線驗證
  = satellite message schedule + T_verify + T_state
```

目前四訊息 draft 從 `AccessInit` 到 `AccessAccept` 的時序約包含兩次 `RTT_sat`；這是由訊息順序
推得的概念成本，不是 benchmark。若首則 access authenticator 與 AKE 能安全完成，兩訊息候選
可把衛星交換降為約一次 `RTT_sat`，但 `T_verify` 與 `T_state` 仍存在。

是否值得使用較大的 NIZK，必須比較「多出的 proof bytes／proving／verification time」與
「少掉的一次衛星 RTT」，不能只看到訊息數下降就宣稱端到端一定更快。

## 6. 離線發行換來的新成本

| 成本 | 為什麼出現 | 本專案目前的處理方向 |
| --- | --- | --- |
| UE 票券庫存 | 接入時不再臨時向 HNCC 取票 | 預先取得足夠的短效票券；wallet policy 尚未完成 |
| 過期與撤銷散布 | FGS 不能每次直接問 HNCC 最新帳戶狀態 | short-lived ticket、可信時間與受認證 revocation data；distribution 未完成 |
| 一次性使用狀態 | 固定票券沒有 unlinkable reusable `Show` | FGS 以 digest／`sn` 原子消耗；production distributed store 未完成 |
| 裝置遺失／秘密外洩 | 票券與 `k_hold` 保存在 UE | revocation、wallet protection 與 recovery policy 仍需完成 |
| 發行高峰與預取 | 成本由接入時移到較早時段 | 應分開量測 issuance latency、ticket inventory 與 availability |

因此，離線發行並沒有消除工作，而是把工作重新放到較適合的位置，並用票券效期、撤銷、庫存與
消耗狀態管理它。這是 latency、privacy、availability、storage 與 policy freshness 的綜合取捨。

## 7. 三種失敗情境能看出差別

### HNCC 暫時無法連線

- 每次在線查詢：通常無法確認資格，接入需 fail closed。
- 離線票券：若 FGS 有可信設定、所需撤銷資料且可存取 replay state，仍可能驗證既有票券。

### Replay store 無法連線

- 即使 HNCC 正常，strictly one-use 的 FGS 仍不能安全建立新 session。
- 因此離線發行不能解決所有 ground-network partition。

### 使用者資格剛被撤銷

- 在線 HNCC 查詢較容易立即反映最新狀態。
- 離線票券取決於短效期、撤銷更新散布速度與 FGS 的 snapshot freshness；這是降低在線依賴的代價。

## 8. 為什麼不能只快取「HNCC 說可以」

若快取內容包含固定帳號或可辨識 identifier，FGS 與 HNCC 仍可能把後續活動連回 `rid`。若快取
沒有明確 expiry、context、service policy、holder binding 與防重放語意，又可能被搬到其他環境、
過期後沿用或由只有副本的人使用。

本專案的票券不是任意快取結果：它具有 canonical fields、issuer signature、holder binding、
context／policy、visible serial 及 trace ciphertext，並搭配 holder authentication 與 lifecycle state。
這些額外機制正是離線驗證仍能維持授權與追責邊界所付出的複雜度。

## 9. 目前正式設計與實作邊界

| 項目 | 目前可說的狀態 |
| --- | --- |
| 離線發行、在線驗證 | 已是架構與 methodology 的設計原則 |
| 發行關係與大型 PQ-RBBC 工程 | 有 executable relation、circuit／producer checkpoints 與局部證據；不等於完整 production issuance |
| 在線 ticket/access objects | canonical framing 與四種 draft codecs 已實作／測試 |
| 發行 NIZK `pi_issue` | 正式 relation 已定義；合格 PQ SE-NIZK backend 尚未封閉 |
| Access holder authenticator／PQ AKE | suite-bound interface 已保留，production primitive 與完整協定尚未選定 |
| 一次性 replay state | 單程序 reference 已測試；durable／distributed backend 尚未完成 |
| 低 RTT access 候選 | 已記錄需求與候選條件，尚未成為 canonical protocol，也沒有端到端 benchmark |

本堂是在解釋既有設計理由，沒有新增 D-編號決策、修改正式 access protocol 或產生效能結果。
正式依據見 [methodology](../../methodology.md)、[architecture M2／M5／M6](../../ARCHITECTURE_zh-TW.md)、
[一次性票券規格](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md) 與
[接入延遲補充](../notes/ACCESS_LATENCY_AND_NIZK_zh-TW.md)；完成程度仍以
[研究狀態](../../RESEARCH_STATUS_zh-TW.md) 為準。

## 10. 口試時可以怎麼回答

> 我們將身分認證、發行關係證明與盲簽署移到接入前，讓 FGS 日後用票券完成在線驗證。
> 這樣可避免每次透過 backhaul 向 HNCC 查詢身分，降低 HNCC 在線依賴，也避免 HNCC 直接建立
> 註冊身分與每次使用的對應。代價是 UE 必須預取短效票券，FGS 必須維護撤銷與一次性消耗狀態。
> 發行 NIZK 不會自動減少 access RTT；若要單往返，還需另外設計首則 holder authenticator、
> freshness、PQ AKE 與原子 replay state，並以端到端實驗比較 proof 成本和省下的衛星 RTT。

下一堂繼續階段四：比較目前選擇的 short-lived、strictly one-use ticket 與 reusable anonymous
`Show`，說明一次性設計如何處理固定票券可連結問題，以及它在庫存、狀態與可用性上的代價。
