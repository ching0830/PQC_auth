# 第十七堂：流程不同，怎麼公平比較衛星認證論文

日期：2026-09-15。所屬階段：4／設計取捨。
接續[第十六堂](16_OFFLINE_ISSUANCE_ONLINE_VERIFICATION_zh-TW.md)，本堂回答：其他衛星認證
論文的角色與流程和本研究不同，還能不能比較？答案是可以，但必須先固定比較事件、成本邊界及
證據等級，不能只把各篇論文的總時間放在一起排名。

## 1. Related work、comparison paper 與 baseline 不完全相同

- **Related work（相關研究）**：用來說明研究領域已經解決哪些問題、還有哪些缺口。
- **Comparison paper（比較論文）**：挑選出來進行機制、安全性或效能比較的論文。
- **Baseline（比較基準）**：具有清楚設定、輸入、參數與量測方法，能作為本研究參考點的方案。

一篇論文可以是 related work，卻不一定能直接成為數值 baseline。例如只有作者報告的總延遲，
卻沒有相同硬體、security level 或計時範圍，就可以整理其機制與作者報告值，但不能把該數字和
本機實測值直接相減後宣稱快了多少。

所以在論文正式寫作中，現階段把以下四篇稱為**候選比較論文**較準確。只有在量測條件和重現
方法固定後，才把其中某個實作或模型稱為 performance baseline。

## 2. 目前四篇候選論文真的在做什麼

| 論文 | 主要事件／研究焦點 | 與本研究不同之處 |
| --- | --- | --- |
| AnFRA | Space Information Network 的匿名快速 roaming authentication | 主要焦點是 roaming；不能直接把其 roaming delay 當成本研究 initial access delay |
| PkT-SIN | 使用 PkT-KVAC，讓使用者在每個期間內最多匿名認證 `k` 次，並處理 handover | `k`-time token 與本研究每張票券一次消耗的狀態語意不同 |
| N3PA-STIN | user、satellite、ground station 的三方認證；以 one-time pseudonym、batch verification 處理隱私與大量請求 | 驗證角色及批次成本模型不同；batch throughput 不能直接當單一請求 latency |
| QPCASIN | Frodo-based quantum-defended、continuous authentication 與 preemptive handover | 同樣有 PQ 目標，但研究事件與 primitive 組合不同；不能宣稱本研究是唯一 PQ 衛星認證 |
| 本研究 | 接入前完成 blind accountable ticket issuance；接入時驗票、holder authentication、PQ AKE 與一次性消耗；另有授權門檻 opening | 發行 NIZK、access authenticator、PQ AKE、distributed replay state 與完整 proof 尚未全部封閉 |

這裡的用途是先辨認每篇論文自己的問題，沒有把四篇協定重畫成本研究的 HNCC–FGS 流程。
論文資訊來源是 [AnFRA](https://doi.org/10.1109/TIFS.2018.2854740)、
[PkT-SIN](https://doi.org/10.1109/TIFS.2024.3409070)、
[N3PA-STIN](https://doi.org/10.1109/JIOT.2025.3527214) 與
[QPCASIN](https://doi.org/10.1109/TIFS.2025.3583246)。專案已有一份依使用者提供 PDF 建立的
[security-property 對齊草稿](../../docs/security/END_TO_END_SECURITY_GAMES_DRAFT_zh-TW.md#16-衛星認證文獻的-security-property-術語對齊)，
但正式 bibliography、完整 protocol extraction 與可重現效能 baseline 尚未封閉。

## 3. 公平比較的第一步：先選「同一事件」

衛星認證不是只有一種事件：

- **Initial access**：尚未有 session，第一次完成認證與建立 session key。
- **Roaming／handover**：已有可信 session 或先前狀態，換到另一個 satellite／FGS。
- **Continuous authentication**：session 存續期間反覆確認裝置或使用者仍可信。
- **Batch authentication**：驗證端同時處理多個使用者請求。

如果研究 A 量的是 initial access，研究 B 量的是持有舊 session key 的 handover，B 較快並不能
直接推出其完整認證機制較有效率。因為 B 可能使用 A 沒有的先前狀態。

本研究目前最適合先比較的是 **initial access**。Handover 仍是需求與 open game，尚未完成正式
協定及實測；因此可以在功能表中標出支援目標，不能拿未實作的 handover 數值參與排名。

## 4. 第二步：固定相同的在線成本邊界

本研究的主要設計主張是把昂貴 PQ issuance work 前移。因此效能表至少要分成：

1. **Precomputation／offline cost**：接入前完成的計算、通訊、儲存和有效期限。
2. **Online access cost**：從 UE 發出本次接入請求，到 UE 可使用已認證 session 的關鍵路徑。
3. **Amortized cost**：一次預先工作能服務幾次接入；例如一次產生 `n` 張票券時，哪些成本可除以 `n`。

在線延遲可先用下面的分解式建立量測表：

\[
T_{online}=T_{UE}+T_{satellite\ path}+T_{verifier}+T_{backhaul}+T_{state}+T_{queue}
\]

這是分類框架，不代表所有項目一定串行相加。若兩個工作平行執行，真正延遲取決於 critical path，
不能把所有 CPU time 重複相加。每篇論文都要標出：

- 計時起點和終點；
- 訊息數，以及每則訊息經過哪一條 satellite／ground link；
- transmitted bytes，並區分 online 與 offline；
- UE、satellite、FGS／GS、HNCC 等角色各自的 online computation；
- backhaul 或共享 state 存取是否位於接受結果之前；
- precomputed key、credential、pseudonym 或 ticket 是否已排除在 online time 之外。

「三則訊息」不一定等於「三個 RTT」。RTT 要由訊息依賴關係判斷：只有等待前一則回覆才能產生
下一則訊息時，該等待才進入 sequential critical path。

## 5. 第三步：不要把不同 primitive 的一次運算當成一樣

論文常用 `T_h`、`T_e`、`T_p` 等符號表示 hash、exponentiation、pairing 或 encryption 的成本。
但一個 hash、一次 elliptic-curve scalar multiplication、一次 pairing、一次 Frodo encapsulation，
以及一次 NIZK proof verification 的成本完全不同。

因此可以採三種證據等級：

| 等級 | 做法 | 可以支持的說法 |
| --- | --- | --- |
| A．作者原報告 | 保留原論文的硬體、參數、網路模型及計時範圍 | 「原作者報告為……」；不能直接當成本機同比實驗 |
| B．共同分析模型 | 從協定抽出 operation counts、message bytes、依賴順序，再套用同一成本表 | 可以在明列假設下比較 modeled cost |
| C．同環境實測 | 取得或重作各方案，在相同硬體、實作語言、security level 與量測程式執行 | 才能做較強的 empirical baseline 比較；仍需交代實作品質差異 |

碩士論文不一定要完整重作所有方案。合理組合通常是：

- 用機制與 security-property 表做質性比較；
- 對能可靠抽出的項目做 operation／message／RTT 模型；
- 對自己的方案做完整實測；
- 對無法重現的外部數值清楚標成 paper-reported，不冒充同環境 benchmark。

## 6. 四個容易比較錯的例子

### 6.1 AnFRA roaming 與本研究 initial access

事件不同，延遲不能直接排名。若未來本研究完成 handover，應以 handover 對 handover；現在只能
比較研究功能、信任狀態及訊息依賴，數值欄標成 N/A 或 not implemented。

### 6.2 PkT-SIN 的 `k` 次與本研究的一次性票券

兩者都限制重複使用，但 security semantics 不同。PkT-SIN 的問題是期間內最多 `k` 次匿名認證
及重複 token 辨認；本研究額外要求成功 initial access 後的 ticket 進入權威 `CONSUMED` 狀態，
並處理平行競爭。不能因兩者都有 replay resistance 就填成完全相同。

### 6.3 N3PA-STIN 的 batch verification

若一次處理 `b` 個請求，總 CPU time 除以 `b` 可以得到平均 cost，但其中一位使用者等待的 latency
還包含湊 batch、排隊和整批驗證時間。因此至少同時報告 batch size、throughput（單位時間完成的
請求數）及 per-request latency；不能只選其中最好看的數值。

### 6.4 QPCASIN 與本研究的 PQ 比較

兩者都可列在 PQ／quantum-defended 類別，但使用的 primitive、認證事件與證據狀態不同。公平的
initial-access 比較要固定 security level、計時起訖和 key-confirmation 要求。本研究的離線發行
可以排除於 online latency，但必須另報發行時間、票券大小、預存數量和過期浪費；不能讓成本消失。

## 7. 論文建議使用三張表，而不是一張總排名

### 表 A：機制與系統模型

記錄事件、角色、信任假設、認證端點、是否需要既有 session、是否 precompute、是否需要 backhaul。

### 表 B：安全目標與證據

記錄 mutual authentication、session-key security、anonymity 的 observer、unlinkability 的範圍、
accountability／opening、replay semantics、handover，以及證據是 informal analysis、symbolic tool、
computational proof、open game 或實作測試。

### 表 C：效能與量測邊界

記錄 security level、硬體、軟體、事件、online messages／bytes／RTT、各角色計算、backhaul、state、
precomputation、batch size、paper-reported／modeled／measured 標籤。

分成三張表的原因是：功能較多不代表延遲一定較低；延遲較低也不代表安全證據較完整。把三種問題
塞進單一「最佳方案」排名，反而會失去論文可以辯護的依據。

## 8. 本研究目前可以與不可以說的話

可以說：

> 本研究以 computation placement 為設計重點，將不依賴當次接入的 PQ blind issuance 與發行
> relation work 前移；效能評估將把 offline cost、online critical path 與 amortized cost 分開，
> 並依相同事件、security level、角色計算、bytes、RTT、backhaul 及 state boundary 比較。

目前不可以說：

- 「所有既有衛星認證都需要 FGS 在線查 HNCC。」
- 「本研究是第一個或唯一的 PQ 衛星認證。」
- 「其他論文沒有 replay protection／unlinkability」，只因其定義與本研究不同。
- 「本研究比四篇都快」，因為 access protocol、PQ AKE、實驗 baseline 和完整 benchmark 尚未封閉。

## 9. 閱讀一篇新論文時的抽取順序

依序回答下面九項，不要一開始只找 performance table：

1. 它解決 initial access、roaming、handover、continuous authentication，還是哪一種事件？
2. 誰認證誰？驗證發生在 satellite、GS，還是其他控制端？
3. 攻擊者能控制哪些角色、鏈路與長期／暫時秘密？
4. 哪些資料在認證前已預先取得？
5. online path 從哪裡開始，到哪裡才算完成？
6. 每個角色做哪些 primitive operations？傳送多少 bytes？
7. replay、anonymity、unlinkability、accountability 各自對哪個 observer／winning event 定義？
8. 安全結論來自 theorem、proof sketch、formal tool、informal discussion，還是 test？
9. 數值是作者報告、共同模型換算，還是相同環境重測？

只要其中一項不知道，就填 `NR`（not reported）、`NA`（not applicable）或 `OPEN`，不要自行補成
對論文有利或不利的假設。

## 10. 口試時可以怎麼回答

> 比較方案的流程不必相同，但比較事件與成本邊界必須相同。我會先保留每篇論文原本的角色、
> 訊息與安全模型，再將 initial access、roaming、handover、continuous authentication 分開。
> 效能上分開報告 offline precomputation、online critical path 與 amortized cost，並核對 security
> level、bytes、RTT、每個角色的計算、backhaul、state、batch size 及硬體。作者原報告、共同模型
> 與同環境實測會標成不同證據等級；無法對齊的項目只做質性比較或標示 N/A，不做虛假的總排名。

下一堂回到本研究本身，比較 one-use ticket 與 reusable anonymous `Show`：為什麼本研究選擇每張
票券只建立一次 initial session，以及這個選擇在不可連結性、庫存、狀態與可用性上的代價。
