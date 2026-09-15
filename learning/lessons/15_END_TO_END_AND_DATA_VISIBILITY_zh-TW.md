# 第十五堂：完整生命週期與資料可見性總整理

日期：2026-09-15。所屬階段：3／完整系統流程總整理。
前面六堂分別拆解設定、發行、接入、一次性狀態、換手與受控開啟。這一堂把它們放回同一個
案例，重點不是再記一組新公式，而是隨時回答三個問題：**現在在哪個階段、誰正在處理、誰能看見什麼。**

## 1. 先看完整生命週期

以小明申請一張票券並使用衛星服務為例，整體分成四段：

1. Operator 與 FAC 建立可信的共同設定及有限發行授權。
2. 小明的 UE 與 HNCC 完成註冊認證及離線盲發行，票券與持票者秘密留在 UE。
3. UE 經衛星向 FGS 接入；所有檢查通過後，session 與一次性消耗狀態共同提交。
4. 正常連線可按 session 授權換手；發生合格案件時，另走 authorization-gated threshold opening。

「另走」很重要：conditional opening 不是每次接入的最後一步，也不在衛星在線驗證路徑中。
下列流程中的箭頭表示資料與狀態相依，不表示已固定的訊息數或網路往返數。

## 2. 第一段：設定決定後面所有人要相信什麼

Operator 提出 epoch、domain、policy、expiry bucket 與 serving rules；FAC 成員依獨立門檻機制
認證共同設定及 HNCC 的發行授權。共同設定形成 `ctx`，並指定 issuer 與 opening key identifiers。

這段的輸出不是使用者票券，而是後面各方共同接受的規則與信任起點。HNCC 不能替每位使用者
產生獨特的公開 metadata，否則後續即使使用盲簽章，也可能從這個 watermark 連結發行與使用。

## 3. 第二段：HNCC 知道申請者，但不應知道最後是哪張票券

小明註冊時，HNCC 必須知道並認證他的 `rid`。UE 在裝置內產生：

- 持票者秘密 `k_hold`；
- 票券序號 `sn`；
- 摘要 `h = H(k_hold)`；
- 加密 `(rid, sn)` 的追責密文 `C`；
- 盲化與追責加密所需的隨機資料。

UE 使用發行 NIZK 證明 I1–I5：隱藏票券格式正確、使用相同 `ctx`、盲化請求確實對應這份票券、
`h` 綁定持票者秘密，而且 `C` 加密 HNCC 此次已認證的 `rid` 與同一個 `sn`。HNCC 驗證後回傳
盲簽署回應 `z`；UE 在本機 Finalize 並驗簽，得到 `T = (M, sigma)`。

在正式協定資料邊界中，`sn`、`h`、`C` 與完整 `M` 是隱藏發行見證的一部分。HNCC 看見 `rid`、
`sid`、`ctx`、公開盲化請求與 `pi_issue`，不應看見最後可出示的 `T`。這是 issuer unlinkability
想保護的關係：HNCC 知道小明曾申請，卻不應能把該次發行紀錄對應到日後出示的票券。

目前 reference `IssueStatement` 含完整 payload，不能直接當成正式網路輸入；否則會破壞上述
邊界。它是本機關係／電路工程物件，不是已凍結的 issuance wire message。

## 4. 第三段：FGS 看見票券，但不取得註冊身分

接入時，UE 將最終票券及該次 access authentication／key establishment 所需資料經衛星送到 FGS。
`pi_issue`、`rid`、`sid` 與 `k_hold` 不會作為明文附件送給 FGS。

FGS 需要完成：

1. canonical parsing、版本與長度檢查；
2. 票券簽章、`ctx`、epoch、policy、expiry 與 revocation 檢查；
3. 驗證 UE 能證明掌握與 `h` 綁定的 `k_hold`，但不取得秘密本身；
4. 將 holder authentication、serving context、freshness 與 PQ AKE transcript 綁在同一次接入；
5. 前面通過後，才對票券執行原子 Reserve／Commit。

成功時，session、受保護接受結果與 `CONSUMED` 狀態需要共同可靠提交。驗證失敗不消耗票券；
不同 attempt 競爭只有一個 winner；相同 attempt 的合法重試只能恢復原結果。

現有四種 `Access*V1` 是接入草稿的 codec 與時序表示，並不是所有安全設計的必要往返下界。
首則附 NIZK 的單往返候選仍待正式選擇與驗證；無論訊息怎麼減少，跨 FGS 的權威消耗狀態
仍可能產生 replay-store backhaul delay。

## 5. Session 可被連結，換手延續的是同一份 session

票券一次性限制的是建立 initial session 的次數。連線建立後，FGS 會知道後續活動屬於同一份
session；這種連續性是維護通訊狀態所需的，不應誤稱為「同一 session 內完全不可連結」。

換手時，UE 使用由原 session 導出的 authorization，綁定目標 serving context、新鮮值與 handover
sequence。新端點核驗的是既有 session 的合法延續，不是讓 `CONSUMED` 票券重新建立 initial session。
無法核驗換手授權時，應改用另一張尚未使用的票券執行 full access。

## 6. 第四段：案件開啟是票券的獨立例外分支

開啟請求 `Q` 綁定確切票券、case、evidence、purpose、expiry、nonce、設定與 key IDs。每位 OA
先驗票、驗 authorization、期限及 opening replay，通過後才產生綁定同一 `Q` 的 share。

Combiner 需要至少 `t_O` 位不同 OA 的有效一致份額，再重建 `(rid, sn)`；最後仍要驗證 trace
authentication，並確認解密 `sn` 等於票券公開 `sn`。正常接入的 FGS 不會因為系統支援 opening，
就自動取得 `rid`。開啟也不會恢復裝置內的 `k_hold`。

## 7. 四項敏感資料要一直分開追蹤

| 資料 | 何時產生／出現 | 哪些角色能取得 | 不能混淆成什麼 |
| --- | --- | --- | --- |
| `rid` | 註冊時已存在；發行時綁入追責密文 | UE、註冊時的 HNCC；合格開啟後的受授權結果接收者 | 不是 FGS 的日常登入名稱，也不是 holder secret |
| `k_hold` | UE 為票券取樣 | 正常協定中只留在 UE；FGS 驗證掌握證明 | 不在票券追責明文中，也不能直接傳給 FGS |
| `sn` | UE 為每張票券新取樣 | 最終票券中可見，因此 UE、FGS 及能讀票券者可見；開啟明文也含同一值 | 不等於真實身分；同一票券重送仍可用它連結 |
| `C` | UE 發行時建立的 trace ciphertext | 位於最終票券中，可被看到；明文只在合格 threshold opening 後恢復 | 看見密文不等於知道 `rid`，也不等於可以任意解密 |

這四項資料分工解釋了為什麼系統同時需要 holder authentication 與 conditional opening：前者證明
「目前裝置掌握票券秘密」，後者在合格案件中恢復「發行時已認證的註冊身分」。

## 8. 逐角色的資料可見性

| 角色 | 正常能看見的資料 | 不應自動取得／仍有限制的資料 |
| --- | --- | --- |
| UE | 自己的 `rid`、`k_hold`、`sn`、發行 witness、最終 `T`、session state | 裝置被控制或秘密外洩後的安全需另行處理 |
| HNCC | 註冊 `rid`、`sid`、共同設定、公開發行 statement／request、`pi_issue` | 不應取得隱藏 `M`、`k_hold` 或可連到最終 `T` 的個人化 metadata |
| FGS／replay store | 最終 `T`、可見 `sn`、access transcript、serving context、consumption 與 session state | 正常接入不取得 `rid` 或 `k_hold`；仍可連結同票券重送與同 session 活動 |
| LEO／FLEO | 經過的協定 bytes、時間、路徑與流量等可觀察資料；可讀範圍由通道設計決定 | 不持有 issuer／OA secret keys；中繼本身不保證內容機密性或流量不可連結 |
| FAC | 共同設定、issuer authorization；開啟治理所需的案件授權資料 | FAC authorization 不是 OA 解密份額；具體案件治理流程仍未完成 |
| 單一 OA | 完整 `Q`、自己的 OA key/share 與本機 replay 狀態 | 未達 `t_O` 不能單獨重建 `rid`；不得提供任意 ciphertext 的解密 API |
| Combiner／結果接收者 | 達門檻的一致 shares；終點檢查通過後取得 `(rid, sn)` | 身分輸出後仍需 purpose-limited access、audit 與保存政策 |

## 9. 「匿名與不可連結」要附上觀察者和時間範圍

不能只說「系統是匿名的」，而要說對誰、在哪一段：

- **對 HNCC：**目標是不能把已知身分的發行紀錄連到最終票券及後續出示；仍依賴盲簽章、
  發行 NIZK、共用 metadata 與明確的 timing assumptions。
- **對 FGS：**正常接入不揭露 `rid`，但 FGS 看得到固定票券、`sn` 與 session；同一票券重送可連結，
  所以 v0.1 選擇短效且一次性，而不是允許同票券多次匿名出示。
- **對衛星路徑觀察者：**是否看得到票券內容取決於通道；即使內容加密，時間、位置、封包大小與
  路徑 metadata 仍可能形成連結線索。
- **對 OA：**低於門檻的成員集合不應恢復身分；達門檻且授權有效的開啟本來就會輸出身分。

因此，盲簽章解決的是發行紀錄與最終票券的連結，holder authentication 解決的是持票者資格，
one-time state 解決的是重複建立 session，threshold opening 解決的是受控追責。它們不能互相替代。

## 10. 整套系統不是由一個測試或一個 proof 一次證完

| 流程 | 已有的工程／證據邊界 | 仍未封閉的主要部分 |
| --- | --- | --- |
| 設定與 issuer authorization | versioned objects、驗證順序、quota／replay 管理邊界與測試 | production FAC threshold signature、DKG、distributed quota／deployment |
| PQ-RBBC 發行核心 | executable relation、native/circuit／producer 工程、checkpoint 與部分 proof work | 合格 PQ SE-NIZK backend、完整 Blind-UOV production Prove／Verify、proof closure |
| Satellite access | `Access*V1`／framing codecs、transcript identities、reference replay state 與測試 | holder authenticator、PQ AKE、正式低 RTT 協定、durable distributed store |
| Revocation／handover | one-time state 規格中已有要求 | revocation distribution、session policy、handover specification／implementation |
| Conditional opening | canonical request/share、bounded gate、replay 與 combiner control-flow tests | production PQ authorization、OA DKG／keys、robust decoder、share proof、audit transcript |

這張表同時保留 Defined、Implemented、Tested 與 Production-closed 的差別。某段測試通過，只支持
該測試所涵蓋的資料或控制流程；不能自動提升整套衛星認證、匿名性或門檻密碼學宣稱。

## 11. 階段三結束時應能說出的版本

可以用以下順序向口試委員解釋：

> 系統先由 FAC 認證共同設定及 HNCC 的有限發行權。HNCC 在註冊時知道使用者身分，但 UE 透過
> 關係綁定的盲發行取得最終票券，使發行紀錄不應能連到後續出示。接入時，FGS 驗證票券、
> 持票者、服務環境與金鑰建立，不取得註冊身分；成功 session 與一次性消耗狀態共同提交。
> Handover 延續既有 session，不重用票券。只有合格案件授權與足夠 OA 份額同時成立時，才受控
> 恢復票券綁定的 `rid` 與 `sn`。

本堂提供了階段三所需的完整說明，但「教材已提供」不等於學習者已獨立畫圖或口述驗證。
正式對照入口是 [架構的協定階段](../../ARCHITECTURE_zh-TW.md)、
[Protocol 到實作導覽](../../docs/guides/PROTOCOL_TO_IMPLEMENTATION_GUIDE_zh-TW.md)、
[一次性票券規格](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md)、
[Conditional Opening Gate](../../docs/artifacts/CONDITIONAL_OPENING_GATE_v0_1_zh-TW.md) 及
[研究狀態](../../RESEARCH_STATUS_zh-TW.md)。

下一堂進入階段四，分析高成本 PQ 運算的前移邊界：哪些 issuance work 可在接入前完成，
哪些 freshness、holder authentication、PQ AKE 與 replay state 必須留在衛星在線路徑。
