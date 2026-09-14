# 第十三堂：過期、撤銷、已消耗與換手

日期：2026-09-14。所屬階段：3／完整系統流程。
接續 [第十二堂](12_ONE_TIME_TICKET_STATE_zh-TW.md)：我們已知道票券成功建立初始 session 後，
會留下 `CONSUMED` 紀錄。現在要區分三個看起來都會「不能再接入」、實際意義卻不同的原因。

## 1. 三個原因不能合併成同一個狀態

| 名稱 | 判斷依據 | 表示什麼 | 對新初始接入的結果 |
| --- | --- | --- | --- |
| `EXPIRED` | 可信時間、epoch 與票券有效期間 | 票券已超出允許使用的時間 | 拒絕 |
| `REVOKED` | 受治理的撤銷資料或 registry | 營運或安全政策已禁止這張票券／序號繼續使用 | 拒絕 |
| `CONSUMED` | 權威 replay store 的成功提交紀錄 | 票券已建立過唯一 initial session | 新 attempt 拒絕；同 attempt 只能恢復原結果 |

目前規格將 `UNSEEN`、`RESERVED`、`CONSUMED` 視為 consumption state；`EXPIRED` 與
`REVOKED` 則是 acceptance predicates，也就是每次判斷能否接受時另外檢查的條件。

這個分類很重要。票券可能同時已消耗且後來過期，也可能在尚未使用時被撤銷。
若把所有情況都改寫成一個 `INVALID`，系統就難以定義並行順序、保存期限、session 是否已存在，
以及內部稽核原因。

## 2. 過期是時間條件，不是刪除紀錄

票券只有在共同設定允許的 epoch／有效期間內才能用。FGS 需要可信時間來源，部署 profile
還要固定容許的 clock skew，也就是不同可信時鐘之間可接受的有限誤差。

`UNSEEN` 只表示 replay store 沒有使用紀錄。若票券已過期，即使狀態仍是 `UNSEEN`，
也不能建立 session。反過來說，已消耗票券後來過期，也不能將 `CONSUMED` 改回 `UNSEEN`。

規格要求 consumption record 至少保存到票券期限再加上最大時鐘誤差與 replay grace。
還要確認所有 verifier 都已拒絕相關 epoch、延遲封包已超出網路存活時間，並滿足 audit retention，
才能依政策清理紀錄。清理舊紀錄是儲存管理，不是讓舊票券恢復有效。

## 3. 撤銷是後來發生的政策決定

撤銷處理的是「票券原本可能有效，但後來不得繼續接受」。例如裝置遺失、相關金鑰疑似外洩，
或營運政策要求停止某張票券。具體誰能撤銷、撤銷物件格式、如何認證與散布，尚未完成。

FGS 在 pure validation 階段先核對一份 revocation snapshot。進入 Reserve／Commit transaction
時，還要重新確認相同或更新的 revocation generation，避免發生以下競爭：

1. FGS 查詢時尚未撤銷。
2. 管理端緊接著提交撤銷。
3. FGS 卻依舊使用舊結果建立 session。

`generation` 可理解為撤銷資料版本。重新確認版本的目的，是讓「撤銷成功」與「接入成功」
之間產生可判定的順序，不是只比較檔名或收到時間。

## 4. 撤銷與消耗同時發生時，誰先決定結果

目前草稿規定：

- 撤銷先 commit：這次初始接入必須拒絕。
- consumption 先 commit：初始 session 已經建立，票券保持 `CONSUMED`；是否立即終止既有
  session，由另外的 session-revocation policy 決定。
- 兩者競爭：由 replay／revocation store 的 serializable order 決定，並留下 audit evidence。

`serializable order` 表示多項交易的最後效果等同某個逐一執行的順序。這裡關心的不只是
兩個查詢各自是否成功，而是跨越撤銷與建立 session 的整體結果不能互相矛盾。

本規格尚未完成「票券撤銷後，既有 session 是否立刻斷線」的政策。不能從票券被撤銷，
直接推論現有連線必然已終止；也不能因 session 曾合法建立，就忽略後來的撤銷事件。

## 5. 對外只回一般拒絕，內部才保留原因

FGS 對外若精確回答「票券格式錯誤」「已撤銷」「已消耗」或「已過期」，攻擊者可能利用
差異反覆探測一張票券的生命週期。因此草稿要求外部回傳 generic reject，避免直接提供
精細分類 oracle。

內部 audit log 可以保存穩定的 reason code、digest、狀態轉移、時間、FGS identity 與
revocation generation，以支援故障調查與受控稽核；但不應保存 holder secret、session key、
裸 opening share 或不必要的完整票券。

統一錯誤文字仍不能自動消除 timing 或封包大小差異。不同拒絕路徑是否可被觀察者區分，
需要在之後的 privacy analysis 與實驗中量測。

## 6. 為什麼 handover 不能再次使用原票券

小明已在 FGS 甲成功建立 session，票券因此是 `CONSUMED`。衛星移動或服務環境改變時，
裝置可能需要轉到 FGS 乙。這稱為 handover（換手）。

如果 FGS 乙重新把原票券當作新的接入憑證，就會產生第二個 initial session，直接違反
strictly one-use。因此，handover 應使用由原 session 導出的 authorization，並綁定：

- 原本的 session；
- 目標 serving context；
- handover 的新鮮值；
- 單調處理的 handover sequence。

FGS 乙驗證的是「這是既有 session 的合法延續」，不是「這張已消耗票券又可以用一次」。
Handover 不重新呼叫 ticket consumption，也不改變原本的 `CONSUMED` 紀錄。

若無法核驗 session-derived authorization，v0.1 要求使用另一張尚未使用的新票券重新執行
full access。不能退回重用舊票券。

## 7. Handover 的隱私邊界

Handover 的目的包含不暴露註冊身分，也不在線向 HNCC 查詢小明是誰。但它是同一 session
的延續，因此參與換手的端點需要辨認「新環境承接哪一份既有 session」。不能同時把它宣稱為
對這些端點完全不可連結的新獨立連線。

註冊身分隱藏、不同票券之間的不可連結性、同一 session 的連續性，以及網路 timing／位置
metadata 是四個不同問題。後續正式 handover security game 必須清楚寫出哪些端點能串聯
這次換手，哪些觀察者仍不應取得註冊身分。

## 8. 與延遲和 backhaul 的關係

效期檢查在 FGS 已有可信時間與設定時可以本機完成。撤銷則需要足夠新鮮且受認證的撤銷資料；
它可以事先散布到 FGS，但更新延遲會影響撤銷何時真正生效。嚴格一次性使用仍需權威的
Reserve／Commit 決定，可能讓 replay-store backhaul 留在接入關鍵路徑。

Handover 的用意之一，是延續既有 session，而非每次環境改變都重新執行完整票券驗證與發行。
但目前只定義必要條件，尚未定義訊息數、PQ primitive 或延遲上限。因此不能先宣稱 handover
一定比 full access 快多少。

## 9. 目前實作到哪裡

| 部分 | 目前狀態 |
| --- | --- |
| `CONSUMED` 與 `retention_deadline` 資料欄位 | [replay.py](../../src/pq_sat_auth/replay.py) 的單程序記憶體 reference 已表示 |
| 過期與撤銷規則 | [正式草稿 §9、§11](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md) 已定義要求；access production registry／distribution 尚未實作 |
| Handover | 正式草稿只有必要邊界，[研究狀態](../../RESEARCH_STATUS_zh-TW.md) 列為未開始 |
| Session revocation | 尚待 policy、協定、實作與測試 |

本堂整理的是 Defined 規則。沒有新增 revocation／handover 程式、執行協定測試或提升安全宣稱。
下一堂將進入 conditional opening：合法接入平時不揭露註冊身分，發生合格事件時又如何由
受授權的門檻成員共同開啟。
