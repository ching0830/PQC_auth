# 第十二堂：一次性票券的狀態、並行與失敗恢復

日期：2026-09-14。所屬階段：3／完整系統流程。
接續 [第十一堂](11_SATELLITE_ACCESS_FLOW_zh-TW.md)：地面站完成票券、持票者、服務範圍
與連線資料的必要驗證後，仍要保證同一張票券不會建立兩個初始連線。

本堂處理的不是新的密碼學公式，而是「多人同時操作時，系統如何只接受一次」。
這組狀態規則同樣適用於目前四訊息草稿，以及待評估的
[單往返候選](../notes/ACCESS_LATENCY_AND_NIZK_zh-TW.md)：改變網路訊息數量，不會自動取代
一次性使用狀態。

## 1. 為什麼「先查、成功後再寫」仍可能使用兩次

假設同一張票券的兩個不同接入嘗試，同時抵達 FGS 甲與 FGS 乙：

1. 甲查詢使用紀錄，看到「尚未使用」。
2. 乙也在甲寫入前查詢，看到「尚未使用」。
3. 甲建立 session A，然後把票券記為已使用。
4. 乙建立 session B，也把票券記為已使用。

最後的資料庫雖然顯示「已使用」，實際上已經產生兩個 session。問題不在驗票公式，
而在「檢查」與「取得唯一使用權」被拆成兩個可交錯的動作。

解法需要一個原子決定：所有競爭者看起來像依序完成同一個 `Reserve` 操作，只有一個
不同 attempt 能從尚無紀錄變成已預留。這種對外可視為單一先後順序的性質稱為
linearizability（線性一致性）。它不表示所有電腦真的在同一瞬間執行，而是不能讓兩個
競爭者都觀察到自己成功取得唯一使用權。

## 2. 三個狀態分別表示什麼

| 狀態 | 白話意思 | 不能誤解成什麼 |
| --- | --- | --- |
| `UNSEEN` | 權威使用紀錄中沒有這張票券的紀錄，可以進入驗證 | 不代表票券、證明、期限或服務授權一定有效 |
| `RESERVED` | 一個已通過必要驗證的 attempt 暫時取得唯一建立 session 的資格 | 不代表 session 已可靠建立，也不能讓另一個 attempt 接手 |
| `CONSUMED` | 唯一 session、接受回應與使用紀錄已可靠共同提交 | 不代表刪掉票券 bytes；狀態不得回復供新 session 使用 |

`EXPIRED` 與 `REVOKED` 在目前規格中是另外檢查的接受條件，不是第四、第五個可來回轉移
的 consumption state。即使 store 中是 `UNSEEN`，過期或被撤銷的票券仍然必須拒絕。

## 3. 為什麼要先完成驗證，再 Reserve

FGS 應先完成格式、共同設定、期限、服務環境、票券簽章、撤銷狀態、持票者認證、
接入 transcript 與金鑰確認等必要檢查。任一項失敗，都不建立 reservation。

這個順序可避免旁觀者只複製票券或送出錯誤資料，就長時間占住合法使用者的票券。
在現有四訊息草稿中，`AccessInit` 只能觸發初步驗證與 challenge，不能 reserve 或 consume。
若未來改成首則附 access NIZK 的單往返候選，也必須先驗證足以證明持票者與通道控制的
資料，才可以進入原子使用狀態；具體接受點須由新版協定重新定義。

## 4. Reserve：決定哪一個 attempt 可以繼續

一次接入嘗試由 `attempt_id` 與綁定內容的 `transcript_digest` 辨認。兩種重送必須分開：

- **不同 attempt 使用同一張票券：**可能是競爭、重放或另一個新連線要求。只有第一個
  原子 Reserve 的 winner 可以繼續，其他 attempt 拒絕。
- **同一 attempt、同一 transcript 重送：**可能是封包或回應遺失。系統回到同一筆
  reservation 或已提交結果，不建立第二個 worker 或 session。相同操作重做仍得到相同
  邏輯結果，稱為 idempotency（冪等性）。

系統以 `use_key` 尋找使用紀錄。它由 `ctx`、票券序號 `sn` 與 ticket digest 共同導出；
reference store 另外保存序號與 digest 的交叉索引。相同序號卻搭配不同 digest，或相同
digest 卻搭配不同序號時，會 fail closed，而不是猜測哪一份才正確。

使用紀錄不需要保存註冊身分 `rid`，但 FGS／權威 store 能辨認同一張票券的重試與競爭。
這是 v0.1 為執行 strictly one-use 所接受的連結邊界；同一票券的失敗重送不是不可連結的
multi-show。短效且一次性的不同票券仍須避免帶有可跨票券串聯的個人化 metadata。

## 5. Commit：成功狀態必須一起留下

Reserve 成功後，FGS 才能為該 attempt 建立 session。接著必須在同一個可靠提交邊界中保存：

- `session_id` 與 session record；
- 接受回應的 digest，以及密封回應或足以重建相同回應的狀態；
- 票券的 `CONSUMED` transition。

這三項不能分開留下。例如先讓 session 生效，程式卻在寫入 `CONSUMED` 前中斷，重新啟動後
便可能把同一張票券再次接受。相反地，先寫已消耗、但沒有保存 session 或可恢復回應，
合法使用者可能永久失去票券，卻拿不到成功連線。

規格要求 commit 完成後才傳送 `AccessAccept`。因此「Accept 沒有抵達 UE」不等於 FGS
沒有成功：地面站可能已經提交 session，只是最後一個封包在衛星路徑遺失。

## 6. 回應遺失時，為什麼不能重新建立 session

小明送出的合法 attempt A 已成功 commit，但 `AccessAccept` 遺失。小明以相同 attempt A
重試時，FGS 應核對 retry binding，回復完全相同的 session response。

如果將票券改回 `UNSEEN`，小明的重試可能建立 session B；先前 session A 又可能其實已在
下游生效，於是一次性保證遭破壞。因此 `CONSUMED` 永遠不能回到 `UNSEEN` 或 `RESERVED`。
不同 attempt B 即使持有相同票券，也不能取得 attempt A 的密封回應。

這就是為什麼 store 需要同時記住「票券已用過」與「哪個 attempt 得到哪個結果」。
只保存一個布林值 `used = True`，可以拒絕第二次使用，卻無法安全回答合法的同次重試。

## 7. 程式在不同時點中斷時怎麼辦

| 中斷時點 | 安全恢復結果 |
| --- | --- |
| Reserve 之前 | 沒有 session、沒有使用紀錄；請求可以重新驗證 |
| Reserve 之後、Commit 之前 | 維持 `RESERVED`；只有能證明沒有 session、回應或下游授權，而且原 worker 不再可能 commit，才可 Abort 回 `UNSEEN` |
| Commit 之後、Accept 送出之前 | 保持 `CONSUMED`；同 attempt 重試取得原來的受保護回應 |
| Accept 已送出但 UE 沒收到 | 與上一列相同；網路是否送達不能回滾已提交的唯一 session |

Reservation 可以有 lease deadline，但「時間到了」本身不足以 Abort。舊 worker 若仍可能醒來
完成 commit，而另一個 attempt 已因 lease 到期取得使用權，仍會產生兩個 session。
無法確定時，規格選擇保持 `RESERVED` 並 fail closed。這提高安全性，但可能讓合法使用者
暫時無法接入，是安全性與 availability（可用性）之間的取捨。

## 8. 這對單往返與 backhaul delay 的影響

把 UE–FGS 接入改成一個 RTT，主要減少衛星路徑的訊息往返。若不同 FGS 都能接受同一張票券，
它們仍需共同做出唯一的 Reserve／Commit 決定；目前規格要求線性一致的共享 store，或提供
等價保證的 single-writer／consensus 分片。

因此，首則 access NIZK 可以省掉逐次 challenge 的衛星往返，但不能單獨省掉權威使用狀態。
如果 FGS 因 ground-network partition 無法存取該狀態，v0.1 要求拒絕建立新 session。
後續做延遲實驗時，必須把 UE–FGS RTT、NIZK 驗證與 replay-store backhaul 等待分開量測。

## 9. 對照目前的 Python reference

| 檔案 | 已表示的行為 | 目前界線 |
| --- | --- | --- |
| [replay.py](../../src/pq_sat_auth/replay.py) | `reserve()`、`commit()`、`abort()`、同 attempt 冪等處理，以及序號／digest 衝突拒絕 | 以 `threading.Lock` 保證單一 Python process 內的線性一致性；不耐程式中斷，不跨程序或跨 FGS |
| [replay tests](../../tests/system/test_pq_sat_auth_replay.py) | 24 個不同 attempts 並行時只有一個 winner；24 個相同 attempt 重送時只有一筆新 reservation | 證明 reference 行為符合測試案例，不是分散式資料庫或端到端安全證明 |
| [正式草稿 §6–8](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md) | 狀態、允許轉移、atomic commit 與 crash recovery 要求 | 屬於 Defined 規格；production durable／distributed store 尚未實作 |

`InMemoryLinearizableReplayStore.production_ready = False` 是刻意保留的界線。它適合讓我們
執行狀態規則與並行測試，不適合宣稱多個真實地面站在斷線或程序中斷後仍安全恢復。

## 10. 本堂應保留的判斷順序

面對一次性票券問題時，依序問：

1. 請求是否已完成所有不應消耗票券的驗證？
2. 這是不同 attempt 的競爭，還是同一 attempt 的合法重試？
3. 誰原子取得唯一 reservation？
4. session、接受回應與 `CONSUMED` 是否一起可靠提交？
5. 中斷後能否證明沒有任何已生效結果，再決定是否 Abort？

本堂只整理既有規格及 reference 行為，沒有新增協定、執行測試或提升 production claim。
下一堂將接著區分「票券過期、被撤銷、已消耗」三種不同原因，並說明 handover 為何不能
重新使用原票券。
