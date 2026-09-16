# 第二十二堂：短效票券的有效期、庫存與補發策略

日期：2026-09-16。所屬階段：4／設計取捨。
接續[第二十一堂](21_GROUND_SATELLITE_WORK_PLACEMENT_zh-TW.md)，本堂處理離線發行帶來的下一個
工程問題：UE 若不能在每次接入時才向 HNCC 取得票券，就必須事先保存多少張票券，以及票券可以
有效多久。

這裡沒有「越短越安全」或「越多越可靠」的單一答案。有效期與庫存量同時影響：

- HNCC 暫時無法連線時，UE 還能使用多久；
- 未使用票券被竊後，可被冒用的時間與數量；
- UE wallet 與 FGS Replay backend 的儲存量；
- 發行頻率、失敗重試與 handover fallback；
- expiry、batch timing 和使用節奏形成的 metadata linkage。

## 1. 先分清四種不同期限

本專案目前至少出現四種容易都被叫作 expiry 的欄位：

| 期限 | 控制什麼 | 不是什麼 |
| --- | --- | --- |
| Configuration `expiry_bucket` | 共同 `ctx` 所屬票券期間；FGS 用可信 configuration 判斷 ticket 是否仍在接受範圍 | 不是每位使用者任意選的個人化到期時間 |
| `IssuerGrant.not_before／expiry` | HNCC 在哪段時間內可使用該 grant 發行，以及 grant quota 是否仍可消耗 | 不是已發出票券必然相同的使用期限 |
| `challenge_expiry` | 現有四訊息草稿中的 challenge／cookie 可接受多久 | 不是 ticket 或 session 的生命週期 |
| `session_expiry` | 接入成功後建立的 session 可維持到何時 | 不是讓已消耗 ticket 恢復可用的時間 |

尤其要注意：目前票券 payload 是

\[
M=(ctx,sn,h,C)
\]

它沒有另外攜帶一個 per-ticket expiry 欄位。`ctx` 是由共同 `SystemConfiguration` 算出的 digest，而
configuration 中包含 `expiry_bucket`。因此 FGS 必須先可信地取得與 `ctx` 對應的 configuration，
才能解讀該票券所屬的共同期間。

目前 contract 只固定 `expiry_bucket` 是 canonical `u64` 並被綁入 `ctx`；時間單位、bucket 長度、
相鄰 bucket 如何重疊，以及它是否直接代表絕對截止時間，仍需 deployment profile 正式固定。

## 2. 為什麼使用共同 expiry bucket

假設 HNCC 為每位使用者設定精確到秒、彼此不同的 expiry：

| 使用者 | 公開或可解析的 expiry |
| --- | ---: |
| 小明 | 12:03:17 |
| 小華 | 12:03:42 |
| 小美 | 12:04:09 |

即使 blind signature 本身完全正確，FGS 或後來取得 ticket 的 HNCC 仍可能用唯一 expiry 當成
watermark。盲簽章無法刪除協定外層自己放入的個人化 metadata。

較合理的方法是只提供少量、由 federation 認證的共同 profiles，例如所有同 policy／epoch 的票券
共享同一個 expiry bucket。這樣單一 expiry 值對應一群使用者，而不是一個人。

共同 bucket 也方便 Replay backend 在「整個 bucket 已不可能被接受，加上 clock skew、in-flight
time 與 replay grace 均已結束」後，按 partition 成批清理 consumption records。

代價是：接近 bucket 尾端才取得票券的 UE，實際可用時間會比較短。如果系統直接在 bucket 結束前
補發同一批票券，可能很快全部過期。因此發行端與 wallet 必須知道目前 bucket 還剩多少時間。

## 3. 短有效期與長有效期交換了什麼

| 面向 | 較短有效期 | 較長有效期 |
| --- | --- | --- |
| HNCC／issuance 暫時失聯 | 較容易在補發前耗盡 | 較能維持 disconnected availability |
| 票券或 wallet 被竊 | 可被使用的時間窗口較短 | 攻擊者有較長嘗試時間 |
| Revocation | 舊票券自然失效較快，但有效期內仍需撤銷 | Revocation freshness 與散布更重要 |
| Replay backend retention | 每筆 spent identity 可較早安全清除 | 記錄需保存更久 |
| UE wallet | 規劃期間短，但需更頻繁補發 | 要涵蓋更長期間，通常需更多票券 |
| Issuance metadata | 補發頻率高，時序可能更明顯 | 一次大批次的數量與後續使用順序可能形成線索 |

短效票券不會取代 revocation。如果票券在接下來一小時內仍有效，而裝置現在回報遺失，FGS 仍要
在這一小時內取得並執行撤銷資訊。短 expiry 只是縮短 stale credential 最長暴露時間。

長效票券也不會自動改善全部可用性。FGS 若取不到權威 Replay backend，v0.1 為維持 strictly
one-use 仍必須 fail closed；UE wallet 有票不代表 ground state 一定可用。

## 4. 預先發行多少張：`B ≥ N + R + S`

可先用一個容量模型思考：

\[
B \ge N+R+S
\]

- `B`：UE 在一個規劃期間內準備的票券數量。
- `N`：預估需要建立的 full initial access 次數。
- `R`：為不確定結果、封包遺失、crash 或 handover fallback 保留的數量。
- `S`：面對使用量波動與補發延遲的安全餘裕。

例如預估一天需要 4 次 initial access，歷史上可能有 1 次結果不確定，另留 2 張餘裕，容量模型會
得到 `B ≥ 7`。這只是一個教學示例，不是目前系統已選定的參數，也不是密碼學安全公式。

正式設定不能只用平均值。若平均每天 4 次，但移動或故障時曾出現 12 次，按平均值配置會在真正
需要網路時耗盡。應由實測的 access rate、handover fallback、issuance outage、packet loss、clock
skew 和 crash ambiguity 分布，估計 p50／p95／p99 的需求。

## 5. Batch 太小和太大各有什麼問題

### Batch 太小

- UE 經常觸發補發，HNCC issuance load 增加；
- HNCC 暫時失聯時可能無票可用；
- 緊急補發若發生在接入前一刻，offline work 又靠近 latency-critical path；
- 頻繁且可觀察的 issuance timing 可能協助關聯後續使用。

### Batch 太大

- UE secure storage 約隨 `B × serialized_ticket_size` 增長；
- wallet 被完整複製時，攻擊者可能取得更多仍未使用的票券；
- 未使用票券到期會浪費已完成的 PQ proving、verification 與 blind issuance 成本；
- FGS 成功使用紀錄與 retention storage 會隨實際 access 次數增加；
- 每位使用者若有獨特 batch size 或票券排序標記，可能形成 side information。

所以 batch size 應是 wallet 的本機庫存政策，或從少量共同 profile 中選擇；不應把「這是小明的
第 7／23 張票券」放進公開 ticket。HNCC 仍會知道某個 `rid` 進行過多少次 issuance session，因此
blind issuance 不會隱藏所有發行頻率 metadata。

`IssuerGrant.quota` 也不要誤認為單一 UE 的 batch size。Grant quota 是 federation 給 HNCC 的有界
發行權限，由 issuer-side quota store 消耗；UE 要保存幾張票，是另一層 wallet policy。

## 6. 不要等到零張才補發

一個常見策略是設定 low watermark `L`：

1. Wallet 目標保存 `B` 張目前或即將生效的票券。
2. 每次成功 initial access 使用一張。
3. 當可用庫存降到 `L` 時，在網路條件允許時開始補發，恢復到目標 `B`。
4. 下一個共同 expiry bucket 開始前，先取得一部分下一 bucket 的票券，形成短暫重疊。
5. 已過期票券從可用集合移除，但本機 journal 仍依 recovery／audit policy 處理必要狀態。

`L` 必須涵蓋從「觸發補發」到「新票券可安全使用」之間可能發生的 access 數量。若 HNCC 最長可能
失聯 6 小時，就不能只按平常幾分鐘的補發時間設定。

相鄰 bucket 的重疊可以避免舊 bucket 結束時瞬間斷糧，但 FGS 必須清楚知道哪些 authenticated
configurations 同時仍可接受。允許無限期接受舊 `ctx` 會讓 expiry 失去作用。

## 7. UE wallet 也需要狀態機

FGS 有 `UNSEEN → RESERVED → CONSUMED`；UE 本機也不能只保存一個普通 Python list。最低限度需要
crash-safe journal，例如：

\[
unused \rightarrow reserved \rightarrow outcome\text{-}known
\]

- `unused`：尚未放入接入 attempt。
- `reserved`：已用於一個 attempt，但 UE 尚不能確定 FGS 是否提交成功。
- `outcome-known`：已知道成功／最終失敗，依協定決定封存或移除。

如果 UE 傳出請求後立刻斷電，FGS 可能已經把 ticket 設為 `CONSUMED`。裝置重開後若直接把它放回
`unused`，便可能以新 attempt 重用。正確方向是用相同 request／attempt identity 查回原結果，或在
無法確認時保守放棄該票券；後者正是容量模型中 `R` 的來源之一。

備份與多裝置同步也要避免同一張未使用 ticket 同時出現在兩個可獨立操作的 wallets。Blind
signature 與 holder-secret binding 不會自動提供 wallet anti-rollback 或安全同步。

## 8. 隱私不能只看票券 bytes

每張 batch ticket 仍必須使用獨立的：

- `sn`；
- holder-related randomness；
- trace-encryption randomness；
- blind issuance randomness／session。

此外，`ctx`、policy、expiry bucket、key IDs 與 wire length 應對足夠大的 anonymity set 共用。
即使這些密碼條件成立，以下行為仍可能提供關聯線索：

- HNCC 一次為某個 `rid` 執行大量 issuance，之後 FGS 在短時間看見相同數量的 tickets；
- UE 完全依發行順序使用票券；
- 只有單一使用者採用特殊 batch size、補發時間或 expiry profile；
- wallet 耗盡後立即在線聯絡 home domain，再立刻於 visited domain 接入。

因此 batch policy 除了容量，還要評估 issuance／use timing decorrelation。Core cryptographic
blindness 不會自動隱藏網路時序與使用節奏。

## 9. Replay backend 要保存多久

票券變成 `CONSUMED` 後，Replay backend 不能立刻刪除紀錄，否則同一張仍在有效期內的 ticket
可能再次看起來像 `UNSEEN`。保存期限至少要涵蓋：

\[
retention\_deadline = ticket\_expiry + maximum\_clock\_skew + replay\_grace
\]

更完整的容量分析還應考慮 maximum in-flight time。若成功 access rate 是 `r`、保存窗口是 `W`、
每筆實測資料庫記錄大小是 `s_record`，replication factor 是 `f`，可先估：

\[
storage \approx r \times W \times s_{record} \times f
\]

這是容量模型，不是目前 benchmark。刪除 spent record 後，FGS 仍必須靠 authenticated configuration
拒絕已過期 ticket；資料列消失不能讓舊票券恢復有效。

## 10. 目前正式與實作邊界

| 項目 | 目前狀態 |
| --- | --- |
| D-001 short-lived、strictly one-use 選擇 | 已記錄於 methodology／architecture |
| `expiry_bucket` canonical encoding 與 `ctx` binding | 已由 `SystemConfiguration` contracts 實作／測試 |
| Exact ticket lifetime／bucket size／overlap policy | 尚未由 deployment profile 凍結 |
| `IssuerGrant` 的 not-before、expiry 與 quota | Control-plane prototype 已實作／測試；不是 UE wallet policy |
| Replay retention 下限與 cleanup invariants | Draft spec 已定義；production backend 未完成 |
| UE wallet journal、low-watermark replenishment、anti-rollback／multi-device sync | 尚未實作 |
| `B`、`L`、ticket bytes、exhaustion rate 與 issuance-gap benchmark | 尚未量測／選定 |

本堂沒有替專案選擇「一小時」「一天」或固定張數，也沒有把容量公式當成安全證明。正式依據見
[methodology D-001](../../methodology.md#d-001--system-profile-v01-採-strictly-one-use-ticket)、
[system initialization contracts](../../docs/artifacts/SYSTEM_INITIALIZATION_CONTRACTS_v0_1_zh-TW.md)、
[issuer authorization](../../docs/artifacts/ISSUER_AUTHORIZATION_v0_1_zh-TW.md)、
[one-time ticket state](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md) 與
[ticket lifecycle review](../../docs/literature/TICKET_LIFECYCLE_REVIEW_zh-TW.md)。

## 11. 口試時可以怎麼回答

> 離線發行把高成本 PQ 工作移出接入路徑，但 UE 必須預先保存 short-lived one-use tickets。我的
> ticket payload 沒有個人化 expiry；共同 configuration 的 `expiry_bucket` 被綁入 `ctx`，使同一
> anonymity set 使用共同期間，避免 expiry watermark。較短期間縮小失竊、撤銷延遲與 FGS spent-state
> retention，卻增加補發頻率和耗盡風險；較長期間提升 disconnected availability，但增加 wallet、
> revocation 與 metadata 暴露。Batch 可先用 `B ≥ N+R+S` 建模，再依 access、handover fallback、
> outage、loss 與 crash 的實測分布選擇，並在庫存低於 `L` 前補發。UE 還需要 crash-safe wallet
> journal，避免不確定結果或備份 rollback 讓同一 ticket 再次使用。目前專案只固定 short-lived
> one-use 原則與 `expiry_bucket` encoding，實際 bucket 長度、batch size、補發和 wallet implementation
> 仍是待完成項目。

下一堂把各角色的 `honest-but-curious`、malicious、compromised 與 unavailable 情境整理成 threat
model，學會判斷一個安全結論究竟依賴哪個角色沒有做什麼。
