# 第十八堂：One-use ticket 與 reusable anonymous `Show`

日期：2026-09-15。所屬階段：4／設計取捨。
接續[第十七堂](17_FAIR_SATELLITE_AUTH_COMPARISON_zh-TW.md)的比較方法，本堂回到本研究的
D-001 決策：為什麼 system profile v0.1 選擇 short-lived、strictly one-use ticket，而沒有讓同一張
匿名票券反覆使用？

## 1. 先分清楚：重複傳送 ticket 不等於 `Show`

目前票券可簡化寫成：

\[
T=(M,\sigma)
\]

`M` 是固定 ticket payload，`σ` 是對應簽章。相同票券再次傳送時，bytes、`sn` 與 canonical digest
仍然相同。因此 FGS 或觀察者可以判斷「這是先前看過的票券」。

在 anonymous credential 中，`Show` 是另一套協定。UE 不直接把同一份 credential 原封不動傳出，
而是每次使用新的 randomness 產生 presentation proof：

\[
\pi_1=Show(C,context_1;r_1), \qquad
\pi_2=Show(C,context_2;r_2)
\]

即使 `π₁` 和 `π₂` 都由同一份 credential `C` 產生，合格的 presentation unlinkability 仍要讓指定
observer 難以判斷它們是否來自同一 holder。`r₁`、`r₂` 是 presentation randomization，不是把任意
亂數附在固定 ticket 旁邊；驗證 relation、proof 與 encoding 都必須配合設計。

本專案目前只有 fixed ticket 的 `VerifyTicket(T)`，沒有獨立、可 rerandomize、zero-knowledge 的
`Show` protocol。因此「關掉 consumption check，讓 `T` 多用幾次」只會造成可連結重用，不會自動
得到匿名 multi-show credential。

## 2. One-use ticket 怎麼運作

UE 在接入前取得一批彼此獨立的短效票券：

```text
wallet = [T1, T2, T3, ...]
```

第一次 initial access 使用 `T1`，FGS 在全部驗證成功後，原子地把 `T1` 的 use identity 寫成
`CONSUMED`。下一次 initial access 必須改用 `T2`。

這個模型有兩層檢查：

1. `VerifyTicket(T1)`：無狀態地檢查票券密碼學有效性；同一張有效票券驗證十次仍可能得到 valid。
2. Lifecycle consumption：有狀態地確認 `T1` 尚未成功使用，並保證競爭請求至多一個成功。

所以 `VerifyTicket` 的 stateless 行為不是錯誤。Signature 回答「是不是合法發行的票券」；consumption
state 回答「這張合法票券是否已建立過 initial session」。

## 3. Reusable anonymous `Show` 怎麼運作

UE 只保存一份 credential `C`。每次驗證時，針對新的 context、freshness 和 session transcript
產生新的 randomized proof。Verifier 檢查 proof，卻不應取得可跨 session 固定比對的識別值。

這種模型的優點是：

- UE 不必儲存大量完整 tickets；
- 同一 credential 可以支援高頻 reauthentication 或 handover；
- 若政策允許無限次使用，FGS 不必為每一次 presentation 保存 consumed ticket digest。

但它不會自動提供：

- one-use 或 `k`-use quota；
- credential revocation freshness；
- 被複製的 credential／holder secret 只能由原裝置使用；
- 對舊 `π` 的 replay resistance；
- conditional opening 與每次 presentation evidence 的正確綁定。

舊 proof 仍需靠 context、freshness 與 session binding 防止 replay。若要限制使用次數，還需加入
nullifier、rate-limited credential、k-TAA 或 online state；加入固定且反覆出現的 nullifier，又可能
形成新的 linkability domain。

## 4. 不可連結性的差別

### One-use ticket

- 正常情況每張 ticket 只出現一次，不會因同一 ticket 的合法多次使用形成固定識別值。
- 不同 tickets 是否不可連結，仍依賴 blind issuance、獨立 randomness、共同 metadata 與使用時序。
- 同一 ticket 的失敗重送或攻擊 replay 可被連結；一次性只限制成功使用次數，不會隱藏重送。
- FGS 的 consumption log、時間、位置與 serving context 仍可能產生 operational linkage。

### Reusable `Show`

- 同一 credential 合法使用多次，因此 presentation proof 必須每次 rerandomize。
- 若 proof、pseudonym、nullifier 或 disclosed attribute 含有固定值，仍可能被連結。
- 即使密碼學 presentation unlinkability 成立，traffic timing、裝置網路位址和移動路徑仍可能連結。

因此兩種模型都不能只用「匿名」兩字概括。One-use 依靠不同 ticket 避免固定物件重複出現；multi-show
依靠新的 randomized presentation 隱藏相同 credential 的關係。

## 5. Replay、quota 與 double spend

三個問題需要分開：

| 問題 | One-use ticket | Reusable `Show` |
| --- | --- | --- |
| 舊訊息 replay | freshness／transcript binding | freshness／transcript binding |
| 合法物件再次使用 | authoritative check-and-consume 拒絕 | 原則上允許再次產生新 Show |
| 使用次數上限 | 每 ticket 一次；batch 數量近似可用次數 | 原生通常沒有限制；需要額外 quota 機制 |

如果多個 disconnected FGS 都先接受同一張 ticket，之後才發現重複，這叫 **offline double-spend
detection**。本研究 v0.1 要的是 **online prevention**：第二個 initial session 不得先建立再事後追責。
因此 FGS 需要 authoritative state；發生 network partition 而無法確認時，必須 fail closed 才能保留
strict one-use，代價是 availability 下降。

## 6. 在線與離線成本放在哪裡

### One-use ticket batch

- **接入前：**每張票券的 blind issuance、`pi_issue`、Finalize 與 wallet storage。
- **接入時：**fixed ticket verification、holder authentication、PQ AKE、state Reserve／Commit。
- **系統成本：**票券補發、過期浪費、wallet anti-rollback、FGS state retention 與跨站一致性。

### Reusable `Show`

- **發行時：**通常只發一份或少量長效 credential。
- **接入時：**每次產生及驗證新的 randomized ZK presentation，另加 PQ AKE。
- **系統成本：**presentation relation／proof backend、revocation witness、reset／concurrent-show 安全分析；
  若需要 quota，仍要 tag、nullifier 或共享狀態。

所以 `Show` 可能降低 wallet storage 和發行頻率，卻增加每次在線 proof 成本。One-use ticket 能把較多工作
前移，卻增加票券庫存和權威消耗狀態。哪一個在衛星場景較快，仍須量測 proof bytes、proving／
verification time、state backhaul、補發流量與實際使用頻率。

## 7. 票券和秘密一起被偷時

這裡接回學習者第二堂提出的問題。

- **只複製 ticket，沒有 `k_hold`：**holder authentication 應阻止使用。
- **ticket 與 `k_hold` 一起外洩：**攻擊者可能在合法使用者之前搶先使用；one-use state 只能決定
  誰先成功，不能辨認誰是真正裝置擁有者。
- **整份 reusable credential 與 holder secret 外洩：**攻擊者可能持續產生新的合法 Shows，直到
  credential 被撤銷或額外裝置綁定機制阻止。

One-use 能限制每張被竊 ticket 最多成功一次，但若 wallet 中有很多票券一起被偷，風險仍可能接近
剩餘票券數量。Reusable `Show` 的單一 credential 外洩則可能影響更長時間。兩者都需要裝置秘密
保護、撤銷、短效期或重新註冊流程；密碼學持有證明不會判斷操作裝置的人是不是原使用者。

## 8. 為什麼 v0.1 選 one-use

正式 D-001 的理由可以整理成四點：

1. **目前 core 已有 fixed ticket validity，尚無 PQ rerandomizable `Show`。**One-use 不需要假裝
   現有票券已具有不存在的 multi-show privacy。
2. **安全語意清楚。**每個 canonical ticket identity 最多建立一個成功 initial session，可直接寫成
   state-machine invariant 和並行測試目標。
3. **配合計算前移。**較重的 issuance relation work 可在接入前完成；在線仍保留 holder
   authentication、AKE 及必要 state operation。
4. **新增密碼假設較少。**真正加入 `Show` 需要新的 relation、encoding、PQ proof backend、
   presentation unlinkability／concurrency games、opening evidence、revocation 與 benchmark。

這不是宣稱 one-use 在所有面向更好。選擇的代價同樣明確：

- UE 必須預取、保存並補充足夠票券；
- FGS 必須維護 durable、跨副本一致的 consumption state；
- state backhaul 可能成為在線 latency；
- commit 後回覆遺失可能安全地消耗票券，卻沒有成功交付 session；
- partition 時保留 strict one-use 需要犧牲 availability。

未來若量測顯示 ticket bytes、wallet 容量、補發頻率或 state consensus 已成主要瓶頸，可以研究
「master credential 離線導出 unlinkable one-use presentations」、PQ k-TAA 或真正的 PQ multi-show。
這些會是新 protocol version，不是刪掉 v0.1 consumption check 就能得到。

## 9. 目前實作與宣稱邊界

| 項目 | 目前狀態 |
| --- | --- |
| D-001 short-lived、strictly one-use 決策 | 已定義於 methodology／architecture |
| `VerifyTicket(T)` | Stateless core verification；不提供 one-use |
| Canonical access codecs、transcript／use identities | 已實作／測試局部介面 |
| Process-local replay reference | 已實作／測試，不是 durable distributed production store |
| Holder authenticator、PQ AKE、UE wallet journal | 尚未完成 |
| Reusable anonymous `Show` | 尚未定義或實作，屬於未來擴充 |
| 兩種方案的衛星效能 benchmark | 尚未執行 |

正式依據見 [methodology D-001](../../methodology.md#d-001--system-profile-v01-採-strictly-one-use-ticket)、
[architecture](../../ARCHITECTURE_zh-TW.md)、[一次性票券狀態規格](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md)
及 [ticket lifecycle 文獻回顧](../../docs/literature/TICKET_LIFECYCLE_REVIEW_zh-TW.md)。

## 10. 口試時可以怎麼回答

> Reusable anonymous Show 不是重送同一張固定票券，而是同一 credential 每次以新 randomness
> 產生不可連結的零知識 presentation。目前 PQ-RBBC 只有 fixed ticket 的 stateless verification，
> 沒有這種 Show protocol；直接允許票券重用會被 FGS 連結。v0.1 因此選擇預發行一批短效 one-use
> tickets，以 atomic consumption 保證每張最多建立一個 initial session，並把較重的 issuance work
> 移到接入前。這個選擇減少新增密碼機制，但代價是 UE wallet、補發、FGS durable state、跨站
> 一致性與 partition availability。未來若這些成本成為瓶頸，才以相同安全目標評估 PQ multi-show
> 或 master credential 導出的 unlinkable one-use presentations。

下一堂比較 blind issuance 與普通 signed ticket：為什麼發行端已經知道註冊身分，仍需要讓它看不到
最終票券，以及盲簽章究竟保護哪一段連結。
