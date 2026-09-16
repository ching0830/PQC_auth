# 第二十三堂：Threat Model——誰可以做什麼，系統還保證什麼

日期：2026-09-16。所屬階段：4／設計取捨。
接續[第二十二堂](22_TICKET_LIFETIME_AND_INVENTORY_zh-TW.md)，本堂把前面反覆出現的
`honest-but-curious`、malicious、compromised、untrusted 與 unavailable 整理成一套判讀方法。

Threat model（威脅模型）不是「系統裡有壞人」這種概括描述。它至少要回答：

1. 攻擊者能控制哪些角色？
2. 能讀取哪些訊息、logs、secrets 與內部 state？
3. 能否修改、插入、重放、延遲或刪除訊息？
4. 哪些角色仍按協定正確工作？
5. 什麼事件發生時，算攻擊者成功？

缺少其中任何一項，「系統是匿名的」或「系統可以追責」都會過於模糊。

## 1. 五個常見詞不代表同一件事

### Honest（誠實）

角色依協定產生 randomness、執行所有檢查、保存規定狀態，不故意額外洩漏資料。安全分析仍可讓
網路或其他角色攻擊它，但它自己的內部行為符合規格。

### Honest-but-curious（誠實但好奇）

角色會正確執行協定，卻保存並分析自己正常看得到的所有資料，希望推測額外資訊。

本專案目前對 HNCC 的核心假設就是這一類：它知道 `rid`、issuance session、quota 與正常 transcript，
也可以日後取得最終 tickets 嘗試配對；但它必須使用共同 metadata、正確驗證 `pi_issue` 並依協定
產生 blind-signing response。

如果 HNCC 故意替小明使用特殊 expiry、policy、key ID 或格式當 watermark，它已經偏離共同協定，
不能再稱為 honest-but-curious。

### Malicious（惡意）

角色可以任意偏離協定，例如選擇畸形輸入、說謊、重放、並行競爭、跳過檢查、拒絕服務或與其他
角色分享資料。`Malicious` 不自動表示它能讀取其他誠實端點的秘密，也不表示它能破解密碼學。

### Compromised／corrupted（被攻陷／被控制）

攻擊者取得角色的內部控制權，可能讀取 secret keys、randomness、資料庫或 session state，並讓該
角色任意傳送訊息。這通常比只控制網路強得多。

分析時要說清楚被拿到的是什麼。例如「ticket bytes 洩漏」和「整個 UE wallet、`k_hold` 與裝置狀態
都被取得」會得到完全不同的結論。

### Unavailable（不可用）

角色因 crash、斷線、網路 partition、維修或 DoS 無法回應。Unavailable 不一定洩漏 secret，也不一定
發送惡意內容；它主要影響 availability。這個維度和 honest／malicious 是分開的：一個誠實 FGS
可以暫時斷線，一個惡意 FGS 也可以保持在線。

## 2. 「Untrusted」是設計態度，不是觀察結果

若架構說 LEO／FLEO **不預設可信**，意思是安全性不能依賴它一定忠實轉送。威脅模型應允許衛星或
網路攻擊者：

- 竊聽沿途可見資料；
- 複製、重放與跨路徑轉送封包；
- 修改、插入、重排、延遲或丟棄訊息；
- 讓多個接入 attempt 競爭。

簽章、NIZK、canonical transcript binding 與 PQ AKE 的目標是讓竄改或冒充被誠實端點拒絕。它們
無法強迫中繼一定交付訊息，因此通常能保護 authentication／integrity，不能保證 availability。

`Untrusted relay` 也不等於「衛星已取得 HNCC、FGS 或 OA 的秘密」。除非威脅模型另外腐化那些端點，
網路控制權不能直接被當成 endpoint memory disclosure。

## 3. 依正確組織拓撲列出各方假設

| 行政域／角色 | 目前允許的攻擊能力或假設 | 超出後哪些結論受影響 |
| --- | --- | --- |
| UE／holder | 可以 malicious：複製 ticket、選擇輸入、平行接入、重放並與 network attacker 合作 | 系統必須拒絕偽造、錯誤 relation 與第二次成功接入；整個裝置被攻陷則另論 |
| Home NCC：HNCC＋HGS | HNCC 目前是 honest-but-curious；HGS protocol role 尚未定義，若看見資料應算入同一 home-domain view | Malicious HNCC watermark／framing 不在目前 core 結論；不能先宣稱 HGS 看不到特定資料 |
| Other／visited NCC：FGS | v0.1 的 access／one-use／revocation 保證依賴 FGS 正確驗證及提交 state | 完全惡意 FGS 可跳過檢查、追蹤、拒絕或自行建立錯誤服務狀態；目前沒有對它的完整 theorem |
| Satellite operator：LEO／FLEO | 中繼不預設可信；可成為 active network attacker | 可破壞 availability 並觀察 metadata；不應僅靠它的行為維持 ticket 或 session 安全 |
| Replay backend | 假設 atomic、durable、linearizable，且不 rollback／fork consumption state | 惡意或 split-brain backend 可能讓同票券建立多個 sessions；partition 時 fail closed 會拒絕合法使用者 |
| 最高治理組織：FAC＋OA | FAC／OA 是同組織內不同功能；分析可控制的 FAC／OA shares 數量及實際 compromise domain | 達到 `t_F` 可偽造治理授權的假設邊界；達到 `t_O` 可完成 opening，完整治理域失陷不受少於門檻的隱私主張保護 |

這張表不能取代 HGS 的正式定義。它只表示：HGS 既然隸屬 HNCC，未來賦予它的 logs、keys 與網路
觀察應合併進 home-domain threat view，不能假裝成完全獨立組織。

## 4. 每一項安全性都有自己的攻擊者

### Issuer unlinkability

想保護的是：HNCC 知道誰完成發行，卻不能把之後看見的最終 ticket 配回 issuance session。

目前條件包括：

- HNCC 依協定誠實發行，但會分析全部正常 view；
- ticket 使用共同 visible metadata；
- honest holders 使用獨立 randomness；
- HNCC 沒有足夠 opening shares；
- 結論不涵蓋 traffic timing、位置、radio fingerprint 或 active watermark。

因此它不是「HNCC 無論做什麼都無法追蹤」。

### Ticket validity／unforgeability

Malicious UE 可以要求多次 issuance、選擇輸入並嘗試製造額外 tickets。Core one-more unforgeability
的方向是：完成 `q` 次接受的 issuance 後，不能得到超過 `q` 個 distinct verifying ticket digests。

這不代表每張 ticket 只能 access 一次。One-use 還需要 holder authentication、FGS 和 Replay backend。

### Trace soundness 與 opening privacy

Trace soundness 的方向是：malicious holder 不能讓一張被接受發行的 ticket 開成另一個 `rid` 或
serial。它不處理 malicious issuer framing。

Opening privacy 的門檻條件是攻擊者控制的有效 OA shares 少於 `t_O`。若達到 `t_O`，已超出這項
privacy assumption。實際 FAC／OA 同屬一個最高治理組織，所以論文還必須說明 shares 是否真的由
不同人員、HSM、帳號或管理控制域保護。

### Access authentication 與 one-use

這些是 system profile 新增的性質，目前仍是 open games／assumptions。它們依賴：

- FGS 正確驗證 ticket、holder、context、freshness 與 PQ AKE；
- Replay backend 不 fork、rollback 或同時接受兩個 writers；
- 驗證失敗不消耗，成功 commit 後不恢復 `UNSEEN`；
- 網路攻擊者即使控制 relay，也不能讓誠實 UE／FGS 接受沒有 partnered session 的訊息。

目前有 codecs、binding tests 與 process-local state-machine tests，沒有完成 PQ AKE／holder
authenticator 的端到端安全證明。

### Availability

若 LEO／FLEO、FGS、Replay backend 或網路被阻斷，合法 UE 可能無法建立 session。密碼學通常無法
保證敵對網路一定傳送封包。v0.1 在狀態不確定時選擇 fail closed，是以可用性換取不重複接受。

所以「攻擊者不能冒充」和「合法使用者一定能連上」是兩個不同主張。

## 5. 三個具體情境

### 情境 A：惡意 UE 送出隨機假票券

格式、簽章或 relation 不成立時，FGS 應拒絕且不消耗任何合法 ticket。因為這份資料不是正確發行、
也沒有綁定可信 `rid` 的 ticket，系統不保證能從垃圾 bytes 找出真人身分。

「可追責」應描述為：對經正確發行並包含合法 trace ciphertext 的特定 ticket，在案件授權與 OA
threshold 成立時可恢復其綁定註冊身分。它不是所有無效封包的身分辨識器。

### 情境 B：攻擊者取得 ticket 和 `k_hold`

只複製 ticket 而沒有 holder secret，應無法產生新的有效 holder authentication。若完整 wallet、
`k_hold` 與必要裝置狀態一起被取得，攻擊者可能在撤銷前使用尚未消耗的 tickets。

此時 opening 會恢復票券原本綁定的 registered `rid`，不會自動辨認操作裝置的實際竊賊。這屬於
credential／endpoint compromise，需要 secure storage、device binding、compromise reporting 與
revocation 處理；不能只靠 trace ciphertext 解決。

### 情境 C：惡意衛星重放一份真實接入請求

這份訊息的 signature／NIZK 可能仍然有效，因為它原本就是真的。誠實 FGS 必須靠 freshness、完整
transcript／key binding 和 Replay backend，避免建立第二個 session。衛星仍可丟棄所有封包造成
DoS；這不會變成 authentication break，卻是 availability failure。

## 6. 共謀要合併的是能力，不是角色名稱

正確問法是：參與者共同控制後，總共取得哪些 views、keys 與 state？

- HNCC／HGS 是既有 home domain，不把正常隸屬稱為共謀；HGS 未來的 view 應直接算入該域。
- Home NCC 與 visited NCC 交換 issuance／access logs，會增加 timing 與 metadata correlation。
- FGS 與少於 `t_O` 個 OA shares 合作，依 threshold privacy 目標仍不足以解密；達到 `t_O` 即超出假設。
- FAC／OA 同屬最高治理組織。形式上不同 key roles 不足以證明實際 compromise domains 獨立。
- Satellite operator 與 NCC 分享 routing、cell 與 timing metadata，可能形成不需要破解票券的關聯。

因此論文不要只寫「A 與 B 不共謀」。要寫可被檢查的上限，例如「攻擊者控制少於 `t_O` 個 opening
shares，且 HNCC 不取得 opening threshold」，並另外列出 metadata sharing 的範圍。

## 7. 一個安全主張的完整句型

可以用下面五格檢查論文中的每一句安全宣稱：

> 在 **系統與密碼假設**成立時，具有指定**能力與可見資料**的**攻擊者**，除了 negligible
> probability 外，不能造成明確的**成功事件**。

例如：

> 在 blind-signature／NIZK／trace privacy assumptions、共同 metadata、honest-protocol HNCC 且
> 不控制 opening threshold 的條件下，HNCC 即使保存 issuance views 並取得兩張最終 tickets，也不能
> 以顯著優勢判斷 tickets 與兩個 issuance sessions 的配對。

這句話比「本系統對 NCC 匿名」長，但能清楚指出：對哪個 NCC、什麼觀察者、保護哪一條連結、哪些
攻擊不在結論內。

## 8. Security game 是什麼

Security game 是把上述句型寫成實驗：challenger 建立 keys／state，攻擊者可呼叫明確允許的操作，
最後嘗試觸發 winning event。若所有有效率的攻擊者成功機率都只比隨機猜測多 negligible amount，
才得到相應的密碼學安全定義。

不同性質需要不同 games：

- `G-ACCESS-AUTH`：讓誠實端點接受沒有對應 partner 的 session；
- `G-ONE-CONSUME`：讓同一 ticket 對兩個不同 sessions 成功；
- `G-REPLAY`：沒有新的合法執行，卻用舊 transcript 建立新 session；
- issuer-unlinkability game：判斷 tickets 與 issuance sessions 的配對；
- opening privacy game：少於門檻仍區分 trace identity。

單元測試只能跑有限輸入與排程，能抓 parser、binding 或 state-machine bug；它不能代表所有有效率
攻擊策略都失敗，也不能替代 reduction proof。

## 9. 目前文件與實作邊界

| 項目 | 目前狀態 |
| --- | --- |
| HNCC honest-but-curious、FGS／LEO 等頂層角色假設 | Canonical architecture 已記錄；HGS／組織邊仍待正式同步 |
| Core issuer unlinkability、trace soundness／privacy、one-more 等 | 有 conditional theorem basis；仍受 proof／primitive／production blockers 限制 |
| End-to-end access、session、replay、handover、revocation games | 已有 security-games draft；仍是 `OPEN-GAME`／`PROFILE-ASSUMPTION` |
| Access codecs、mutation／binding 與 process-local replay tests | 已有局部實作／測試；不是 cryptographic proof |
| Production holder authenticator、PQ AKE、distributed state、FAC／OA primitives | 尚未完成 |
| HGS threat model 與 data visibility | 尚未定義，不能自行宣稱 |

正式依據見 [architecture roles](../../ARCHITECTURE_zh-TW.md#角色)、
[end-to-end security games draft](../../docs/security/END_TO_END_SECURITY_GAMES_DRAFT_zh-TW.md)、
[methodology](../../methodology.md) 與[research status](../../RESEARCH_STATUS_zh-TW.md)。

## 10. 口試時可以怎麼回答

> 我的威脅模型不是把所有角色都稱為不可信。UE 可以惡意並發、重放或選擇輸入；LEO／FLEO 與
> network attacker 可竊聽、修改、重排、延遲或丟棄訊息；HNCC 目前假設 honest-but-curious，會分析
> 發行紀錄但必須遵守共同 metadata 與 blind issuance；access one-use 則依賴 FGS 正確驗證以及
> Replay backend 的 atomic、durable、linearizable state。OA privacy 只保護少於 `t_O` shares 的攻擊者，
> FAC／OA 同屬最高治理組織，所以還要列實際 compromise domain。完全惡意 HNCC framing、惡意 FGS
> enforcement、完整治理域或 UE endpoint compromise 都不能被現有 theorem 自動涵蓋。每項主張都要
> 寫出 adversary、view、assumptions 與 winning event；單元測試只驗實作不變量，不能當成密碼證明。

下一堂進入階段 5，開始學怎麼閱讀這個 repository：先理解資料夾、Python package、module、import、
test 與 manifest 各自是什麼，再沿一條最短路徑找到「正式規格寫在哪裡、程式在哪裡、測試怎麼驗」。
