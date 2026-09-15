# 第十九堂：Blind issuance 與普通 signed ticket

日期：2026-09-15。所屬階段：4／設計取捨。
接續[第十八堂](18_ONE_USE_VS_REUSABLE_SHOW_zh-TW.md)，本堂回答一個看似矛盾的問題：HNCC 在
註冊／發行時本來就需要知道使用者身分，盲簽章還能保護什麼？

答案是：它不隱藏「誰來申請」，而是保護「這次申請最後產生哪張票券」。

## 1. 我們要切斷的是哪一條連結

HNCC 合理知道：

- 小明以註冊身分 `rid_A` 完成身分認證；
- 小明符合哪個共同 policy／epoch；
- 這次 issuance 是否在 quota 內；
- 這個 issuance session 的 `sid`。

但它不應因此得到：

```text
rid_A → 最終票券 T_A → FGS 的使用時間與位置
```

Issuer unlinkability 的目標是：HNCC 即使保存完整 issuance transcripts，之後再看到兩張最終票券，
仍難以判斷哪一張由哪個已知身分的發行 session 產生。

這和「HNCC 不知道小明身分」是不同目標。註冊匿名不是本研究的假設；發行與使用之間不可配對才是。

## 2. 普通 signed ticket 為什麼會留下直接連結

假設使用普通簽章：

1. 小明向 HNCC 證明自己是 `rid_A`。
2. UE 把完整 ticket payload `M_A` 傳給 HNCC。
3. HNCC 計算並簽署 `m_A = H_ticket(Encode(M_A))`。
4. HNCC 可以保存 `(rid_A, m_A, σ_A)`。
5. 日後 FGS 把 `T_A=(M_A,σ_A)` 的紀錄交給 HNCC，HNCC 重新計算 `m_A` 即可查回小明。

即使 `M_A` 只放加密後的身分 `C_A`，結果也不會改善。HNCC 在發行時已看過完全相同的 `C_A`、
serial 或 digest，日後可以做 equality matching，不需要解密。

以下替代方式也有相同問題：

- **由 HNCC 發 pseudonym：**HNCC 可以保存 `pseudonym → rid` 對照。
- **UE 自選完整 ticket 再請 HNCC 簽：**HNCC 仍看見確切 ticket／digest。
- **要求 HNCC 不保存 log：**這是組織政策，無法提供 cryptographic unlinkability。
- **只把 `rid` hash 後放入 ticket：**若發行端知道輸入或看過相同摘要，仍能直接比對。

普通簽章的優點是簡單、發行計算較少，也不需要 issuance NIZK；代價是發行者天然具有配對能力。

## 3. Blind issuance 如何切斷配對

本研究的簡化資料流是：

```text
UE：建立 hidden M、m、blind randomness
UE → HNCC：β、pi_issue，以及公開 statement
HNCC：驗 rid、sid、quota、policy、pi_issue
HNCC → UE：blind-signing response z
UE：Finalize(m, ..., z) → sigma
UE：得到最終 T = (M, sigma)
```

HNCC 在 issuance 時知道 `rid`，但接觸的是 blind request `β` 和零知識證明，不直接取得最終 `M`、
`m` 或可直接比對的最終 `σ`。UE 取得回應 `z` 後，結合本機保存的 randomness 完成簽章。

在 blind-signature blindness、NIZK zero knowledge、trace-encryption privacy、hash collision resistance
與共同 metadata 等條件成立時，HNCC 日後只看到最終 ticket，仍不能可靠地把它配回其中一個 issuance
session。這就是本研究的 **Issuer Unlinkability**。

## 4. 發行端看不到內容，為什麼敢簽

若只做 blind signature，卻不檢查隱藏訊息，惡意 UE 可能要求簽署不符合規則的內容。例如：

- ticket 使用錯誤 `ctx` 或格式；
- blind request 實際對應另一個 message；
- `h` 沒有綁定 UE 掌握的 `k_hold`；
- trace ciphertext 沒有加密這次已認證的 `rid`；
- 密文內 serial 與票券外的 `sn` 不一致。

`pi_issue` 的用途是讓 HNCC在**不取得 hidden witness**的情況下，確認五組關係：

| 關係 | 白話意義 |
| --- | --- |
| I1 | hidden ticket 的形狀、版本與 `ctx` 正確 |
| I2 | 要簽的 message 是 canonical ticket payload 的 digest |
| I3 | blind request `β` 確實綁定同一個 message 與 blinding data |
| I4 | ticket 中的 `h` 來自 UE 的 holder secret `k_hold` |
| I5 | trace ciphertext `C` 正確綁定這次 HNCC 已認證的 `rid`、同一 `sn`、`ctx` 與 `h` |

因此兩個元件的責任不同：

- **Blindness：**HNCC 看不出最後是哪張票券。
- **NIZK soundness／binding：**HNCC 不必看見票券，也能拒絕不符合發行規則的隱藏內容。

只有 blindness，發行者可能盲目簽錯東西；只有 NIZK 而沒有 blindness，發行者仍可能看到並記錄
最終 ticket。兩者必須組合。

## 5. 匿名與追責為什麼沒有互相抵消

`M` 中包含追責密文：

\[
C=Ntr.Enc(tpk,ctx,h;rid,sn,e)
\]

日常接入時，FGS 看見 `C`，但不取得裡面的 `rid`。HNCC 知道 issuance session 的 `rid`，但在盲發行
條件下無法把最終 `C`／ticket 配回該 session。只有案件授權成立且至少 `t_O` 個 OA 提供有效份額，
combiner 才能恢復票券綁定的 `(rid,sn)`。

I5 很重要，因為它阻止惡意 UE 把別人的身分、空資料或不可合法開啟的內容放進 `C`。因此這個設計
不是在「匿名」與「追責」二選一，而是把兩者放在不同時間與權限邊界：

```text
正常使用：不能由 issuance log 配對身分
合法案件：經授權且達 OA threshold 後開啟特定 ticket
```

## 6. Home-domain 與 visited-domain 資料被共同分析時能保護到哪裡

這一點必須按 threat model 說清楚。

目前 issuer-unlinkability game 已讓 honest-protocol curious HNCC 保存兩個完整 issuance views，之後
取得兩張最終 tickets 並嘗試配對。這涵蓋「其他 NCC 所屬 FGS 的 ticket contents／digests 與 HNCC
的 issuance records 被共同分析」時的核心密碼學問題：只靠 issuance transcript 和 ticket，仍不應
能可靠配對。這是在分析跨行政域分享資料，不表示 HNCC 與 FGS 原本是同一組織。

但目前結論有以下限制：

- HNCC 必須依共同 protocol 誠實發行；惡意 issuer 任意簽票、誣陷或偏離 relation 不在現有 theorem。
- HNCC 不持有足夠 opening shares；若它和至少 `t_O` 個 OA 共謀，系統設計本來就允許完成開啟運算，
  是否有合法授權則由 opening governance 另行限制。
- 每位使用者必須使用共同 `ctx`、policy、expiry bucket、key IDs 與 wire length。若 HNCC 為不同使用者
  安排唯一 metadata，就可能形成 watermark。
- 發行時間、接入時間、封包大小、路徑與位置可能形成 traffic correlation；blindness theorem 不隱藏
  這些 network metadata。

因此不能把結果寫成沒有條件的「防 HNCC–FGS 共謀」。較準確的說法是：

> 對遵循發行協定、沒有 opening threshold 的 curious HNCC，即使取得最終 ticket contents，核心目標
> 是隱藏 ticket 與 issuance session 的配對；active watermark、opening-threshold collusion 與 traffic
> analysis 需要治理、角色分離及額外系統假設。

## 7. Blind issuance 與計算前移的關係

Blind issuance 的代價主要發生在接入前：

- UE 建立 hidden ticket、blind request、trace ciphertext 與 `pi_issue`；
- HNCC 驗證 identity、quota、relation proof 並產生 `z`；
- UE Finalize 並驗證最終票券。

接入時，FGS 不需要重新驗證大型 issuance witness 或 `pi_issue`；它驗證的是 issuer 已認證的固定
ticket，再執行 holder authentication、PQ AKE 與一次性狀態處理。

所以 blind issuance 同時完成兩件事：把發行者與後續票券的配對能力降低，並讓大型合法性證明在
接入前完成。代價是 issuance protocol、proof bytes、UE proving time、HNCC verification time、
Blind-UOV Finalize 和安全證明都比普通簽章複雜。

## 8. 目前正式與實作邊界

| 項目 | 目前可說的狀態 |
| --- | --- |
| Hidden ticket、public statement／witness 與 I1–I5 | Formal core 已定義，且有 executable relation／大量 circuit work |
| Blind-UOV request／response／Finalize 工程 | 有研究實作與 checkpoints；不等於 production closure |
| Issuer Unlinkability | 有 honest-protocol、common-metadata 等前提下的 conditional theorem basis |
| Fork-specific blindness／one-more proof | 仍有未封閉的 proof 與 independent-review blockers |
| `pi_issue` 的合格 PQ SE-NIZK backend | 尚未封閉 |
| Malicious-issuer framing resistance | 現有 core 不處理；需要 threshold issuer、可稽核發行或其他機制 |
| Traffic／timing unlinkability | 不在 core cryptographic theorem 內，仍需系統分析與實驗 |

本堂解釋現有設計，不提升 proof 或 production claim。正式依據見
[architecture M1／M2](../../ARCHITECTURE_zh-TW.md)、[研究狀態](../../RESEARCH_STATUS_zh-TW.md)、
[protocol-to-implementation guide](../../docs/guides/PROTOCOL_TO_IMPLEMENTATION_GUIDE_zh-TW.md) 與
[core proof source](../../docs/proof/source/pq_rbbc_sgtd_core_proof_v1.tex)。

## 9. 口試時可以怎麼回答

> HNCC 在發行時必須知道註冊身分，盲簽章保護的不是 enrollment anonymity，而是 issuer
> unlinkability：HNCC 不應把某個已知身分的 issuance session 配到日後 FGS 看見的最終 ticket。
> 普通簽章會讓 HNCC 看見並記錄確切 payload、ciphertext 或 digest；blind issuance 只讓它接收
> blind request，UE 之後自行 Finalize。因為 issuer 看不到 hidden ticket，UE 還要提供 `pi_issue`，
> 在零知識下證明 ticket shape、canonical digest、blind request、holder secret 及 trace ciphertext
> 都綁定同一份資料與這次已認證的 `rid`。這個設計把大型證明放在接入前，但需要 Blind-UOV、
> PQ SE-NIZK 及額外安全證明。目前 issuer unlinkability 是有 honest-protocol、common-metadata、
> no-opening-threshold 和非 traffic-analysis 等條件的目標，不能宣稱抵抗所有形式的共謀。

下一堂分析「為什麼發行、接入驗證與身分開啟要分給不同角色」，以及角色合併後哪些權力會集中。
