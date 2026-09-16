# 第十四堂：受控身分開啟為什麼需要兩道門

日期：2026-09-15。所屬階段：3／完整系統流程。
接續 [第十三堂](13_EXPIRY_REVOCATION_HANDOVER_zh-TW.md)：正常接入只驗證票券、持票者與服務條件，
不把註冊身分交給 FGS。現在處理例外情境：發生符合規則的案件時，系統如何在不讓單一單位
任意查人的前提下，恢復票券綁定的註冊身分。

## 1. 先分清楚「允許調查」與「有能力解密」

受控開啟需要同時通過兩道門：

1. **案件授權門**：證明這次開啟針對哪張票券、哪個案件、哪份證據、什麼用途，並且仍在期限內。
2. **門檻解密門**：至少 `t_O` 位不同 OA 成員各自核驗同一份請求，提供可驗證且互相一致的份額。

只有第一道門，取得授權的一方可能獨自解密所有票券。只有第二道門，足夠 OA 成員可能在沒有
合格案件時自行湊份額。因此「治理上准許開啟」與「密碼學上能完成開啟」必須分開。

FAC 與 OA 即使由相同組織營運，也要使用不同金鑰、門檻、儀式、儲存與協定角色。這樣的分離
使一種權限或金鑰外洩時，不會自動取得另一種能力。

## 2. 一份開啟請求必須綁定什麼

開啟請求可簡寫成 `Q`。目前 v0.1 邊界要求它至少明確包含或綁定：

| 欄位 | 用途 |
| --- | --- |
| canonical ticket 與 `ticket_digest` | 指定要開啟的確切票券，不能事後換票 |
| `ctx`、`epoch` | 指定適用的共同設定與期間 |
| opening key ID、authorization key ID | 指定哪組解密份額與哪組授權金鑰 |
| `case_id` | 指定案件，避免把某案授權搬到另一案 |
| `evidence_digest` | 綁定支持這次開啟的證據 |
| `purpose` | 限制開啟用途，而不是給予一般查詢權 |
| `expiry` | 過期後不得繼續要求份額 |
| request nonce | 區分請求並形成 replay key |
| `authorization` | 對上述授權敘述的認證資料 |

授權所簽的 statement 不包含 `authorization` 自己，否則會形成「簽章內容必須先包含尚未產生的
簽章」的循環；完整 `request_digest` 則包含 authorization，使 OA 份額綁定最後收到的整份請求。

因此，簽完授權後再更換 ticket、case、evidence、purpose、expiry、nonce 或 key ID，驗證都應失敗。
這叫做 purpose-limited opening：不是「這個人有開啟權」，而是「這個案件對這張票券的這個用途
在這段時間內獲得授權」。

## 3. 每位 OA 都要先驗證，再碰自己的秘密份額

目前 `OpenShareService` 的設計順序是：

1. 嚴格解析版本與 canonical encoding，拒絕未知版本、長度錯誤、替代編碼或多餘 bytes。
2. 確認本機初始化資料與釘選的信任起點有效。
3. 完整驗證票券，得到可信的 ticket view；不能相信請求者自行描述的票券欄位。
4. 比對 `ctx`、`epoch`、兩種 key ID、issuer、ticket digest、case、purpose 與 expiry。
5. 驗證案件 authorization。
6. 以 case、nonce 與 authorization key 等資料原子地登記 opening replay。
7. 前面全部通過後，才呼叫該 OA 的 threshold backend 產生 share。
8. 先提交 replay 紀錄，再釋出 share。

這個順序的安全意義是：無效票券或無效授權不能觸碰 threshold backend。對外 API 只接受完整
的 `Q`，不提供「傳入任意 ciphertext 就替你做 partial decrypt」的入口。

## 4. Opening replay 與票券消耗是兩套狀態

第十二堂的 ticket consumption 防止同一張票券建立第二個 initial session。本堂的 opening replay
則防止同一案件授權／請求被反覆拿去取得份額。兩者目的、儲存位置與識別鍵都不同。

Opening replay 目前也分為 `fresh → in_progress → committed`：

- 產生 share 前先取得 reservation；同一 replay key 不能同時取得多份輸出。
- backend 在產生任何輸出前失敗，只有持有正確 reservation token 的執行可 abort。
- share 已算出但 replay commit 失敗時，結果不釋出，也不能假定安全地退回 fresh。
- commit 完成後才回傳 share；若之後傳輸失敗，可能犧牲可用性，但不留下未記錄的 share。

這是 fail-closed 取捨：狀態不確定時寧可不開啟，也不冒著同一請求重複產生份額的風險。

## 5. 湊到數量還不夠，所有份額必須屬於同一件事

Combiner 收到份額後，不是只做 `len(shares) >= t_O`。它還要拒絕：

- 成員數低於門檻，或超過設定的成員總數；
- 重複的 member ID；
- 混用不同 request、ticket、case、epoch 或 opening key 的份額；
- 過時金鑰、錯誤票券、格式不正確或認證失敗的份額。

通過後才重建追責明文 `(rid, sn)`。接著還有兩個終點檢查：驗證 trace authentication，並確認
解密得到的 `sn` 等於票券上可見的 `sn`。序號相等檢查阻止把甲票券的身分密文或解密結果，
拼接到乙票券上輸出。

測試 fixture 目前使用 **5-of-7** 作為一組測試參數：五份相符份額通過、四份失敗。這只證明
控制流程在該 fixture 下有相應測試，不代表論文已把正式部署門檻固定為 5-of-7，也不代表目前
已經有真實的門檻密碼學實作。

## 6. 小明案件的完整例子

假設稽核單位取得一張已通過格式與票券驗證的 `T_A`，並有案件 `case-42` 的證據：

1. 依政策產生只適用於 `T_A`、`case-42`、指定 evidence 與 purpose 的限時 authorization。
2. 每位 OA 收到相同 `Q_A`，獨立執行票券、授權、期限與 replay 檢查。
3. 合格 OA 各自回傳綁定 `Q_A` 的 share；低於 `t_O` 時無法完成開啟。
4. Combiner 核對成員不同、份額一致且有效，重建 `(rid_A, sn_A)`。
5. 只有 trace authentication 通過且 `sn_A` 等於 `T_A` 的明文序號，才輸出 `rid_A`。

若有人把 purpose 改成另一用途、換成 `T_B`、混入另一案件的 share，或只有 `t_O - 1` 位成員，
流程都應停止，不輸出身分。

## 7. 這個設計能保護什麼，不能直接推論什麼

- 正常接入不執行 opening；FGS 驗票不會因此自動取得 `rid`。
- 在適用的 threshold security 假設下，少於 `t_O` 份 OA 秘密份額不能重建身分。
- 合法開啟恢復的是票券綁定的 `rid` 與 `sn`，不是裝置內的 holder secret `k_hold`。
- 成功合併後已經出現身分，因此誰能接收結果、如何保存及稽核，仍需要治理與存取控制。
- 隨機偽造且連格式／票券驗證都失敗的資料，沒有保證含有可歸責的有效追責明文。
- 防止嫁禍還依賴發行關係把 trace plaintext 綁定 HNCC 已認證的 `rid` 與同一 `sn`，並依賴
  opening 終點的認證與序號比對；只有「可以解密某段 bytes」並不夠。

## 8. 目前實作與宣稱邊界

| 部分 | 目前狀態 |
| --- | --- |
| canonical OpeningRequest／authorization statement／OpenShare codecs | 已實作 deterministic v0.1 邊界與格式拒絕測試 |
| `OpenShareService` 驗證順序、replay gate 與 fail-closed 控制流 | 已實作並有正反例、replay 與失敗路徑測試 |
| Combiner 的門檻數量、一致性、序號比對控制流 | 已實作抽象邊界，使用 test-only backend 測試 |
| 正式 authorization signature | 尚未實例化為 production PQ signature |
| OA DKG、真實份額金鑰、robust threshold decoder／share proof | 尚未完成 |
| trace authentication 與 production opening transcript | 尚未完成；目前測試 adapter 不是密碼學證據 |
| trace KDF 的 80-byte 分割順序 | TeX 與 reference 仍有未解歧義，production decoder 因此 fail closed |

所以現在可說的是：**開啟請求、檢查順序、replay 與 combiner 的工程邊界已被定義並測試**。
不能說已完成可部署的後量子門檻身分開啟，也不能把單元測試當成 threshold security proof。

本堂的正式對照入口是 [Conditional Opening Gate v0.1](../../docs/artifacts/CONDITIONAL_OPENING_GATE_v0_1_zh-TW.md)
與 [Protocol 到工程實作導覽 §7](../../docs/guides/PROTOCOL_TO_IMPLEMENTATION_GUIDE_zh-TW.md)。對應程式分別在
[request.py](../../src/pq_rbbc/opening/request.py)、[gate.py](../../src/pq_rbbc/opening/gate.py) 和
[combiner.py](../../src/pq_rbbc/opening/combiner.py)；閱讀時仍以
[研究狀態](../../RESEARCH_STATUS_zh-TW.md) 判斷哪些只是介面、哪些已測試、哪些尚未 production-closed。

下一堂會把設定、發行、接入、一次性狀態、換手與受控開啟串成一個完整案例，整理每個角色
在每個階段能看到什麼，作為階段 3 的總複習；這也會讓我們進入階段 4 時能逐項比較設計取捨。
