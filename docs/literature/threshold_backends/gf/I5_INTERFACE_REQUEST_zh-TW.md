# TH-GF TB2：I5 witness 與共享介面變更需求

狀態：候選內部 reference **Implemented／Tested**；common／B／opening integration **OPEN**。
本文件為具體 change request，不會自行修改共用介面或 canonical relation。
基準 TB1 commit：`6bb4dab80fe577041b7eb517be11f0e2ef2e9c9c`。

## 已具體化的 witness 與 evaluator

Profile：`gf-hybrid2-pompeii-d4-shake256-otp-ref-v1`。
`ReferenceWitness.u` 為 128 bytes，以 d=4 個、各 n=256 的升冪 bit coefficients 編碼 `R_2^d`。
每一 bit 都有定義，無 alternate encoding 或 padding。這是 secret encryption witness，
不是 OA secret key、不是 sender authentication，也不能公開作 audit evidence。
本 OTP DEM 為給定 u 的確定函數，故不另有 DEM coins。

`check_encryption_relation_reference(pk, inputs, C, witness)` 重新計算本 profile 的完整
`c1||c2||c3||c4`，與 C 比較。TraceInputs 固定 `rid[32],sn[16],ctx[32],h[32]`，由同一 sn
同時導出 plaintext=`rid||sn` 與 AD=`ctx||sn||h`。
它檢查給定 pk、u、rid、sn、ctx、h 與 C 是否滿足此加密關係；不驗證 holder preimage、其他
I1–I4、authorization 或任何 ZK proof，也不能作只拿 statement/proof 的 `VerifyIssue`。
關係成立之外仍須驗證 tpk 身分：例如合法 witness `u=0` 導致 Pompeii c1 為零，完整 Hybrid2
密文對不同 pk 相同，兩把對應私鑰都可解出它。這個 reference 不檢查 ctx／可信設定／pp
是否指向該 pk。此反例與處置見 [GFR-01 審查紀錄](review/REVIEW_zh-TW.md)。

## CR-GF-01：真正 reference profile 的註冊

本輪只有候選內部 record。TB1 closed-world registry 的 estimate IDs 保持原樣，common
dispatcher 對新 ID 回報 unknown profile，對舊 estimate profile 的 production 操作仍 Unsupported。
需由 common owner 審查後選擇下一版 grammar／registry，釘選完整 descriptor digest，
不能把 `gf-pompeii-d4-estimate-v1` 靜默改成已實作 profile，也不能讓研究成功路徑進 production。

## CR-GF-02：B 的 witness／relation ABI

TB0 唯讀 B tip `fc59ff0c7a8fba8bc443c488e37f9a148f238753` 所見 v1 witness 固定
error vector 836、M payload 368 bytes。本 profile 的 u payload 128、raw C 2848 bytes，
不能塞進該 ABI 或將欄位誤稱 error vector。本輪未重新定義或修改 B 當前工作。

請 B owner 釘選屆時實際 tip，審查以下接點：

| 接點 | 此候選的具體輸入 | 尚待整合 |
| --- | --- | --- |
| Profile／tpk | 此 profile ID、descriptor SHA-256、public-key record | 可信設定驗證 key ID／epoch／用途並對上同一份 pp 的 tpk digest；不能以重加密成功代替身分綁定 |
| Witness slot | secret u，128-byte payload；candidate record 190 bytes | 選擇 payload 或 record 的唯一 grammar、bounds、版本 |
| Ciphertext slot | raw c1/c2/c3/c4 合計 2848；record 2910 | canonical M 是否含 record、profile identity 所在處、新 M 長度 |
| I5 relation | 相同 u 導出 Pompeii、H/H'/H''/G、AD 與 rid/sn | 完整 constraints、同一 M/rid/sn/h wires 與 I1–I4 join |
| Public partition | canonical `pp,ctx,sid,rid,beta` | M／u 留在 private witness；Verify 不取得它們 |

Reference evaluator 不提供 row streams／BR1CS／proof；不能把 Python 回傳 True 當成 constraint。
接受流程需從同一份已驗證 pp／設定取得 tpk，並核對 profile／公鑰 record identity，再做 I5。
測試須包含 u=0 的跨 key 反例：I5 關係可成立，但 expected-key mismatch 必須由整合層拒絕。
這個要求已有 canonical ctx 的 OA key ID 綁定方向；GF adapter 尚未實作。
SHAKE256 的多次不同輸出長度、integer rounding、q/p centered lift、負係數、packing、
reencryption 對應的 circuit 成本與 witness topology 都未量測。

## CR-GF-03：opening 與安全邊界

Full-secret-key `decrypt_reference_for_test` 僅在隔離 reference 使用。正式 opening 的 trusted
TicketView→AD 來源、canonical d_M、授權、share validity、multi-round session、replay／crash
恢復與 OA DKG 均仍依 TB0 IR-01–IR-05 處理，不能直接接上此函式。
本輪不把 Python full-key 解密包成 `create_share`，也不把 centralized reconstruction 稱為 threshold。

TH-GF T1–T4／QROM 實例資格仍 OPEN：此 descriptor 固定研究 choices，不代表來源 proof
條件已滿足。後續應先審查獨立向量、bad-key／failure 分析、具體 hash／DEM composition 與
選定 MPC／DKG 模型，再決定是否進 TB3。嚴格 one-use access 仍是另一個 M6 系統義務。
