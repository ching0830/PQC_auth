# Threshold backend：安全義務與整合關卡

此文件是 TB1 工作線的 obligation register，不改寫 root canonical status。
依據 core `pq_rbbc_sgtd_core_proof_v1.tex` 在 main
`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb` 的 T1–T4（L479–518）及 I1–I5（L530–572）。
論文來源、exact digest 與原文適配缺口見
[來源稽核](../literature/threshold_backends/HANDOFF_VERIFICATION_zh-TW.md)。

| ID | 必須交付的證據 | TH-GF | TH-UT | TH-NIED |
| --- | --- | --- | --- | --- |
| O-T1 | Valid-input correctness，完整參數、failure event、bound、reference vectors | OPEN：rounding、bad keys、Hybrid2 | OPEN：非 perfect correctness 與 multi-bit failure | OPEN：真實 key／decoder、failure |
| O-T2 | QPT threshold privacy game，corruption／query／setup 模型及 reduction | OPEN：完整 Fulham QROM 條件 | OPEN：UT/PZK simulation、E.4 view 與 CCA game | OPEN：原文 NIZK construction 到本案 gate／issuance 適配 |
| O-T3 | 固定 tpk、AD、C 的 unique opening，含拒絕值語意 | OPEN | OPEN：完整 CAE decrypt function | OPEN：DEM 與 decoder 一致性 |
| O-T4 | 偵測無效份額與 robust reconstruction；authentication 不替代數學證明 | OPEN | OPEN | OPEN |
| O-I5 | 完整 encryption relation，與同一 M/sn/h/rid 的 I1–I4 wires 相接 | OPEN：u／randomness descriptor | OPEN：KEM／DEM coins descriptor | OPEN：真實 Enc relation／e descriptor |
| O-SETUP | tpk、member set、threshold、epoch、setup／DKG evidence，OA/FAC key-purpose 分離 | OPEN | OPEN | OPEN |
| O-GATE | 同票證驗證來源的 AD、canonical d_M 與 authorization、transcript、replay／retry／crash 綁定 | OPEN | OPEN | OPEN |
| O-WIRE | 完整 candidate payload grammar、拒絕 alternate encodings、profile／relation identity migration | OPEN | OPEN | OPEN |
| O-COST | 分開量測 offline issuance、ground opening、satellite online path | 無候選實測 | 無候選實測 | 無候選實測 |

TB1 codec／accounting 28 項 tests 的通過，只支持共同 grammar、算術與 fail-closed dispatch。
它們沒有 oracle simulation、cryptographic adversary、distributed parties、durable state 或
實際 proving；不能把任何 O-T1–O-COST 項目改為 Proof-closed 或 Production-closed。

Canonical `VerifyTicket` 是 stateless；strict one-use 另屬 M6 holder authentication 與
linearizable FGS consumption。門檻 backend 不建立或繞過 M6。LEO 不因 literature handoff
文字而取得可信／HBC 假設；角色與信任邊界以 architecture 為準。

實作整合變更應依 [TB0 IR-01–IR-07](../literature/threshold_backends/TB0_INTERFACE_INVENTORY_zh-TW.md)
交給 owner：opening context／session、canonical digest、share validity、KDF metadata、B 的
I5/witness ABI 及 root 文件。後續候選提交 reference evidence 時，須逐項回報 PASS／OPEN／FAIL，
不得由本機測試 PASS、paper-verified locator 或 schema valid 推論整體安全性。

本輪未批准、執行或宣稱完成 candidate reference、threshold crypto、production proving、
大型 relation replay、independent review 或 production launch。
