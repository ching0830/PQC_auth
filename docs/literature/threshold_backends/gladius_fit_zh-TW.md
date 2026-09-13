# TH-GF：Gladius／Fulham 適用性草案

判定：**OPEN**。共同 codec／算術測試 PASS，不代表 Fulham profile 已具體化。
來源為 `2021-096.pdf`，SHA-256
`b730d4640218b5ea86b019a52501be2e4682b562e61a468abd08658ee393678e`。
完整 revision／bytes 見 [來源索引](SOURCE_INDEX_zh-TW.md)；原文核對見
[HANDOFF_VERIFICATION](HANDOFF_VERIFICATION_zh-TW.md) 的 TH-GF 與 F-02。

## 原文支持與本案適配

Hybrid2 的 Fig. 5（p. 24）與 Theorem 3.2（pp. 23–24）是候選 construction／QROM
分析來源。它仍依賴 rigid deterministic OW-CPA、collision、bottom-aware、failure 等條件，
不能用 paper title 或 handoff 的公式宣稱本案 T1–T4 已成立。

Table 2（p. 46）兩列是底層 **Pompeii Module-LWR**，並非完整 Fulham 的所有參數：

| n | d | t | q | p | ell | sigma | mu_scale |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 256 | 4 | 2 | 4,188,161 | 2^10 | 2^20 | sqrt(1/2) | 256 |
| 256 | 9 | 2 | 33,550,849 | 2^11 | 2^23 | sqrt(1/2) | 512 |

Table 中 sigma 是分佈參數，與 ticket 簽章大小 `sigma_bytes` 不同；mu_scale 與 trace
plaintext 也不是同一物件。§6 pp. 41–42 的 worst-case-message／bad-key bound 不因選
prime q 或省略 LVP 而消失。GF modulus t=2 更不是 OA threshold。

本案將 `ad||plaintext` 合計 128 bytes 放入 Hybrid2 DEM；`Mp=R_t^d`，
`H':Mp->Mp`、`H'':Mp->Mp`、H 到 DEM key 的 domains／輸出編碼仍需候選明確化。
Fig. 14（p. 45）的兩個 module vectors 合計為 c1，不與 Hybrid2 c1 重複計數。
採 packed t=2 encoding 的推導大小為：

| 草案 | c1 | c2 | c4 | B_C | B_ticket（sigma=11644,extra=0） |
| --- | --- | --- | --- | --- | --- |
| d4 | 2560 | 128 | 128 | 2816+g | 14540+g |
| d9 | 6336 | 128 | 288 | 6752+g | 18476+g |

以上 **estimated**；g 是 c3 完整編碼長度，未知不作 0。
§9 的 4.99 秒、136,491 rounds 為 plain-LWR／Hispaniensis 的特定實驗，
不是本案 Module-LWR Fulham、也不是本工作線 observed runtime。

## Reference 階段需先決定的項目

1. 精確 Hybrid2／Pompeii 組合、message sampler、centered representation，以及 pp. 9–10 的 nearest rounding（ties toward zero）；正負 tie 與 reencryption 必須有獨立 vectors。
2. H、H'、H''、G、g、DEM、packing、失敗值與 canonical rejection；不得由 size preset 推得 full profile。
3. I5 witness 的 exact encoding 及 same rid/sn/h/AD 綁定，另向共同契約與 B owner 提 change request。
4. T1 量化 failure／bad-key bound，T2 的 QPT game／QROM mapping，T3 unique opening 與 T4 robust share validity。
5. Fig. 15（p. 48）DKG 與 distributed decryption 的實際 participant／adversary／round 模型；session／replay adapter 等待 opening owner 決定。

TB1 未實作 reference encryption、rounding、hash instantiation、DKG 或 distributed opening。
下一階段若獲授權，先做 non-threshold reference；單機成功 decrypt 不構成 threshold evidence。
