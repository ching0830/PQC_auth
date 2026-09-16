# TH-UT：Universal Thresholdizer＋ML-KEM hybrid 適用性草案

判定：**OPEN**。來源為 `2017-956.pdf`，SHA-256
`8123d5e1ae1d67f054f6f55d4026bb6d3248356cde1a261c66137fd46bcc45b5`。
完整來源／revision 與補充 FIPS 203 引用見 [來源索引](SOURCE_INDEX_zh-TW.md)。
此文件承接 [逐項稽核](HANDOFF_VERIFICATION_zh-TW.md) F-03–F-06，不重新宣稱已解決原文缺口。

## Construction 與適配範圍

Definitions 7.1–7.6、Construction 7.7（pp. 24–27）給 threshold FHE／UT 的抽象工具；
Construction 8.29 與 Theorems 8.30–8.34（pp. 35–36）給 threshold PKE 的方向。
`F_(C,ad)(sk)` 必須是**完整** ML-KEM decapsulation 加 CAE authentication/decryption
及明確 reject output 的 circuit，不能只 thresholdize KEM secret 再交給單一 combiner 解密。
原文沒有 ML-KEM 或本案 80-byte AD；這個 hybrid 是 derived adaptation。

Definition A.7（p. 44）要求 perfect correctness；ML-KEM 的非零 failure 不能直接套入。
條件式 `Pr[opening failure] <= delta_K + delta_UT` 只在 honest sampling、CAE 正確、
execution 完成且 delta_UT 已涵蓋**整段最終輸出**時成立。若只知 Definition 7.1 的
single output bit failure，需處理 384 message bits 及 reject indicator 的 aggregate failure。
該 union bound 也沒有處理 malicious witness、selective failure 或對手視圖。

## 不可略過的 proof findings

- Appendix E.4 pp. 55–56 的 H2 將 commitments 換為 zero，而 corrupted-party shares 帶有 `tfhesk,ri` openings；一般 hiding 不能直接說明帶 openings 的 view 不可區分。稽核確認了 proof-step 缺口，未宣稱真實協定攻擊或已完成修補。
- Definition 8.27 p. 35 的 step 8 未明寫 challenge ciphertext decrypt 禁令，Appendix G p. 61 卻使用此限制；Theorem 8.33 的 cross-reference 也需明確對映。
- 原文的 PPT PZK／commitment／simulation 假設，不自動提供本案完整 QPT composition。不能把 TFHE 換成任意 generic MPC 仍稱同一 theorem instance。

候選後續應交付修訂 game、逐 hybrid 的 adversary view／simulation argument 與精確量化，
或明確放棄不能支援的 claim；在此之前不把原文 theorem 編號當作 system proof closure。

## 大小與執行成本

FIPS 203 Table 3（印刷 p. 39）ML-KEM-768 ciphertext 是 1088 bytes；本案 48-byte
plaintext 加全部 CAE expansion `Delta_bytes` 後，`B_C=1136+Delta_bytes`。
在 provisional sigma=11644、extra=0 假設下 `B_ticket=12860+Delta_bytes`。
Δ 必須涵蓋 nonce／tag／commitment 及所有 DEM expansion；28 bytes 僅是算術示例，未選定 CAE。

此 profile 沒有 observed key、ciphertext、rounds、TFHE cost 或 opening time。
Reference 階段需先提供完整 KEM-DEM correctness、AD／tag mutation／reject 測試及 I5
witness descriptor；TFHE／UT 的 setup、PZK、commitments、參數與 transcript 另行具體化。
所有相關 TB1 backend 方法維持 Unsupported。
