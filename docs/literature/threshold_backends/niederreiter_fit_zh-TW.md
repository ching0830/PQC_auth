# TH-NIED：Threshold Niederreiter baseline 適用性草案

判定：**OPEN**。來源為 `2025-757.pdf`，SHA-256
`5e6135b80cac690d95beb73914d89b77280c6ea739ff7a1f7add0da39663ffb6`。
這是 attachment 的 2025 revision；不同於後續 DCC version of record。完整 revision／bytes
見 [來源索引](SOURCE_INDEX_zh-TW.md)，詳細核對見 [稽核 F-07](HANDOFF_VERIFICATION_zh-TW.md)。

## 原文與 repository 的差別

原文 Fig. 7（p. 24）／Fig. 8（p. 30）的 ciphertext 包含 syndrome、masked message 與
NIZK `pi`。各 decryptor 在 distributed decoder 前先驗證 NIZK；原文 reconstruction 暴露 e。
Definitions、games、Theorems 3–5／8 都必須依該 construction 與對手模型解讀。

Repository reference 的形式則是 `C=(s,c_mu,gamma)`：

```text
Z = SHAKE256("PQ-RBBC/KDF" || Encode(e) || s || ctx, 80)
P = Z[0:48]; K_mac = Z[48:80]
c_mu = (rid || sn) XOR P
ad = ctx || sn || h
gamma = KMAC256(K_mac, s || c_mu || ad, custom="PQ-RBBC/TAG", 32)
```

這是本案 KDF／KMAC trace DEM。把 issuance relation 放 offline，並在 opening 前加
authorization gate，不等於原文 NIZK-before-decoder 的 threshold CCA construction。
本案所需為 canonical T1–T4；未要求或自動獲得 bare IND-CCA。必須另處理惡意 issuance、
無效 syndrome、gate-compliant chosen-ciphertext query、e 暴露與 robustness 的適配論證。

`src/pq_rbbc_reference.py` 的 `SystematicParityCheck` 是 deterministic test fixture，
不是 production Goppa key。既有 source/vector／relation tests 的 PASS 不能解讀為
已實作 McEliece keygen、Patterson decoder、OA DKG 或 threshold reconstruction。

## 大小與下一階段

6688/5024/128 的 repository 格式算術為 `(6688-5024)/8 + 48 + 32 = 288 bytes`。
M 的固定 prefix 80 加 C 為 368 bytes；provisional sigma=11644、extra=0 得 12012 bytes。
這是 **estimated 格式大小**，不含原文的 NIZK，也不是實測 threshold ciphertext。
原文 §6/Table 1 pp. 31–32 的 `|pi_L|=42.1 KB` 與 `|c_CM|=208 B` 是不同協定實驗的
literature_reported 值；不把兩者挪成此 288-byte profile 的 observed evidence。

後續需先選定 key／decoder 的可信來源、正確性與 failure 行為、final code／sharing／MPC
參數及 I5 error-vector encoding，再決定 non-threshold reference 的可測範圍。
重用 canonical KDF 時仍需固定 e 的 836-byte little-endian 編碼、syndrome 及 ctx 的順序。
DKG、robustness、數學 share validity、多輪 session 與本案 adapted proof 全部 OPEN；
TB1 的 encrypt/decrypt/share/combine 均 Unsupported。
