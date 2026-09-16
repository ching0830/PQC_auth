# TH-GF TB2 技術複核

日期：2026-09-13。審查對象為 `b003c3d61ca8fa3382fc85848f81efaace634278`，tree
`57b3ec1dbd6dafba7aff3c671a36047125cefa90`。本輪以 `codex/threshold-gf-tb2-review`
獨立 worktree 進行，local main 仍為 `6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`。

**結論：bounded reference 的第二套算術／完整解密對照 PASS；發現一項需修正的公鑰綁定
宣稱，已修正文義並補反例測試。Common/B/opening 接合、外部獨立審查及 production 均 OPEN。**
本輪由原作者代理執行，新增另一套演算法計算作交叉檢查；這不是外部 independent reviewer
attestation，不能填入 B 或 production 所要求的獨立審查證明。

## 精確來源與方法

重新驗證 19 份先前已讀 canonical／research／policy 來源及 TB2 summary 的 10 個
code/test/profile identities。`2021-096.pdf` 為 695,683 bytes，SHA-256
`b730d4640218b5ea86b019a52501be2e4682b562e61a468abd08658ee393678e`；
完整名稱與 2021-08-31 revision 歸屬限制延用 [來源索引](../../SOURCE_INDEX_zh-TW.md)。
本輪從 exact PDF 重新抽取 pp. 8、24、45，核對 centered convention、Hybrid2 及 Pompeii。
沒有把 PDF 或抽出文字加入 Git；publisher byte identity 仍未確認。

新增 `tests/threshold_candidates/gf/review/oracle.py`，只 import `fractions`、`hashlib`、
`struct`。它不 import implementation、profile constants 或既有 test helpers：

- 原 reference 的環乘法是 nested loops 與 negacyclic wraparound；新 oracle 將非負 mod-q coefficients 以足夠寬的 radix packing 放入大整數，完整相乘後折回 `X^n=-1`。
- 選 `B=2^w > n(q-1)^2`，每個普通 convolution coefficient 都小於 B，因此沒有跨 coefficient carry；折回後再 modulo q。
- 另寫 bit-by-bit parser／packing、record parser、Fraction rounding、Pompeii decrypt／reencryption、Hybrid2 c4/c3/DEM／AD／serial checks。
- 3 組 deterministic full-key fixtures × 4 類 u（零、全一、交錯、SHAKE fixture）共 12 組，完整 encoded ciphertext 相同，雙向交叉解密相同。
- 對 ciphertext 各 component、AD、內外 serial 做交叉拒絕檢查；另驗新 oracle 的 record type/length 拒絕（原 decoder 由既有 TB2 codec tests 覆蓋），並加入零 witness 跨 key 及重用 u 的反例。

Python bigint、stdlib SHAKE256 及本機 runtime 是共同依賴；新 oracle 並非另一個 crypto
library，也不是 upstream KAT。測試的 pk／R1 仍由受測 reference KeyGen 產生，新的 oracle
不另實作 KeyGen。這些 checks 沒有提供小到密碼學量級的 failure bound 或 security proof。

## GFR-01：I5 關係檢查不能提供 universal key identity authentication

優先序：P2（介面／文件 claim boundary）。位置：原 `I5_INTERFACE_REQUEST_zh-TW.md`
的 evaluator 說明，把「拒絕錯誤 pk」與一般 input mutation 並列，容易推論為可拒絕任何
expected-key mismatch。反例使用兩把由正確 reference KeyGen 產生且 record 不同的 key：

```text
u = 0 in R_2^d
u^T A1 = u^T A2 = 0 for every public key
Pompeii.Enc(pkA, u) = Pompeii.Enc(pkB, u) = all-zero c1
```

本 profile 的 c2/c3/c4 僅再依賴 u、同一 AD 與 plaintext，故完整 C 對 pkA/pkB 相同。
I5 evaluator 使用 pkB 仍接受 pkA 的 C；用 skB 解密亦回傳同一 plaintext。
此結果已由 reference 與新 oracle 重現，不能靠再跑一次 reencryption 改變。

這是合法 message/witness，沒有偏離 Fig. 14 的算式。理想均勻抽樣 1024-bit u 時，
指定零值的機率為 `2^-1024`；可選擇 witness 的研究 harness／對手則能直接指定它。
因此這個反例不宣稱打破 honest-encryption privacy，亦不是 T3 固定 tpk 的不同明文反例。

Canonical core L290–301 已讓 ci 包含 OA key ID／epoch，並以 federation signature 驗證
ci/ctx；GF reference 只取得 caller-supplied 32-byte ctx，沒有驗證這個來源。
本輪固定 ctx 卻換 key 的測試，不代表 canonical 的已驗證設定允許這種替換。
實際含意是：整合層必須驗證 expected tpk／profile／pp／ctx 的綁定，不能從 I5 或解密成功
推論 key identity 正確。

**處置：** 修正 I5 文件，加入
`test_zero_witness_is_counterexample_to_key_identity_authentication`，並交付
[接合驗收提案](KEY_BINDING_ACCEPTANCE_zh-TW.md)。加密 source、既有 descriptor、vectors、
TB2 checkpoint/evidence 均保留原樣；未任意排除 u=0 或增加新的 frozen hash input。

## 其他審查觀察

| 項目 | 結果／界線 |
| --- | --- |
| Centered lift 與 exact rounding | 既有測試＋新完整解密對照 PASS；未發現本輪涵蓋案例的方程差異 |
| c4 → c3 → DEM、AD／內外 serial | 交叉拒絕及既有呼叫順序測試 PASS |
| u reuse | 兩次 c2 的 XOR 等於兩次 `(ad||plaintext)` 的 XOR；與原文件的 OTP 限制一致，沒有把 I5 當 freshness 證明 |
| KeyGen seed expansion | 32-byte seed 展開 A1/R1/R2 依賴具體 SHAKE 計算假設，既有文件已明列；本輪未推成原文的資訊理論獨立抽樣 |
| 本地 vectors | Public digests 是回歸錨點；外部 KAT／獨立實作者對照仍 OPEN |
| Security／threshold | T1 failure/bad-key、T2 QPT model、T3、T4、DKG／MPC／gate/replay 均未由本輪封閉 |

## 更新的 B 工作線唯讀觀察

本輪未執行、import、修改或合併 B source。讀取以下兩個 exact snapshots 的介面：

| Branch／revision | 位置 | 實際接點 |
| --- | --- | --- |
| `codex/pq-rbbc-formal-issuance-relation-v1`，`ff4341bfa18f4cd77c2811e26a7753397cfe7fe8` | `src/pq_rbbc_issuance_relation_v1.py:227`、`:364` | Parameters 有 trace profile/key digest；P0 驗 statement 的 pp digest；現有 I5 仍用 NIED `_derive_trace` 與 error weight |
| `codex/pq-rbbc-issuance-production-inputs-v1`，`e7af82e1e2c176485c03e08dad0e221adf0ee1e9` | `src/pq_rbbc_issuance_production_inputs_v1.py:268`、`:328` | Trace key parser 固定 NIED；common PP 綁 profile、公鑰 SHA-256、certification SHA-256、issuer key 與 relation manifest |

這些欄位支持 GFR-01 所需的外層 identity binding 方向，不表示 GF 已可接入。GF 的 u=128、
C=2848／record=2910、M encoding 與 full relation 仍需新版本化 mapping。
不可只把舊 836-byte error slot 改長度，或把 GF public-key bytes 當作 NIED matrix body。
精確檔名、revision、bytes 與 SHA-256 見 [review_summary_v1.json](review_summary_v1.json)。

## 驗證

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates/gf/review -t tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

| 檢查 | Passed | Failed/errors | Skipped | Elapsed |
| --- | --- | --- | --- | --- |
| 新 review tests | 6 | 0 | 0 | 6.352 s |
| Threshold targeted（含上述 6） | 60 | 0 | 0 | 11.105 s |
| Full regression | 736 | 0 | 12 | 759.093 s |

Full regression 共 748 項；12 項略過皆因對應 optional external artifacts 未安裝。
本輪沒有為消除 skips 下載附件。精確命令、log bytes／digest 與個別略過原因列於
[驗證摘要](review_summary_v1.json)，raw logs 保留在 repository 外。
`git diff --check`、來源 identity、文件連結及禁止 artifact 檢查 PASS；
既有 crypto source、profile、vectors 與 TB2 歷史 checkpoint/evidence 均未變更。

## 決定與後續

本輪技術複核完成，GFR-01 的文件修正與回歸案例已落地；外層 identity binding 的實作仍 OPEN。
下一關先定稿 GF key/profile/pp 與 witness/M ABI 接合方案，再審查多輪設計。
本輪未啟動 TB3、註冊 production profile 或核發任何獨立 reviewer attestation。
Root canonical 文件由 integration owner 更新；本紀錄提供 methodology／experiments／status
的可審查輸入，未直接改寫共用文件。
