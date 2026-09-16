# Handoff 原文核對與 findings v1

日期：2026-09-13。輸入身分與 revision 限制見 [來源索引](SOURCE_INDEX_zh-TW.md)；
所有 `SRC-*` 均指 [inventory](source_inventory_v1.json) 中的 exact bytes。
本次只完成 pre-TB0／TB1 source audit；沒有執行附件提出的工作分配或 TB0／TB1 實作。

## 判定方式與權威

- `paper-verified`：此列陳述已對照指定附件的原文；只涵蓋列出的命題／位置。
- `repository-verified`：此列已對照固定 base 的 canonical 文件或程式。
- `derived`：由已列明前提作本次推導／算術核算，不是原文直接給出的系統結果。
- `OPEN`：欠缺具體參數、來源、定理擴充、版本核對或實作證據。
- `finding`：記錄差異、缺漏或需釐清的論證；不自動代表真實協定攻擊，也不等同整個候選 FAIL。

未設置整份 handoff 或整個候選的 `paper_verified=true`。三篇原文沒有替本專案完成
T1–T4、同票證 I1–I5、授權治理、真實開啟視圖與量子安全的組合審查。

Repository base：`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`。
Canonical core proof blob：`c842c31ebbabbd1b8f1ed5ee8fa74d85f63ef177`，與 handoff §2 所列一致。
Repository canonical contract 決定本專案語意；原論文決定該論文 construction／theorem 的內容。
兩者之間的改造需另外證明，不能以其中一方的名稱替另一方背書。

## 共同契約對照

下列位置均指 base 下的 [core proof](../../proof/source/pq_rbbc_sgtd_core_proof_v1.tex)、
[architecture](../../../ARCHITECTURE_zh-TW.md) 與
[reference](../../../src/pq_rbbc_reference.py)。這些不是三篇候選論文的票證契約。

| Handoff 位置／陳述 | Canonical 核對位置 | 結果 |
| --- | --- | --- |
| §3、§4：明文 `rid[32] \|\| sn[16]`，共 48 bytes | core source L2053–2062；reference `_derive_trace` | repository-verified |
| §3、§4.1：`M=(ctx,sn,h,C)`，AD=`Encode(ctx,sn,h)`，80 bytes | core L530–567、N2；reference `_derive_trace` 中 `common_ctx + sn + holder_hash` | repository-verified；不是帶任意額外 prefix 的新 envelope |
| §4.1：`x=(pp,ctx,sid,rid,beta)`，同一 I1–I5 | core L553–572；I5 明確使用 `M.C`、`M.sn`、`M.h` 與本次 `rid` | repository-verified（formal statement）；不把 legacy `IssueStatement` witness evaluator 當作真實 `Pi_issue.Verify` |
| §4.2：T1 valid-input correctness、T2 threshold privacy、T3 unique opening、T4 robust shares | core L479–518 | repository-verified；T1 沒有自動容許任意失敗，T2 指 QPT；bare IND-CCA 明確不要求也不宣稱 |
| §1、§3：OA 與 FAC 金鑰／用途分離，開啟在地面，不把 issuance proof 放入在線票證 | architecture 角色表、M2–M5；core Setup | repository-verified；不因此認定 ML-KEM AKE 已選定或已實作 |
| §3：LEO honest-but-curious 的先前聊天敘述 | architecture 角色表、methodology 信任假設：LEO／FLEO 不預設可信 | finding F-10；canonical 優先，不能以附件的歷史敘述改 threat model |
| §9：`sigma_budget=11644` | reference `SIGNATURE_BYTES`；core L2357–2370 的 provisional target | repository-verified 的預算來源；不是本次實測簽章大小，也未重新核對 Blind-UOV 原論文 |

## TH-GF：Gladius–Fulham

| Handoff 位置／陳述 | 原文位置與核對結果 | 判定 |
| --- | --- | --- |
| §5 A：完整 Hybrid2＋Module-LWR | SRC-GF p. 7 family table；§3.2 pp. 23–24；§7 pp. 44–45 | paper-verified：Fulham 的組合識別正確 |
| `C=(c1,c2,c3,c4)`；`c1=Ep(pk,u)`；`c3=G(c2,H'(u))`；`c4=H''(u)` | Fig. 5 p. 24；將原文斜體 `k` 改記 `u`，避免與 DEM key 混淆 | paper-verified：變數重新命名後對應一致 |
| `c2=Encode(ad,mu) XOR H(u)` | 原文是 `Es(H(u),m;r)`，容許 one-time IND-CPA DEM；本 handoff 選 OTP 並取 `m=ad \|\| mu` | derived：可作研究實例，但 128-byte 訊息、H 輸出長度及 AD 接合是本專案選擇 |
| H／H'／H''／G 定義域、值域 | §3.2 p. 23：`H: Mp -> Ks`，`H',H'': Mp -> Mp`，`G: {0,1}* × Mp -> {0,1}^{\|G\|}` | paper-verified；不能任意把 H'' 改成較短 digest |
| 解密檢查 | Fig. 5：Dp 拒絕、c4、c3 檢查，再解 DEM；底層 Fig. 14 p. 45 明確含 re-encryption check | paper-verified；外部 AD 與解出的 AD 相等是本專案另需加入的檢查 |
| QROM 與 failure 條件 | Theorem 3.2 pp. 23–24 同時含 one-time DEM、OW-CPA、rigid deterministic PKE、collision／⊥-Aware 及 failure 項 | paper-verified 的 theorem 前提；不能只從「Hybrid2」推出本系統量子安全 |
| prime-q 無 LVP 分支、Table 2 參數 | Table 2 p. 46 確有 handoff 的兩列；§6 pp. 41–42 的 worst-case-message／bad-key 分析 | paper-verified 的底層參數來源；完整 Fulham profile OPEN，見 F-02 |
| `u` 不同卻同一 c4 則 H'' collision；同一 u 則 c2 固定訊息 | 依 Fig. 5 作本次關係推導 | derived；需量子 collision resistance 與 canonical encoding，非原文對 PQC_auth T3 的定理 |
| 4.99 秒不是本 Fulham 後端數字 | §9 pp. 48、51–52：plain LWR／Hispaniensis，3 parties、1 dishonest，`q=2^21-9,n=1024`，136,491 communication rounds | paper-verified；僅 literature_reported，沒有本機 benchmark |
| DKG 與互動解密 | Fig. 15 p. 48 有 distributed key generation 描述；§3.3 p. 35 與 §9 有 MPC 解密 | paper-verified 的協定描述；不能說原文完全沒有 DKG，也不能說本專案已實作 |

Table 2 的兩個被 handoff 引用的底層 row，目視核對如下。這裡 `t=2` 是明文係數模數，
`mu_scale` 是原文 μ 的 scaling constant，兩者都不是 OA 門檻或本專案 48-byte 明文。

| n_ring | d_module | t | q | p | ell | sigma | mu_scale |
| ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| 256 | 4 | 2 | 4,188,161 | 2^10 | 2^20 | sqrt(1/2) | 256 |
| 256 | 9 | 2 | 33,550,849 | 2^11 | 2^23 | sqrt(1/2) | 512 |

Table 2 的標題是 **Gladius–Pompeii parameters (based on module LWR)**；其 deterministic
Module-LWR 元件可供 Fulham 組合研究。兩列的 ⊥-Aware 欄為 `c'=N/A`、`Adv^-1=2^infinity`，
不可讀成所有金鑰、所有模型下零失敗。§6 pp. 41–42 仍保留 exponentially small bad-key set，
§7 p. 45 的參數列表也包含 epsilon；handoff 的四個數字不是完整參數。
原文 Table 2 的 LWE、LWR theoretical、best-attack 三種估計不可混為單一安全等級，
也不能用任一欄直接宣稱與 ML-KEM-768 同級。

§2 p. 9 的取整是 nearest integer，正負 half-tie 朝零，且使用 centered representatives；
Fig. 14 的模數轉換及再加密檢查均須保留。未指定 hash 實例／domain encoding、`|G|`、
epsilon／壞金鑰界、OA access structure 與 MPC 前，TH-GF 仍不是 production canonical profile。

## TH-UT：Universal Thresholdizer＋ML-KEM hybrid

| Handoff 位置／陳述 | 原文位置與核對結果 | 判定 |
| --- | --- | --- |
| §5 B、§12：Construction 7.7 | SRC-UT pp. 26–27，使用 TFHE、PZK with preprocessing、non-interactive commitment | paper-verified：編號與元件正確 |
| Setup／Eval／Verify／Combine | Definition 7.1 pp. 24–25；Construction 7.7 把 `x` 的 bits 加密，公開 key-share commitments；Eval 產生 partial decryption 與一致性證明 | paper-verified；不是只把 ordinary secret key 用 Shamir 拆開 |
| Construction 8.29 | pp. 35–36：先產生 PKE key，再以 secret key 為 UT input，`C_ct(sk)=PKE.Decrypt(sk,ct)` | paper-verified：門檻化完整解密函數 |
| 完整 `F_(C,ad)(sk)` 含 ML-KEM 及 CAE | 8.29 支持完整 PKE decrypt 的抽象方向；原文沒有 ML-KEM 或本案 AD／CAE | derived 的設計適配，不是 paper-verified 具體 construction |
| `C=(c_K,v,c_D)`、`a=Encode(domain,ad,c_K)` | 不在 SRC-UT；handoff 沒指定 CAE、v、domain 編碼 | OPEN：本專案 hybrid 草案 |
| Definition A.7 要求完美正確性 | p. 44 的成功機率為 1；Theorem 8.31 p. 36 引用此定義 | paper-verified；ML-KEM 非零 failure 需要定理擴充 |
| UT correctness 允許 negligible failure | Definition 7.3 p. 25 與 TPKE Definition 8.25 p. 34 | paper-verified；不可與底層 PKE 的 A.7 混同 |
| `delta_K + delta_UT` | 原文沒有 ML-KEM 版此式 | derived 的 union bound；條件及全輸出 failure 定義見下段 |
| CAE 金鑰承諾性可支撐不同 witness 的唯一明文 | SRC-UT 沒有此 CAE 結果；handoff 另引 2022/268，但未指定 construction／量子模型 | OPEN 的條件式推導，不是已完成 T3 proof |
| Appendix E.4 commitment 替換疑點 | pp. 55–56；與 Definition 7.5、Construction 7.7 對照後確有需說明的 opening 一致性問題 | finding F-04；不是已證實的 deployed-protocol attack |
| Appendix G | pp. 59–61 以完整 plaintext oracle 模擬 UT outputs；p. 61 明確假設不查詢 challenge ciphertext | paper-verified 的論證位置；Definition 8.27 文字不完整，見 F-05 |
| Setup 是完整 DKG 的替代？ | 8.29 明確先生成完整 PKE secret key；7.7 setup 使用 x 與所有 TFHE shares | 否；這些 construction 本身不等於免 dealer 的完整 DKG 實作 |

本次另從 [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) 的線上原文核對：
Table 3（印刷 p. 39）給 ML-KEM-768 ciphertext 1,088 bytes；Table 1（p. 15）給
`2^-164.8` failure estimate，抽樣量詞涵蓋均勻 keygen／encapsulation seeds 並採 hash/XOF heuristic。
它不是惡意挑種子的最壞界。Algorithm 18（p. 34）保留 re-encryption 與 implicit rejection；
失敗時仍輸出替代 key，secret rejection flag 不可輸出。
§3.3（p. 16）將內部 derandomized API 限於測試。

`Pr[opening failure] <= delta_K + delta_UT` 只能在誠實抽樣、CAE 正確、執行完成，且
`delta_UT` 已表示**完整最終輸出**失敗事件時作 union bound；若 CAE／execution 另有失敗，
必須另計。Definition 7.1 原文的 circuit 輸出為一 bit；48-byte 明文與拒絕標記的擴充、
384 個資料 bits 及其他輸出 bits 的總失敗界、深度及成本未固定。
若只有每一輸出 bit 的 `delta_UT_bit`，不能直接把它當作整段的 `delta_UT`。
此處只是條件式推導，未封閉惡意 witness 的有效輸入正確性。

CAE 唯一性方向也只具條件性：固定 AD、nonce、ciphertext 時，若兩 witness 的 K 相同，
perfect correctness 與 deterministic decrypt 固定同一明文；若 K 不同，才交由相應
key-commitment game 排除。未凍結 primitive、key／AD／nonce／ciphertext 編碼、量子遊戲及
正確性量詞，不能升格為本案 T3。一般 AE authentication 不自動提供這個承諾性。

## TH-NIED：原始方案與 repository 改造

| Handoff 位置／陳述 | 原文／canonical 位置與核對結果 | 判定 |
| --- | --- | --- |
| §5 C：`s=H_pub e^T`，`wt(e)=t_error` | SRC-NIED Fig. 1 p. 13；repository N1 | paper-verified 的 Niederreiter 底層關係 |
| 原文以 NIZK 確保 well-formedness | SRC-NIED Definition 7 p. 14、Fig. 4 p. 16、Fig. 7 p. 24 | paper-verified；原文完整 C 包含 proof pi |
| 不能忽略 c2 綁定 | §4 p. 17：language statement 含 `(H,c1,c2)`，雖 witness 條件只用 c1，仍須防止換 c2 後重用 proof | paper-verified；與本案 I1–I5 同票證綁定的需求相容，不能省略組合論證 |
| `Z=SHAKE256(label \|\| e \|\| s \|\| ctx,640)`、P／K_mac split、KMAC tag | repository core N3–N7（L2073–2096）、reference `_derive_trace` | repository-verified；不是 SRC-NIED 的原式 |
| 原文 `C=(c1,c2,pi)`，本案 `C=(s,c_mu,gamma)` | SRC-NIED Fig. 7／8 pp. 24／30 對比 repository N7 | 明確改造差異，finding F-07；原文 CCA theorem 不能直接移植 |
| `d_min >= 2t_error+1` ⇒ 小重量 witness 唯一 | repository `Unique syndrome witness` lemma（L2125 起）；SRC-NIED pp. 11–13 的 Goppa／decoder 背景 | repository-verified＋derived 的標準距離論證；仍須對實際公鑰滿足前提 |
| 互動開啟可能釋出 e | SRC-NIED Definition 8 p. 15 返回 message 與 randomness；Fig. 8 p. 30 明確公開 e | paper-verified；本案不可將 e 放入宣稱不洩漏身分的公共 audit |
| distributed decoding 的安全取決於 MPC | Theorem 8 p. 30 假設相應 semi-honest 或 malicious privacy，依 IND-CCA2+ 作模擬 | paper-verified 的條件定理；不等同已封閉本案 QPT／多次 gated opening |
| setup model | Fig. 8 p. 30 允許 generic MPC 或 trusted party 產生 shares 與 field-switching 資料 | paper-verified；未實作 DKG 不可寫成已完成 |
| 6688128 的 208-byte syndrome | SRC-NIED Table 1 p. 32；repository `N=6688,K=5024,T=128` | paper-verified／repository-verified；208 是 syndrome，非完整原文加密物件 |
| 288-byte C／12,012-byte ticket | repository N1–N7 與 provisional sigma 算術 | derived 的本專案格式；不是原文完整 ciphertext benchmark |

原文 Eq. (5) p. 31 與 Table 1 p. 32 對 6688128 給的 proof 參數為
`N=2^12, tau=11, s=5, delta=2^13, Delta=2^26`，`|pi_L|=42.1 KB`，`|c_CM|=208 B`。
這些 N／tau 是 **MPC-in-the-head proof** 的玩家數／重複次數，不是 OA 數與 OA 門檻；
Delta 也不是 TH-UT 的 DEM overhead。表中的 proof security 欄不可當成整套方案安全等級。
原文此表的單位照錄為 KB，不猜測為精確十進位 bytes 或 KiB。
Table 2 把 ciphertext expansion 表為 syndrome 加 proof；若計算 Fig. 7 的完整 wire object，
還需包含 c2 的訊息長度。288-byte repository ciphertext 是另一 profile 的 `208+48+32`。

Repository reference 的 `_derive_trace` 將 e 編成 836-byte little-endian 值，採
`b"PQ-RBBC/KDF"` 與 `b"PQ-RBBC/TAG"`，80-byte KDF output 再按 N4 切割。
但 `SystematicParityCheck` 的 docstring 明確標記它是 deterministic test fixture，
不是 production Goppa key。這個 fixture 的 relation／格式測試不能證明公鑰滿足
`d_min >= 2t_error+1`，也不能提供真實 OA key／threshold decoder 資格。

## 大小公式逐項核算

Handoff §9 的算術，在其明示假設下均相符；下表不是 observed backend output。
`g_bytes` 表示 GF c3 的完整編碼，`Delta_bytes` 表示 UT 除 48-byte 明文外的全部 DEM
expansion／nonce／tag／commitment；unknown 不設為 0。`B_extra` 保留尚未決定的 envelope／framing。

```text
B_ticket = 80 + B_C + B_sigma + B_extra

TH-NIED: B_C = (6688 - 5024)/8 + 48 + 32 = 288
TH-UT:   B_C = 1088 + 48 + Delta_bytes = 1136 + Delta_bytes

TH-GF (t=2, packed coefficient encoding):
    B_c1 = 2*n_ring*d_module*log2(p)/8
    B_c2 = 80 + 48 = 128
    B_c4 = n_ring*d_module/8
    B_C  = B_c1 + B_c2 + B_c4 + g_bytes
```

GF 的 c1 是 Fig. 14 輸出的**兩個** module components 合併成 Hybrid2 c1；
兩個層次不可重複計數。c4 的大小從 `H'':Mp->Mp` 及 `Mp=R_2^d` 推得；它不是
原文直接提供的本票證 ciphertext size。此算式預設 packed bytes，後續 encoder 未固定前仍是估計。

| 候選／示例 | 已知 B_C 部分 | B_sigma=11,644 且 B_extra=0 的條件式票證預算 | 類型 |
| --- | ---: | --- | --- |
| TH-NIED，6688128 結構 | 288 | 12,012 | 本案格式算術；sigma provisional |
| TH-UT，ML-KEM-768 | 1,136 | 12,860 + Delta_bytes | estimated；Delta 未知 |
| TH-GF，n=256,d=4,p=2^10 | 2,816（2,560+128+128） | 14,540 + g_bytes | estimated；g 未知 |
| TH-GF，n=256,d=9,p=2^11 | 6,752（6,336+128+288） | 18,476 + g_bytes | estimated；g 未知 |

若**僅作格式示例**設 `Delta_bytes=28`，得到 12,888 bytes；未證明任何具體 CAE 在此
overhead 下符合所需安全性。`B_extra=0` 只用於重算 handoff 示例，不能保存成實測 envelope 開銷。
固定欄位的算術成立，也不表示更換 I5 後的簽章 profile／大小不變。

## Findings 與處置

### F-01 — Revision provenance 尚未達 publisher byte identity

四份主要附件與 pasted draft 的 exact bytes 已建檔，但論文 revision 歸屬仍有上游 bytes
核對缺口。SRC-UT 有 ePrint 2017 收件日與 CRYPTO 2018 出版日兩種日期；SRC-NIED 的
2025 ePrint 與 2026 DCC final 不能互換。處置：引用固定 digest 及其頁碼，catalog history
另列，未驗證的 revision number／publisher digest 保留 unknown。此 finding 不妨礙閱讀附件，
但阻止「已精確重現 publisher revision」的主張。

### F-02 — Table 2 不是完整 Fulham profile

Handoff 的數值引用正確，但 Table 2 屬 Pompeii 的底層 Module-LWR 參數。Fulham 還依賴
Hybrid2、完整 hash domains／ranges、DEM、epsilon、bad-key／failure 界與 MPC。
處置：引用 Table 2 時附全 row 與 variant 關係；g 及其他未定欄位保留 OPEN。
這是來源粒度的補正，不是判定手稿的兩組數字錯誤。

### F-03 — UT A.7 與非零 failure 需定理擴充

Handoff 已提醒此缺口；原文 p. 44 確認 A.7 為 perfect correctness。
`delta_K+delta_UT` 是本案條件式 union bound，未解決惡意 witness、multi-bit UT 或失敗視圖。
處置：不能標為 Theorem 8.31 已適用於 TH-UT；T1 與真實開啟模擬維持 OPEN。

### F-04 — UT E.4 的 H1→H2 commitment-opening 一致性

可直接核對的原文事實：Construction 7.7 的 `s_i=(tfhesk_i,sigma_P,i,r_i)` 包含 opening randomness，
Definition 7.5 step 4 交出腐敗集合的 shares；E.4 H2 卻把所有 `com_i` 換成對零字串的 commitment，
其餘沿用 H1。這些敘述在 SRC-UT pp. 25–27、55–56 實際存在，不只是 handoff 的轉述。

本次推論：按該文字直接執行時，腐敗方能以所得 `(tfhesk_i,r_i)` 重算 commitment 並與 pp
比較；computational hiding 本身不涵蓋同時揭露 opening 的情境。
這足以定位 H1→H2 需補說明，**未證明真實 UT 協定已被攻破**。
只說改成「僅換 honest-party commitments」也還不是完整修復，因腐敗集合在 pp 之後才選，
仍須展示 simulator、setup 與後續 hybrids 的一致性。
處置：本案引用該實例證明的資格維持 OPEN；需後續版本／作者說明或完整可核對的修正論證。

### F-05 — UT CCA 定義與附錄的查詢限制、編號不一致

SRC-UT Definition 8.27 p. 35 的 step 8 只說繼續 decryption queries，沒有明寫禁止
challenge ciphertext；Appendix G p. 61 的 reduction 卻明確使用該禁止條件。
Theorem 8.33 p. 36 將 security 指到 Definition 8.26，但 8.26 實為 partial-verification
correctness，security 是 8.27。這是已核對的原文文字差異。
處置：引用時同時列 definition／appendix 位置，不能默默將文字修成自己的遊戲後宣稱逐字沿用。
本案允許哪些 challenge shares、腐敗集合及量子查詢，仍要獨立定義。

### F-06 — Post-quantum 元件不自動封閉 UT 的量子模擬

SRC-UT Definitions 7.5／8.27 以 PPT 表述，Construction 7.7 的 PZK／commitment、
跨多次 evaluation simulation 仍需具體資格。SRC-GF Theorem 3.2 的 QROM hybrid 定理
也不替任意 MPC 實作背書；SRC-NIED 的 ROM extraction 與 Theorem 8 不能僅因題目稱
quantum-resistant 就視為本案 QPT 組合已證明。
處置：將 primitive assumption、原文 adversary/oracle model、實際多機 transcript 與本案遊戲分列；
三候選 Proof-closed 均未成立。

### F-07 — Niederreiter 原文的 online NIZK 被本案離線發行／gate 接合取代

Handoff 已明說兩者不同，原文 Fig. 7／8 確認此差異：每個 decryptor 在 decoder 前驗證 pi，
而 repository 採 N1–N7 與 I1–I5 的 issuance binding／signature gate。
原文的 42.1 KB proof 不存在於本案 288-byte ciphertext，省去它需要本案安全論證。
處置：288 bytes 僅屬 repository hash-DEM profile；不宣稱重現原文完整 CCA ciphertext。
若真實 transcript 釋出 e／u，須納入可見輸出與模擬，不能只模擬最終 rid／sn。

### F-08 — KDF source 已一致，gate metadata 仍舊

Base core N4、reference `split_trace_kdf_output`／`split_trace_kdf_wires`、
`_derive_trace`／circuit path 與 frozen-vector tests 均使用 `Z=P||K_mac`，byte slices 為
`[0:48]`／`[48:80]`。既有 source-transition manifest 的 current-tree 驗證本次亦通過。
但 [gate.py](../../../src/pq_rbbc/opening/gate.py) L255 仍列
`trace_kdf_80_byte_split_order_unresolved=true`。
處置：記錄 canonical/source 與 metadata 差異，交由 opening／integration lane 建立適當 successor。
本次不改 flag、不改 historical evidence，也不把此項測試通過解讀成真實 decoder 已存在。

### F-09 — Handoff 的 AD／單次呼叫／share 驗證差異仍存在

[interfaces.py](../../../src/pq_rbbc/opening/interfaces.py) 的 `TicketView` 沒有 h 或完整 AD；
`ThresholdOpeningContext` 連 ctx／visible_serial 也未直接攜帶，只有 digest 等綁定與 ciphertext。
`create_share(context)` 是單次呼叫。`ThresholdReconstructionBackend` docstring 仍特指 Niederreiter。
[combiner.py](../../../src/pq_rbbc/opening/combiner.py) 依次呼叫 share authentication verifier、
reconstruction、trace authentication 與 inner-serial check；Protocol 沒有提供具體份額數學證明。
處置：保留為 TB0 的可核對輸入；後續 ABI 必須從同一已驗證票證供給 AD，顯式表達互動 session／
participants／transcript，並列明 math validity 的承擔者。這裡只查核 handoff 指出的接點，
未宣稱完成全部 TB0、併發／replay／crash 稽核。

### F-10 — 附件中的需求／授權敘述不能取代會話與 canonical contract

Handoff §3 說過去聊天採 honest-but-curious LEO；canonical 不預設 LEO 可信，故以 canonical 為準。
附件中「使用者已確認」的 latency、工作分配與 branch 啟動段落未在本次會話中成為執行指令。
處置：本次只做使用者明確要求的來源核對；沒有建立 TB1 envelope、實作後端、啟動後續 agents、
產生 TB2 prompts 或更改 lifecycle 語意。

## 本次驗證與整合交付

實際 worktree 為 `/tmp/PQC_auth_threshold_source_audit`，branch 為 `codex/threshold-source-audit`，
從上述 local main 建立。原主目錄是另一個 `codex/thesis-learning` 工作線，未用作寫入目錄。
可見 worktree／branch inventory 未出現另一條 threshold source-audit lane；本次只新增本 literature
目錄四個檔案，未觀察到檔案權責重疊。其他 worktree 的後續變更不納入本次 base。

已閱讀 AGENTS.md 要求的四份 research context、documentation policy、artifact policy、
architecture／status／roadmap，再對上述 core／reference／opening 接點作唯讀核對。
19 份 consulted repository files 的 bytes、SHA-256 與 Git blob 收於 inventory。
沒有修改 source、tests、manifests、root canonical 文件，亦未修改其他分支、merge 或 push。

為確認 F-08，執行既有 targeted tests：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest -v \
  tests.test_pq_rbbc_trace_kdf_source_transition \
  tests.test_pq_rbbc_reference.RelationTests.test_trace_kdf_canonical_split_and_frozen_vector \
  tests.test_pq_rbbc_reference.RelationTests.test_trace_kdf_split_rejects_noncanonical_boundaries \
  tests.test_pq_rbbc_reference.RelationTests.test_trace_kdf_wrong_order_rejected_by_direct_relation
```

結果：**10 passed、0 failed、0 errors、0 skipped，0.855 秒，exit 0**。
測試只支持 source-transition／KDF-vector／direct-relation 的 bounded assertions；本次未重跑
constraint-circuit test、大型 relation replay 或完整 regression suite。
Full regression：**not_run**，原因是本次僅新增來源文件；不冒用 base 歷史的 676 passed／12 skipped。

另核算上述四列大小預算與 Delta=28 示例；附件與 repository source identities 對固定 inventory
重新比較，並檢查 JSON、相對文件連結、`git diff --check`、`git status` 及本次新增檔案類型／大小。
原始 PDF／下載內容／抽出的全文／圖片／logs／私鑰／大型 artifacts 均未加入 Git。

交由 integration lane 考慮的更新：

- `research-notes.md` 文獻表可引用本索引及核對表；不將來源查核升格成全專案 claim closure。
- `methodology.md` 可記錄「完整 primitive／原文條件」與「本案改造」分離的理由。
- `experiments.md` 可收錄上述來源驗證與 bounded test 紀錄；`RESEARCH_STATUS_zh-TW.md` 不提升 threshold claims。
- Opening lane 接手 F-08／F-09；security lane 處理 F-03–F-07；更新時保留本次歷史摘要。

本次 observed 只有檔案 bytes／digests 與 10 項既有 tests 的結果；算術核算另列為 derived。
三候選的 ciphertext 實作觀測、issuance proving／opening latency、MPC network／memory 均為 unknown。
GF 4.99 秒與 NIED proof 42.1 KB 是 literature_reported；票證大小是 estimated／provisional。
TH-GF、TH-UT、TH-NIED 的正式系統適用性均 **OPEN**；尚無勝出者，也沒有新增 crypto capability。

下一個 bounded 步驟是以本索引與 findings 作 TB0 的前置輸入；若要宣稱 precise publisher revision、
無缺口 UT theorem 或完整候選安全，須先補對應 OPEN 項目的證據。本來源稽核不構成 TB0／TB1 完成宣告。
