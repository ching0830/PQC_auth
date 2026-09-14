# FAC configuration／issuer-grant authentication primitive 盤點 v0.1

- 狀態：S0 research assessment；非 canonical primitive selection
- 盤點日期：2026-09-14
- 基準 commit：`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`
- 適用範圍：`FEDERATION_CONFIGURATION` 與 `ISSUER_AUTHORIZATION`

## 1. 結論與 claim boundary

現有 system contracts 已定義完整 initialization bundle、五種 key role、
configuration authentication domain、issuer-grant authentication domain 與抽象
verifier；本輪不重建 codec 或 role registry。尚未具現的是 FAC 的真實簽署／驗證
primitive、實際 verification-key bytes 的可信解析、成員與門檻、key ceremony，
以及 production verifier 的 trust-store 邊界。

本盤點建議把 **Mithril 當作小型 FAC 的第一個 threshold research
evaluation candidate**，不是把它升為 canonical protocol。理由是其目標輸出可由
FIPS 204 ML-DSA verifier 驗證、已有官方團隊的 Go proof-of-concept，且預覽描述
trusted dealer、a-posteriori sharing 與 DKG 三種 key-generation 路徑。它目前仍有
static-corruption、至多八方、缺乏 identifiable abort／robustness、簽署狀態持久化、
專利與 NIST Threshold Call 尚在進行等缺口。

因此 S2 可先以普通單 key ML-DSA-65 建立真實正例，驗證既有完整 bundle／grant
authentication domain 與 pinned trust-store plumbing；此正例必須標記
`non-threshold`，不能據此宣稱 FAC threshold authentication 已實作。

## 2. 角色、責任與分離

| 項目 | owner／要求 | S0 判定 |
|---|---|---|
| Configuration authentication | S；`FEDERATION_CONFIGURATION` key | 依 core proof 與 architecture 需要 FAC threshold authorization；實際 primitive／參數 OPEN |
| Issuer-grant authentication | S；`ISSUER_AUTHORIZATION` key | 依 core proof 與 architecture 需要 FAC threshold authorization；應與 configuration key 分離 |
| Opening authorization | opening governance／主整合線；`OPENING_AUTHORIZATION` key | 必須與 configuration、grant、opening-encryption key 分離；最終是否由 FAC 同一成員集或另一委員會執行仍 OPEN |
| Opening encryption | T；`OPENING_ENCRYPTION` key | threshold identity-encryption key，不是 threshold signature key |
| Issuer blind-signing verification | B；`ISSUER_VERIFICATION` key | blind-signing profile/key，不是 FAC authorization key |
| Initialization bundle | S 組裝、發布、驗證；B/T 提供被綁定參數 | bundle 只保存公開 key reference/digest；不產生或保存 secret key |

Configuration、issuer authorization、opening authorization 三種簽章權限必須使用
不同 role、key id、key bytes 與 ceremony/transcript；不可因成員重疊而共用 secret
key。T 的 OA encryption key 與 B 的 issuer blind-signing key 也須維持其各自 profile。

## 3. FAC 要求與 OPEN 參數

設 FAC 成員數為 `n_F`、簽署門檻為 `t_F`，腐敗上限為 `f_F`，同時不可用成員
上限為 `u_F`。最低治理條件為：

- safety：`t_F > f_F`；
- availability：`n_F - u_F >= t_F`；
- 候選 protocol 若要求 honest majority、同步網路、預處理或每 key 簽署次數上限，
  還要加入更強的 candidate-specific 條件；
- abort、identifiable abort、robustness 與 guaranteed output delivery 必須分開聲明，
  不能只用「threshold」一詞代替。

`n_F`、`t_F`、`f_F`、`u_F`、網路與可用性目標目前全部 **OPEN**。既有測試中的
FAC 3-of-5 與 OA 5-of-7 只是 deterministic test fixture，不是最終參數。

### Setup、dealer、sharing 與 DKG

- `Setup` 是包含參數、通道、身分、隨機性、金鑰生命週期與驗證資料發布的總稱，
  本身不表示 DKG。
- trusted dealer 產生完整 secret 後再分發 share；dealer 或其殘留資料成為額外信任
  假設。
- a-posteriori sharing 先有完整 secret，再轉成 shares；即使之後刪除，生成或匯入
  期間仍存在完整 secret。
- DKG 讓單一參與者不必持有完整 secret，但需要 authenticated channels、廣播／
  complaint 規則、transcript、隨機性及成員變更處理；它不會自動提供可用性、
  identifiable abort 或 proactive refresh。

## 4. 不可混同的四種能力

1. 普通 PQ signature（例如單一 ML-DSA key）只有一個 secret-key holder。
2. 收集 `m-of-n` 個獨立 PQ signatures 是 application-level quorum；它改變 envelope、
   signer set 與 verification rules，並非共享一把 secret 的 threshold signature。
3. threshold signature 讓多方持 share，共同產生一份由 reference verifier 接受的
   signature；其 corruption、abort 與網路模型屬 primitive 的一部分。
4. DKG 是建立 shared key 的方法，不等於簽署 protocol，也不等於 threshold signature
   的所有安全／可用性性質。

若採多個獨立 ML-DSA signatures 作為暫時治理批准，必須由主整合線版本化新的
authentication envelope 與驗證規則；不能把它包裝成目前未選定的 threshold
signature，更不能由 S 自行替換 core protocol。

## 5. 候選 primitive 與正式來源查核

NIST IR 8214C（2026-01）把 threshold scheme 定義為分散執行 primitive、共享
secret key，並要求成功輸出與 reference primitive 相容；Threshold Call 目前仍在
Phase 1，candidate package 預計之後才提交。因此下列 preview 都是研究輸入，
不是 NIST 標準或 production approval。

| 候選／版本 | 輸出與 key generation | 腐敗／可用性模型與能力 | 官方實作／授權／主要缺口 | S0 評估 |
|---|---|---|---|---|
| Mithril PW01 v1.0（2026-01-19） | FIPS 204 ML-DSA verifier-compatible；dealer、a-posteriori sharing、DKG | 小型 `n <= 8`；預覽主張 static dishonest majority、至多 `t-1` corrupt；目前無 identifiable abort／robustness | 團隊 Go POC；repository 警告非 production，Go 1.19；依賴 BSD/MIT、計畫 permissive；兩件 pending patents；single-use signing state 的 durable anti-reuse 由 caller 負責 | **首選 research evaluation**，不是 canonical selection |
| Quorus PW01 v0.1（2026-01-21） | 輸出供 FIPS verifier 驗證；keygen/signing 對 ML-DSA randomness/noise 有變體；含 DKG | 約至 64 方；同步 authenticated pairwise channels；honest majority；目前 security-with-abort | preliminary C++ research implementation 以 restricted Zenodo 提供、預期大改；計畫 Apache-2.0；adaptive/identifiable abort 尚後續 | 規模較大，但網路、honest-majority 與成熟度代價高 |
| TALUS PW02 v0.22（2026-08-11） | FIPS verifier-compatible；兩個 online rounds、offline preprocessing | `N >= 2T-1` honest majority；有 per-key signing cap／rotation | Rust code 計畫 Apache-2.0；MPC crate／distributed construction 尚在完成；核心技術有 provisional patents；v0.22 已因 cryptanalysis 取代 v0.21 | round count 有吸引力，但變動、cap、專利與未完成元件需先解決 |
| Hermine PW01 v1.0（2026-01-19） | Raccoon-style lattice threshold signature；不是 ML-DSA format；含 DKG | `n <= 64`、dishonest majority、proactive refresh、identifiable abort | 預覽時只有未來發布計畫；計畫 Apache-2.0、依賴 Lattigo；預覽稱無已知專利 | 治理性質佳，但會改簽章 primitive／format，須明確 protocol 決策 |
| Haystack PW01 v0.1（2026-01-21） | standard LMS/XMSS verifier-compatible；stateful hash-based threshold | trusted dealer；以 signing coalition 維護 state | 約 0.1--10 GiB correlated randomness、每 coalition state；預覽時 Python reference 尚未公開；預覽稱無專利主張 | state/dealer/儲存複雜度不適合作 FAC 第一候選 |

### 來源

- [NIST FIPS 204：ML-DSA final standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST IR 8214C：Threshold Schemes for Cryptographic Primitives](https://csrc.nist.gov/pubs/ir/8214/c/final)
- [NIST Threshold Call、階段與候選清單](https://csrc.nist.gov/Projects/threshold-cryptography/tcall-1)
- [Mithril official NIST preview](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/Mithril-PW01.pdf)
- [Mithril team proof-of-concept repository](https://github.com/Threshold-ML-DSA/Threshold-ML-DSA)
- [Quorus official NIST preview](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/Quorus-PW01.pdf)
- [TALUS official NIST preview](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/TALUS-PW02.pdf)
- [Hermine official NIST preview](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/Hermine-PW01.pdf)
- [Haystack official NIST preview](https://csrc.nist.gov/csrc/media/Projects/threshold-cryptography/documents/TCall-1/Haystack-PW01.pdf)
- [OpenSSL 3.5 ML-DSA provider documentation](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)

## 6. Post-quantum 與實作假設

- FIPS 204 ML-DSA 是普通 PQ signature 標準；threshold variant 的 security proof、
  composition 與 implementation attack surface 必須另行評估。
- reference-verifier-compatible 只代表輸出格式／驗證相容；不代表 threshold keygen、
  signing transcript、share refresh、side-channel 或 operational recovery 已標準化。
- candidate preview 的 security claim、程式碼與 patent/licensing 狀態可能變動；S2
  必須 pin exact source commit、toolchain、dependency licenses 與 test vectors。
- 本機環境是 OpenSSL 3.0.18，沒有 OpenSSL 3.5 的 ML-DSA provider；S2 的普通
  ML-DSA 真實正例須先以隔離、可重現方式 provision OpenSSL 3.5+ 或另選經核准
  backend，不可把 deterministic hash fixture 當簽章。

## 7. S2 前需要使用者／主整合線決策

- FAC 的 canonical primitive 或是否先採明確標記的非 threshold staging profile；
- `n_F/t_F/f_F/u_F`、網路模型、abort/robustness 與 service availability 目標；
- configuration 與 issuer-grant 是否同成員但不同 key，或完全不同委員會；
- opening authorization 的 owner、threshold 要求與是否沿用 FAC membership；
- trusted dealer、a-posteriori sharing 或 DKG 的可接受信任邊界；
- 專利、license、外部實作成熟度與供應鏈政策。

在這些決策完成前，S1 的 persistent quota/SID store 可獨立前進，但任何測試通過都
不能擴張成「真實 FAC authentication 已實作」或「initialization／issuance 已完成」。
