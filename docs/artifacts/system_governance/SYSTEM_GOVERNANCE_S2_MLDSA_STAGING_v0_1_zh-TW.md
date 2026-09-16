# System Governance S2：真實 ML-DSA authentication staging v0.1

- workline：S — System initialization／Issuer authorization
- branch：`codex/system-governance-s2`
- worktree：`/tmp/PQC_auth_system_governance_s2`
- exact S2 base：`35316ac953846a8bc970e4060c576639589f245e`
- code／test commit：`1624e2b049df0cee866607464df3078be30b2475`
- 狀態：ordinary ML-DSA-65 staging **Implemented／Tested**；FAC threshold／production **OPEN**

## 1. 本輪結論

S2 已取得第一個真實 PQ signature 正例：以兩把不同的普通 ML-DSA-65 key 分別認證
configuration 與 issuer grant，並以 operator-owned pinned trust registry 把實際 SPKI DER
bytes、SHA-256 digest、key ID、role 與 profile 綁回既有 `KeyReference`。Request-facing
service 不接受 caller 傳入 trust anchor、verifier、public-key bytes 或 `verified=true`。

認證涵蓋的仍是既有、未修改的完整訊息：

```text
PQ-RBBC/SYSTEM-INIT-AUTH/V1 || SystemInitializationBundle.encode()
PQ-RBBC/ISSUER-AUTHORIZATION/V1 || u16le(ISSUER_AUTHORIZATION) || IssuerGrant.encode()
```

不是只簽 `ctx`、configuration 或 `common_parameters_digest`。測試逐一改動
configuration、common parameters、threshold policy、T key reference、grant field、簽章與
application context，均不能沿用原簽章通過。

這個 profile 明確命名為：

```text
PQRBBC-OPENSSL-ML-DSA-65-NON-THRESHOLD-STAGING-V1
```

它是單一 secret-key holder 的 FIPS 204 ML-DSA，不是多簽批准、threshold signature 或
DKG。它不取代 S0 對 Mithril 等 threshold candidates 的盤點，也不把任何候選升格為
canonical protocol。

## 2. Frozen dependency 與 owner 邊界

S2 以 exact S1 re-review commit 建立新 branch/worktree；沒有切換主工作目錄，也沒有使用
其他活動 worktree 的未提交成果。本輪唯讀核對的最新相關 committed handoff 為：

| owner | exact committed input | S2 使用方式 |
|---|---|---|
| B | `47cfd584b4fa1ace9db79a84ccd1be33a3775fd3`，issuance production producer ABI pre-freeze v1 | 只核對其要求 authenticated initialization、issuer verification key、common parameters 與 production qualification 仍是外部輸入；沒有執行 B producer 或變更 B profile |
| T | `d682b8b08892f663a81c4ef9d295b0c385354d0b`，GF trusted adapter contract v0.1 | S2 實作其中 S-AUTH 的真實非門檻 staging 路徑；T-ORIGIN、GF qualification 與 owner acceptance 仍 OPEN |
| T review | `bcefd1b2cb92673bb278e0d9099a38f3816d1a87`，partial issuance evaluator review | 僅記錄最新已提交 review；沒有把 partial evaluator 當成 threshold／production backend |

Bundle assembly 只從 S registry 取得 role 1／2 public references，並接受 B/T/owner 提供的
role 3／4／5 `KeyReference` opaque inputs。它不生成 key、不保存 secret、不更動 B/T 的
cryptographic profile。S2 測試使用的 B/T references 是明確 synthetic fixture，不是真實
組織、production 或 key-origin evidence。

## 3. 新增 protocol flow

### 3.1 Operator startup

1. Operator 在 repository 外 provision 一個絕對路徑 trust directory；目錄不可
   group/world writable。
2. `trust-registry-v1.json` 採 ASCII、sorted keys、compact separators、單一結尾 LF；
   duplicate/unknown fields、alternate encoding、trailing bytes 與錯誤順序 fail closed。
3. Registry 必須恰有 `FEDERATION_CONFIGURATION`、`ISSUER_AUTHORIZATION` 兩筆，依固定
   順序列出互異的 key ID、SPKI file、SHA-256 與 exact staging profile。
4. Directory、registry 與 public key file 都以 `O_NOFOLLOW` handle 開啟；只接受 regular
   file，拒絕 group/world writable。Key bytes 只 capture 一次，以實際 bytes 重算 SHA-256，
   之後 request 不重開 pathname。
5. Service 啟動時驗證兩份 DER 恰為 canonical ML-DSA-65 SPKI，並固定 registry、backend
   與 configuration trust anchor。

### 3.2 Assemble／publish

1. `assemble_initialization_bundle()` 以 pinned role 1／2 references，加上 owner/B/T 提供的
   role 3／4／5 references，呼叫既有 bundle validator；只產生公開 bundle。
2. `publish_initialization()` 要求 configuration signer reference 精確等於 bundle role 1，
   簽署完整既有 initialization message。
3. `publish_issuer_grant()` 要求 signer 是 role 2、key ID 等於 grant binding，簽署包含
   signing role 與完整 grant 的既有 message。
4. `OpenSSLMLDSA65NonThresholdSigner` 只接受 repository 外的既有 absolute private-key
   pathname；每次以 `O_NOFOLLOW` 開啟 regular `0600` file，從同一 FD 導出 public key 並與
   captured trust bytes constant-time 比對後才簽署。它沒有 key-generation API。

### 3.3 Verify／authorize／consume

1. Request 只傳 authenticated initialization bytes；service 以啟動時固定的 role-1 anchor
   與 real ML-DSA verifier 呼叫既有 `verify_initialization()`。
2. 驗證成功後再要求 bundle role-2 reference 也精確解析到同一 pinned registry；attacker
   即使產生自己的 key、bundle 與有效 self-signature，也不能把它變成 operator trust。
3. Issuer request 傳 initialization、grant、quota store、SID 與 time；沒有 request-level
   anchor／verifier／`verified` 參數。
4. 既有 `authorize_issuance()` 先驗完整 initialization，再驗 grant binding/time/role 與
   real role-2 signature，全部通過後才呼叫 S1 SQLite atomic consume。
5. 因此「真實普通 PQ authentication 通過後的 quota 消耗」現在可跨程序與重啟保存；
   相同 `(grant_digest, issuer_sid)` 在 commit 後重送仍依現有 API 回 `REPLAY`。

低階 `verify_initialization()`／`authorize_issuance()` 的 dependency-injection API 為相容既有
研究測試而保留；它們可以接受 caller-supplied verifier，所以不可直接暴露成 production
request endpoint。S2 的 `PinnedSystemGovernanceService` 才是本輪 request-facing boundary。

## 4. Backend identity 與供應鏈

| 項目 | S2 pin／觀測 |
|---|---|
| OpenSSL release | 3.5.8，2026-08-25；3.5 LTS |
| source tarball | `openssl-3.5.8.tar.gz`，53,213,818 bytes |
| source SHA-256 | `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`，與官方 checksum 相符 |
| source license | Apache License 2.0 |
| local build | `no-shared`，prefix `/tmp/pqrbbc-openssl-3.5.8`；GCC；Linux x86-64 |
| executed binary SHA-256 | `e32ed95a3c645aa706256fb2cf94d697e6d600c8e150b023a6f687c39cd921d0` |
| exact version line | `OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026)` |
| signature profile | ML-DSA-65；SPKI DER 1,974 bytes；signature 3,309 bytes |
| application context | ASCII `PQ-RBBC/SYSTEM-GOVERNANCE/STAGING/V1` |

Backend constructor 要求 absolute executable path、exact binary SHA-256、exact version line，
且確認 provider 列出 ML-DSA-65。每次 operation 都重新以 `O_NOFOLLOW` 開啟 executable、
hash 同一 FD，並以 `/proc/self/fd/<fd>` 和 `pass_fds` 執行；不透過 PATH。Subprocess 使用
argument vector、不用 shell，清除 inherited environment，只設定 `LANG/LC_ALL=C` 與
`OPENSSL_CONF=/dev/null`，且 timeout 不得超過 60 秒。

此 adapter 因 `/proc/self/fd` 明確依賴 Linux procfs；尚未宣稱其他 OS 可部署。使用 FIPS
204 algorithm 不表示本地 OpenSSL build 是 FIPS 140 validated module；本輪 build 沒有
取得這項 validation claim。

來源：

- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [OpenSSL ML-DSA provider documentation](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/)
- [OpenSSL pkeyutl ML-DSA options](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/)
- [OpenSSL 3.5.8 release/source](https://github.com/openssl/openssl/releases/tag/openssl-3.5.8)
- [OpenSSL license](https://github.com/openssl/openssl/blob/openssl-3.5.8/LICENSE.txt)

## 5. 官方向量與測試證據

外部 sample vectors 只放 `/tmp`，沒有加入 Git。測試在 parse 前先驗 exact file digest：

| NIST ACVP sample | identity |
|---|---|
| repository commit | `975de31eb83d87039ec88934fdc47d8c312b892d` |
| `ML-DSA-sigVer-FIPS204/prompt.json` | 3,125,947 bytes；SHA-256 `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e` |
| `expectedResults.json` | 13,956 bytes；SHA-256 `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6` |
| executed cases | group 3，ML-DSA-65／external／pure：tcId 31 expected false；tcId 33 expected true |

來源為 [NIST ACVP-Server sample repository](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204)。
NIST repository 說明其內容以 public service 提供、要求 source acknowledgment，並以 AS IS
方式提供；S2 不把 3 MiB vectors 複製進 repository。

官方 OpenSSL upstream targeted tests：

```text
make test TESTS='test_ml_dsa test_ml_dsa_codecs test_pkeyutl'
Files=3, Tests=288 — PASS（另有 preparation NOTESTS，不是 failure）
```

Repository targeted tests（exact backend 與 NIST paths 由環境變數 opt in）：

```text
PQRBBC_TEST_OPENSSL=/tmp/pqrbbc-openssl-3.5.8/bin/openssl \
PQRBBC_TEST_OPENSSL_SHA256=e32ed95a... \
PQRBBC_TEST_OPENSSL_VERSION='OpenSSL 3.5.8 ...' \
PQRBBC_NIST_ACVP_MLDSA_PROMPT=/tmp/pqrbbc-s2-acvp-prompt.json \
PQRBBC_NIST_ACVP_MLDSA_EXPECTED=/tmp/pqrbbc-s2-acvp-expected.json \
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
python -m unittest discover -s tests/system_modules/governance/authentication -v

Ran 22 tests in 0.667s — passed 22, failed 0, errors 0, skipped 0
```

既有 S1 storage targeted：33 passed、0 failed/errors/skipped，1.945 秒。既有 governance
codec／authorization targeted：33 passed、0 failed/errors/skipped，0.040 秒。

完整 regression：

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
Ran 743 tests in 755.773s — passed 731, failed 0, errors 0, skipped 12
```

完整 run 使用同一組 exact OpenSSL／NIST environment variables，所以 S2 real crypto／official
vector tests 沒有 skip。12 個 skips 均為既有 optional v2.13–v2.25 external artifacts 未安裝；
沒有新增 S2 skip 類型。

實測環境是 Ubuntu 22.04.5 LTS、Linux `6.8.0-138-generic` x86-64、Python 3.12.9、
Python sqlite3 module 2.6.0／SQLite 3.45.3／threadsafety 3；`/tmp` 位於本機 NVMe ext4。
此環境觀測不構成其他 OS、OpenSSL build、filesystem 或 production host 的 qualification。

測試中的兩把 private keys 都只產生在獨立 `/tmp` temporary directory，mode `0600`，suite
結束即刪除；trust registry、public keys、SQLite/WAL 也在各自 temporary directory。沒有
key、database、WAL、raw logs 或 external vectors 加入 Git。

## 6. 安全與部署限制

- Trust directory 安全仍依賴 operator account、parent-directory traversal、mount namespace、
  ACL/MAC、已存在 writable FD 與 provisioning ceremony；mode/no-follow 不是完整 OS hardening。
- Staging signer 使用本機 plaintext PEM path，沒有 HSM/KMS、encrypted-key callback、audit
  authorization、key rotation、zeroization 或 production secret-management qualification。
- Binary pin 能拒絕 pathname/symlink/replacement drift；沒有完成 compiler/toolchain bit-for-bit
  reproducibility、package signature、SBOM、runtime dynamic loader 或 host compromise 的完整
  supply-chain closure。
- 測試是正常執行與 process/filesystem negative tests；沒有 side-channel、fault injection、
  physical power loss、hardware entropy、network filesystem、container escape 或 production load。
- ML-DSA verification success 不證明 threshold signing transcript、share security、DKG、
  corruption threshold、robustness、availability 或 key-origin 正確。
- S1 consume 之後仍沒有 B signer response/outbox；commit 後 response 遺失只會重送成 REPLAY，
  不能取得先前 blind-signing response。

更細的 trust/security rationale 見
`docs/security/system_governance/MLDSA65_STAGING_TRUST_BOUNDARY_v0_1_zh-TW.md`。

## 7. Integration requests

### B

1. 提供 exact role-4 issuer verification SPKI/key bytes、profile/version、key ID 與 digest；
2. 提供 complete issuance common parameters bytes、relation/backend identities，供 S assembly
   放入 `common_parameters_digest` 並由完整 bundle signature 覆蓋；
3. 以 versioned contract 接受 `PinnedSystemGovernanceService` 的 successful decision，定義
   quota consume、signer response、outbox/result retrieval、process crash 與 same-attempt retry；
4. 不得把 S2 test fixture key/reference 或普通 ML-DSA signer當成 B blind-signing primitive。

### T

1. 提供 exact role-5 OA public key bytes、threshold profile/version、key ID/digest 與 key-origin；
2. 與 opening owner 提供 role-3 opening-authorization key／membership／policy；S2 不假設它由
   FAC 或 T 持有；
3. 完成 `d682b8b…` 的 T-ORIGIN verifier/evidence 與 owner acceptance；完整 bundle signature
   只證明 FAC 對 reference 的批准，不證明底層 threshold key 正確生成。

### 主整合線／使用者

1. 決定 canonical FAC primitive、`n_F/t_F/f_F/u_F`、同／異 committee、network、abort、
   robustness、availability、dealer/a-posteriori/DKG 與 patent/license policy；
2. 決定 role-3 opening authorization owner 與 threshold 要求；
3. 若 threshold candidate 產生標準 ML-DSA signature，仍須另立 threshold profile、ceremony、
   signer/backend identity 與 evidence，不能沿用本 `NON-THRESHOLD-STAGING` profile 自稱完成；
4. 合併後才由 integration owner 更新 `ARCHITECTURE*`、`RESEARCH_STATUS*`、`ROADMAP*`、
   `methodology.md` 與 `experiments.md`。

## 8. 最終 claim boundary

| claim | 狀態 |
|---|---|
| 普通 ML-DSA-65 keygen/sign/verify 真實正例 | **Tested**（OpenSSL 3.5.8、官方 sample vector + ephemeral keys） |
| 完整 initialization／grant message authentication | **Implemented／Tested**（non-threshold staging） |
| 實際 public-key bytes/digest/profile/role pinned resolution | **Implemented／Tested** |
| request caller 無 anchor/verifier/verified bypass | **Implemented／Tested**（本輪 service boundary） |
| 與 S1 SQLite authorize/consume/restart/REPLAY 接合 | **Implemented／Tested**（單主機） |
| FAC threshold signature／DKG／committee ceremony | **未實作，OPEN** |
| 真實 B/T key material／key-origin／organization authorization | **未 provision／未驗證** |
| blind-signing response／完整 issuance transaction | **未完成** |
| FIPS 140 module validation、Proof-closed、Production-closed | **否** |

S2 的可執行成果是：「完整 bundle 與 grant 現在可以由實際 ordinary PQ signatures 驗證，
且只有固定 operator trust 能進入 S1 quota consume。」它不等於「FAC threshold 已完成」或
「整套 initialization／issuance 已可正式部署」。
