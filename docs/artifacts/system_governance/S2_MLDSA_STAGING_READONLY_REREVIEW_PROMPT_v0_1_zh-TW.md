# S2 ML-DSA staging 唯讀重審 prompt v0.1

請對 PQC_auth 的 System Governance S2 做一次**唯讀實作品質與 claim-boundary 重審**。

## Exact review target

- repository：`/home/ucheng0830/Documents/PQC_auth`
- branch：`codex/system-governance-s2`
- worktree（只能查狀態，不可修改）：`/tmp/PQC_auth_system_governance_s2`
- base：`35316ac953846a8bc970e4060c576639589f245e`
- code/test commit：`1624e2b049df0cee866607464df3078be30b2475`
- review target commit：`699867d36f59e39f32d444b38edd10212d0371a3`
- expected linear chain：
  `35316ac953846a8bc970e4060c576639589f245e`
  → `1624e2b049df0cee866607464df3078be30b2475`
  → `699867d36f59e39f32d444b38edd10212d0371a3`

先確認 commit objects、parents、branch/worktree status。請從 exact target commit 建立 repository
外的唯讀／temporary archive 或 detached review worktree；不要切換、修改、commit、merge、
rebase 或 push target worktree，也不要使用其他活動 worktree 的未提交檔案。

本 prompt 所在的後續 commit 只加入 review instructions；實作重審範圍固定為上述
`35316ac…699867d`。

## Required files

- `src/pq_rbbc/governance/authentication/__init__.py`
- `src/pq_rbbc/governance/authentication/trust_registry.py`
- `src/pq_rbbc/governance/authentication/openssl_mldsa.py`
- `src/pq_rbbc/governance/authentication/service.py`
- `tests/system_modules/governance/authentication/`
- `docs/artifacts/system_governance/SYSTEM_GOVERNANCE_S2_MLDSA_STAGING_v0_1_zh-TW.md`
- `docs/security/system_governance/MLDSA65_STAGING_TRUST_BOUNDARY_v0_1_zh-TW.md`
- `manifests/system_governance/fac_authentication_mldsa65_staging_v1.json`
- 既有 frozen `src/pq_rbbc/contracts/system.py`、`system_init.py`、
  `issuer_authorization.py` 與 S1 SQLite store，僅用來核對 integration／無退化

## Review questions（High → Medium → Low）

### 1. Trust registry 與 caller boundary

- Registry 是否 exact/canonical/versioned，拒絕 duplicate/unknown fields、alternate/trailing
  encoding、unsafe basename、wrong role order/profile、duplicate key ID/digest/bytes？
- Directory、manifest、public keys 是否使用同一安全開啟後捕捉的 bytes，實際重算 DER
  SHA-256，而非信任 self-reported digest？Symlink、非 regular、group/world writable 是否拒絕？
- 啟動後 request 是否只使用 captured keys，不會因 pathname 後續替換而改變 trust？
- Request-facing `PinnedSystemGovernanceService` 是否完全沒有 caller-supplied anchor、verifier、
  key bytes 或 `verified=true` 參數？Attacker 自己產生 key、完整 bundle 與有效 self-signature
  是否仍因不在 operator registry 而拒絕？
- 既有低階 DI APIs 雖保留，文件是否明確禁止把它們直接當 request endpoint？

### 2. OpenSSL backend identity 與 command boundary

- Constructor 是否要求 absolute path、exact executable SHA-256/version，並確認 ML-DSA-65？
- 每次 operation 是否重新 `O_NOFOLLOW` 開啟、hash 同一 executable FD，再透過該 FD 執行，
  而非 hash 一個 pathname 後執行另一個？是否避開 shell/PATH/inherited OpenSSL environment，
  並使用 bounded timeout？
- Public key 是否限制為 exact 1,974-byte canonical ML-DSA-65 DER SPKI 並 round-trip；signature
  是否 exact 3,309 bytes；message/context lengths 是否 fail closed？
- 固定 application context 與既有 protocol-domain message 是否在 sign/verify 兩側一致？
- Private key 是否只從 absolute、`O_NOFOLLOW`、regular、exact `0600` FD 使用，且每次先導出
  public key與 pinned bytes 比對？Bundle assembly 是否完全不產生/保存 secret key？
- Backend error、binary replacement、wrong digest/version/context/key/signature 是否都不可能
  回報成功？請特別核對 check/use identity 一致性、FD lifecycle、temp-file、subprocess 與
  result-code 語意。

### 3. Protocol binding 與 role separation

- Initialization 必須簽完整既有
  `PQ-RBBC/SYSTEM-INIT-AUTH/V1 || bundle.encode()`；grant 必須簽完整既有
  `PQ-RBBC/ISSUER-AUTHORIZATION/V1 || role || grant.encode()`。確認沒有退化成只簽 ctx、
  configuration、pp digest 或 metadata。
- `FEDERATION_CONFIGURATION` 與 `ISSUER_AUTHORIZATION` 是否使用互異 key ID/digest/bytes，
  wrong-role signer 是否拒絕？
- Bundle role 1/2 是否取自 pinned S registry，而 role 3/4/5 仍是 owner/B/T opaque inputs；
  是否不小心改變 B/T cryptographic profiles 或 frozen encodings？
- Configuration signature 通過後，service 是否另確認 role-2 reference 也屬 pinned trust？
- Grant binding/time/signature 全通過後才進 S1 atomic consume；authentication/backend failure 是否
  不扣 quota；成功後重啟與相同 SID 是否維持既有 REPLAY semantics？

### 4. Tests、external identities 與 claims

- Negative tests 是否真的觸發上述 defensive paths，而非 mock 掉 OpenSSL、registry 或 SQLite？
- NIST ACVP sample files是否在 parse 前驗 exact SHA-256，group 3 tcId 31/33 的 expected false/true
  是否由 OpenSSL real verifier產生一致結果？
- Ephemeral private keys、SQLite/WAL、vectors/logs 是否只在 repository 外，測試後刪除且未提交？
- Manifest/document/constants/commit identities 是否一致，且沒有把 ordinary ML-DSA、兩把分離
  key 或 passing tests 說成 threshold signature／DKG／production/FIPS 140 approval？
- 請核對 `git diff --check 35316ac…699867d` 與禁止 artifact inventory。

## Exact external inputs used by author

先自行重算，不可信任本段文字：

- `/tmp/pqrbbc-openssl-3.5.8/bin/openssl`
  - SHA-256 `e32ed95a3c645aa706256fb2cf94d697e6d600c8e150b023a6f687c39cd921d0`
  - version `OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026)`
- `/tmp/pqrbbc-s2-acvp-prompt.json`
  - SHA-256 `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e`
- `/tmp/pqrbbc-s2-acvp-expected.json`
  - SHA-256 `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6`

若 inputs 不存在或 identity 不符，請報告「無法重跑 real external test」，不要下載不明替代物、
不要把 skip 當 pass，也不要因此否定仍可唯讀檢查的 code paths。

## Suggested verification

在 exact commit 的乾淨 temporary snapshot 執行：

```bash
export PQRBBC_TEST_OPENSSL=/tmp/pqrbbc-openssl-3.5.8/bin/openssl
export PQRBBC_TEST_OPENSSL_SHA256=e32ed95a3c645aa706256fb2cf94d697e6d600c8e150b023a6f687c39cd921d0
export PQRBBC_TEST_OPENSSL_VERSION='OpenSSL 3.5.8 25 Aug 2026 (Library: OpenSSL 3.5.8 25 Aug 2026)'
export PQRBBC_NIST_ACVP_MLDSA_PROMPT=/tmp/pqrbbc-s2-acvp-prompt.json
export PQRBBC_NIST_ACVP_MLDSA_EXPECTED=/tmp/pqrbbc-s2-acvp-expected.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/system_modules/governance/authentication -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check 35316ac953846a8bc970e4060c576639589f245e..699867d36f59e39f32d444b38edd10212d0371a3
```

Full regression 要實跑 S2 tests 時也必須帶同一組五個 environment variables；否則 S2 external
tests 會明確 skip。Author observation：targeted 22 passed／0 failed／0 errors／0 skipped；full
743 ran、731 passed／0 failed／0 errors／12 existing optional-artifact skips。重審須回報自己的
passed/failed/errors/skipped 與耗時，不得把 author 數字當成重跑結果。

## Output format

1. Findings 依 High → Medium → Low；每項給 exact file/line、可重現理由、影響與最小修正方向。
2. 若 no findings，明寫 `No findings`，再逐項列出實際核對過的 invariants；不要用測試數量
   取代 reasoning。
3. 分開報告 code review、targeted、full regression、diff/artifact checks 與無法執行的項目。
4. 最終結論必須清楚標示：
   - ordinary ML-DSA-65 staging 是否 Implemented／Tested；
   - 真實 FAC threshold authentication／DKG 是否仍未實作；
   - 真實組織 anchors、B/T keys、完整 initialization/issuance、Proof/Production closure 是否仍未完成。

本重審只授權唯讀檢查與 repository 外 temporary test outputs；不授權修改、提交、merge、push、
部署、建立真實組織 key/authorization 或啟動 production/high-cost proving。
