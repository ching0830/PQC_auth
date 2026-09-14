# System Governance S0／S1 實作與交接 v0.1

- workline：S — System initialization／Issuer authorization
- branch：`codex/system-governance-s0-s1`
- worktree：`/tmp/PQC_auth_system_governance_s0_s1`
- exact local-main base：`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`
- 狀態：S0 assessment complete；S1 bounded implementation complete

## 1. 現況與 frozen dependency

本輪以 local `main` 的上述 commit 建立隔離 worktree，沒有切換或修改原工作目錄，
也沒有引用其他活動 worktree 的未提交內容。

| 工作線 | 最新唯讀、已提交輸入 | 本輪使用方式 |
|---|---|---|
| B | `0e4e2d792716b08be07901e34aa4439bacf469a0`，`PQ_RBBC_ISSUANCE_PRIVATE_SPOOL_HANDOFF_V1_zh-TW.md` | 只記錄 private-spool handoff 邊界；它不提供本輪可凍結的 `pi_issue` proof/backend 或 signer-response transaction contract |
| T | `737b4ec8d93ed2eb8090b3cda623f3c5a0931f6d`，GF CAP provider handoff v0.1 | 只記錄 proposed binding；其 legacy18 provider／production threshold 能力及 B/system 接受狀態仍 OPEN |

現有能力沿用而未重建：frozen initialization/grant codec、五種 key role、
initialization 與 grant 的完整 authentication message domain、初始化 trust-anchor
reference matching、grant 對 ctx/version/epoch/policy/key/time 的 binding、抽象 verifier、
以及 `IssuerQuotaStore.consume()` 語意。

## 2. 責任與依賴表

| owner | 本工作線依賴／交付 |
|---|---|
| S | FAC configuration/grant 簽署驗證方案；帶外 trust anchor 與真實 key bytes/digest 的解析綁定；authorization、quota/SID persistence；bundle 組裝、發布、驗證流程 |
| B | issuer verification key/profile；issuance relation/proof backend 的 parameters 與 identity；授權後 signer response 與 transaction/idempotency 邊界 |
| T | OA public key、threshold profile、key-origin；初始化／parameters binding 要求 |
| 主整合線 | canonical primitive/parameters 與 OPEN governance 決策；合併後更新 root canonical status、methodology、experiments、roadmap |

S0 的 FAC primitive 比較、來源、建議與未決事項見
`docs/security/system_governance/FAC_AUTHENTICATION_PRIMITIVES_v0_1_zh-TW.md`。

## 3. S1：SQLite quota／SID store

新增 `SQLiteIssuerQuotaStore`，相容既有 `IssuerQuotaStore.consume()` 呼叫形狀，
服務範圍是 **單主機、多程序、可重啟**，不含跨主機一致性。

### 3.1 Protocol flow 的新增能力

1. `authorize_issuance()` 先 decode 並驗證 authenticated initialization。
2. 再檢查 grant role、ctx、protocol version、epoch、policy、issuer key、authorization
   key、`not_before/expiry` 與抽象 grant authentication。
3. 全部通過後，才呼叫 persistent store。
4. store 在同一個 `BEGIN IMMEDIATE` transaction 中完成：首次 grant 建立／既有
   initial quota 一致性、`(grant_digest, issuer_sid)` replay check、quota check、SID
   insert 與 remaining-quota decrement。
5. commit 成功後才回傳結果；busy、corrupt、schema mismatch 或 backend exception
   都 fail closed，不回報 authorization success。

因此，「授權成功後的額度消耗」現在能跨程序及重啟保留。這不會產生
blind-signing response，也不代表完整 issuance transaction 已完成。

### 3.2 Schema 與 lifecycle

- SQLite application id：`0x50514731`（`PQG1`）；schema version：1；
- exact schema objects／columns、singleton metadata 與 schema SHA-256 都會驗證；
- quota 以 canonical 8-byte `u64le` BLOB 保存，避免 SQLite signed integer 截斷；
- `issuer_grants` 保存 initial/remaining quota；`consumed_issuer_sids` 以
  `(grant_digest, issuer_sid)` 為 primary key；
- 每次 `consume()` 開一條 connection，設定 PRAGMA、取得 immediate writer
  transaction，完成後 commit/rollback 並關閉；不跨 call 共用 connection；
- 新資料庫的 schema 建立也在 `BEGIN IMMEDIATE` 中重新確認空白 identity，避免兩個
  程序同時首次初始化各自判斷成功；
- 相同 digest 不能以不同 quota 重建；同一 digest/SID 重試為 `REPLAY` 且不再扣額；
  不同 digest 的相同 SID 仍可各自消耗，未擅自改成 global replay rule；
- `busy_timeout` 有界且預設 5000 ms；逾時回傳 typed backend error，不做盲目 retry。

### 3.3 Durability 與部署假設

- 強制 `journal_mode=WAL`、每條 connection 設 `synchronous=FULL`，並拒絕 WAL 被改掉；
- database、`-wal`、`-shm`、journal/raw logs 與任何秘密資料必須位於 repository 外；
  parent directory 由部署者先建立並施加權限、備份與容量政策；
- 所有程序必須指向同一個絕對 database path，且底層是正確支援 SQLite locking、
  atomic write 與 fsync 的本機 filesystem；網路檔案系統與跨主機不在能力範圍；
- constructor 做 `quick_check(1)`，每個 transaction 驗證 identity、schema metadata、
  columns/objects 與 foreign keys；未知 version、schema drift、錯誤 application id、
  corrupt/non-database bytes 都拒絕；
- 真實測試涵蓋程序在 commit 前／後被 kill 及重新開啟；**沒有**做實體斷電、控制器
  write-cache、filesystem fault injection 或所有硬體 power-loss qualification。

Commit 已持久化但 caller 未取得回覆時，相同 tuple 的下一次呼叫依既有 API 回報
`REPLAY`。backend 不知道 blind-signing response，因此不會退 quota 或刪 SID；需要
成功回覆重取時，必須由 B／主整合線另定 versioned issuance transaction protocol。

## 4. 實作與測試證據

程式與 machine-readable claim boundary：

- `src/pq_rbbc/governance/storage/sqlite_quota.py`
- `manifests/system_governance/issuer_quota_sqlite_v1.json`

真實 database tests 使用各自的 `TemporaryDirectory`，沒有 mock SQLite：

- 多程序爭用最後一份 quota；
- 多程序爭用同一 SID；
- 多程序同時首次建立同一 grant；
- injected pre-commit exception 的完整 rollback；
- 真實 child process 在 commit 前或 commit 後、回覆前終止；
- reopen 後 remaining quota 與 SID 仍存在；
- writer busy/locked、corrupt bytes、unknown version、schema drift、wrong app id；
- connection 關閉／writer lock 釋放與 full-u64 quota；
- 透過既有 `authorize_issuance()` 的全部 validation-before-consumption 控制流。

Targeted command：

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/system_modules/governance/storage -v
Ran 20 tests in 1.546s — passed 20, failures 0, errors 0, skipped 0
```

完整 baseline command：

```text
PYTHONPATH=src python -m unittest discover -s tests -v
Ran 708 tests in 739.909s — passed 696, failures 0, errors 0, skipped 12
```

12 個 skips 都是既有 optional external artifacts 未安裝。Targeted／baseline pass 只支持
上述 S1 bounded claim，不支持 FAC signature、proof closure、完整
initialization／issuance 或 production closure。

## 5. Integration requests

### 給 B

1. 提供 exact issuer verification-key bytes、profile/version、key id 與 digest 計算方式；
2. 提供 issuance relation／proof backend parameters 的 canonical bytes、identity 與
   `common_parameters_digest` binding；
3. 版本化授權後 signer response 的 transaction boundary。若要求 caller 在回覆遺失後
   取回相同成功結果，需採 reservation/commit/result retrieval、outbox 或等價設計；
   現有 `consume()` 對已 commit tuple 只能回 `REPLAY`，S 不會盲目 refund；
4. 測試 authorization consumed、signer failure、process crash、same-attempt retry 與
   duplicated transport request。這會擴充 issuance transaction，不改本輪 quota 語意。

### 給 T

1. 提供 exact OA public-key bytes、threshold profile/version、key-origin、key id/digest；
2. 明定 dealer／DKG、participant identities、threshold/corruption/availability 參數，及
   OA key 對 initialization/common parameters 的完整 binding；
3. 釐清 `OPENING_AUTHORIZATION` signer committee 是否屬 FAC、另一 governance group，
   及其與 `OPENING_ENCRYPTION` shares 的角色分離；
4. 在 system owner 接受前，GF CAP handoff 維持 proposed dependency，不升格 frozen
   production backend。

### 給主整合線

1. 決定 FAC primitive、`n/t/f/u`、dealer/DKG、abort/robustness、opening-authorization
   ownership 與 patent/license policy；
2. 合併後在 root canonical 文件登記 S1 的 Implemented/Tested boundary 與 S0 OPENs；
3. 與 B 定義 issuance outcome/idempotency vNext；與 S 定義 operator-owned trust registry
   介面。本輪 S1 不改 protocol，後兩項可能需要版本化 protocol/API。

## 6. 下一輪 S2：真實設定與 grant authentication

可直接執行的順序：

1. 以隔離、pin-version 的 OpenSSL 3.5+ provider 建立普通 ML-DSA-65 keygen/sign/verify
   adapter 與官方 test-vector／negative tests，取得第一個真實 PQ signature 正例；本機
   OpenSSL 3.0.18 尚無此能力。adapter 必須命名並標示 `non-threshold`。
2. 用該 adapter 分別簽署既有完整
   `PQ-RBBC/SYSTEM-INIT-AUTH/V1 || SystemInitializationBundle.encode()` 與完整
   issuer-grant authentication message；不得只簽 ctx、`pp_digest` 或 metadata。
3. 建立 operator-owned、read-only/pinned trust registry：輸入 `(role, key_id)` 解析到
   實際 verification-key bytes 與 profile，重新計算 digest 並與 bundle reference
   constant-time 比對後才 parse/verify。production entry point 不接受 caller 自帶
   trust anchor、任意 verifier、`verified=true` 或「已驗證」布林值。
4. 以不同 key material 實測 configuration 與 issuer-grant role separation；加入 wrong
   role/key/digest/profile/version、alternate encoding、trailing bytes 與 mutation tests。
5. 平行 pin Mithril exact commit/toolchain，驗證 DKG/dealer 路徑、FIPS verifier
   compatibility、signing-state crash/reuse、abort 與 license/patent；只產出 evaluation
   report，不在決策前接成 canonical FAC。
6. 取得本文件第 5 節的使用者／主整合線決策後，才版本化 threshold authentication
   envelope、ceremony manifest 與 production verifier；若最後選 Quorus/TALUS/Hermine
   或多獨立簽章，重新做 trust/security/protocol delta review。

現有 candidate 中，Mithril 有 DKG/dealer/a-posteriori-sharing 的 POC 路徑；普通
OpenSSL ML-DSA 有真實 keygen/sign/verify、沒有 threshold/DKG。其他 candidate 的實作
可得性與成熟度見 S0 文件，未經使用者決策不得視為已選定。

## 7. 最終狀態

- S1 SQLite store：**Implemented**（單主機、多程序、重啟、原子 consume）。
- S1 SQLite store：**Tested**（真實 SQLite transaction/concurrency/process termination/
  reopen/fail-closed 與現有 authorize control flow；不含實體斷電）。
- 真實 FAC configuration/grant authentication：**未實作**。
- 完整 initialization、blind-signing response 與 issuance transaction：**未完成**。
- Production-closed／Proof-closed：**否**。
