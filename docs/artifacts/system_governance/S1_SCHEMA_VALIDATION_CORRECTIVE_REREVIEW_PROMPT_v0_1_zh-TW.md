# S1 SQLite schema-validation corrective 唯讀重審 prompt v0.1

請在 `codex/system-governance-s0-s1` corrective HEAD 的獨立乾淨 worktree 執行唯讀、
AI-assisted technical re-review。先核對 `git status --short --branch`、HEAD、local
`main`、branch graph 與 worktree list；不得切換或修改其他 task。Corrective HEAD 應為
`ff08c53f1cfc83aecfc44327243b80ed7525c940` 的單一 bounded 後繼 commit；請以 Git
記錄實際 hash，不要由交接文件推測。

本重審只檢查 S1 persistent issuer quota/SID store 的 schema-validation corrective。
它不是 FAC primitive selection、真實 FAC authentication、完整 issuance、實體斷電
qualification、production approval 或 external independent cryptographic review。禁止
開始 S2、merge、push 或修改 repository。

先完整閱讀：

1. `AGENTS.md` 及其要求的相關 canonical／policy 文件；
2. `docs/artifacts/system_governance/SYSTEM_GOVERNANCE_S0_S1_v0_1_zh-TW.md`；
3. `src/pq_rbbc/governance/storage/sqlite_quota.py`；
4. `tests/system_modules/governance/storage/test_sqlite_quota.py` 與
   `test_authorization_integration.py`；
5. `manifests/system_governance/issuer_quota_sqlite_v1.json`；
6. parent `ff08c53` 到 corrective HEAD 的完整 diff。

請獨立核對下列項目，不因新增 tests 已通過就假設修正充分：

1. 建立與 canonical tables/columns/PK/metadata 相同，但移除全部 `STRICT`、`CHECK`、
   `FOREIGN KEY` 的真實 SQLite database；metadata 填入 implementation 預期的
   `schema_sha256`。確認 constructor 與 `consume()` 都 fail closed，且沒有 SID/quota
   mutation。
2. 確認 schema digest 的輸入確實來自當次 connection 讀到的實際
   `sqlite_schema.sql`，依固定 table order canonicalize 後重算；compiled expected
   digest、actual digest、metadata digest 任兩者不符都拒絕。metadata row 不得成為
   actual-schema truth source。
3. 分開變異三張表的 `STRICT` flag。檢查 `PRAGMA table_list` 的 schema/name/type/ncol/
   `wr`/`strict`，並確認缺少 STRICT 或改成 `WITHOUT ROWID` 不會通過。
4. 分開移除、放寬或改寫每類 `CHECK`：metadata singleton/format/version/digest length、
   grant digest type/length、quota type/length、SID type/length/range。確認 validator 綁定
   actual canonical DDL，而不是只靠插入一筆目前剛好合法的資料。
5. 分開移除 FK、改 source/target column、改 referenced table，以及改 `ON UPDATE`／
   `ON DELETE`／`MATCH`。確認 `foreign_key_list` definitions/actions 與
   `foreign_key_check` data consistency 是兩個獨立檢查。
6. 變異 column order/type/`NOT NULL`/default/PK ordinal/hidden-generated property；加入
   extra table、explicit index、view、trigger。確認全部拒絕，且 SQLite 自動建立的
   canonical PK indexes 不被誤判為額外 user objects。
7. 檢查 exact canonical DDL 的既有 database 可重開，SQLite schema version／digest
   未因 validator hardening 被不實改寫；manifest 與 implementation deterministic
   output 必須相同。
8. 重新檢查 `BEGIN IMMEDIATE`、rollback、busy、multi-process last-quota/same-SID、
   commit 前後程序終止與 `authorize_issuance()` validation-before-consumption，確認
   corrective 沒有改動既有 consume/API semantics。

獨立 adversarial probe 必須使用真實 SQLite files 與各自的新 `/tmp` temporary
directory；不得 mock database。不得只靠 `sleep` 猜 concurrency。probe source、results
與報告只寫入新 `/tmp/pqc-auth-s1-schema-rereview-*`，不要覆寫既有 test evidence。

執行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover \
  -s tests/system_modules/governance/storage -v

PYTHONPATH=src python -m unittest discover -s tests -v
```

另執行 `git diff --check ff08c53..HEAD`，核對 corrective 只改 S-owned source、tests、
manifest、handoff 與此 prompt，且沒有 database/WAL/journal/log/cache/pickle/checkpoint/
external artifact 進入 Git。

每項 finding 請提供 priority、精確 file/line、trigger、observed vs expected、最小重現、
claim impact 與具體 corrective 建議。即使沒有 finding，也須列 passed/failed/errors/
skipped、SQLite/Python/filesystem assumptions、未測實體斷電與跨主機限制。完成前再次
核對 repository clean；不得 commit、merge 或 push。
