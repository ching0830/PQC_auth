# S1 SQLite schema-inventory corrective 唯讀重審 prompt v0.2

請對 PQC_auth 的 SQLite issuer quota store schema-inventory corrective 執行唯讀、
防禦性程式碼審查。

授權範圍：

- Repository：`/home/ucheng0830/Documents/PQC_auth`
- Branch：`codex/system-governance-s0-s1`
- Parent：`b13cad856637ed5fb8e6a44dacc52929bce32221`
- Corrective HEAD：應為 parent 的單一 bounded 後繼；請用 Git 記錄實際 hash

限制：

- 只讀取程式碼、tests、manifest、文件與 commit diff；
- 不修改 repository，不 commit／merge／push；
- 不存取 production database，不連線外部系統；
- 只執行 repository 已有 tests，不建立額外工具；
- 不開始 S2 或 FAC authentication。

請閱讀：

1. `AGENTS.md` 與相關文件政策；
2. `src/pq_rbbc/governance/storage/sqlite_quota.py`；
3. `tests/system_modules/governance/storage/test_sqlite_quota.py`；
4. `manifests/system_governance/issuer_quota_sqlite_v1.json`；
5. `docs/artifacts/system_governance/SYSTEM_GOVERNANCE_S0_S1_v0_1_zh-TW.md`；
6. `b13cad8..HEAD` 的完整 diff。

請確認：

1. Schema inventory query 不再使用 `LIKE 'sqlite_%'` 或其他模糊名稱過濾，並讀取
   完整 persistent `main.sqlite_schema`。
2. Exact allowlist 只包含三張 canonical tables 與兩個預期 PK autoindexes；table DDL
   必須為 canonical SQL，autoindex 的 `sql` 必須為 `NULL`。
3. `sqliteX...` 名稱的 explicit index／trigger，以及一般額外 table/index/view/trigger
   都由既有 tests 證明會拒絕。
4. `PRAGMA index_list` 驗證 owning table、sequence、unique、`origin='pk'` 與 partial；
   `index_xinfo` 驗證 columns/order、collation、key flags 與 rowid auxiliary entry。
5. Canonical PK autoindexes 可正常建立與重開；不是把所有 SQLite internal objects
   一概接受或一概誤拒。
6. `sqlite_sequence` 與 `sqlite_stat*` 的 policy 是 default-reject，且有既有 tests。
7. Actual DDL digest、compiled digest、metadata digest、STRICT、CHECK、columns/PK 與 FK
   definitions/actions 的既有驗證仍存在。
8. Constructor 與每次 `consume()` 都使用相同 validator；quota、SID、REPLAY、rollback、
   concurrency、crash-recovery 與 `authorize_issuance()` 語意未改。
9. Manifest／交接 claim 與 validation profile V2 一致；schema version／digest 未被誤改，
   因 on-disk canonical DDL 並未改變。

執行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover \
  -s tests/system_modules/governance/storage -v

PYTHONPATH=src python -m unittest discover -s tests -v

git diff --check b13cad8..HEAD
git status --short --branch
```

請直接在回覆中提供審查報告，不寫入 repository。每個 finding 請列 severity、file/line、
原因、對 S1 claim 的影響與建議修正；若沒有 finding，也請列 passed/failed/errors/
skipped、SQLite/Python/filesystem assumptions，以及未測實體斷電與跨主機限制。

本審查只支持 S1 schema inventory 的工程判斷，不代表 production approval、FAC
authentication、cryptographic proof、physical power-loss qualification 或 S2 completion。
