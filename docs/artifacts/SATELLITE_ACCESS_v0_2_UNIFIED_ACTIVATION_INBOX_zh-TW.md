# Satellite access v0.2 unified activation-inbox checkpoint

日期：2026-09-15

狀態：Implemented／Tested（single-host bounded SQLite reference）；非distributed、
非Production-closed、非Proof-closed

基準parent：`513488483606c7e2264de670c8d72111b48e9d59`

## 1. 本checkpoint封閉的窗口

前一個protected inbox checkpoint已有可恢復的`PENDING -> COMPLETED` work item，但FGS
仍依序提交兩筆交易：

```text
activate session COMMIT
  <crash gap>
enqueue protected inbox COMMIT
```

若程序在中間停止，ticket與session已是`CONSUMED_ACTIVE`，卻沒有可由dispatcher自主恢復
的work item，只能等待UE重送exact first record。

本checkpoint新增`SQLiteFGSUnifiedActivationInboxStoreV2`，使用一個database file、一個
connection及一個`BEGIN IMMEDIATE` transaction：

```text
BEGIN IMMEDIATE
  authenticate and load exact pending grant
  UPDATE replay -> CONSUMED_ACTIVE
  INSERT inbox -> PENDING(record_digest, protected plaintext)
  validate composed result
COMMIT
```

它不是把兩個WAL databases以`ATTACH`連接；`PRAGMA database_list`的checkpoint測試只允許
`main`，schema則精確包含`fgs_replay_records`及`first_application_inbox`兩張表。

## 2. Processor composition

`FGSActivationProcessorV2`新增`ActivationCommitRequestV2`及optional
`activation_committer`。既有caller未提供hook時仍呼叫原`activate_session()`，保持舊
delivery及separate-inbox路徑相容。Unified first-record processor則必須同時滿足：

- `activation_processor.replay_store is atomic_inbox_store`；
- application AEAD及client Finished先完整通過；
- commit hook只接收processor已驗證的grant identity與activation values；
- unified store的獨立`activate_session()`入口固定拒絕，不能繞過inbox insert；
- commit成功後才釋出`QUEUED`／`ALREADY_QUEUED`／`ALREADY_COMPLETED` metadata，仍不
  釋出plaintext capability。

三種FGS sink profile維持互斥：legacy direct delivery、compatibility separate inbox及
recommended unified activation-inbox。

## 3. Atomicity、retry與lifecycle

- replay update後若inbox sealing／insert失敗：整筆transaction rollback，grant仍為
  `CONSUMED_PENDING_CONFIRM`且inbox不存在；
- exact concurrent activation：只有一個`NEW + NEW` winner，其餘取得
  `EXISTING_ACTIVE + EXISTING_PENDING`；
- exact restart retry：讀回同一active grant及同一pending／completed inbox identity；
- competing authenticated first record：不得替換既有record digest或plaintext；
- inbox完成後exact first-record retry：只回`ALREADY_COMPLETED`；
- session在record已接受後才逾期：既有queued work仍可dispatch／complete；expiry不撤銷
  已提交的application acceptance。

## 4. 驗證結果

執行環境：branch `codex/satellite-access-v0-2`，Python unittest，無production或大型
artifact execution。

- unified activation-inbox定向測試：12 passed、0 skipped／failures／errors；
- activation／first-record／inbox／unified相鄰回歸：60 passed、0 skipped／failures／
  errors；
- 全部system tests：237 passed、0 skipped／failures／errors；
- repository-wide：914 total，其中902 passed、12個既有optional external-artifact
  skips、0 failures／errors；耗時755.063秒。

涵蓋項目包括single-database exact schema、無`ATTACH`、manifest一致性、新record、seal
failure rollback、restart、跨process race、competing record、dispatch completion、expiry
after acceptance及錯配store object拒絕。

## 5. Claim boundary

可以宣稱：在可信單一host、SQLite WAL、`synchronous=FULL`及現有filesystem假設下，
session activation與protected inbox `PENDING` creation共用同一transaction，且bounded
failure／restart／跨process retry已測試。

不可宣稱：

- activation前取得的revocation snapshot與activation已原子化；
- production replay-record或plaintext protection backend已實例化；
- production external application已提供或證明`apply_once`；
- external application side effect exactly once；
- 多FGS／多host distributed linearizability；
- rollback／hostile-filesystem防護或實體斷電已測試；
- concrete PQ AKE／access NIZK已實例化；
- Production-closed或Proof-closed。

## 6. 實作與證據位置

- Unified store：`src/pq_sat_auth/v2/storage/sqlite_unified.py`
- Activation commit contract：`src/pq_sat_auth/v2/activation.py`
- First-record composition：`src/pq_sat_auth/v2/application.py`
- Tests：`tests/system/test_pq_sat_auth_unified_activation_inbox_v2.py`
- Standalone machine claims：
  `manifests/pq_sat_auth_fgs_unified_activation_inbox_sqlite_v0_2.json`
- Aggregated first-record claims：`manifests/pq_sat_auth_first_application_v0_2.json`
