# Satellite access v0.2 authoritative activation-revocation checkpoint

日期：2026-09-15

狀態：Implemented／Tested（single-host exact per-query SQLite reference）；非distributed、
非Production-closed、非Proof-closed

基準parent：`2ba5013`

## 1. 本checkpoint處理的剩餘窗口

前一個unified checkpoint已將session activation與protected inbox insert放入同一
transaction，但processor檢查revocation snapshot後，authoritative state可能在activation
commit前改變：

```text
read revocation snapshot
  <revocation publication race>
activate + enqueue COMMIT
```

本checkpoint新增獨立schema identity的
`SQLiteFGSAuthoritativeActivationInboxStoreV2`。它保存exact per-query revocation fence，
並要求processor把已檢查的query與snapshot傳到commit boundary。單機reference順序為：

```text
read exact local snapshot
BEGIN IMMEDIATE
  re-read exact fence and compare every field
  validate query/grant/time/generation/non-revoked state
  replay: CONSUMED_PENDING_CONFIRM -> CONSUMED_ACTIVE
  inbox: insert PENDING(record_digest, protected plaintext)
COMMIT
```

## 2. Linearization與retry語意

- revocation publication先commit：commit-time re-read與舊snapshot不相同，activation與inbox
  一併rollback；
- 非revoked generation在snapshot後更新：舊attempt同樣rollback，重新取得fresh snapshot
  的exact retry可成功；
- activation先commit：之後的revocation不刪除已接受的inbox work，dispatcher仍可依
  `record_digest` idempotency identity完成；
- exact publication retry：回傳相同record及revision；
- changed publication：generation必須嚴格增加，已設為true的revocation flag不得清除；
- missing、corrupt、inactive、stale、revoked或query/grant-unbound fence全部fail closed。

這個順序刻意把「是否接受第一筆受保護application record」作為linearization point。
已經commit的work item依既有application lifecycle完成；revocation不倒轉已提交的接受結果。

## 3. Schema與完整性邊界

新database以application ID `0x50515356`、schema version 1、WAL及
`synchronous=FULL`建立，且只允許三張表：

1. `fgs_replay_records`；
2. `first_application_inbox`；
3. `activation_revocation_fences`。

Fence canonical record固定query digest、generation、revision、validity interval及四個
revocation flags，拒絕錯誤長度、trailing bytes與非0／1 flags。Row metadata必須與canonical
record相同，另以domain-separated SHAKE-256 checksum偵測非預期mutation。Checksum不是MAC，
不提供惡意本機管理者或hostile filesystem authenticity。

## 4. 驗證結果

執行環境：branch `codex/satellite-access-v0-2`，Python unittest，無production或大型
artifact execution。

- authoritative checkpoint定向測試：14 passed、0 skipped／failures／errors；
- activation／first-record／unified／authoritative相鄰回歸：59 passed、0 skipped／
  failures／errors；
- 全部system tests：251 passed、0 skipped／failures／errors；
- repository-wide：928 total，其中916 passed、12個既有optional external-artifact
  skips、0 failures／errors；耗時799.317秒。

定向測試涵蓋canonical codec、schema identity、row mutation、missing fence、exact retry、
publication monotonicity／sticky flags、revocation先commit、non-revoked generation race、
activation先commit及後續dispatch。

## 5. Claim boundary

可以宣稱：在可信單一host、同一SQLite database、現有WAL／filesystem假設下，exact
per-query revocation publication、session activation與protected inbox creation具有單一
transaction ordering；所列bounded failure及retry已測試。

不可宣稱：

- local publication caller已有production authentication／authorization；
- configuration、FGS key、ticket或其他general-scope revocation已fan out到所有query rows；
- production record／plaintext protection backend已實例化；
- external application side effect與本SQLite transaction原子或exactly once；
- 多FGS／多host distributed linearizability；
- rollback／hostile-filesystem防護或實體斷電已測試；
- concrete PQ AKE／access NIZK已實例化；
- Production-closed或Proof-closed。

## 6. 實作與證據位置

- Authoritative store：`src/pq_sat_auth/v2/storage/sqlite_authoritative.py`
- Processor commit context：`src/pq_sat_auth/v2/activation.py`
- Atomic activation／inbox base：`src/pq_sat_auth/v2/storage/sqlite_unified.py`
- Tests：`tests/system/test_pq_sat_auth_authoritative_activation_v2.py`
- Standalone machine claims：
  `manifests/pq_sat_auth_fgs_authoritative_activation_inbox_sqlite_v0_2.json`
- Aggregated first-record claims：`manifests/pq_sat_auth_first_application_v0_2.json`
