# Satellite access v0.2 atomic grant-query registration checkpoint

日期：2026-09-15

狀態：Implemented／Tested（bounded single-host SQLite composition）；非distributed、
非Production-closed、非Proof-closed

基準parent：`be841d7`

## 1. 本checkpoint處理的缺口

前一checkpoint已實作authenticated scoped revocation ingestion與current／future query
fanout，但grant commit與activation-query registration仍由caller分兩次執行。若process在
兩者之間終止，ticket可能已成為`CONSUMED_PENDING_CONFIRM`，而activation因missing query
安全拒絕；M2必須等待額外恢復動作才能釋放。

本checkpoint在`FGSGrantProcessorV2`加入explicit optional atomic composition，並強制
atomic activation-query store與grant replay store是同一object。Scoped store停用缺少query
的direct `commit_grant()`，改以單一`GrantCommitRequestV2`攜帶：

1. exact pending `GrantRecordV2`；
2. `ActivationRevocationQueryV2`；
3. pure-check輸出的source `AccessRevocationQueryV2`。

## 2. Binding與transaction ordering

Grant processor與activation processor共用
`derive_activation_revocation_query_v2()`。Composed request檢查兩層query與grant的：

```text
suite ID, system configuration, acceptance domain, ctx, ticket use key,
source revocation-query digest, FGS identity, FGS authentication key,
ticket digest / visible serial, request digest, response digest, session ID
```

Scoped store的唯一composed commit順序為：

```text
BEGIN IMMEDIATE
  validate exact RESERVED grant identity
  replay row -> CONSUMED_PENDING_CONFIRM
  register one exact activation query for the ticket/session
  replay matching historical revocation commands into its fence
  if fence.revoked: ROLLBACK
COMMIT
release M2 only after commit
```

同一ticket或session不能登錄第二個不同query。Query registration或record protection失敗時，
grant transition與query insert一併rollback，原reservation保留。Matching revocation先commit
時，historical replay使grant拒絕；grant先commit時，後續command fanout更新已存在的fence。
Concurrent execution只能形成這兩個write orders之一。

## 3. Retry與recovery

若grant-query transaction已commit但ack遺失，第一次呼叫不釋放M2；same-attempt retry先
recover並重新驗證原response，再要求同一store確認existing grant具有唯一、完整且generation
不落後的registered query，才重新釋放原M2。Missing或corrupt query會回傳
`RECOVERY_REQUIRED`，不會被當成existing-grant成功。

這裡沒有自動修復未知query內容：若transaction沒有完整commit，grant仍是`RESERVED`；若
database內容corrupt，必須走明確operator recovery，不得由untrusted response推測並補寫。

## 4. 驗證結果

執行環境：branch `codex/satellite-access-v0-2`，Python unittest；未執行production proving、
大型artifact replay、實體斷電或distributed fault injection。

- atomic registration新增／既有scoped定向測試：26 passed、0 skipped／failures／errors；
- grant／SQLite replay／scoped focused回歸：68 passed、0 skipped／failures／errors；
- grant至first-application相鄰回歸：127 passed、0 skipped／failures／errors；
- 全部system tests：277 passed、0 skipped／failures／errors；
- repository-wide：954 tests，其中942 passed、12個既有optional external-artifact skips、
  0 failures／errors；耗時763.636秒。

新增測試涵蓋所有grant-query binding mutations、same-store object identity、direct commit
rejection、registration failure rollback、pre-existing ticket revocation、lost commit
acknowledgement、exact retry、restart-visible registration、query corruption、ticket／session
query uniqueness及concurrent grant／revocation ordering。

## 5. Claim boundary

可以宣稱：在可信單一host、同一SQLite database與現有WAL／filesystem假設下，grant commit、
activation-query registration及matching historical revocation replay具有一個transaction；M2
不會在缺少完整registered query時由composed processor釋放。列出的mutation、failure、retry及
race已測試。

不可宣稱：

- pure-check provider的remote revocation snapshot與本SQLite transaction原子；
- failed reservation已有automatic abort或garbage collection；
- schema migration或既有legacy grant自動修復已完成；
- production PQ revocation authentication或獨立revocation authority已實例化；
- authority rotation／unrevocation已完成；
- 多FGS／多host distributed linearizability；
- rollback／hostile-filesystem防護或實體斷電已測試；
- concrete PQ AKE／access NIZK或production protection backends已實例化；
- Production-closed或Proof-closed。

## 6. 實作與證據位置

- Grant composition contract：`src/pq_sat_auth/v2/grant.py`
- Shared activation-query derivation：`src/pq_sat_auth/v2/activation.py`
- SQLite transaction primitive：`src/pq_sat_auth/v2/storage/sqlite_replay.py`
- Atomic registration／revocation store：
  `src/pq_sat_auth/v2/storage/sqlite_scoped_revocation.py`
- Tests：`tests/system/test_pq_sat_auth_scoped_revocation_v2.py`
- Machine claims：`manifests/pq_sat_auth_fgs_grant_v0_2.json`、
  `manifests/pq_sat_auth_fgs_scoped_revocation_sqlite_v0_2.json`、
  `manifests/pq_sat_auth_first_application_v0_2.json`
