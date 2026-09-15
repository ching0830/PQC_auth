# Satellite access v0.2 FGS replay SQLite checkpoint

日期：2026-09-15

狀態：Implemented／Tested（single-host bounded reference）；非distributed、非
Production-closed、非Proof-closed

## 1. 在論文流程中的位置

此checkpoint實作M6 one-time access state的單機durability boundary：

```text
M1 valid
  -> Reserve(use_key, attempt)
  -> CommitGrant(exact sealed M2, sealed pending session)
  -> M2可以送出／exact retry
  -> Activate(client Finished／first protected record)
  -> Expire／Terminate但ticket永不重新可用
```

它替換的是先前僅限單一Python process的replay-store backend，不改變M1 pure-check、
`Core.VerifyTicket`、access NIZK、FGS authentication或AKE的密碼學內容。

## 2. Canonical record與indexes

`SQLiteFGSReplayStoreV2`保存兩類canonical JSON record：`ReservationV2`與
`GrantRecordV2`。Grant record可處於`CONSUMED_PENDING_CONFIRM`、
`CONSUMED_ACTIVE`或`CONSUMED_EXPIRED`。

SQLite rows固定以下authoritative indexes：

- primary key：`use_key`；
- unique：`(ctx,ticket_digest)`；
- unique：`(ctx,serial)`；
- unique：非NULL `session_id`。

因此同一ticket不能換serial／digest／attempt重新reserve，不同ticket也不能取得同一
session ID。`CommitGrant`保存exact `sealed_response`與`sealed_session_state`，restart後
grant processor可回復原M2而不重跑KEM或建立第二個session。

## 3. Record protection與durability ordering

每個canonical record在寫入SQLite前交給`FGSReplayRecordProtectionV2`；protection AAD綁定：

```text
use_key || ctx || serial || ticket_digest
|| state || revision || session-present || session_id
```

Read path必須驗證protection identity、開啟record、strict canonical decode，再比對row
metadata與protected record。State、identity、session、protected bytes或protection ID被
改寫皆fail closed。

Store使用per-operation connection、`BEGIN IMMEDIATE`、WAL、`synchronous=FULL`、固定
application ID／schema version、database mode `0600`及首次建立後parent-directory fsync。
Mutation只有在commit回覆後才對caller可見；突然process exit後可由新store instance
recover。

## 4. 驗證涵蓋

- 完整重跑process-local reference store的transition／idempotency／negative／race suite；
- canonical reservation及pending／active／expired records與frozen SHA-256 vector；
- same／distinct attempt跨程序reservation race；
- competing M2跨程序commit race；
- thread及process activation race，恰一個transition winner；
- restart後exact reservation／M2／active／expired state recovery；
- CommitGrant完成後突然process exit；
- identity、session、deadline、abort及terminal-state fail-closed semantics；
- schema／application ID、protection key／ID及row mutation rejection；
- 真實`FGSGrantProcessorV2 -> store restart -> exact M2 retry ->
  FGSActivationProcessorV2` bounded pipeline。

驗證結果（2026-09-15）：

- SQLite store定向測試：29 passed、0 skipped／failures／errors；
- access相鄰模組回歸：90 passed、0 skipped／failures／errors；
- repository-wide：875 total，其中863 passed、12個既有optional-artifact skips、
  0 failures／errors。

## 5. Claim boundary

可以宣稱：在可信單一host、SQLite與其filesystem假設下，FGS replay state具有
cross-process serialization、restart recovery、exact M2 persistence及唯一session index；
此bounded reference已Implemented／Tested。

不可宣稱：

- 多FGS／多host distributed linearizability；
- production record-protection backend已選型；
- hostile filesystem、rollback、kernel crash／remount或實體斷電安全；
- revocation snapshot與grant／activation是同一authoritative transaction；
- FGS delivery claim或external application side effect已durable／exactly-once；
- production PQ AKE／access NIZK、Production-closed或Proof-closed。

## 6. 實作位置

- Store及canonical record codec：`src/pq_sat_auth/v2/storage/sqlite_replay.py`
- 原始state contract：`src/pq_sat_auth/v2/replay.py`
- Tests：`tests/system/test_pq_sat_auth_sqlite_replay_v2.py`
- Machine claims：`manifests/pq_sat_auth_fgs_replay_sqlite_v0_2.json`
