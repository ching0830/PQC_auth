# Satellite access v0.2 reconciliation audit-journal checkpoint

日期：2026-09-16

狀態：Implemented／Tested（single-host append-only intent／receipt reference）；
非crash-resumable plan、非operator-authenticated audit、非Production-closed

基準parent：`64c0a2a835049852766ca872f64519ac616c51e3`

## 1. 本checkpoint封閉的順序缺口

Parent coordinator能安全執行一次bounded reconciliation，但run result只存在記憶體。
若operator看見completed結果後無法持久保存，exact retry可能重新取樣clock；若程序在執行中
終止，也沒有durable identity指出某次invocation可能已改變replay state。

本checkpoint以獨立SQLite journal建立兩個immutable records：

1. coordinator執行前的intent；
2. coordinator完成後、wrapper回傳completed前的receipt。

這提供可定位的crash window，沒有把兩個database假裝成同一atomic transaction。

## 2. Canonical intent與receipt

Intent固定包含：

```text
format, invocation_id[32], batch_limit, minimum_stale_seconds
```

Receipt保存完整`ReservationReconciliationRunResultV2`：run-level disposition／failure、
`observed_at`、`scan_cutoff`、`scanned_count`及每個item的use-key、attempt、prior／fence
generation、disposition與bounded detail。JSON採ASCII、sorted keys、無額外欄位／trailing
bytes；hex必須小寫且exact length。Journal額外要求：

- receipt invocation等於intent；
- `scanned_count <= batch_limit`；
- 有clock observation時，
  `scan_cutoff = max(0, observed_at - minimum_stale_seconds)`；
- 無clock observation時只能是未處理任何item的`REJECTED`。

Intent及receipt分別使用domain-separated AAD與record-protection backend。Test adapter不是
production encryption／authentication。

## 3. Journaled runner semantics

```text
no intent
  -> append intent NEW
  -> read back exact intent
  -> coordinator.run_once()
  -> append receipt NEW
  -> read back exact receipt
  -> EXECUTED_AND_RECORDED

exact intent + exact receipt
  -> RECORDED_REPLAY without coordinator rerun

exact intent + no receipt
  -> RECOVERY_REQUIRED without coordinator rerun
```

Intent commit acknowledgement不確定時不執行coordinator；後續read會看到incomplete intent。
Receipt acknowledgement不確定時，runner只在exact receipt read-back成立時回復
`EXECUTED_RECEIPT_RECOVERED`。其他journal／coordinator output不確定性不能成為completed。

## 4. SQLite boundary

獨立database固定：

- application ID `0x5051534A`；
- schema version 1；
- WAL、`synchronous=FULL`；
- exact兩個tables：`reconciliation_audit_intents`、
  `reconciliation_audit_receipts`；
- receipt foreign key指向intent；
- public API沒有update／delete；
- 新database mode `0600`並對parent directory執行fsync。

這些支持可信單機SQLite/filesystem假設下的restart persistence與cross-process insert
serialization；不支持hostile administrator、rollback、直接SQL繞過public API或實體斷電。

## 5. 驗證

執行環境：branch `codex/satellite-access-v0-2`；無external artifacts，未執行production
proving、distributed fault injection或physical power-loss測試。

- audit／journal focused：18 passed、0 skipped／failures／errors（0.620秒）；
- reconciliation adjacent：121 passed、0 skipped／failures／errors（6.759秒）；
- access system regression：315 passed、0 skipped／failures／errors（45.451秒）；
- repository-wide regression：992 tests，其中980 passed、12個既有optional skips、
  0 failures／errors（764.926秒）。

定向tests涵蓋canonical codec、unknown／noncanonical／trailing mutation、detail bound、
intent-receipt policy binding、schema／application identity／file mode、exact append retry、
restart、orphan／conflicting receipt、protected-row mutation、seal failure、兩程序intent race、
intent-before-run ordering、completed retry、incomplete restart、lost intent／receipt ack、
receipt failure及coordinator exception。

## 6. Claim boundary

可以宣稱：透過journaled runner執行時，coordinator之前存在exact durable intent；wrapper回傳
completed之前存在exact durable receipt；same-invocation completed retry不重跑coordinator；
incomplete intent跨restart可偵測並阻止自動重跑。上述範圍有positive、negative、mutation、
restart及cross-process tests。

不可宣稱：

- audit journal與replay mutation為同一atomic transaction；
- incomplete intent保存exact scan plan、candidate list或per-item進度；
- incomplete run可自動判定、resume或finalize；
- invocation已由operator簽署、授權、去重或綁定外部case／change ticket；
- record protection已使用production key management；
- direct database administrator不能update／delete；
- distributed coordination、rollback resistance或physical power-loss已封閉；
- Production-closed或Proof-closed。

## 7. 位置

- Intent／receipt codecs與journaled runner：
  `src/pq_sat_auth/v2/reconciliation_audit.py`
- SQLite journal：
  `src/pq_sat_auth/v2/storage/sqlite_reconciliation_audit.py`
- Tests：`tests/system/test_pq_sat_auth_reconciliation_audit_v2.py`
- Machine claims：
  `manifests/pq_sat_auth_fgs_reconciliation_audit_sqlite_v0_2.json`
