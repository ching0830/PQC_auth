# Satellite access v0.2 reservation-reconciliation coordinator checkpoint

日期：2026-09-16

狀態：Implemented／Tested（explicit bounded reference）；非自動排程、非authenticated
operator control、非Production-closed、非Proof-closed

基準parent：`999ccf9716afb6a10fe253f3a9fe13705df6af3a`

## 1. 目的

Parent checkpoint提供expired scan、canonical evidence及persistent fencing primitives，
但caller仍須自行決定clock取樣、stale grace、batch limit、錯誤分類與commit後read-back。
若各呼叫端自行組合，可能重複取樣時間、漏掉scan validation、忽略lost acknowledgement，
或在不確定狀態後繼續回收其他ticket。

本checkpoint新增`ReservationReconciliationCoordinatorV2`，只執行明確呼叫的一次bounded
pass，固定上述控制流程。它不是service daemon，也不自行取得operator權限。

## 2. Invocation與policy

Invocation包含exact 32-byte `invocation_id`；它只在run result中作correlation，不是nonce
registry、operator signature或authorization。Immutable policy包含：

- `batch_limit`：1至10,000；
- `minimum_stale_seconds`：uint64。

Coordinator每次只呼叫clock一次，並以：

```text
scan_cutoff = max(0, observed_at - minimum_stale_seconds)
```

查詢`lease_deadline < scan_cutoff`的active reservations。Clock失敗時不scan；scan失敗或輸出
不是tuple、超量、重複、含fence／grant或未達cutoff時，不執行任何abort。

## 3. Per-item ordering與lost-ack recovery

對每個validated candidate固定執行：

```text
derive evidence from candidate + single observed_at
abort_reservation(exact identity, attempt, request, generation, evidence)
lookup_reservation_fence(exact identity)
validate predecessor fields, generation and evidence digest
```

結果分類：

- `FENCED`：abort回覆及store read-back都是本invocation的exact fence；
- `FENCED_RECOVERED`：abort acknowledgement遺失或回覆被改寫，但exact store fence成立；
- `FENCED_BY_PEER`：另一worker已寫入同一predecessor的可驗證fence；
- `NOT_RECONCILED`：commit／re-reserve／dependency等合法state race使本次未回收；
- `UNRESOLVED`：unexpected backend或read-back不確定，立即停止同批後續項目。

`COMPLETED`只表示bounded pass沒有fatal uncertainty；它可以包含`NOT_RECONCILED`，所以
operator不能只看run-level `accepted`。

## 4. 驗證

執行環境：branch `codex/satellite-access-v0-2`；未使用external artifacts，未執行
production proving、distributed fault injection或實體斷電測試。

- coordinator focused：18 passed、0 skipped／failures／errors（0.048秒）；
- coordinator／replay／grant／SQLite／scoped-revocation adjacent：102 passed、
  0 skipped／failures／errors（6.789秒）；
- access system regression：297 passed、0 skipped／failures／errors（15.658秒）；
- repository-wide regression：974 tests，其中962 passed、12個既有optional skips、
  0 failures／errors（763.874秒）。

定向tests涵蓋strict invocation／policy、單次clock取樣、minimum-stale邊界、batch續跑、
clock／scan failure、四類惡意scan輸出、state race、lost acknowledgement、peer fence、
mutated abort output、missing／mutated read-back、unexpected abort halt、雙coordinator競爭及
SQLite restart persistence。

## 5. Claim boundary

可以宣稱：在parent replay-store contract及其單機假設下，顯式caller可透過一個bounded
coordinator安全組合scan、policy、evidence、abort與read-back；已列出的輸入mutation、
lost-ack、race與halt情境有executable tests。

不可宣稱：

- `invocation_id`已認證、去重或寫入persistent audit log；
- clock是production trusted／rollback-resistant time source；
- background scheduler、rate control、alerting或operator workflow已部署；
- 所有`NOT_RECONCILED`項目都可安全重試或自動釋放；
- schema v1→v2 migration、distributed worker coordination或跨主機一致性已完成；
- 實體斷電、hostile filesystem或production cryptographic backends已封閉；
- Production-closed或Proof-closed。

## 6. 位置

- Coordinator與typed results：`src/pq_sat_auth/v2/reconciliation.py`
- Replay／fence primitives：`src/pq_sat_auth/v2/replay.py`
- SQLite store：`src/pq_sat_auth/v2/storage/sqlite_replay.py`
- Tests：`tests/system/test_pq_sat_auth_reconciliation_v2.py`
- Machine claims：
  `manifests/pq_sat_auth_fgs_reservation_reconciliation_v0_2.json`
