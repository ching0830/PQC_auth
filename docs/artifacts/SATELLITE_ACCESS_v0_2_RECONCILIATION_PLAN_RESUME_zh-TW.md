# Satellite access v0.2 reconciliation plan／progress resume checkpoint

日期：2026-09-16

狀態：Implemented／Tested（single-host resumable reference）；非distributed lease、
非operator-authenticated、非Production-closed

基準parent：`83019935a5242b732bf68263eb92ad5718e73331`

## 1. 封閉的failure window

Parent `8301993`能在coordinator前保存intent、完成後保存receipt，但`intent + no receipt`無法
區分尚未執行、執行一部分或已完成。為避免把舊profile的incomplete intent誤當成安全續跑
狀態，本checkpoint建立不同SQLite application identity的resumable journal，不遷移舊資料。

新ordering為：

```text
intent -> read-only prepare -> immutable plan -> progress[0..n) -> receipt
```

第一筆replay mutation只能發生在exact plan commit及read-back之後；下一個candidate只能在前一筆
progress可讀回後執行。Restart沿用plan內的`observed_at`與candidate list，不重新scan。

## 2. Coordinator phase contract

`ReservationReconciliationCoordinatorV2`保留原`run_once()`，並新增三個可組合phase：

1. `prepare_run()`：單次取樣clock、套用stale cutoff、驗證bounded scan並回傳immutable plan；
2. `reconcile_plan_item()`：只處理指定zero-based candidate，保留atomic fence與read-back語意；
3. `finalize_plan()`：只接受exact contiguous terminal prefix，導出`COMPLETED`或`HALTED`。

原one-shot path改由同三個phase組合，既有disposition與fail-closed behavior不變。

## 3. Canonical durable records

Plan包含完整reservation snapshot，而不只保存use-key；progress同時綁定invocation、index、
candidate identity與item result。所有codec使用ASCII canonical JSON、sorted keys、lowercase exact
hex、fixed version、bounded size，拒絕unknown／missing fields、trailing bytes、gap、conflict與
terminal progress之後的append。

SQLite使用獨立application ID `0x50515352`、schema version 1、WAL、`synchronous=FULL`、新檔
mode `0600`及parent-directory fsync。四個exact tables為intent、plan、progress、receipt；public
API沒有update／delete。Record protection只是backend boundary，本次測試adapter不是production
cryptography或key management。

## 4. Recovery semantics

- intent存在、plan不存在：可重新執行read-only prepare，因本profile禁止plan前mutation；
- plan存在：從已驗證的contiguous progress長度繼續，不重取clock／不重掃；
- replay fence已commit、progress未commit：重做同plan item並由exact fence read-back收斂成
  `FENCED_RECOVERED`；
- progress已commit但ack遺失：read-back該row後繼續；
- terminal receipt存在：直接replay，不執行scan或item；
- `UNRESOLVED` progress為terminal，後續candidate不得執行。

## 5. 驗證

執行環境：branch `codex/satellite-access-v0-2`；無external artifacts，未執行production
proving、distributed fault injection或physical power-loss測試。

- resumable focused：17 passed、0 skipped／failures／errors；
- reconciliation adjacent：53 passed、0 skipped／failures／errors（1.735秒）；
- access system regression：332 passed、0 skipped／failures／errors（17.260秒）；
- repository-wide regression：1009 tests，其中997 passed、12個既有optional skips、
  0 failures／errors（758.321秒）。

定向tests涵蓋canonical round-trip、unknown／trailing／uppercase mutation、plan policy／candidate
binding、phase equivalence、schema／application identity／mode、append ordering、exact retry、
restart、protected-row mutation、跨程序intent serialization、lost intent／plan／progress ack、
中斷後保留prefix、clock變更不影響resume、mutation-before-progress窗口、terminal halt及
preparation rejection。

## 6. Claim boundary

可以宣稱：在新resumable runner profile內，exact plan先於任何replay mutation持久化；每筆完成
的item形成contiguous durable prefix；重啟使用原plan繼續；state mutation與progress之間的
crash可由相同plan item及exact fence read-back安全收斂。上述為可信單機SQLite/filesystem假設
下的reference，並有restart、mutation及cross-process insert測試。

不可宣稱：

- journal與replay mutation屬同一atomic transaction；
- 舊receipt-only incomplete intent可由新profile自動resume；
- single active executor、distributed lease或跨主機一致性已實作；
- operator invocation已簽章／授權，或clock是production trusted source；
- record protection已接production key management；
- hostile administrator、database rollback或physical power loss已封閉；
- background scheduler、Production-closed或Proof-closed。

## 7. 位置

- Phased coordinator：`src/pq_sat_auth/v2/reconciliation.py`
- Plan／progress codecs及runner：`src/pq_sat_auth/v2/reconciliation_resume.py`
- SQLite journal：`src/pq_sat_auth/v2/storage/sqlite_reconciliation_resume.py`
- Tests：`tests/system/test_pq_sat_auth_reconciliation_resume_v2.py`
- Machine claims：`manifests/pq_sat_auth_fgs_reconciliation_resume_v0_2.json`、
  `manifests/pq_sat_auth_fgs_reconciliation_resume_sqlite_v0_2.json`
