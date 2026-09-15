# Satellite access v0.2 reconciliation execution-lease checkpoint

日期：2026-09-16

狀態：Implemented／Tested（single-host lease-fenced resumable reference）；
非distributed consensus、非operator-authenticated、非Production-closed

基準parent：`fd75f2dcd4eaf0e7ef177498a803690350a2592a`

## 1. 本checkpoint封閉的併發缺口

Parent resumable runner已能保存plan及逐項progress，但未限制兩個process同時執行同一
invocation。本checkpoint新增immutable execution-lease generations，並提供lease-fenced runner：

1. replay item前必須取得、assert或renew current lease；
2. progress與receipt insert和current-lease驗證位於同一SQLite transaction；
3. live peer持有lease時，新owner在第一筆replay mutation前fail closed；
4. deadline到達後，新owner可用下一個generation takeover；
5. 舊generation即使仍在執行，也不能再提交progress或receipt。

## 2. Lease contract

Canonical lease固定包含：

```text
format
invocation_id[32]
owner_id[32]
lease_generation: positive SQLite int64
acquired_at, lease_deadline: SQLite int64
lease_seconds: 1..86400
renewal_margin_seconds: 0..lease_seconds-1
```

`lease_deadline = acquired_at + lease_seconds`；active interval為
`[acquired_at, lease_deadline)`。相同owner在live interval取得existing token；不同owner得到
`HELD_BY_PEER`；`observed_at >= lease_deadline`才能append下一個generation takeover。Clock
同一runner內的clock rollback、早於current acquisition的observation、policy變更及int64
overflow全部拒絕。Caller必須為同時存活的executors配置不同
`owner_id`；目前沒有process attestation或系統機制防止兩個process誤用相同ID。

## 3. Transactional fencing

`append_progress_under_lease()`與`append_receipt_under_lease()`使用`BEGIN IMMEDIATE`，在同一
transaction內重讀current protected lease，驗證exact owner／generation／deadline，再驗證既有
plan／progress／receipt binding並insert。這封閉「先檢查lease、另一process takeover、舊process
仍提交journal」的TOCTOU窗口。

Replay mutation不在相同SQLite transaction中。若舊process已通過pre-item lease check，仍可能在
takeover後呼叫一次replay store；exact candidate、reservation fencing generation與read-back使
它不能釋放第二次，而舊token的journal write會被拒絕。這項限制在machine claims明確為false。

## 4. Schema migration

Resumable SQLite application ID維持`0x50515352`，schema由v1升至v2並新增
`reconciliation_resume_leases`。Migration只接受exact v1 application ID、user version及四個
table schemas；在writer transaction中新增table及更新version。既有intent／plan／progress／
receipt bytes不重寫。未知或突變schema持續fail closed。

## 5. 驗證

執行環境：branch `codex/satellite-access-v0-2`；無external artifacts，未執行production
proving、distributed fault injection或physical power-loss測試。

- lease focused：17 passed、0 skipped／failures／errors（1.053秒）；
- reconciliation adjacent：70 passed、0 skipped／failures／errors（2.769秒）；
- access system regression：349 passed、0 skipped／failures／errors（17.521秒）；
- repository-wide regression：1026 tests，其中1014 passed、12個既有optional skips、
  0 failures／errors（763.742秒）。

定向tests涵蓋canonical codec、bounds／mutation、acquire／existing／peer refusal、exact-deadline
takeover、renewal generation、stale token、clock rollback、policy conflict、progress／receipt
transactional fencing、terminal refusal、cross-process acquisition、protected lease mutation、
schema v1 migration、live peer在mutation前拒絕、mutation-before-progress後的expired takeover
、lost acquisition acknowledgement、acquisition-output mutation及runner renewal。

## 6. Claim boundary

可以宣稱：選用lease-fenced runner時，同一可信主機上的process使用SQLite serialization選出
current execution lease；progress／receipt只能由current unexpired generation提交；live peer在
replay mutation前被拒絕；crashed owner逾期後可被fenced takeover。

不可宣稱：

- lease與replay database mutation屬同一transaction；
- takeover能取消已通過lease check的舊process或網路call；
- unfenced base runner API已被全域移除；
- lease跨主機、具consensus／quorum或partition availability；
- lease clock已接production trusted／monotonic source；
- owner ID已由operator authentication或process attestation驗證；
- unique owner ID已由reference自動配置或強制；
- production key management、rollback resistance或physical power loss已封閉；
- background scheduler、Production-closed或Proof-closed。

## 7. 位置

- Lease codec／policy／runner：`src/pq_sat_auth/v2/reconciliation_lease.py`
- SQLite lease及fenced writes：
  `src/pq_sat_auth/v2/storage/sqlite_reconciliation_resume.py`
- Tests：`tests/system/test_pq_sat_auth_reconciliation_lease_v2.py`
- Machine claims：
  `manifests/pq_sat_auth_fgs_reconciliation_execution_lease_v0_2.json`
