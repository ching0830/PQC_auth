# Satellite access v0.2 expired-reservation reconciliation checkpoint

日期：2026-09-16

狀態：Implemented／Tested（bounded process-local與single-host SQLite reference）；
非distributed、非Production-closed、非Proof-closed

基準parent：`b9de873`

## 1. 本checkpoint處理的缺口

Grant／grant-query建構、protection或commit失敗後，fail-closed processor可能保留
`RESERVED`。先前`abort_reservation()`只檢查三個opaque digest的長度，而且刪除row後可立刻
建立相同attempt的reservation。若舊worker稍後醒來，它可能把舊commit套到新建但identity相同
的reservation，形成ABA gap。

本checkpoint沒有把「lease到期」誤當成充分證據，而是加入exact observation evidence及
持久化、單調worker fence，使commit與reconciliation只能形成一個可判定的store order。

## 2. Exact evidence與fencing generation

每個active reservation包含正整數`fencing_generation`。Canonical abort evidence的三個
domain-separated digests共同綁定：

```text
ticket-use identity, attempt ID, request digest, serving-context digest,
reserved_at, lease_deadline, revocation generation,
fencing generation, observed_at
```

Store重新導出並逐項核對evidence；任一欄位改動、錯誤generation、
`observed_at <= lease_deadline`或已consumed state都拒絕。這些digests是bounded audit
identity，不是外部publication service的簽章或密碼學absence proof。`observed_at`仍由caller
提供；production recovery clock backend尚未實例化。

## 3. Atomic recovery order

SQLite recovery transaction固定為：

```text
BEGIN IMMEDIATE
  read and authenticate exact RESERVED row
  require observed_at > lease_deadline
  verify attempt / request / fencing generation / canonical evidence
  scoped successor: require no activation-query dependency
  rotate generation g -> g + 1
  replace row with protected FENCED_RESERVATION_INTERNAL tombstone
COMMIT
```

Public `lookup()`與live-record count把tombstone視為`UNSEEN`，但store仍保存identity、舊lease、
rotated generation及evidence digest。下一次`Reserve`從tombstone建立generation `g + 2`；
`CommitGrant`與atomic `GrantCommitRequestV2`必須攜帶取得reservation時的generation。因此：

1. commit先linearize：reconciliation看到consumed grant並拒絕；
2. reconciliation先linearize：stale commit看到fenced row並拒絕；
3. 新reservation已建立：舊commit因generation mismatch拒絕；
4. generation耗盡：fail closed，不wrap around。

## 4. Restart discovery與schema boundary

Replay schema升為version 2，`fgs_replay_records`新增受constraint保護的
`lease_deadline` metadata，並允許internal state 5。Protected canonical record仍是完整真值，
metadata與protected bytes不一致會fail closed。`expired_reservations(observed_at, limit)`以
metadata執行有上限的restart scan，只回傳state 1且lease已過期的authenticated records。

Unified activation-inbox、authoritative activation及scoped-revocation profiles同步採用新的
replay row schema與schema version 2。沒有自動migration：舊schema version 1 database會明確
拒絕，必須由後續獨立migration checkpoint處理，不能原地猜測或靜默升級。

## 5. 驗證結果

執行環境：branch `codex/satellite-access-v0-2`，Python unittest；未執行實體斷電、
hostile-filesystem、distributed fault injection、production proving或大型artifact replay。

- reservation／grant／SQLite focused：85 passed、0 skipped／failures／errors；
- access system相鄰回歸：279 passed、0 skipped／failures／errors（15.117 秒）；
- repository-wide：956 tests，其中944 passed、12個既有optional skips、
  0 failures／errors（767.192 秒）。

定向測試涵蓋canonical evidence逐欄mutation、未到期拒絕、錯誤generation、protected fence
codec／restart、bounded expired scan、lease metadata corruption、fence後相同M1 re-reserve、
stale worker rejection、reconciliation-vs-commit race、consumed-state non-release、generation
binding及scoped activation-query dependency guard。

## 6. Claim boundary

可以宣稱：在所有M2只經由commit-before-return processor發布、可信單一host、同一SQLite
database及既有WAL／filesystem假設下，expired reservation可在exact evidence驗證後atomic
轉為protected fence；後續reservation具有不同generation，已列出的stale-worker／ABA、
mutation、restart及race情境已測試。

不可宣稱：

- evidence證明repository之外沒有side-channel response publication；
- caller-supplied `observed_at`已由production trusted clock產生；
- background reconciliation scheduler或operator policy已部署；
- schema v1資料已migration；
- distributed lease authority／multi-FGS fencing已實作；
- rollback resistance、secure erasure或實體斷電已測試；
- concrete PQ AKE／access NIZK或production protection backend已實例化；
- Production-closed或Proof-closed。

## 7. 實作與證據位置

- State／evidence／process-local model：`src/pq_sat_auth/v2/replay.py`
- SQLite codec／schema／scan／reconciliation：
  `src/pq_sat_auth/v2/storage/sqlite_replay.py`
- Grant generation binding：`src/pq_sat_auth/v2/grant.py`
- Scoped dependency guard：`src/pq_sat_auth/v2/storage/sqlite_scoped_revocation.py`
- Tests：`tests/system/test_pq_sat_auth_replay_v2.py`、
  `tests/system/test_pq_sat_auth_sqlite_replay_v2.py`、
  `tests/system/test_pq_sat_auth_scoped_revocation_v2.py`
- Machine claims：`manifests/pq_sat_auth_fgs_replay_sqlite_v0_2.json`及三個successor
  SQLite manifests。
