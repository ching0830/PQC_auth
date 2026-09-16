# Satellite access v0.2 FGS first-record delivery SQLite checkpoint

日期：2026-09-15

狀態：Implemented／Tested（single-host bounded reference）；非distributed、非
Production-closed、非Proof-closed

## 1. 在論文流程中的位置

此checkpoint位於M5 session activation與M6 one-time lifecycle交界：

```text
authenticated FirstApplicationRecordV2
  -> CONSUMED_PENDING_CONFIRM -> CONSUMED_ACTIVE
  -> Claim(session_id, record_digest)
  -> NEW：釋放一次plaintext capability
  -> EXISTING：回覆ALREADY_DELIVERED，不再釋放
```

它把先前process-local delivery claim換成單機SQLite authoritative identity，不改變
client Finished、application AEAD、activation或ticket consumption的密碼學內容。

## 2. Claim identity與transaction ordering

`SQLiteFirstApplicationDeliveryStoreV2`固定：

- primary key：`session_id`；
- value：`record_digest`；
- revision：1；
- public corruption checksum：
  `SHAKE256("PQ-SAT/FGS-FIRST-DELIVERY-CLAIM/v0.2" || revision_u64be ||
  session_id || record_digest, 256)`。

同一session第一次atomic insert得到`NEW`；相同record retry得到`EXISTING`；不同record
digest一律拒絕。FGS processor只有在claim commit回覆`NEW`後，才建立包含plaintext的
內部delivery capability。

Public checksum可偵測bounded accidental row mutation，但不是MAC。資料庫刪除、rollback
或具權限攻擊者可重算checksum，均不在本reference的安全claim內。

## 3. Durability與failure semantics

Store使用per-operation connection、`BEGIN IMMEDIATE`、WAL、`synchronous=FULL`、固定
application ID／schema、database mode `0600`及首次建立後parent-directory fsync。

目前ordering是兩筆獨立交易：

```text
T1: activate session in replay store
T2: insert delivery claim
T3: caller執行external application side effect
```

因此：

- T1後、T2前crash：exact retry可繼續claim；
- T2 commit後、caller收到ack前crash：retry只能看到`EXISTING`，工作可能遺失；
- T2後、T3執行中crash：是否重做side effect不是本store能判定；
- restart不會因process-local記憶消失而再次釋放plaintext capability。

這是durable at-most-once gate，不是exactly-once transaction。

## 4. 驗證涵蓋

- manifest與frozen claim-checksum vector；
- exact claim／retry／restart及competing digest；
- thread及process races只有一個`NEW` winner；
- competing process digests只有一個winner，其餘拒絕；
- claim commit後突然process exit及restart recovery；
- database identity、schema、mode、輸入bound與row mutation rejection；
- 實際`FGSFirstApplicationRecordProcessorV2`在delivery-store restart後不重複釋放；
- lost claim acknowledgement回覆`COMMIT_UNCERTAIN`，retry不重複delivery；
- 第二個authenticated sequence-zero record由SQLite claim拒絕。

驗證結果（2026-09-15）：

- SQLite delivery定向測試：12 passed、0 skipped／failures／errors；
- activation／first-record／SQLite replay與delivery相鄰回歸：74 passed、
  0 skipped／failures／errors；
- 全部system tests：210 passed、0 skipped／failures／errors；
- repository-wide：887 total，其中875 passed、12個既有optional-artifact skips、
  0 failures／errors。

## 5. Claim boundary

可以宣稱：在可信單一host、SQLite與其filesystem假設下，第一筆application record的
delivery identity可跨程序serialization並在restart後維持；bounded at-most-once
plaintext-capability gate已Implemented／Tested。

不可宣稱：

- activation與delivery claim是同一authoritative transaction；
- external application side effect exactly once；
- 多FGS／多host distributed linearizability；
- hostile filesystem integrity、deletion／rollback resistance；
- kernel crash／remount或實體斷電安全；
- production AEAD／PQ AKE、Production-closed或Proof-closed。

## 6. 實作位置

- Store：`src/pq_sat_auth/v2/storage/sqlite_delivery.py`
- FGS processor及claim contract：`src/pq_sat_auth/v2/application.py`
- Tests：`tests/system/test_pq_sat_auth_sqlite_delivery_v2.py`
- Machine claims：`manifests/pq_sat_auth_first_application_v0_2.json`
