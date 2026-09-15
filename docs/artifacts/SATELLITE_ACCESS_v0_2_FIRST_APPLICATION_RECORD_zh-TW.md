# Satellite access v0.2 第一個受保護 application record checkpoint

日期：2026-09-15
狀態：Implemented／Tested（bounded reference）；非 Production-closed、非 Proof-closed

## 1. 這個 checkpoint 完成什麼

本 checkpoint 把論文流程中的：

```text
UE_ACCEPTED
  -> first protected UE-to-FGS application record + client Finished
  -> FGS_ACTIVE
  -> one application delivery capability
```

連到可執行的byte、durability與state-transition boundary。它不重做M1的access NIZK，
也不改變ticket已在M2前唯一消耗的語意。

新增的`FirstApplicationRecordV2`使用frame type `0x0104`，固定：

- `suite_id`、`request_digest`、`attempt_id`、`session_id`、`response_digest`；
- `sequence_number = 0`；
- exact canonical `SessionActivateV2`（含client Finished）；
- application ciphertext。

前述fixed fields、sequence及完整activation frame全部進入domain-separated AAD。
Nonce context由suite ID、session ID與sequence衍生；concrete suite仍須另行固定如何映射到
實際AEAD nonce。

## 2. UE端：先commit exact bytes，才允許傳送

`UEFirstApplicationRecordProcessorV2`只接受已驗證的`UEAcceptedSessionV2`。處理順序為：

1. 驗證session、期限及application plaintext size；
2. 以domain-separated plaintext digest在outbox執行`RESERVED`；
3. 只有相同session與相同plaintext identity可以retry；
4. 使用`K_application`與固定AAD／nonce context產生ciphertext；
5. SQLite outbox執行`RESERVED -> READY`並保存exact record bytes；
6. commit output與read-back完全一致後，才回傳可送出的wire bytes。

先reserve plaintext identity的理由，是避免兩個process同時以同一session／sequence-zero
nonce context加密不同plaintext。Exact retry可重做相同的deterministic suite operation，
也可在READY後直接恢復原bytes而不reseal；不同plaintext永遠不能取代既有reservation。

SQLite profile固定獨立application ID、schema version、WAL、`synchronous=FULL`、database
file mode及parent-directory fsync。Outbox只保存會上wire的authenticated ciphertext與公開
header，不保存application plaintext或`K_application`。這不代表hostile-filesystem integrity、
rollback resistance或實體斷電已驗證。

## 3. FGS端：先驗證整個record，才activate與release

`FGSFirstApplicationRecordProcessorV2`先strict decode並驗證embedded activation bindings，
再透過`FGSActivationProcessorV2`的pure pre-activation check完成：

1. client Finished與既有configuration／time／revocation checks；
2. 使用pending session的`K_application`驗證整個application record；
3. 只有上述檢查全部成功才atomic `CONSUMED_PENDING_CONFIRM -> CONSUMED_ACTIVE`；
4. process-local store取得該session的唯一delivery claim；
5. winner取得含plaintext的內部delivery capability；exact retry只取得
   `ALREADY_DELIVERED`，不再釋放plaintext。

因此ciphertext corruption不會activate session，holder若以相同session送出第二個可驗證
的sequence-zero record也會被delivery gate拒絕。

## 4. 明確未完成的transaction與crash邊界

FGS activation state與delivery claim目前不是同一durable／distributed transaction，外部
application side effect更不在其中。Reference語意是「同一process state下的at-most-once
plaintext capability release」，不是crash-safe exactly-once side effect：

- activation完成、delivery claim前crash：exact retry可再次走到claim；
- claim完成、外部side effect前crash：工作可能遺失；
- process restart：process-local claim消失，不能據此宣稱不會再次release。

Production方案必須把activation、delivery identity及實際application mutation納入一致的
durable transaction，或以application idempotency key／inbox-outbox protocol明定可恢復
語意。

## 5. 實作與證據位置

- Record、AAD、nonce context、UE／FGS processors：
  `src/pq_sat_auth/v2/application.py`
- UE SQLite outbox：`src/pq_sat_auth/v2/storage/sqlite_first_record.py`
- Activation pure pre-check：`src/pq_sat_auth/v2/activation.py`
- Frame type：`src/pq_sat_auth/v2/framing.py`
- Machine claims：`manifests/pq_sat_auth_first_application_v0_2.json`
- Tests：`tests/system/test_pq_sat_auth_first_application_v2.py`及既有activation tests

## 6. 驗證涵蓋

Targeted tests涵蓋：

- canonical round-trip與frozen record SHA-256 vector；
- wrong type、truncation、trailing bytes、非zero sequence；
- exact AAD／nonce flow binding；
- commit/read-back-before-release；
- restart recovery、parallel exact retry、competing plaintext、lost acknowledgement；
- SQLite identity／schema／corruption rejection；
- UE到FGS bounded end-to-end activation與plaintext recovery；
- corrupt ciphertext不activation、不release；
- parallel FGS retry只有一個delivery winner；
- 第二個authenticated sequence-zero record拒絕；
- suite mismatch與delivery-store uncertainty fail closed；
- production／durability claims保持false。

本checkpoint commit前的實際結果：

- Targeted activation／first-record：33 passed、0 skipped、0 failures／errors；
- Repository-wide：846 tests，834 passed、12個既有optional-artifact skips、
  0 failures／errors；
- `git diff --check`：通過。

## 7. Claim boundary

可以宣稱：canonical first-record format、AAD／sequence-zero binding、UE單機durable exact
outbox reference、FGS AEAD-before-activation ordering，以及process-local one-time delivery
capability已Implemented／Tested。

不可宣稱：production AEAD／PQ AKE已選型、FGS store durable／distributed、activation與
delivery atomic、external side effect exactly once、實體斷電安全、Production-closed或
Proof-closed。
