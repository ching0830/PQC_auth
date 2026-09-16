# Satellite access v0.2 FGS protected application inbox checkpoint

日期：2026-09-15

狀態：Implemented／Tested（single-host bounded reference）；非distributed、非
Production-closed、非Proof-closed

## 1. 解決的failure window

前一個durable delivery-claim checkpoint能防止restart後重複釋放plaintext，但claim
commit與caller取得work item之間仍可能crash，造成永久漏做。本checkpoint將claim
identity與受保護plaintext放入同一個durable enqueue：

```text
FGS_ACTIVE
  -> PENDING(session_id, record_digest, protected plaintext)
  -> apply_once(record_digest, plaintext) -> stable receipt
  -> COMPLETED(receipt)
```

FGS first-record processor的inbox模式不直接回傳plaintext delivery capability，只回覆
`QUEUED`、`ALREADY_QUEUED`或`ALREADY_COMPLETED`及非秘密identity metadata。

## 2. Inbox record與protection

`FirstApplicationInboxEntryV2`固定兩個states：

- `PENDING`／revision 1：保存session ID、record digest及plaintext；
- `COMPLETED`／revision 2：保留同一identity／plaintext並加入stable receipt。

Canonical JSON使用format `PQ-SAT-FGS-APPLICATION-INBOX-RECORD-v0.2`。整份record在
寫入SQLite前交給`FGSApplicationInboxProtectionV2`，AAD綁定：

```text
"PQ-SAT/FGS-APPLICATION-INBOX-AAD/v0.2"
|| session_id || record_digest || state_u16be || revision_u16be
```

Row metadata、state／revision、protection identity或protected bytes不一致均fail closed。
測試用XOR／HMAC adapter不是production encryption；production plaintext protection仍未
實例化。

## 3. Idempotent application contract

`FGSApplicationInboxDispatcherV2`要求application backend提供：

```text
apply_once(
    idempotency_key = first_application_record_digest,
    plaintext
) -> (APPLIED | EXISTING, plaintext_digest, stable_receipt)
```

Backend必須在實際application mutation的同一authoritative transaction內，以
`idempotency_key`原子去重。相同key／plaintext retry須回傳相同receipt；相同key若對應
不同operation必須拒絕。Dispatcher驗證輸出identity後才將inbox轉成`COMPLETED`。

Repository測試使用單機SQLite ledger代表一個bounded idempotent side effect。它能驗證
composition與crash windows，但不是論文系統的production application。

## 4. Crash與retry語意

- activation commit後、inbox enqueue前crash：尚未完全封閉，依賴UE exact record retry；
- enqueue commit後、dispatch前crash：pending scan可自主恢復；
- application commit後、ack前crash：inbox保持pending，retry的`apply_once`回傳既有receipt；
- inbox completion commit後、ack前crash：restart讀回completed，不再次apply；
- competing dispatchers：可同時讀pending，但application adapter必須以idempotency key只
  執行一次effect。

因此在test-only idempotent backend假設下可重播上述composition；不能把這解讀為任意
外部side effect已具有exactly-once保證。

## 5. 驗證涵蓋

- pending／completed canonical round-trip及frozen SHA-256 vector；
- exact enqueue／complete retry、competing record／plaintext／receipt拒絕；
- thread／process enqueue race及commit後突然process exit；
- pending scan、restart recovery、schema／protection identity／row mutation；
- seal／open failure不釋放plaintext；
- FGS processor只回queue metadata，不回plaintext delivery；
- apply acknowledgement與completion acknowledgement遺失恢復；
- parallel dispatchers只產生一個test-ledger effect；
- missing／wrong-type／mutated／conflicting application backend fail closed；
- legacy delivery-store模式保持相容。

驗證結果（2026-09-15）：

- Application inbox／dispatch定向測試：15 passed、0 skipped／failures／errors；
- activation／first-record／delivery／inbox相鄰回歸：60 passed、
  0 skipped／failures／errors；
- 全部system tests：225 passed、0 skipped／failures／errors；
- repository-wide：902 total，其中890 passed、12個既有optional-artifact skips、
  0 failures／errors。

## 6. Claim boundary

可以宣稱：protected single-host inbox、pending restart recovery、stable receipt state及
idempotent application adapter contract已Defined／Implemented／Tested；在test-only
SQLite application ledger下，apply／completion acknowledgement遺失不造成重複effect。

不可宣稱：

- production external application已提供或證明`apply_once`；
- activation與inbox enqueue是同一transaction；
- 任意external side effect exactly once；
- distributed linearizability、rollback／hostile-filesystem或實體斷電安全；
- production plaintext protection／PQ AKE、Production-closed或Proof-closed。

## 7. 實作位置

- Inbox types及FGS enqueue path：`src/pq_sat_auth/v2/application.py`
- Protected SQLite inbox：`src/pq_sat_auth/v2/storage/sqlite_inbox.py`
- Dispatcher／application contract：`src/pq_sat_auth/v2/dispatch.py`
- Tests：`tests/system/test_pq_sat_auth_application_inbox_v2.py`
- Machine claims：`manifests/pq_sat_auth_first_application_v0_2.json`
