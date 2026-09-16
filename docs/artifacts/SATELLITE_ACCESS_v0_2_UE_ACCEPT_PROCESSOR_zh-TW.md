# Satellite Access v0.2 UE AccessAccept processor checkpoint

## 結論

本checkpoint完成UE收到M2後的bounded reference processing：

```text
strict AccessAcceptV2
-> recover protected exact M1 attempt
-> authenticated current configuration + response binding
-> trusted acceptance time + policy deadlines
-> query-bound current FGS verification key
-> FGS authentication
-> KEM decapsulation + shared canonical KDF context
-> server Finished
-> client Finished + SessionActivateV2
-> release UE-local application/exporter keys
```

實作位置：

- `src/pq_sat_auth/v2/ue.py`；
- `src/pq_sat_auth/v2/grant.py`的shared KDF context／authenticator digest helpers；
- `src/pq_sat_auth/v2/backends.py`的server Finished verification contract；
- `tests/system/test_pq_sat_auth_ue_v2.py`；
- `manifests/pq_sat_auth_ue_accept_v0_2.json`。

## 1. Protected attempt state

`UEAccessAttemptStateV2`保存：

```text
exact AccessRequestV2 bytes
authenticated AccessConfigurationSnapshotV2
request_digest / attempt_id
ticket_expires_at / created_at
UE ephemeral KEM secret key
```

Processor重新strict parse／exact re-encode M1與其中的canonical ticket，從ticket payload
重建`TicketUseIdentity(ctx,sn,d_M)`，再重算request digest及attempt ID。Current
authenticated configuration provider必須回傳與wallet snapshot完全相同的configuration，
並重新核對suite、epoch、FGS／key、serving／authorization及channel policy。

這只固定typed handoff與檢查順序。Reference state直接持有secret bytes，並沒有實作wallet
encryption、filesystem durability、rollback protection、transactional state transition、
hardware-backed key handle或secure erasure。

## 2. Response、時間與FGS key

M2必須通過strict decode、exact re-encode及原M1的configuration、context、request digest與
attempt binding。UE使用單次trusted-time sample，要求configuration及ticket仍有效、
activation／session尚未過期，且M2期限不超出authenticated configuration／ticket validity。
因M2沒有server creation timestamp，reference另以「UE接收時間＋policy window＋允許clock
skew」限制最大activation及session期限；這是fail-closed upper bound，不是clock
synchronization proof。

FGS verification key以獨立domain-separated query取得：

```text
PQ-SAT/UE-FGS-KEY-QUERY/v2
```

Query固定suite、system configuration、acceptance domain、epoch、FGS及key ID。Provider
snapshot必須echo exact query digest、在UE時間有效、未撤銷且具有verification handle。
Provider的「authenticated」性、key rotation distribution及key-to-handle correctness仍是
deployment boundary。

## 3. Cryptographic processing order

Processor先驗證：

```text
FGS.Verify(
    authenticated verification key,
    "PQ-SAT/FGS-AUTH/v2" || transcript_digest,
    fgs_authenticator
)
```

只有明確`True`才進行KEM decapsulation。由於transcript包含M1 digest與M2 core，ciphertext、
session及期限的改寫會在decapsulation前被FGS authentication拒絕。之後UE與FGS共同呼叫
`encode_key_schedule_context_fields()`，避免兩端維護不同context ordering。

KDF導出的server Finished key驗證FGS對相同KEM secret／transcript的持有；驗證成功後才以
client Finished key及完整response digest建立canonical `SessionActivateV2`。Authentication、
server Finished與所有backend verification均拒絕truthy非boolean回傳。

Reference adapters使用deterministic SHA-256測試函式，不是production KEM、signature、KDF
或MAC。Python暫存shared secret與Finished keys也沒有secure erasure保證。

## 4. Bounded end-to-end結果

Honest測試同時執行：

```text
FGS pure-check
-> FGS grant / committed M2
-> UE verify M2 / generate SessionActivateV2
-> FGS verify client Finished / CONSUMED_ACTIVE
```

UE導出的application／exporter keys與FGS sealed pending state完全相同。Exact M2 retry及12個
parallel processors產生相同session／activation output；processor不寫wallet state，所以
這不等於durable exactly-once UE transition。

## 5. Claim boundary

本checkpoint只支持UE acceptance control flow、canonical binding及test-only backend
wiring為Implemented／Tested。以下全部維持未完成：

- production FGS verification-key distribution／revocation；
- concrete PQ KEM、FGS authentication、KDF及Finished suite qualification；
- durable encrypted wallet、crash recovery、rollback protection與secure erasure；
- first protected application record、AEAD sequence／nonce與side-effect transaction；
- PQ AKE composition proof、cross-language vectors與satellite-path benchmark；
- Production-closed或Proof-closed。

## 6. 驗證紀錄

定向測試涵蓋honest end-to-end activation、exact retry、12-worker deterministic replay、
canonical response／wallet／ticket／configuration binding、FGS-key query與snapshot、trusted
time／policy bounds、suite mismatch、authentication-before-decapsulation、ciphertext／
authenticator／Finished mutation、truthy-nonboolean return、backend exception／wrong type及
no-session-on-failure。

驗證結果：

- Access v0.2定向測試：99 passed，0 failures／errors／skips；
- `tests/system`：128 passed，0 failures／errors／skips；
- repository-wide：805 total，793 passed，12個既有optional skips，0 failures／errors，
  執行時間741.512秒。

完整回歸命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python -m unittest discover -s tests -q
```

Optional external-artifact skips不計為通過，也不改變production claim。
