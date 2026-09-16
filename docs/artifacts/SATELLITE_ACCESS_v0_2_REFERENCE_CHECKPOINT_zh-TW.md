# Satellite Access v0.2 bounded reference checkpoint

> 日期：2026-09-14
> Formal-spec parent：`1f872d10e5e776d947c05f25fd40c252b261e85c`
> 狀態：Implemented／Tested（bounded reference only）
> Production／proof closure：false

## 1. 這個 checkpoint 做了什麼

本 checkpoint 將 `SATELLITE_ACCESS_v0_2_zh-TW.md` 與
`ONE_TIME_TICKET_STATE_v0_2_zh-TW.md` 的byte、relation及process-local state邊界降成
可執行Python reference，同時保留V1四訊息implementation不變。

| 邊界 | 實作 | 證據 |
| --- | --- | --- |
| V2 framing | `src/pq_sat_auth/v2/framing.py` | magic／version／type／length／opaque negative tests |
| M1／M2／activation | `src/pq_sat_auth/v2/access.py` | round-trip、frozen digest、truncation、binding mutations |
| `R_access` | `src/pq_sat_auth/v2/proof.py` | honest witness、wrong secret／hash／tag／request core rejection |
| crypto abstraction | `src/pq_sat_auth/v2/backends.py` | test-only suite cannot cross production gate |
| one-time state | `src/pq_sat_auth/v2/replay.py` | retry、race、unique grant、activation、expiry、termination |

## 2. Frozen reference vectors

測試fixture使用`0xffff` test-only access／proof suites。它們不是production尺寸或
cryptographic parameters。

```text
request_core bytes = 342
AccessRequestV2 bytes = 416
response_core bytes = 306
AccessAcceptV2 bytes = 382
SessionActivateV2 bytes = 175

request_core_digest = 90763fd09a9227e18e06cdc0d2b07bc2ae77797cdceb3b2436edab99e92d7751
request_digest      = 41f01cc4ea603b802c822465a6aec05d9251a4294ece3a36b2ae2cde9bbbfd3c
attempt_id          = 40049590cdabb711018d6ed52ada7933c5bd10370e4e808507df03368da7c89d
transcript_digest   = fe054f0a65ad44982f7b08536f230cc260a4278f58f24ad17ea5cf9b91ba20bf
response_digest     = 1c60d11f95767f6039b21b82672714c27c066c879c78ec51fd24d39da874009d
activation_digest   = f6428b81183fe909ce5aa9416e4004e0471cfa69f18c7a1e8f6be05b8ad67c5b
```

## 3. Validation

```text
V2 targeted: 39 passed, 0 skipped, 0 failures/errors
Full suite: 715 passed, 12 existing optional skips, 0 failures/errors
Full runtime: 744.079 seconds
```

完整命令、環境與coverage見`experiments.md`的`EXP-20260914-01`。

## 4. 明確未完成

- 完整FGS parse-to-accept processing pipeline及stable `VerifyTicket` integration；
- 真實access NIZK proof backend／circuit與composition proof；
- concrete PQ KEM、FGS authentication、KDF、MAC及system-init key role；
- UE wallet journal與crash recovery；
- durable／distributed authoritative replay store與partition tests；
- cross-language vectors、satellite-path bytes／latency benchmark及independent review。

因此這個checkpoint不能產生正式`pi_access`或production session，也不能支持
authentication-security、Proof-closed或Production-closed宣稱。
