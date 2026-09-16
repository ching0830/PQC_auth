# Satellite Access v0.2 FGS grant processor checkpoint

## 結論

本checkpoint將`ValidatedAccessRequestV2`接到process-local one-time state model，完成：

```text
handoff recheck
-> Reserve
-> KEM.Encaps + session_id
-> response_core + transcript_digest
-> KDF + FGS.Auth + server Finished
-> pre-commit revocation recheck
-> response/session-state protection
-> CommitGrant
-> return exact AccessAcceptV2
```

實作刻意只在`CommitGrant`成功後回傳M2 bytes；任何reservation後的KEM、authentication、
KDF、clock、revocation、sealing或commit failure皆不回傳response，也不自動abort
reservation。此類record必須交給具fencing及publication evidence的recovery流程處理。

實作位置：

- `src/pq_sat_auth/v2/grant.py`；
- `src/pq_sat_auth/v2/replay.py`；
- `tests/system/test_pq_sat_auth_grant_v2.py`；
- `manifests/pq_sat_auth_fgs_grant_v0_2.json`。

## 1. Authenticated timing inputs

Pure-check configuration snapshot新增下列deployment policy：

```text
pure_check_max_age_seconds
reservation_lease_seconds
activation_window_seconds
session_lifetime_seconds
replay_retention_grace_seconds
```

這些欄位不是M1的自我宣告；必須由authenticated access configuration provider提供。
Stable `VerifyTicket` adapter亦輸出authenticated System Initialization中的
`expiry_bucket`作為`ticket.expires_at`。Grant processor在state mutation前重新驗證
handoff age、configuration validity與ticket expiry。

新session與activation期限為：

```text
session_expiry = min(
    build_now + session_lifetime,
    configuration.valid_until,
    ticket.expires_at
)

activation_deadline = min(
    build_now + activation_window,
    session_expiry
)

retention_deadline =
    max(ticket.expires_at, session_expiry)
    + maximum_clock_skew
    + replay_retention_grace
```

所有加法均檢查uint64 overflow；在commit前已無有效lease、ticket、configuration或
activation interval時fail closed。

## 2. Handoff與reservation

Processor不只依賴Python type。它在`Reserve`前重新核對：

- exact request bytes、request-core／full digests及attempt ID；
- authenticated configuration對`ctx`、epoch、FGS／key、serving／authorization、
  channel policy及suite allow-list的bindings；
- stable-ticket `ctx`、issuer key、base initialization digest、`d_M`與one-time identity；
- verifier-owned`x_access`；
- configuration、acceptance domain、FGS／issuer key、ticket、serial與holder-bound
  revocation query。

這些檢查不重新執行NIZK或ticket signature；它們保護pure-check到stateful grant階段的
typed handoff。只有`ReserveDispositionV2.NEW`的worker可以進行KEM encapsulation。
`EXISTING_RESERVATION`只回內部pending狀態；`EXISTING_GRANT`從recovery backend取回原始
response，不重新產生KEM、session ID、FGS authenticator或Finished。

Recovered response仍須通過strict decode／exact re-encode、request binding、response
digest、transcript digest、session ID及deadline核對。Expired grant不重新發布M2，也
不會把ticket變回unused。

## 3. M2與session state

`AccessAcceptV2`依正式spec建立。KDF context使用固定寬度、domain-separated encoding，
綁定protocol／suite、兩層configuration identity、access profile／parameters、acceptance
domain、`ctx`／epoch、FGS／key、serving／authorization／channel、request／attempt及
session identity。

```text
FGS authenticator input = "PQ-SAT/FGS-AUTH/v2" || transcript_digest

server Finished input =
    transcript_digest || SHAKE256(fgs_authenticator, 32)
```

Pending state只把activation仍需要的`K_client_finished`、application key及exporter key
交給`GrantRecoveryBackendV2`。Exact response recovery與secret session state使用分開的
backend methods。Reference processor只能檢查backend回傳non-empty bytes，不能由介面
本身證明confidentiality、integrity、nonce uniqueness、rollback protection、key erasure
或HSM isolation。

`SessionIdentifierSourceV2`在production必須由合格CSPRNG／collision-resistant allocator
支援；processor只能檢查32-byte且非全零，不能由單一output證明entropy或全域唯一性。
`FGSAuthenticationKeyHandleV2`綁定configured key ID，但private handle確實對應該public
key的保證仍由authentication backend／HSM負責。

Python reference也沒有securely erase KEM shared secret或暫存key material，不能據此
宣稱production secret-lifecycle closure。

## 4. Revocation ordering

完成M2 cryptographic construction後，processor對pure-check固定的exact query再取得一次
authenticated revocation snapshot。Snapshot必須：

- echo exact query digest；
- generation不低於pure-check及configuration floors；
- 在commit time仍有效；
- 六種revoked flags全部為false。

Reference replay store允許`CommitGrant`把reservation的generation單調提升至較新的
non-revoked generation，但禁止rollback。

這仍不是production所需的serializable revocation／consumption transaction：外部
revocation snapshot驗證與process-local`commit_grant()`之間存在TOCTOU window。Production
backend必須在同一authoritative ordering中重查revocation並commit grant；manifest因此
維持`atomic_revocation_and_commit_implemented = false`。

## 5. Failure與publication boundary

| 時點 | 結果 | State／response |
| --- | --- | --- |
| handoff／time無效 | reject | 無state mutation、無M2 |
| competing attempt | reject | winner state不變 |
| same attempt仍在建構 | pending | `RESERVED`、不啟動第二個KEM |
| KEM／auth／KDF／sealing／revocation失敗 | recovery required | 保留`RESERVED`、無M2 |
| commit失敗或回傳identity錯配 | recovery required | 不回傳M2；backend狀態須reconcile |
| commit成功 | new grant | `CONSUMED_PENDING_CONFIRM`後才回傳M2 |
| committed exact retry | existing grant | recovery、驗證並回傳byte-identical M2 |

Internal disposition／failure不得直接成為wire oracle；外層service必須映射成generic rejection
或適當的same-attempt retry行為。

## 6. Test與claim boundary

定向測試涵蓋：

- new grant的response／transcript／record binding與deadline；
- exact retry不重做KEM／FGS auth／KDF／session ID；
- 16個same-M1 concurrent workers至多一個KEM／new grant；
- malformed typed handoff、stale pure-check及configuration／revocation-query mutation；
- existing reservation、expired grant與recovered-response tamper；
- KEM、authentication、KDF、session-ID、sealing與commit failure；
- pre-commit revoked、stale generation、wrong query及expired snapshot；
- revocation generation只能單調前進；
- machine manifest與implementation一致。

2026-09-15驗證結果：

```text
Targeted Access/VerifyTicket: 87 passed, 0 failed/errors
All tests/system:             96 passed, 0 failed/errors
Repository-wide:             775 total; 763 passed,
                             12 existing optional-artifact skips,
                             0 failed/errors
```

完整命令為`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover
-s tests -v`，耗時749.131秒。這組執行沒有安裝production crypto backend、讀取optional
large assignments或啟動production proving。

所有crypto、key、clock、recovery與store adapters均為test-only。此checkpoint支持grant
control flow及process-local state semantics為Implemented／Tested；不支持下列宣稱：

- concrete ML-KEM／ML-DSA／KDF／Finished suite已Instantiated；
- response／session state已由production AEAD／HSM保護；
- revocation與commit已形成distributed serializable transaction；
- store crash-durable、multi-process或cross-FGS linearizable；
- `SessionActivateV2`／first protected packet processor已完成；
- PQ AKE或access NIZK security proof已封閉；
- Production-closed。

下一個bounded checkpoint是activation processor：recover pending session state、strictly
validate `SessionActivateV2`、verify client Finished、重新檢查session／FGS-key revocation，
atomic activate後才釋放application side-effect capability。
