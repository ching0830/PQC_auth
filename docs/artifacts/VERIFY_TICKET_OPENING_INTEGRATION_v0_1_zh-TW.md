# VerifyTicket × Conditional Opening integration v0.1

## 結論

本 checkpoint 將 commit
`28980cfdcac030abc2fbcb0b84288c47dcd72fda` 的真實
`SystemTicketVerifier` 接入既有 `OpenShareService` 與 `OpeningCombiner`，證明
canonical ticket 經 issuer authentication 後產生的 `TicketView` 可以沿用
Conditional Opening v0.1 已固定的 request、share、replay 與 combiner contracts。

本 checkpoint 沒有修改 production source。所有新增程式都位於
`tests/system_modules/integration/`，另新增一份 frozen manifest 與本 artifact。
舊 opening fixtures 的 `FixedTicketVerifier` 沒有用於這條 integration path。

## 已接通的路徑

```text
AuthenticatedSystemInitialization + pinned FEDERATION_CONFIGURATION anchor
    -> OpenShareService parses OpeningRequest
    -> SystemTicketVerifier revalidates initialization
    -> strict CanonicalTicket parser
    -> ctx / protocol / ISSUER_VERIFICATION role / issuer key / expiry checks
    -> abstract issuer backend verifies d_M
    -> TicketView(ticket transport digest, ctx, sn, C, issuer key ID)
    -> opening request ctx / epoch / key IDs / ticket digest checks
    -> abstract OPENING_AUTHORIZATION backend
    -> atomic opening replay begin
    -> test-only share backend
    -> atomic opening replay commit before share release
    -> authenticated share validation
    -> test-only threshold reconstruction and trace authentication
```

Initialization 在這條 prototype path 會被驗證兩次：一次由
`OpenShareService` 保護整個 opening request，另一次由 `SystemTicketVerifier`
保護 ticket-verification boundary。這保留兩個元件各自 fail-closed 的獨立合約；若未來
要避免重複驗證，必須新增可明確表示「已驗證 bundle」的 typed boundary，不得直接
把 untrusted bundle 當作已驗證輸入。

## Cross-module identities

Issuer signature backend 的訊息仍是既有 payload identity：

```text
d_M = SHAKE256("PQ-RBBC/TICKET" || Encode(M), 32)
```

本 frozen vector：

```text
d_M = 41284b146af4f04412e8e39d4a82d2a76a855014951f05223aa1f000ac0364d5
```

Conditional Opening request 與 share 綁定 exact canonical transport：

```text
ticket_digest = SHA-256(canonical_ticket_bytes)
              = 25800ecc6190e8474b8848866b47d11f31d2819c4abcdefecacb14ae41cb7cc6
```

測試確認：

- `OpeningRequest.ticket_digest` 等於成功 `TicketView.ticket_digest`；
- `OpenShare.ticket_digest` 等於同一 transport digest；
- ticket payload `ctx` 等於 authenticated bundle `ctx`；
- ticket issuer key ID 等於 bundle 的 `ISSUER_VERIFICATION` key ID；
- 五個不同 OA members 的 share 可通過既有 5-of-7 combiner control flow；
- reconstructed serial 必須等於 ticket clear serial。

`d_M` 與 transport digest 用途不同。未來 one-time access state 仍應依
`ONE_TIME_TICKET_STATE_v0_1` 使用 payload digest、serial 與 ctx；opening authorization
則維持對 exact ticket transport bytes 的 case-specific binding。

## Fail-closed integration tests

測試不只驗證 happy path，也確認下列輸入在 opening authorization、replay reservation
及 share backend 之前拒絕：

- mutated issuer signature；
- 使用正確 issuer test key 重新 authentication、但 payload `ctx` 錯誤的 ticket；
- known but wrong ticket key role；
- `SystemTicketVerifier` 使用錯誤的 pinned federation trust anchor；
- issuer authentication backend exception；
- system configuration expiry。

另有一項明確的 boundary test：同一有效 ticket 搭配兩份各自合法、case ID 與 request
nonce 不同的 opening authorizations，兩者都可通過。這證明 `VerifyTicket` 仍是
stateless，也證明 opening request replay control 不等於 access ticket one-use
consumption。

## Frozen evidence

Manifest：
`manifests/pq_rbbc_verify_ticket_opening_integration_v0_1.json`

主要 lengths／identities：

- canonical ticket：462 bytes；
- opening request：832 bytes；
- test-only OpenShare：303 bytes；
- opening request digest：
  `7bc8965e40ae23621d70b0cf0758e27fd5d0dcba713d34d404731e70149143c6`；
- OpenShare SHA-256：
  `a928c243015db656f8377b71b3db28c4a5a856e3714eb4e0b89a37af0d2bcf9f`。

定向測試：

```bash
PYTHONPATH=src python -m unittest \
  tests.system_modules.integration.test_verify_ticket_opening -v
```

## Claim boundary

目前只可宣稱：

- 真實 canonical ticket parser／`SystemTicketVerifier` 已接入 Conditional Opening
  control flow；
- `TicketView`、opening request digest、OpenShare digest 與 combiner bindings 可相容；
- initialization、ticket、authorization、replay 與 share backend 的 fail-closed order
  已由 deterministic integration tests 覆蓋；
- integration path 不再依賴 `FixedTicketVerifier`。

不得宣稱：

- test-only deterministic issuer／opening authorization／share backends 是 cryptographic
  signatures；
- Blind-UOV production signature backend、CAP Prove／Verify 或 issuance proof backend
  已完成；
- OA DKG、threshold Niederreiter decoding、robust reconstruction 或 production opening
  已完成；
- holder authentication、PQ AKE、ticket consumption、distributed replay store、revocation
  或 strictly one-use access 已完成；
- production `VerifyTicket`、production Conditional Opening 或完整 PQ-RBBC system 已完成。

舊的 Conditional Opening manifest 是歷史 checkpoint，本次不改寫其當時的
`full_verify_ticket_implemented=false` 或 trace-KDF blocker。新的 integration manifest
記錄目前可驗證的 cross-module evidence，而不回溯修改歷史 artifact。
