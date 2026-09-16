# VerifyTicket contract v0.1

## 結論

本 checkpoint 實作 PQ-RBBC System Profile v0.1 的 stateless
`VerifyTicket` control-flow contract、canonical ticket transport、strict parser
及與 Conditional Opening `TicketVerifier`／`TicketView` 的接合。

它直接使用既有的 `pq_rbbc_reference.TicketPayload`、
`SystemInitializationBundle`、`ctx` 與 `KeyRole`，沒有建立另一套
SystemConfiguration、context derivation、payload encoding 或 key-role registry。

本 checkpoint 的 issuer-authentication backend 維持抽象。測試中的 32-byte
deterministic checksum 只用來固定 control flow 與 byte vectors，不是 Blind-UOV
signature，也不代表 production `VerifyTicket` 已完成。

## Canonical ticket transport

核心票券仍是架構定義的 `T = (M, sigma)`：

```text
M = ctx || sn || h || C
C = syndrome || masked_identity || trace_tag
```

`M` 精確沿用 `TicketPayload.encode()` 的 368-byte fixed-width encoding。新增的
transport envelope 只提供 strict framing 與明確 key routing：

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 16 | magic `PQRBBC-TICKET-V1` |
| 16 | 2 | schema version `u16le`，固定為 1 |
| 18 | 2 | system-profile protocol version `u16le` |
| 20 | 2 | signing `KeyRole` `u16le` |
| 22 | 32 | issuer verification key ID |
| 54 | 4 | payload length `u32le`，固定為 368 |
| 58 | 368 | canonical `TicketPayload` |
| 426 | 4 | signature length `u32le` |
| 430 | variable | opaque issuer signature |

Signature 必須非空且不得超過 65,536 bytes。這只是 system boundary 的 bounded
opaque field；實際 suite 必須由 future production backend 再強制 exact signature
encoding。Parser 拒絕錯誤 magic、unknown schema／protocol version、unknown role、
錯誤 payload length、零長或超限 signature、truncation、field reordering、trailing
bytes 與無法 exact round-trip 的 encoding。

### Frozen payload offsets

368-byte `M` 的 half-open offsets 是：

| Offset | Bytes | Field |
| --- | ---: | --- |
| `M[0:32]` | 32 | system `ctx` |
| `M[32:48]` | 16 | visible serial `sn` |
| `M[48:80]` | 32 | holder hash `h` |
| `M[80:288]` | 208 | Niederreiter syndrome |
| `M[288:336]` | 48 | masked identity／serial |
| `M[336:368]` | 32 | trace tag |

因此交給 opening backend 的 trace ciphertext 固定為
`M[80:288] || M[288:336] || M[336:368]`，共 288 bytes。本 checkpoint 只擷取
opaque ciphertext；不執行 threshold decoding 或 trace authentication。

## Ticket identities 與 issuer authentication

Issuer backend 驗證的 message digest 精確沿用既有 RBBC core：

```text
d_M = SHAKE256("PQ-RBBC/TICKET" || Encode(M), 32)
```

沒有新增會與 Blind-UOV message 不相容的簽章 domain。Transport 中 role 與 key ID
是 redundant routing metadata；verifier 只接受 `ISSUER_VERIFICATION` role，且 key ID
必須等於 authenticated initialization bundle 中該 role 的 key ID。實際呼叫 backend
時也只傳入這個 bundle key reference、`d_M` 與 opaque signature。

Conditional Opening v0.1 已使用另一個 representation identity：

```text
canonical_ticket_digest = SHA-256(canonical transport bytes)
```

成功結果的 `TicketView.ticket_digest` 延用此 identity，以保持既有 opening request／
share binding 相容；`TicketVerification.payload_digest` 則明確回傳 `d_M`。兩者用途
不同，不得互換。未來 M6 one-use access state 應依其規格使用 payload identity、serial
與 context，不應把 signature re-encoding 當成新票券。

## Fail-closed 驗證順序

`verify_ticket()` 依下列順序執行：

1. strict parse 並驗證 `AuthenticatedSystemInitialization`；
2. 使用 caller 提供的 out-of-band pinned `FEDERATION_CONFIGURATION` key reference，
   禁止 bundle 自我指定 trust anchor；
3. strict parse canonical ticket；
4. 要求 protocol version、`ISSUER_VERIFICATION` role、issuer key ID 與 payload `ctx`
   全部符合已驗證 bundle；
5. 從可信時間 backend 取得 `now`，接受窗為
   `now < configuration.expiry_bucket`；
6. 只用 bundle 中 `ISSUER_VERIFICATION` key 驗證 `d_M` 與 signature；
7. 建立並驗證 `TicketView`。

Initialization、clock 或 issuer-authentication backend 拋出例外、回傳非明確 `True`
或產生無效資料時全部 fail closed。Initialization authentication 失敗時不解析 ticket，
也不觸碰 ticket backend。

`SystemTicketVerifier` 把同一流程封裝成 Conditional Opening 所需的
`verify(canonical_ticket) -> TicketView | None`。此 adapter 是 stateless；同一張有效
ticket 可被純驗證多次，且不在這一步消耗 quota 或 one-use state。

## Frozen test vector

Manifest 位於 `manifests/pq_rbbc_verify_ticket_contract_v0_1.json`：

- canonical payload：368 bytes；
- `d_M`：
  `41284b146af4f04412e8e39d4a82d2a76a855014951f05223aa1f000ac0364d5`；
- test-only signature：32 bytes；
- canonical transport：462 bytes；
- canonical transport SHA-256：
  `25800ecc6190e8474b8848866b47d11f31d2819c4abcdefecacb14ae41cb7cc6`。

定向測試命令：

```bash
PYTHONPATH=src python -m unittest \
  tests.system_modules.tickets.test_verification -v
```

測試涵蓋 canonical round trip、與既有 `TicketPayload`／`H_ticket` 的 exact
identity、frozen vector、honest acceptance、initialization-first ordering、ctx／policy／
epoch／issuer key mutations、wrong／unknown role、unknown versions、expiry、signature／
payload mutation、truncation、reordering、trailing bytes、wrong pinned trust anchor、
clock／authentication backend exceptions、non-boolean backend success、stateless repeated
verification，以及 Conditional Opening `TicketView` 相容性。

## Claim boundary

目前只可宣稱：

- canonical ticket transport 與既有 368-byte payload 的 strict inverse parser 已實作；
- authenticated initialization、pinned federation trust anchor、bundle `ctx` 與
  `ISSUER_VERIFICATION` role separation 已強制；
- `d_M` 計算與現有 PQ-RBBC reference relation 一致；
- stateless verification control flow、abstract authentication／clock boundaries 及
  Conditional Opening adapter 已實作並有 deterministic tests。

不得宣稱：

- Blind-UOV `Respond`／`Finalize`／signature parser 或 production verification backend
  已實作、選定或通過安全 qualification；
- CAP `Prove`／`Verify`、issuance proof backend或 `c_x` production closure由本模組提供；
- FAC threshold signature、DKG、issuer key ceremony或 production system initialization
  已完成；
- holder authenticator、PQ AKE、ticket consumption、distributed replay store、revocation
  或 strictly one-use access 已完成；
- production `VerifyTicket` 或完整 PQ-RBBC system 已完成。

舊的 Conditional Opening artifact／manifest 是歷史 checkpoint，本次不回寫其當時的
blocker flags。Trace KDF `Z = P[48] || K_mac[32]` 的修正由 v2.40 checkpoint 記錄；
本 checkpoint 只在其已同步基準上建立新的 ticket-verification contract。
