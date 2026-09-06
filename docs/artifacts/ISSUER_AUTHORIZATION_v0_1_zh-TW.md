# Issuer authorization v0.1 control-plane prototype

## 結論

本 checkpoint 實作 federation 對 HNCC issuer 的 bounded authorization
control-plane prototype。它直接使用 system initialization checkpoint 的
`SystemConfiguration`、32-byte `ctx`、`KeyRole` 與 authenticated bundle，不建立平行
configuration、context encoding或key-role registry。

Authorization成功只代表某個issuer-side session identifier（`sid`）在指定grant下
通過一次atomic quota consumption。它不呼叫CAP `Prove`／`Verify`、不產生
blind-signing response，也不是issuance proof backend。

## Canonical IssuerGrant

`IssuerGrant`採固定欄位順序與exact-length parser。所有整數皆為little-endian：

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 22 | magic `PQRBBC-ISSUER-GRANT-V1` |
| 22 | 2 | grant schema version，固定為1 |
| 24 | 32 | system `ctx` |
| 56 | 2 | system-profile protocol version |
| 58 | 8 | epoch |
| 66 | 32 | policy digest |
| 98 | 32 | issuer verification key ID |
| 130 | 32 | issuer-authorization key ID |
| 162 | 8 | quota |
| 170 | 8 | not-before |
| 178 | 8 | expiry |
| 186 | 32 | grant identifier／nonce |

Canonical grant固定為218 bytes。Quota必須非零，expiry必須大於not-before，所有key
IDs、policy digest與grant identifier必須為nonzero 32-byte values。Parser拒絕錯誤
magic、未知schema／protocol version、truncation、trailing bytes與任何無法重新編碼成
完全相同bytes的輸入。

Authenticated envelope使用magic `PQRBBC-ISSUER-GRANT-AUTH-V1`、schema version、
signing `KeyRole`、length-prefixed canonical grant及length-prefixed authentication。
未知role與未知version皆fail closed；已知但不是`ISSUER_AUTHORIZATION`的role也拒絕。

## Domain separation與bundle binding

Grant authentication message固定為：

```text
"PQ-RBBC/ISSUER-AUTHORIZATION/V1"
|| u16le(ISSUER_AUTHORIZATION)
|| canonical_issuer_grant
```

Authorization依下列順序執行：

1. 先strict parse並驗證`AuthenticatedSystemInitialization`；
2. 使用caller提供的外部pinned `FEDERATION_CONFIGURATION` key reference作trust
   anchor，禁止bundle自我指定信任根；
3. strict parse authenticated issuer grant；
4. 要求grant的`ctx`、protocol version、policy digest、epoch及issuer key ID與已驗證
   initialization bundle一致；
5. 要求grant的issuer-authorization key ID等於bundle中
   `ISSUER_AUTHORIZATION` role的key ID；
6. 接受時間窗固定為`not_before <= now < expiry`；
7. 只把bundle中`ISSUER_AUTHORIZATION` key reference交給外部authentication
   backend驗證；
8. authentication成功後才呼叫issuer-side atomic quota store。

Initialization authentication、grant authentication或quota backend只要回傳無效結果
或拋出例外，一律fail closed。Authentication backend保持抽象；fixed digest verifier
只存在測試檔案中，不是cryptographic signature implementation。

## Quota與replay semantics

Grant digest定義為：

```text
grant_digest = SHA-256(canonical_issuer_grant)
```

每次consumption identity為tuple：

```text
(grant_digest, issuer_side_sid)
```

同一grant可用不同`sids`反覆授權，直到quota由N依序遞減至0；第一次成功使用不會使
整份grant失效。同一tuple再次出現時回報replay、拒絕authorization，且不得再次扣除
quota。同一`sid`搭配不同grant digest屬於不同consumption identity。

`IssuerQuotaStore.consume()`的contract要求replay check、quota check、SID記錄與quota
decrement必須是一個atomic operation。`SingleProcessMemoryQuotaStore`以process-local
lock提供reference behavior，只供unit tests與單程序prototype；它不持久化，也不能
協調多程序或多機器。Production implementation需要transactional shared store，並
保存相同atomic semantics。

## Frozen test vector

Test-only vector保存在
`manifests/pq_rbbc_issuer_authorization_v0_1.json`：

- canonical grant：218 bytes；
- grant SHA-256：
  `65f1f98aa846cd983d61f081303a5020e20855e217fb15ba34f89177d2257ee1`；
- deterministic authenticated envelope：289 bytes；
- envelope SHA-256：
  `d069b1fb8bccbf13b59acfed7ea637748ac3de852fb4c25a22af21b37b75ef77`。

Manifest內的authentication只衍生自測試程式的deterministic backend；它不是FAC
signature、threshold transcript、key ceremony evidence或production credential。

定向測試命令：

```bash
PYTHONPATH=src python -m unittest \
  tests.system_modules.governance.test_issuer_authorization -v
```

測試涵蓋canonical round trip、exact frozen vector、honest acceptance、所有bundle
binding mutations、wrong／unknown role、unknown version、time window、signature
mutation、malformed／truncated／reordered／trailing encodings、quota遞減與耗盡、same
SID replay、different SID、backend exception、wrong initialization trust anchor及
single-process concurrent atomic consumption。

## Claim boundary

目前只可宣稱：

- issuer grant與authenticated-envelope canonical codecs已實作；
- authenticated system initialization與外部pinned federation trust anchor為必要條件；
- `ISSUER_AUTHORIZATION` role separation與bundle binding已強制；
- abstract authentication backend與atomic quota-store protocol已定義；
- 單程序memory reference store符合本checkpoint的quota／replay tests。

不得宣稱：

- FAC threshold signature已選定、實作或部署；
- FAC DKG或production key ceremony已完成；
- production issuer authorization或distributed quota service已完成；
- CAP proof、Blind-UOV backend或blind-signing response由本模組提供；
- 本checkpoint擴張任何既有CAP／RBBC security claim。
