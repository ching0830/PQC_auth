# Conditional opening gate v0.1 checkpoint

## 結論

本 checkpoint 實作 signature-gated conditional opening 的 canonical request、
固定驗證順序、replay reservation、`OpenShareService.open_share(...)` 邊界、
authenticated `OpenShare` codec 與 threshold-combiner control flow。

它不是 production opening 實作。`TicketVerifier`、opening-authorization
signature、OA member share/proof、threshold reconstruction、trace authentication
均是抽象 backend；測試 adapter 只回傳 deterministic fixture，不能解讀為
threshold cryptography。

## 既有 system-initialization checkpoint

本模組直接使用既有：

- `SystemConfiguration` 與其 `ctx`；
- `SystemInitializationBundle`；
- `KeyRole.OPENING_AUTHORIZATION`；
- `KeyRole.OPENING_ENCRYPTION`；
- bundle 的 `opening_policy.threshold` 與 `member_count`。

沒有另建 configuration、context、key role 或 threshold encoding，也沒有修改
`src/pq_rbbc/contracts/system.py`。

## Canonical `OpeningRequest`

wire format 為：

```text
magic || schema_version:u16le || field_count:u16le || fields
field := tag:u8 || length:u32le || value
```

field tag 必須依下列順序各出現一次：

1. protocol version
2. canonical ticket bytes
3. `ctx`
4. epoch
5. OA opening／`OPENING_ENCRYPTION` key ID
6. `OPENING_AUTHORIZATION` key ID
7. case ID
8. evidence digest
9. purpose（strict UTF-8、Unicode NFC、無 control character）
10. expiry
11. request nonce
12. opening authorization

decoder 有整體與逐欄長度上限，拒絕 unknown schema/protocol version、wrong
order、duplicate/unknown tag、truncated、oversized、wrong fixed width、invalid
UTF-8、non-NFC 與 trailing bytes。decode 後會重新 encode 並要求 byte-for-byte
相同。

`ticket_digest = SHA-256(canonical_ticket_bytes)`。authorization statement
以獨立 domain 與 canonical tagged encoding 綁定 protocol version、ticket digest、
`ctx`、epoch、兩個 key ID、case ID、evidence digest、purpose、expiry 與 nonce；
authorization bytes 本身不進入 statement，以避免循環定義。

`request_digest` 綁定完整 canonical request（含 authorization）。replay key 則
由 authorization key ID、case ID 與 nonce 經 domain-separated SHA-256 產生，
因此同一授權不能只靠重新編碼或 signature malleability 規避 replay。

## 固定 validation order

`OpenShareService.open_share(opening_request)` 接受 bytes，並依程式控制流固定
執行：

1. parse 完整 canonical request；
2. 驗證 authenticated initialization 與 out-of-band pinned
   `FEDERATION_CONFIGURATION` trust anchor；
3. 呼叫抽象 `TicketVerifier`，成功後才接受 trusted `TicketView`：ticket
   digest、`ctx`、visible serial、trace ciphertext、issuer key ID；
4. 比對 request/ticket `ctx`、epoch、opening key ID、authorization key ID 與
   issuer key ID；
5. 比對 ticket digest、檢查 expiry，並只用初始化 bundle 中的
   `KeyRole.OPENING_AUTHORIZATION` 驗證完整 case authorization statement；
6. atomic replay `begin`；
7. 前述全部成功後才呼叫私有持有的 threshold share backend；
8. replay `commit` 成功後才回傳 `OpenShare`。

任何 authentication、clock、replay 或 threshold backend exception 都回傳
reject，不會把 exception 當成接受。invalid ticket 或 authorization 路徑不會
呼叫 threshold backend。

## Replay state 與 crash boundary

`OpeningReplayStore` 定義等價於三態狀態機：

```text
fresh --atomic begin--> in_progress --atomic commit--> committed
                              |
                              +--exact-token abort--> fresh
```

- 對同一 replay key 的並行 `begin`，至多一個取得 reservation；其餘將
  `in_progress` 與 `committed` 都視為 replay。
- threshold backend 尚未產生可回傳 share 而失敗時，service 使用 exact token
  `abort`；abort failure 仍 fail closed。
- commit exception 是 indeterminate outcome，service 不做 abort，也不回傳
  share。store 必須讓 possibly-committed key 保持 committed 或 in-progress，
  不得自動變回 fresh。
- crash after begin 會留下 in-progress 並 fail closed，直到 backend-specific、
  audited recovery policy 處理；不可僅憑 timeout 自動重開。
- service 先 commit 再 release share。因此 crash after commit/before response
  可能造成 availability loss，但不會產生未記錄的回傳 share。

## `OpenShare` 與 combiner

每份 strict-canonical `OpenShare` 綁定：OA member ID、opening key ID、epoch、
request digest、ticket digest、case ID、opaque share value，以及 share
authentication/proof placeholder。package `__init__.py` 不匯出任何
`partial_decrypt` 或 arbitrary-ciphertext API；OA member 唯一 operation 是
`OpenShareService.open_share(opening_request)`。

combiner 在 reconstruction 前拒絕：

- 少於初始化 bundle threshold 或超過 member count；
- duplicate member；
- mixed request、ticket、epoch、opening key 或 case；
- 與 authenticated bundle 不同的 opening key 或 stale epoch；
- 與 trusted ticket view 不同的 ticket digest；
- 任一 share authentication/proof invalid 或 verifier exception。

全部通過後才呼叫抽象 threshold reconstruction backend。成功 reconstruction
後仍必須通過抽象 trace authentication verifier，且 decoded serial 必須等於
ticket visible serial；任一不符均輸出 reject，不回傳 decoded identity。

## Integration blocker：80-byte KDF split

目前核心 TeX 的 trace profile 把 80-byte `Z` 切成：

```text
(K_mac, P) = Z       # 32 bytes, then 48 bytes
```

但 `src/pq_rbbc_reference.py` 的 `_derive_trace` 使用：

```text
pad, mac_key = key_stream[:48], key_stream[48:]
```

亦即先 48-byte `P`、再 32-byte `K_mac`。本 checkpoint 不選邊、不凍結任何
一種順序，也不解析真正 trace ciphertext；syndrome decoding、80-byte KDF
切分、plaintext extraction 與 authentication material 都留在 reconstruction／
trace-authentication backend boundary。這是接上 production decoder 前必須先
由規格與 reference implementation 共同解決的 integration blocker。

## Deterministic test vector

`tests/system_modules/opening/_fixtures.py` 明確標為 test-only，使用 SHA-256
checksum adapter 與 fixture plaintext。manifest 凍結 exact canonical byte
length、SHA-256、request digest、ticket digest、authorization-statement digest
及 member ID；測試會重新產生並逐欄比對：

- request：441 bytes；
- request digest：
  `df66fe26ed8220de539c090ed47480eb45ac12b539fd40035adba52285121c28`；
- share：303 bytes；
- frozen identity：
  `manifests/pq_rbbc_conditional_opening_gate_v0_1.json`。

這些資料只證明 codec 與 control flow 的 deterministic regression identity，
不是 cryptographic known-answer test 或 security claim。

## Claim boundary

已完成：

- canonical request/share codecs；
- authenticated-initialization pinned-anchor gate；
- signature-gated validation order；
- atomic replay interface 與 fail-closed crash semantics；
- share consistency/proof gate、combiner control flow、trace-auth/serial checks。

未完成、不得據此宣稱：

- 完整 `VerifyTicket`；
- OA DKG；
- robust threshold Niederreiter decoder；
- production opening；
- production opening-authorization signature 或 share proof system。

## 驗證命令

```bash
PYTHONPATH=src python -m unittest discover \
  -s tests/system_modules/opening -v

PYTHONPATH=src python -m unittest discover -s tests -v
```
