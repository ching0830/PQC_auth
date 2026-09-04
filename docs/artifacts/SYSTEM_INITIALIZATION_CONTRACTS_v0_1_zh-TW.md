# System initialization／contracts v0.1 checkpoint

## 結論

本 checkpoint 建立新的 package-organized system implementation boundary：

```text
src/pq_rbbc/contracts/
src/pq_rbbc/governance/
```

它凍結 system profile v0.1 的 candidate canonical configuration、32-byte
`ctx` 推導、public key references、FAC／OA threshold policies、public
initialization bundle及authenticated publication envelope。Issuer
authorization與conditional opening可在後續獨立 package 中引用相同 ABI。

本 checkpoint 不搬動既有 `src/pq_rbbc_*.py`，以免改變 active CAP 工作、歷史
commands或artifact identities。

## Canonical configuration

共同資訊固定為：

```text
protocol_version : u16le
epoch            : u64le
domain           : 32 bytes
policy_digest    : 32 bytes
expiry_bucket    : u64le
oa_key_id        : 32 bytes
issuer_key_id    : 32 bytes
```

`domain`與`policy_digest`必須是 federation-wide fixed values，不得加入 per-holder
metadata。Context derivation為：

```text
ctx = SHAKE256("PQ-RBBC/CTX" || canonical_configuration, 32 bytes)
```

Parser要求正確magic、schema version、system-profile protocol version 1、exact
length、nonzero identifiers及無trailing bytes；未知protocol version必須先由新
checkpoint定義，不得由v0.1 parser默認接受。

## Key separation與threshold contracts

Public initialization bundle要求下列五種角色各出現一次且順序固定：

1. `FEDERATION_CONFIGURATION`；
2. `ISSUER_AUTHORIZATION`；
3. `OPENING_AUTHORIZATION`；
4. `ISSUER_VERIFICATION`；
5. `OPENING_ENCRYPTION`。

所有key IDs與public-key digests必須跨角色互異；configuration中的issuer／OA key
IDs必須與相應public references相等。FAC與OA的`member_count`及`threshold`分開
編碼，且必須滿足`1 <= threshold <= member_count`。

Bundle只保存public key identity與digest，不包含issuer secret key、FAC／OA secret
shares、DKG secret、proof-system trapdoor或任何holder資料。

## Authenticated publication

Initialization authentication綁定：

```text
"PQ-RBBC/SYSTEM-INIT-AUTH/V1" || exact_bundle_bytes
```

真正的PQ authentication由外部backend提供。Verifier backend回傳false或發生例外時
一律fail closed。這個介面讓後續FAC primitive選定後可以替換backend，而不改變
configuration與bundle bytes。

Federation configuration key reference必須由caller以out-of-band trust anchor傳入，
並與bundle宣告的key ID及public-key digest精確相等。Verifier不得把未信任bundle
自行攜帶的configuration key當成信任根，否則攻擊者可以產生自己的key並自簽惡意
configuration。

## Test與claim boundary

定向測試命令：

```bash
PYTHONPATH=src python -m unittest \
  tests.system_modules.governance.test_system_init -v
```

測試涵蓋canonical round trip、deterministic `ctx`、role ordering、cross-role key
reuse、configuration/key mismatch、invalid threshold、`ctx` mutation、authentication
mutation、truncation、trailing bytes及backend exception。

Test-only fixed vector保存在
`manifests/pq_rbbc_system_initialization_contracts_v0_1.json`，凍結609-byte public
bundle與其SHA-256
`5103e95793f747be2a4ffb325ebe47d6411dcbfe274e8294254f0a38b9be17e5`。其中的
deterministic digest authentication只存在測試程式，不是簽章或production key
ceremony evidence。

目前只可宣稱：

- canonical configuration／bundle／authenticated-envelope codecs已實作；
- public role separation與threshold shape已驗證；
- authentication backend boundary為fail closed。

不得宣稱：

- FAC PQ threshold signature已選定或實作；
- FAC或OA DKG已實作；
- threshold decoder已實作；
- production system已完成初始化；
- 本 checkpoint 擴張任何既有 RBBC／CAP security claim。
