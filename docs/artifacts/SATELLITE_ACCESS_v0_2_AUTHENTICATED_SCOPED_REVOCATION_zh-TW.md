# Satellite access v0.2 authenticated scoped-revocation checkpoint

日期：2026-09-15

狀態：Implemented／Tested（bounded single-host SQLite reference）；非distributed、
非Production-closed、非Proof-closed

基準parent：`4e6a8b149a217fea497a449bd56d13aaf9a98b42`

## 1. 本checkpoint封閉的工程缺口

前一個authoritative fence checkpoint已讓exact per-query publication與activation在同一
SQLite write order內序列化，但publication caller沒有authentication，且configuration、
FGS authentication key、ticket與session等事件尚不能fan out至所有受影響query。

本checkpoint新增`SQLiteFGSScopedRevocationStoreV2`，把五類狀態放入一個exact schema：

1. replay grants；
2. protected first-application inbox；
3. materialized activation-revocation fences；
4. canonical registered activation queries；
5. append-only authenticated revocation commands。

Direct unauthenticated publication在successor store中停用。Command只有在system
initialization、out-of-band trust anchor、bundle／epoch／policy／key bindings、authorization
time及command authentication全部通過後，才可進入transaction。

## 2. Canonical command與authority邊界

Canonical command固定：

```text
access_protocol_version, ctx, system_bundle_digest, epoch, policy_digest,
signer_key_id, scope, scope_target, generation,
issued_at, authorization_expires_at, command_id, reason_digest
```

Envelope authentication message另加入versioned domain與`signing_role`。Command encoding
固定291 bytes；測試向量的authenticated envelope SHA-256為：

```text
a82a979b7274ba3fb4f24bcf01e673ec60f34a8d19b062ab883c9c5acdbedf91
```

為避免在此checkpoint改動已使用中的system-initialization ABI，reference暫選
`FEDERATION_CONFIGURATION` key作control-plane authority，且要求同一key由caller以
out-of-band trust anchor提供。這是provisional selection，不代表production key reuse決策。
第一筆command後，bundle與authority key identity會被釘住；目前沒有rotation protocol，
看似有效的alternate bundle／key也必須fail closed。

Test backend只是deterministic fixture。Concrete PQ authentication、獨立revocation key role、
key-generation ceremony與rotation security都尚未Instantiated或分析完成。

## 3. Scope fanout與linearization

| Scope | Exact target | Sticky fence flag |
| --- | --- | --- |
| `ACCESS_CONFIGURATION` | `system_config_digest` | `configuration_revoked` |
| `FGS_AUTHENTICATION_KEY` | `fgs_auth_key_id` | `fgs_key_revoked` |
| `TICKET_USE` | `ticket_use_key` | `ticket_revoked` |
| `SESSION` | `session_id` | `session_revoked` |

Command ingestion在一個`BEGIN IMMEDIATE`中完成append-only insert及目前matching queries的
fence updates。之後才register的query會依generation順序重播同一`ctx`的歷史commands。
Exact command replay為idempotent；同一ID改寫、non-increasing generation及row corruption
都fail closed。Command authorization expiry只限制ingestion time，已接受的revocation不會
因到期而解除。

因command ingestion、query registration及activation都使用同一database的
`BEGIN IMMEDIATE`，單機reference只能形成一個明確write order：

- activation先commit：該筆既有accepted inbox work維持有效；
- revocation先commit：matching activation觀察revoked fence而拒絕；
- processor先讀snapshot、revocation後commit：commit-time exact fence re-read使activation
  與inbox一起rollback；
- nonmatching command不改寫該query fence，故不無故拒絕其activation。

## 4. 驗證結果

執行環境：branch `codex/satellite-access-v0-2`，Python unittest；未執行production proving、
大型artifact replay或實體斷電測試。

- scoped-revocation定向測試：17 passed、0 skipped／failures／errors；
- scoped／authoritative／activation／first-application／unified相鄰回歸：76 passed、
  0 skipped／failures／errors；
- 全部system tests：268 passed、0 skipped／failures／errors；
- repository-wide：945 total，其中933 passed、12個既有optional external-artifact skips、
  0 failures／errors；耗時748.912秒。

測試涵蓋strict codec與frozen vector、五表schema、四種scope的正負fanout、future query
replay、exact retry、restart durability、generation與identity mutation、initialization／
bundle／epoch／policy／role／key／time／signature rejection、authority rotation rejection、
transaction rollback、stored-row corruption、snapshot-to-commit race、nonmatching command及
concurrent ingestion／activation ordering。

## 5. Claim boundary

可以宣稱：在可信單一host、同一SQLite database及現有WAL／filesystem假設下，canonical
authenticated command ingestion、四種general-scope fanout、late query replay與activation
具有單一transaction ordering；列出的bounded failure、retry、restart與race已測試。

不可宣稱：

- production PQ command authentication或獨立revocation authority已實例化；
- authority key rotation、unrevocation或撤銷解除語意已完成；
- O(queries) fanout與O(commands) replay已有production規模benchmark；
- 多FGS／多host replication、consensus或distributed linearizability；
- rollback／hostile-filesystem防護或實體斷電已測試；
- production record／plaintext protection backend已實例化；
- external application side effect與本SQLite transaction原子或exactly once；
- concrete PQ AKE／access NIZK已實例化；
- Production-closed或Proof-closed。

## 6. 實作與證據位置

- Scoped store與command codecs：
  `src/pq_sat_auth/v2/storage/sqlite_scoped_revocation.py`
- Activation／first-application composition：`src/pq_sat_auth/v2/application.py`
- Tests：`tests/system/test_pq_sat_auth_scoped_revocation_v2.py`
- Standalone machine claims：
  `manifests/pq_sat_auth_fgs_scoped_revocation_sqlite_v0_2.json`
- Aggregated first-application claims：`manifests/pq_sat_auth_first_application_v0_2.json`
- Formal access semantics：`docs/specs/SATELLITE_ACCESS_v0_2_zh-TW.md`
- One-time state companion：`docs/specs/ONE_TIME_TICKET_STATE_v0_2_zh-TW.md`
