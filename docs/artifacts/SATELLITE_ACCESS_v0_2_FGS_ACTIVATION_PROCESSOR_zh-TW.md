# Satellite Access v0.2 FGS activation processor checkpoint

## 結論

本checkpoint完成explicit `SessionActivateV2`的bounded reference processing：

```text
strict SessionActivateV2 decode / exact re-encode
-> lookup unique committed session_id
-> recover and revalidate exact M2 + protected pending state
-> activation binding + deadline / session expiry
-> query-bound activation-time revocation snapshot
-> verify client Finished
-> atomic Activate
-> release internal session capability
```

實作位置：

- `src/pq_sat_auth/v2/activation.py`；
- `src/pq_sat_auth/v2/grant.py`；
- `src/pq_sat_auth/v2/replay.py`；
- `tests/system/test_pq_sat_auth_activation_v2.py`；
- `tests/system/test_pq_sat_auth_replay_v2.py`；
- `manifests/pq_sat_auth_fgs_activation_v0_2.json`。

## 1. Session lookup與recovery boundary

Replay store新增acceptance-domain-wide `session_id -> use_key` index。不同ticket提交相同
32-byte session ID時fail closed；pending、active及expired grant均保留該index。Activation
processor不接受caller另傳ticket identity，而是先以message中的`session_id`定位唯一
committed record。

定位後，processor透過`GrantRecoveryBackendV2`分別recover exact response bytes與sealed
pending secret state，並重新核對：

- response strict decode／exact re-encode、response digest及transcript digest；
- `ctx`、FGS、request／attempt、session、serving context與deadlines；
- session state中的suite、ticket identity、configuration／acceptance domain、transcript、
  response、session及deadlines；
- 原始grant revocation query與response／ticket bindings；
- `SessionActivateV2`的suite、request、attempt、session與response bindings。

Reference recovery backend只供test。Production sealing仍須提供confidentiality、integrity、
nonce discipline、rollback protection、crash recovery及key lifecycle保證。

## 2. Activation revocation與Finished

Activation-time query使用獨立domain：

```text
PQ-SAT/ACTIVATION-REVOCATION-QUERY/v2
```

Canonical query綁定suite、system configuration、acceptance domain、`ctx`、ticket
`use_key`、原grant revocation query digest、FGS／authentication key、request／response及
session identity。Authenticated snapshot必須echo exact query digest、generation不得低於
grant commit、在單次trusted-time sample時有效，且configuration、FGS key、ticket及
session四種revocation flags皆為false。

Processor隨後以sealed `K_client_finished`及`response_digest`呼叫suite backend。只有
backend明確回傳boolean `True`才接受；truthy非boolean、exception及wrong confirmation均
fail closed。此介面與測試不代表production MAC／KDF或PQ AKE suite已實例化。

## 3. Atomic transition、retry與capability

Store的atomic operation固定：

```text
Activate(
    use identity,
    attempt_id,
    request_digest,
    session_id,
    response_digest,
    activation_digest,
    activated_at
)
```

Pending record只能在activation deadline內轉為active。第一次成功回覆`NEW`；相同client
confirmation retry回覆`EXISTING_ACTIVE`及原record；不同confirmation、session或grant
identity不得改寫active state。16個平行exact activations只有一個transition winner。

Processor會逐欄驗證store回傳的committed grant及confirmation，且只在確認active後建立
`ActivatedSessionCapabilityV2(application_key, exporter_key, ...)`。如果store已commit但
caller只看到exception、錯誤type或mutated output，結果是`COMMIT_UNCERTAIN`且不回傳
capability；同一activation retry可由active record恢復。

Capability只是一個FGS內部handoff object，證明activation control flow已成功；它不是
可跨程序信任的bearer token，也沒有把application side effect包含在同一transaction。

## 4. Security與production限制

下列邊界刻意保持未完成：

- activation revocation snapshot與store transition不是同一authoritative transaction，
  尚有TOCTOU window；
- store只在單一Python process內由lock提供linearizability，沒有durability、multi-process
  或cross-FGS一致性；
- first protected application record、record sequence／nonce、AEAD及side-effect
  exactly-once transaction未實作；
- session-state protection、KDF、Finished及PQ AKE皆未選定production backend；
- active session termination與application action之間沒有production lease／transaction；
- 未完成PQ AKE composition proof、fault injection、satellite-path benchmark或independent
  security review。

因此`production_ready`、`proof_closed`、
`atomic_revocation_and_activation_implemented`、
`first_protected_application_record_implemented`與
`durable_or_distributed_store_implemented`全部維持false。

## 5. 驗證紀錄

本checkpoint的定向測試涵蓋honest activation、exact retry、16-worker race、strict framing、
unknown／cross-bound session、wrong及truthy-nonboolean Finished、clock／deadline、四種
revocation、snapshot freshness／query／generation、response／secret-state tamper、
session-ID collision、post-commit lost acknowledgement、mutated／wrong-type store output及
retry recovery。

2026-09-15驗證結果：

```text
Targeted Satellite Access v0.2: 83 passed, 0 failed/errors
All tests/system:              112 passed, 0 failed/errors
Repository-wide:              789 total; 777 passed,
                              12 existing optional-artifact skips,
                              0 failed/errors
```

完整命令為`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover
-s tests -q`，最終effective tree重跑耗時750.736秒。Optional external-artifact skips
未計為通過；本次沒有讀取large assignments、建立production artifacts或啟動proving，
測試結果不改變production claim。
