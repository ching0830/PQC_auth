# Satellite Access v0.2 FGS pure-check processor checkpoint

## 結論

本 checkpoint 將 `AccessRequestV2` 從 exact input bytes 驗證到
`ValidatedAccessRequestV2`，並刻意停在 authoritative replay store 的 `Reserve` 之前。
它不建立 reservation、KEM ciphertext、session、response 或 application side effect。

實作位置：

- `src/pq_sat_auth/v2/processor.py`；
- `tests/system/test_pq_sat_auth_processor_v2.py`；
- `manifests/pq_sat_auth_fgs_pure_check_v0_2.json`。

## Fail-closed 處理順序

Processor 依序執行：

1. strict `FrameV2`／`AccessRequestV2` parse及exact re-encode；
2. 取得並驗證authenticated access-configuration snapshot；
3. 比對protocol version、`ctx`、epoch、FGS、key、serving／authorization digest及
   suite allow-list；
4. 只取一次trusted `now`，同時供access freshness與`VerifyTicket`使用；
5. 驗證configuration validity、client-time past/future bounds及nonzero UE／attempt
   nonces；此處只能檢查exact length與排除全零sentinel，不能從單一值證明UE RNG entropy；
6. 依configuration policy處理`NONE`或connection-local authenticated exporter；
7. 呼叫stable PQ-RBBC `verify_ticket()` contract，驗證authenticated initialization、
   pinned federation trust anchor、canonical ticket、`ctx`、issuer role／key、expiry及
   issuer authentication；
8. 從同一exact ticket bytes擷取`d_M`、visible serial及holder hash，並交叉核對
   `VerifyTicket` output；
9. 建立跨V1／V2共用的`TicketUseIdentity(ctx,sn,d_M)`、request digests及attempt ID；
10. 驗證query-bound、generation-bounded且仍在有效窗內的revocation snapshot；
11. 由FGS自行建立`x_access`並呼叫access-NIZK backend；
12. 驗證UE KEM public key及最後的pure resource／policy admission；
13. 只回傳可供後續`Reserve`使用的immutable validated object。

所有external backend都必須回傳明確`True`；例外、`None`、truthy non-boolean、suite
錯配、無效output或過期snapshot皆fail closed。Internal failure codes不得直接當成對外
錯誤oracle；wire-facing service仍應回覆generic rejection。

## Stable `VerifyTicket` 接合

Access consumption identity使用RBBC payload identity：

```text
d_M = SHAKE256("PQ-RBBC/TICKET" || Encode(M), 32)
use_key = SHAKE256("PQ-SAT/USE-KEY/v1" || ctx || sn || d_M, 32)
```

Conditional Opening使用的`SHA-256(canonical ticket transport)`是另一個representation
identity。Processor同時保留兩者但不互換；replay state只使用`d_M`。

`SystemAccessTicketVerifierV2`直接呼叫stable `verify_ticket()`。為取得`R_access`所需的
`h`，adapter對同一immutable ticket input再作一次strict decode，並逐項核對
`canonical_ticket_digest`、`d_M`、`ctx`、serial、issuer key及trace ciphertext後才輸出
holder hash。Ticket與Access checks共用processor擷取的一次`now`，避免兩個clock sample
形成邊界差異。

## Configuration、revocation與channel boundary

現有System Initialization v0.1 ABI還沒有FGS authentication key role、access profile、
access proof parameters或suite policy。因此本 checkpoint將
`AuthenticatedAccessConfigurationProviderV2`保留為明確可信邊界；它的snapshot仍須
逐欄驗證及與request／verified ticket比對。這不表示production configuration
authentication或key ceremony已完成。

Snapshot分開保存`system_config_digest`（未來完整access configuration identity）與
`initialization_configuration_digest`（目前stable `VerifyTicket`所驗證的base
`SystemConfiguration` identity）。兩者不得假設相同；如此FGS access key／suite extension
加入後，不會把舊base configuration digest誤當成已承諾新欄位。Acceptance domain亦以
獨立digest傳給後續authoritative-store選擇及revocation query。

Revocation query綁定configuration、`ctx`／epoch、FGS及issuer key、`d_M`、serial與
holder hash：

```text
SHAKE256("PQ-SAT/ACCESS-REVOCATION-QUERY/v2" || Encode(query), 32)
```

Provider必須echo exact query digest，且snapshot generation不得低於configuration固定的
minimum；`effective_at <= now < valid_until`才可接受。Configuration、FGS key、issuer
key、ticket、serial或holder任一revoked flag都拒絕。這只是pure snapshot boundary；
`Reserve`／`CommitGrant`仍須依狀態規格以serializable ordering重查revocation。

Channel mode由authenticated configuration固定。`AUTHENTICATED_EXPORTER`必須呼叫與本次
connection綁定的verifier，不能相信request自己帶來的digest；`NONE`只有在policy明確
允許時可用，且不能宣稱cryptographic channel binding。

規格要求UE以合格CSPRNG產生`ue_nonce`與`attempt_nonce`，但FGS從單一request無法驗證
entropy來源。Processor實作的是wire length及nonzero sentinel檢查；RNG health、重複率與
failure handling必須由UE實作、部署測試及後續operational monitoring另行證成。

## 測試範圍

定向測試涵蓋：

- honest request及`ValidatedAccessRequestV2 -> Reserve`接線；
- malformed／trailing bytes與全部configuration binding；
- clock failure、configuration validity、stale／future client time及zero nonces；
- required／optional／none channel policy及exporter failure；
- stable `VerifyTicket` signature與issuer／configuration binding；
- revocation query、generation、validity及六種revoked categories；
- access-NIZK、KEM與admission的suite mismatch、exception與non-boolean success；
- fail-fast ordering，確認revoked request不觸碰後續proof、KEM或admission backend；
- machine manifest與implementation claim完全相符。

測試中的configuration、ticket authentication、NIZK、KEM及channel verifier都是明確
test-only adapter，不是production cryptography。

2026-09-15驗證結果：

```text
Targeted: 73 passed, 0 failed/errors
Repository-wide: 761 total; 749 passed, 12 existing optional-artifact skips,
                 0 failed/errors
```

完整命令為`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover
-s tests -v`；本結果沒有安裝或執行production cryptographic backend。

## Claim boundary與下一步

目前可宣稱FGS pure-check control flow及其abstract boundaries已Implemented／Tested，且
stable `VerifyTicket` contract已接入。不得宣稱：

- Blind-UOV production verification已實例化；
- access configuration已由production FAC／FGS key ceremony發布；
- access NIZK或PQ AKE suite已選定、實作或Proof-closed；
- UE nonce entropy已由FGS pure-check驗證；
- replay store已durable／distributed；
- 完整M1→M2 grant processor或Production-closed已完成。

下一個implementation gate是在concrete suite研究作出版本化決策後，建立test-only
grant builder，把pure-check output接到`Reserve -> KEM/auth/Finished -> CommitGrant`；
production路徑仍須等待system-init extension、真實crypto backends與durable store。
