# Satellite Access v0.2 UE SQLite wallet checkpoint

## 教學摘要

- **影響的protocol步驟：**M5 UE access acceptance與M6 one-time lifecycle之間的
  UE-local crash／retry邊界。
- **使用者可觀察的訊息：**M1、M2及`SessionActivateV2` bytes均不改變。
- **本次執行內容：**建立canonical wallet record、單機SQLite transition、restart／race／
  corruption與commit-uncertain tests。
- **新增能力：**UE可在M1送出前保存exact attempt，並在M2驗證後先commit再釋放session；
  exact retry可恢復同一M1、M2、session與activation。
- **仍不能做：**不能宣稱production secure wallet、實體斷電durability、rollback
  protection、secure erasure、distributed store或production PQ AKE。
- **下一個gate：**first protected application record與UE／FGS activation handoff；真實
  wallet protection及device keystore qualification另走deployment／crypto gate。

## 1. State與release ordering

本checkpoint固定兩個UE-local states：

```text
ABSENT
  -- Prepare(exact attempt) --> PREPARED(revision=1)

PREPARED
  -- Accept(exact M2 + verified session) -->
     ACCEPTED_PENDING_ACTIVATION(revision=2)
```

同一份exact `Prepare`或`Accept`重送回傳`EXISTING`；同一ticket對應不同attempt或不同
accepted session時fail closed。不存在以下transition：

```text
ACCEPTED_PENDING_ACTIVATION -> PREPARED
accepted record -> second M2/session
conflicting attempt -> overwrite
```

`UEWalletAccessProcessorV2`的成功順序為：

```text
load + authenticate protected PREPARED record
-> UEAccessAcceptProcessorV2 verifies M2
-> atomic wallet Accept
-> read back committed protected record
-> exact record/session/output comparison
-> release application/exporter keys and activation bytes
```

若commit可能已成功但caller收到exception、錯誤型別或被改寫的transition，結果為
`COMMIT_UNCERTAIN`，不得回傳session。後續exact retry先讀取authoritative wallet record；
若revision 2已存在且M2完全相同，直接恢復同一session，不再次decapsulate或重新產生
client Finished。

## 2. Canonical protected record

Record format固定為：

```text
PQ-SAT-UE-WALLET-RECORD-v0.2
```

Canonical JSON使用ASCII、sorted keys、無多餘空白、lowercase hex及exact field set。
Decode後必須重建以下binding並重新encode成相同bytes：

- exact M1、canonical ticket及`TicketUseIdentity(ctx,sn,d_M)`；
- authenticated configuration、`request_digest`及`attempt_id`；
- M2 request／attempt／FGS／context binding；
- transcript／response／session identities與deadlines；
- accepted-time configuration、ticket及policy upper bounds；
- exact canonical `SessionActivateV2`；
- application／exporter key material。

Canonical plaintext上限為2,097,152 bytes；protected record上限為2,359,296 bytes。
SQLite不直接接收plaintext record。`UEWalletRecordProtectionV2`必須先以以下AAD執行
authenticated protection：

```text
"PQ-SAT/UE-WALLET-RECORD-AAD/v0.2"
|| use_key[32]
|| state_u16be
|| revision_u64be
```

SQLite row可見metadata限`use_key`、state、revision及`protection_id`。本checkpoint只有
test-only XOR stream＋HMAC-SHA256 adapter；它只用來測試boundary與mutation rejection，
不是合格encryption、KDF、nonce management或production key storage。

## 3. SQLite boundary

SQLite profile固定：

```text
application_id = 0x50515357
user_version   = 2
journal_mode   = WAL
synchronous    = FULL
writer begin   = BEGIN IMMEDIATE
database mode  = 0600 at initial creation
```

每次operation建立自己的connection，讓同一主機的threads／processes由SQLite writer lock
serialization。初始化時核對application ID、schema version、唯一table set及normalized
schema SQL；database path必須為absolute、既有path不得是symlink，建立後同步parent
directory entry。

這個durability claim只限：

- SQLite commit已回傳；
- 單一可信主機與local filesystem；
- SQLite WAL／FULL synchronous及filesystem遵守其文件化語意；
- cooperative process不繞過record protection或直接改寫database。

測試包含commit回傳後立即`os._exit()`，再由新process／store instance恢復；沒有進行實體
斷電、kernel panic、device-cache、remount、filesystem corruption或hostile pathname race
測試。因此`durable_reference = true`不等於physical-power-loss或production durability。

## 4. Fault、retry與mutation結果

本checkpoint覆蓋：

- exact prepare／accept idempotency及restart recovery；
- 相同ticket、不同attempt conflict；
- 16-thread及6-process prepare race只有一個`CREATED`；
- 12-thread exact M2處理只有一個wallet transition，所有成功session相同；
- M2 malformed／processor exception／wrong type不改變`PREPARED`；
- commit acknowledgement遺失時不釋放session，retry恢復既有revision 2；
- store transition output mutation視為`COMMIT_UNCERTAIN`；
- exact response mismatch及activation deadline expiry不恢復session；
- protected bytes、row state／revision、protection ID、application ID、schema version與
  non-canonical／oversized record mutation拒絕；
- test record中exact M1及KEM secret不以plaintext出現在SQLite protected BLOB。

通過這些tests只支持reference transition與failure wiring，不是wallet security proof。

## 5. Secret lifecycle限制

Accepted record目前仍保留完整attempt，包括ephemeral KEM secret。Logical transition沒有
再次使用它，但SQLite舊page、WAL、Python object與allocator可能保留先前bytes；Python也
無法提供可靠zeroization。本checkpoint因此明確維持：

```text
production_record_protection_instantiated = false
rollback_protection_implemented = false
secure_key_erasure_implemented = false
physical_power_loss_tested = false
distributed_wallet_implemented = false
production_ready = false
proof_closed = false
```

真實部署至少還需要OS／hardware-backed keystore、version／rollback counter、key rotation、
backup policy、device compromise model、secure deletion策略及獨立review。

## 6. 實作位置

- `src/pq_sat_auth/v2/ue.py`：共用attempt與acceptance-time validation；
- `src/pq_sat_auth/v2/wallet.py`：state、transition、store protocol及commit-before-release
  coordinator；
- `src/pq_sat_auth/v2/storage/sqlite_wallet.py`：canonical record、protection boundary及
  SQLite backend；
- `tests/system/test_pq_sat_auth_ue_wallet_v2.py`：positive、negative、mutation、race及
  restart tests；
- `manifests/pq_sat_auth_ue_wallet_v0_2.json`：machine-readable profile與claim boundary。

## 7. 驗證紀錄

驗證結果：

- UE wallet定向測試：21 passed，0 failures／errors／skips；
- Access v0.2定向測試：120 passed，0 failures／errors／skips；
- `tests/system`：149 passed，0 failures／errors／skips；
- repository-wide：826 total，814 passed，12個既有optional skips，0 failures／errors，
  執行時間746.781秒。

完整回歸命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  python -m unittest discover -s tests -q
```

Optional external-artifact skips不計為通過，也不提升production／proof claim。
