# PQ-RBBC issuance CAP child staged-executor checkpoint v1

日期：2026-09-13

## 結論

本 checkpoint 建立 fresh issuance CAP child namespace與可審核的staged-executor
contract，但沒有啟動production 18-tree replay或proving：

- production relation固定為
  `pq-rbbc/issuance/cap576-native/production-child/candidate/v1`；
- 42-stage dependency order固定為snapshot validation、invocation binding、18個
  `tree-pre`、global phase A、18個`tree-post`、global phase B、parent native join及
  final seal；
- formal statement／witness與1,036-byte `rho`均以同一份immutable raw消費；已驗證的
  `CandidateSet` snapshots不得由executor重新開啟pathname；
- 18棵樹各自有fresh namespace、planned interval、四個output ports與空的observed
  identity欄位；沒有沿用其他tree或historical fixture的`stream_bytes`、value digest、
  assignment或private witness；
- canonical JSON cache/resume與per-stage output identity codecs已實作並在bounded
  4-leaf native child上測試；production publisher與durable resume尚未實作；
- 五份external artifacts、trusted handoff、independent review、fresh runner、resource
  reservation、large-run authorization及qualified PQ-SE backend仍未關閉，所以所有
  production／security／large-run claims維持false。

## Protocol位置

Formal issuance relation的I3為：

```text
(r, c_r) <- CAP.Commit(r || x; rho)
h          = H_RBBC(M, c_r)
beta       = r XOR h
```

這個gate只處理`CAP.Commit` child如何安全交給parent relation。就protocol而言：

1. issuer已固定的ticket request statement／private witness形成一次invocation；
2. 同一份private `rho`提供兩個salt及18組tree roots；
3. 每棵tree先產生leaf commitments、`p_plain`與`mhat_plain`；
4. global phase A由所有`tree-pre` outputs導出兩個consistency points；
5. 每棵tree再用這兩點產生`xi_masks`；
6. global phase B產生`c_r`、derived mask、append base與request hash；
7. parent native join只接受同一invocation下已identity-bound的child outputs。

所以不能用舊的monolithic tree runner直接冒充fresh executor：正式runner必須能在
`tree-pre`與`tree-post`之間插入global phase A，並把每個stage的inputs／outputs綁到同一
plan及invocation。

## Production namespace與stage order

Production profile保持576-bit mask、1,472-bit appended signature、2,048-bit witness、
2,450-bit tape，以及2 × 4,096／16 × 2,048 leaves。Production plan SHA-256為：

```text
ececfbf8421dc6593498bf0da8d5b1f9aed61ceee041ca7af0ebf19f594c0943
```

Exact 42-stage order：

```text
validate-snapshots
bind-invocation
tree-pre[0] ... tree-pre[17]
global-tail-phase-a
tree-post[0] ... tree-post[17]
global-tail-phase-b
parent-native-join
final-seal
```

本checkpoint將其固定為closed ordered plan。線性order是deterministic publication順序；
未來若要平行執行tree stages，publisher仍須保留相同ordinal、dependency closure與output
identity，不能以completion order改變canonical plan。

## Per-tree inputs與outputs

每棵tree contract固定：

- fresh relation ID：
  `pq-rbbc/issuance/cap576-native/production-child/tree-{i}/v1`；
- 對應的planned local wire interval與row accounting；
- 共同`salt` byte interval `[84,134)`；
- tree `i`的left／right roots各25 bytes，從`rho[136:1036]`依序且不重疊取用；
- `leaf-commitments`、`p-plain`、`mhat-plain`屬於`tree-pre`；
- `xi-masks`屬於`tree-post`。

Plan只沿用identity-verified historical topology、interval與accounting。所有
`fresh_value_sha256`、`observed_row_stream_bytes`、`observed_row_stream_sha256`及
`assignment_identity`目前均為`null`。它們只能由將來fresh production execution產生，
不能從v2.29或另一棵tree複製。

## Immutable invocation與CandidateSet

`capture_invocation`對canonical `IssueStatementV1`及`IssueWitnessV1`各做一次bytes copy與
strict decode，檢查ABI profile與ticket context binding，再直接從同一witness bytes擷取
1,036-byte production `rho`。Ticket message固定為：

```text
SHAKE256("PQ-RBBC/TICKET" || exact TicketPayload, 32 bytes)
```

Invocation identity domain-separately綁定exact statement、ticket payload、blind mask、
`RhoSnapshotV1.raw`與ticket message。Production preflight只接受caller已capture的
`CandidateSet`與`InvocationSnapshotV1`；identity、parse與binding都只使用這些snapshots，
不再呼叫`read_candidate_set`或重開pathname。

這個same-snapshot contract不能證明capture期間完全沒有writer。Trusted producer handoff、
writer quiescence、owner/mode/ACL、既有writable FD及mount namespace仍是部署前提。

## Cache/resume與stage output identity

Cache identity domain-separately綁定relation/profile、stage-order、invocation、statement、
ticket message、blind mask digest、`rho` digest與predecessor manifest。Checkpoint state只允許
closed-world canonical JSON，記錄contiguous completed-stage prefix及chained result digests；
拒絕wrong invocation、wrong cache identity、noncontiguous stages、mutation與trailing bytes。
不得使用pickle。

`StageOutputIdentityV1`固定以下binding：

- relation ID、profile fingerprint、plan SHA-256、invocation SHA-256與stage ID；
- rows、wires、stream bytes及stream SHA-256；
- ordered output port ID、bit length及value SHA-256；
- assignment materialization、external assertions及verification failures。

Consumer必須用`decode_for`提供預期execution domain；僅通過通用schema parsing不等於接受
該output。Production cache／resume state屬於external runtime artifact，fresh run前必須確認
不存在；它不應提交Git。這個gate尚未實作atomic publisher、crash-durable stage output或
production resume，因此`safe_to_materialize_production_cache=false`。

## Bounded qualification

Bounded wrapper namespace為：

```text
pq-rbbc/issuance/cap576-native/staged-4leaf-insecure-test-only/v1
```

它使用formal fixture的exact statement／witness／production `rho`，但只取第一組root pair，
執行production-width、one-tree、4-leaf、security-bits-0 native shard。四個bounded stages為
`bind-invocation`、`native-shard`、`bind-child-outputs`及`final-seal`。

| Observation | 值 |
|---|---:|
| rows | 73,049 |
| wires | 53,032 |
| generated stream accounting | 46,392,022 bytes |
| transient spool | 77,888 bytes |
| external assertions | 0 |
| verification failures | 0 |
| assignment materialized | false |

Frozen identities：

- final state：`21c9e3bc39a89597d0d94f6f40df9f0d97383bcb786b5fad0257d857884acf39`
- deterministic result：`be70c9779a1d1c8e1250f0edab33ab09b30617fcced3888f061aaa0492717ff0`
- output identity：`198c21f9f609341e361bb62896b81efbbba3d0407f8fac42c4ce9fe5cd8384c4`
- row stream：`635c6efaf3aa25d6f2d787450987b08712de5aaacd21f3107a90f5db9599b0cd`
- spool：`fef9327e5de0c7859db5657a80114efdec692a878cd407f6fe1ccbc259ab8e5c`

Fresh及從`bind-invocation`中斷後resume的state/result完全相同；受控mutation、trailing
bytes及wrong invocation皆拒絕。Resume會重新驗證已完成prefix，不能被解讀為production
crash-durability qualification。

Formal fixture的576-bit blind mask不是這個4-leaf child的derived mask。因此這次只驗證
staging、same-bytes、native child與output identity，不宣稱I3完整relation成立；
`full_i3_relation_claimed=false`、replayed large rows為0、proofs generated為0。

## External blockers與資源邊界

目前環境仍缺少：

1. `pq_rbbc_trace_public_key_v1.bin`
2. `pq_rbbc_trace_public_key_certification_v1.json`
3. `pq_rbbc_authenticated_system_initialization_v1.bin`
4. `pq_rbbc_issuance_common_parameters_v1.bin`
5. `pq_rbbc_issuance_production_inputs_independent_review_v1.json`

即使五份檔案到齊，還需要trusted/authenticated handoff、fresh split tree runner、atomic
publisher與resume qualification、qualified PQ simulation-extractable backend、獨立review、
resource reservation及明確large-run authorization。

Historical估算只能作reservation baseline：589,030,555 combined rows、至少16 GB memory、
64 GB free disk及8,000--12,000秒（約2小時13分至3小時20分）。這不是fresh execution
observation，也不是啟動授權。

## Exact commands

Bounded self-check：

```bash
PYTHONPATH=src python -u \
  src/pq_rbbc_issuance_cap_child_executor_v1.py --self-check
```

External inventory read-only preflight：

```bash
PYTHONPATH=src python -u \
  src/pq_rbbc_issuance_cap_child_executor_v1.py \
  --artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT
```

Targeted regression：

```bash
PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_cap_child_executor_v1 -v
```

Production execution、large replay及large proving command均為`null`；未關閉上述blockers前，
提供可直接啟動的大型command會超出本checkpoint的claim boundary。

## Claim matrix

| 狀態 | Bounded staged child | Production 18-tree |
|---|---:|---:|
| Defined | true | plan／namespace／ports true |
| Instantiated | true | false |
| Implemented | true | false |
| Tested | fresh／resume／negative true | false |
| Evidence-sealed | metadata true | false |
| Proof-closed | false | false |
| Production-closed | false | false |

Tracked outputs：

```text
src/pq_rbbc_issuance_cap_child_executor_v1.py
  bytes:   51,223
  sha256:  930e98f647a7539f9124515931df979cbfe8fb10c4ecda731e6987fcbd15033c

manifests/pq_rbbc_issuance_cap_child_executor_manifest_v1.json
  bytes:   35,544
  sha256:  72ca9390f78c03d31bf4e45e25da3a5cf821d31259782df95e54a3e7c2d4d5e4

artifacts/metadata/issuance_cap_child_executor_v1/
  pq_rbbc_issuance_cap_child_executor_portable_evidence_v1.json
  bytes:   3,163
  sha256:  96c6c6732a11126435c2b6dd94a2e5788a1177a60e4754ff76c1d3187f3787c3
```

Targeted regression為17 passed、0 failed、0 skipped（14.930秒）。完整unittest baseline為
812 tests：800 passed、12個既有optional external-artifact skips、0 failures/errors
（900.813秒）。

## 下一個gate

下一步不是立即啟動18-tree replay。先實作並驗證fresh split `tree-pre`／`tree-post`
production runner及atomic stage-output publisher，在synthetic/bounded topology證明crash-safe
resume不會混用invocation或outputs。External artifacts、trusted handoff與independent review
到齊後，才能產生新的resource reservation與large-run exact command；formal `pi_issue`還需
qualified PQ-SE backend及production proof serialization。
