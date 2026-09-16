# PQ-RBBC issuance CAP576／1472 native-lowering preflight v1

日期：2026-09-13

## 結論

本 checkpoint 已關閉「可否把既有 CAP native lowering 用於 production-width issuance
child」的 bounded 工程問題，但沒有關閉 production relation 或正式 proving：

- production CAP profile仍是18 trees、576-bit mask、1,472-bit appended-signature、
  2,048-bit witness及2,450-bit random polynomial；
- production child的message、commitment、derived mask、append base與request hash
  wire intervals已固定；
- formal `rho`已固定為1,036-byte canonical serialization，並定義single immutable raw
  的same-bytes handoff；
- production-width／4-leaf／one-tree insecure test-only shard已實際stream-lower及驗證；
- v2.29只能重用topology、wire intervals、row accounting、source identity及
  implementation semantics，不能重用assignment、private witness、observed values或其他
  tree的observed `stream_bytes`；
- 五份production external artifacts仍缺少，production execution entry point持續在
  decode或建立CAP trace前fail closed；
- `formal_pi_issue_generated`、`Proof-closed`、`Production-closed`、large replay及large
  proving gate全部為false。

## Protocol位置

Formal issuance relation的I3要求：

```text
(r, c_r) <- CAP.Commit(r || x; rho)
h          = H_RBBC(M, c_r)
beta       = r XOR h
```

因此這個gate處理的是I3 child與parent relation之間的工程邊界：CAP child必須從同一份
private `rho` bytes導出`salt`及18組root pairs，產生canonical commitment `c_r`、576-bit
mask `r`及1,472-bit appended-signature base；parent再把ticket message、`r`與576-bit
`H_RBBC` image接入I1--I5 relation。它不改變ticket statement、ticket lifecycle、system
architecture或`pq_sat_auth`。

## Frozen production profile

| 欄位 | 值 |
|---|---:|
| CAP profile fingerprint | `2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38` |
| tree layout | 2 × 4,096 leaves；16 × 2,048 leaves |
| mask | 576 bits |
| appended signature | 1,472 bits |
| witness | 2,048 bits |
| random polynomial | 2,450 bits |
| canonical commitment | 5,391 bytes |
| canonical `rho` | 1,036 bytes |

## Child port contract

Wire IDs沿用identity-verified v2.9 global tail／v2.29 parent join topology，但fresh issuance
必須產生fresh values。

| Port | Inclusive interval | Bits | Parent用途 |
|---|---:|---:|---|
| `shared.message` | `[387, 642]` | 256 | ticket message equality |
| `global.phase-b.commitment` | `[40084506, 40127633]` | 43,128 | parent `H_RBBC` input |
| `global.phase-b.derived-mask` | `[40127634, 40128209]` | 576 | blind-mask equality |
| `global.phase-b.append-base` | `[40128210, 40129681]` | 1,472 | child/private；非parent public input |
| `global.phase-b.request-hash` | `[40194018, 40194593]` | 576 | `H_RBBC` image equality |

Native parent equality rows是`256 + 576 + 576 = 1,408`。Commitment由parent native
`H_RBBC` relation消費；append base保留於CAP／後續signature flow，所以兩者不能被誤計為
額外public statement bits。

## `rho` same-bytes handoff

Canonical 1,036-byte layout依序為：

```text
RANDOMNESS_MAGIC[20]
|| production profile fingerprint ASCII[64]
|| salt[0][25] || salt[1][25]
|| tree_count u16le[2]
|| repeated tree[0..17](left_root[25] || right_root[25])
```

每個GF(2^193) element使用25-byte little-endian且未使用的高7 bits必須為0。Strict parser
拒絕wrong magic、wrong profile、wrong tree count、noncanonical field element、truncation及
trailing bytes。

Future executor必須先capture一份immutable `RhoSnapshotV1.raw`，identity、strict parse及
所有tree child inputs皆只使用這同一份bytes；不得為每個child重新開啟pathname。`rho`是
每次issuance的private witness，不是應放入global external-artifact directory的公開固定
artifact，也不得寫入portable evidence。

## V2.29 historical reuse boundary

Identity-verified historical evidence：

```text
artifacts/metadata/parent_join_recovery_v2_29/
  pq_rbbc_parent_join_recovery_evidence_v2_29.json
bytes:   5,695
sha256:  1281afaee1d5d784390ee51c96c66ecc7f486ef4b4b7933590826a708f81b20e
```

可重用：

- 18-tree topology及degree配置；
- frozen wire intervals及native join grammar；
- row accounting與resource-estimation baseline；
- exact source/artifact identities；
- 已驗證的composition implementation semantics。

不可重用：

- v2.29 assignment、private witness或`rho`；
- v2.29 commitment、mask、message、request hash等observed values；
- 將historical fixture當成fresh issuance evidence；
- 其他tree的observed `stream_bytes`。

589,030,555 rows只是該historical fixture的完整replay結果，不是新的production execution
authorization，也不是正式`pi_issue`。

## Bounded native-lowering evidence

Qualification profile維持production width，但故意縮成一棵4-leaf tree、extension degree
3、security bits 0。它執行既有CAP/Anemoi streaming lowerer兩次，使用不同`rho`：

| Observation | 值 |
|---|---:|
| rows | 73,049 |
| wires | 53,032 |
| nonlinear rows | 52,136 |
| linear rows | 20,913 |
| XOF calls | 14 |
| transient spool | 77,888 bytes |
| generated stream accounting | 46,392,022 bytes |
| external assertions | 0 |
| verification failures | 0 |
| assignment materialized | false |

兩次執行的row stream及spool SHA-256完全相同，證明topology不依賴witness；commitment、
derived mask與request-hash digests則隨`rho`改變。Stream及spool只送入digest／temporary
spool sink，未建立或提交row archive、assignment或BR1CS。

Frozen shape digests：

- row stream：`635c6efaf3aa25d6f2d787450987b08712de5aaacd21f3107a90f5db9599b0cd`
- temporary wire spool：`fef9327e5de0c7859db5657a80114efdec692a878cd407f6fe1ccbc259ab8e5c`

### Namespace blocker

既有`pq_rbbc_cap_shard_stream.shard_profile()`只對完整4,096-leaf shape分派新ID，其他shape
會落到historical 2,048-leaf relation ID：

```text
pq-rbbc/cap/production-tree-shard-2048/v1
```

所以本fixture另包在
`pq-rbbc/issuance/cap576-native/4leaf-insecure-test-only/v1`，且
`engine_namespace_production_eligible=false`。下一個production implementation必須取得fresh
relation identity／selector，不得把名稱碰撞解讀為production qualification；本gate刻意不改
historical engine source，以保持既有frozen identity。

## External artifacts與production blockers

目前環境缺少全部五份external artifacts：

1. `pq_rbbc_trace_public_key_v1.bin`
2. `pq_rbbc_trace_public_key_certification_v1.json`
3. `pq_rbbc_authenticated_system_initialization_v1.bin`
4. `pq_rbbc_issuance_common_parameters_v1.bin`
5. `pq_rbbc_issuance_production_inputs_independent_review_v1.json`

即使將來schema validation通過，trusted producer handoff、attestation verification、writer
quiescence、owner/mode/ACL、既有writable FD、mount namespace與independent review仍是外部
部署前提。Preflight只消費single-open／single bounded-read snapshots，不能以filesystem
metadata宣稱完全排除concurrent writer。

此外仍缺：fresh production relation namespace、production-scale executor qualification、
qualified PQ simulation-extractable backend、resource reservation與明確large-run authorization。

## Resource boundary與exact commands

本次bounded run使用2 cores，設計上限60秒／128 MiB。Historical 18-tree planning baseline為
589,030,555 combined rows、16 GB minimum memory、64 GB minimum free disk、8,000--12,000秒
（約2小時13分至3小時20分）。這只是重新申請資源時的估算，不是fresh runtime observation；
執行前必須重新reservation及preflight。

Bounded self-check：

```bash
PYTHONPATH=src python -u src/pq_rbbc_issuance_cap576_native_preflight_v1.py --self-check
```

External-artifact read-only preflight：

```bash
PYTHONPATH=src python -u src/pq_rbbc_issuance_cap576_native_preflight_v1.py \
  --artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT
```

Targeted tests：

```bash
PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_cap576_native_preflight_v1 -v
```

本gate不提供large replay或large proving command；因external artifacts、namespace、backend、
review、reservation與authorization尚未成立，產生可執行large command會超出claim boundary。

## Claim matrix

| 狀態 | Bounded fixture | Production |
|---|---:|---:|
| Defined | true | child ports／rho handoff only |
| Instantiated | true | false |
| Implemented | native lowering true | false |
| Tested | positive／mutation true | false |
| Evidence-sealed | bounded metadata true | false |
| Proof-closed | false | false |
| Production-closed | false | false |

Portable evidence：

```text
artifacts/metadata/issuance_cap576_native_preflight_v1/
  pq_rbbc_issuance_cap576_native_preflight_portable_evidence_v1.json
bytes:   1,747
sha256:  c4d6b83b7bc9bd893617761c2424f5551acdcfa6229e778175a03304740caf9f
```

Targeted regression為17 passed、0 failed、0 skipped（9.603秒）。完整unittest baseline為
795 tests：783 passed、12個既有optional external-artifact skips、0 failures/errors
（879.409秒）。

## 下一個gate

下一步是建立fresh production issuance CAP child namespace與staged executor contract：消除
historical shard selector alias、要求executor只消費已驗證CandidateSet與同一
`RhoSnapshotV1`、固定fresh cache／resume identities及per-tree outputs。External artifacts與
independent review未完成前，該gate仍只能做read-only preflight及bounded qualification，不能
啟動18-tree replay或formal proving。
