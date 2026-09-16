# PQ-RBBC issuance I1--I5 reduced constraint prototype v1

## 結論

本 checkpoint 在新 namespace
`pq-rbbc/issuance/reduced-constraint/test-only/v1` 建立可執行的 bounded
constraint-composition prototype。它完成三件工程工作：

1. 固定 public statement `(pp, ctx, sid, rid, beta)` 與 private witness
   `(M, r, rho, k_hold, e)` 的 wire partition；
2. 讓 exact canonical trace public-key bytes 經 reduced parameters 與
   `statement.pp` 綁定；
3. 將 I1／I2／I4／I5 的 bit circuit，與既有 reduced CAP／`H_RBBC`
   `GF(2^193)` native child relation，透過四組 in-memory equality rows接合。

這不是 production issuance relation。CAP child使用既有
`PQ-RBBC-CAP-REDUCED-TEST-ONLY` profile，只導出32-bit mask；prototype將其映射為
`r[0:4] || zero[4:72]`，保留72-byte `beta` public shape。因此本結果不能替代
production profile的576-bit mask、1472-bit appended signature或18-tree relation，
也沒有產生正式 `pi_issue`。

```text
reduced_i1_i5_composition_executed = true
external_assertions = 0
production_cap_576_relation_instantiated = false
certified_trace_key_instantiated = false
qualified_backend_integrated = false
formal_pi_issue_generated = false
safe_to_start_large_replay = false
safe_to_start_large_proving_run = false
```

## 以 protocol 說明

Issuer收到holder的blind request以前，`pi_issue`未來必須證明：

```text
public:  pp, ctx, sid, rid, beta
private: M, r, rho, k_hold, e

I1  M 的形狀正確，且 M.ctx = ctx
I2  m = SHAKE256("PQ-RBBC/TICKET" || Encode(M), 32 bytes)
I3  c_r = CAP.Commit(r; rho)
    beta = r XOR H_RBBC(m, c_r)
I4  M.h = SHAKE256("PQ-RBBC/HOLD" || k_hold, 32 bytes)
I5  e 對 trace public key產生 M.C，且weight、identity、serial、KDF與tag均相符
```

本 prototype 的 I1、I2、I4、I5 使用既有 characteristic-two circuit helper逐wire
執行。I3不再使用舊 formal-relation checkpoint 的shape-only SHAKE adapter；它呼叫既有
native reduced `CAP.Commit`，由同一 child relation內的 `H_RBBC` 接收canonical
commitment bytes。Parent與child之間固定四組ports：

| Port | Bits | Direction／意義 |
| --- | ---: | --- |
| `message` | 256 | parent I2 output → child `H_RBBC` message |
| `rho` | 1,158 | private salt／roots → child CAP inputs |
| `derived_mask_prefix` | 32 | child CAP mask → private `r[0:32]` |
| `request_hash` | 576 | child `H_RBBC` output → parent I3 XOR equation |

合計2,022個join equality rows。這些rows在collision-free wire namespace中以
`GF(2^193)` rank-one equality constraints實際 materialize並 evaluate，但只存在於
bounded process memory；本 checkpoint不寫出row stream或assignment。Parent的Boolean
constraints可依v2.29已驗證的方式嵌入`GF(2^193)`，本次只固定shape digest，沒有重做或
覆寫v2.29大型archive。

## Canonical ABI

Public statement沿用`IssueStatementV1` container shape，但使用本 namespace自己的
`ABI_PROFILE_DIGEST`，所以不能被誤當作production proof statement。各欄固定為：

| Public field | Bytes |
| --- | ---: |
| `pp` digest | 32 |
| `ctx` | 32 |
| `sid` | 32 |
| `rid` | 32 |
| `beta` | 72 |

Reduced private witness另用magic
`PQRBBC-ISSUE-REDUCED-CONSTRAINT-WITNESS-V1`，依序包含ABI digest、368-byte
private ticket payload、72-byte `r`、reduced CAP canonical `rho`、32-byte
`k_hold`及836-byte `e`。Wrong magic/version/order/length/profile、truncation與
trailing bytes均拒絕。

Parameters使用magic `PQRBBC-ISSUE-REDUCED-CONSTRAINT-PP-V1`，包含relation ID、
ABI digest、reduced CAP fingerprint、完整canonical trace public key及test-only mode。
`statement.pp = SHA-256(exact parameters bytes)`，所以trace key的任一byte變動都需要
新的statement。Trace key container沿用上一gate固定的6,688/5,024/128 systematic
`H=(I_R|T)` structural codec；本次fixture仍是deterministic test matrix，不是certified
binary Goppa key。

## Wire partition與bounded accounting

Honest fixture固定accounting如下：

| Item | Count |
| --- | ---: |
| public input bits | 1,600 |
| private witness bits | 11,622 |
| internal child bridge bits | 576 |
| parent rows | 2,969,180 |
| reduced CAP／`H_RBBC` child rows | 88,282 |
| join rows | 2,022 |
| combined rows | 3,059,484 |
| external assertions | 0 |
| failed rows／joins | 0 |

Parent row-shape SHA-256為
`1903f27ab2b6c2f5033aef51e8292cc12a48d8dfeaa10896418a66af8f44c773`。
這是bounded shape identity，不是BR1CS artifact或cryptographic proof。

`sid`確實作為public input進入partition，但I1--I5不證明global freshness。Issuer仍須在
回應前完成linearizable reservation；本工作沒有修改ticket lifecycle或state machine。

## Regression與拒絕邊界

受控測試涵蓋：

- honest composition、所有四組ports與0 external assertions；
- exact public/private/internal partition及row accounting；
- wrong parameter/witness version、reordered sections與trailing bytes；
- wrong CAP profile、wrong `H_RBBC` domain及trace-key identity mismatch；
- `beta`、error vector與zero-extended mask tail mutation；
- stale child port及native child assignment mutation；
- production entry point使用空bytes仍在input decode以前拒絕，且不建立output。

Exact bounded command：

```bash
PYTHONPATH=src python -u \
  src/pq_rbbc_issuance_reduced_constraint_v1.py --self-check
```

Resource envelope為1 CPU、384 MiB以下、180秒內；bounded self-check結果封入
portable evidence。本命令不產生proof，不執行589,030,555-row replay，也不建立
assignment、BR1CS、pickle、cache、checkpoint、resume state或log。

Validation結果：targeted 18 passed；完整baseline共778 tests，766 passed、12個既有
optional external-artifact skips、0 failures/errors，耗時861.258秒。完整baseline的峰值
RSS為1,027,188 KiB，主要來自既有完整suite；上述384 MiB envelope只描述本checkpoint
獨立self-check，不能作為full-suite資源上限。

## Claim matrix

| Maturity | Status | Meaning |
| --- | --- | --- |
| Defined | true | 新namespace、ABI、partition、ports與test-only mapping固定 |
| Instantiated | reduced only | deterministic trace key與CAP32 fixture存在；production inputs不存在 |
| Implemented | reduced only | bounded parent、native child與in-memory join可執行 |
| Tested | reduced only | positive、negative、mutation與fail-closed tests存在 |
| Evidence-sealed | bounded metadata only | manifest與path-free portable evidence；無大型artifact |
| Proof-closed | false | 沒有PQ simulation-extractable backend proof |
| Production-closed | false | 沒有CAP576 relation、certified key、trusted handoff或review |

## 下一個 gate

下一個工程gate是為production CAP profile建立可審查的576-bit mask／1472-bit appended
signature native lowering計畫與bounded shard，不得直接啟動18-tree重建。先固定：

1. production CAP child的exact input/output port intervals；
2. 如何在不修改historical v2.29 evidence下重用已驗證18-tree relation；
3. formal 1,036-byte `rho`與production common-parameter snapshots的same-bytes handoff；
4. 新relation identity、預估rows／RAM／disk／時間及exact commands；
5. independent cryptographic review與identity-pinned backend integration的停止點。

五份真實external inputs仍缺少時，只能完成preflight、bounded shard及test-only evidence；
不得宣稱production relation、`pi_issue`、Proof-closed或Production-closed。
