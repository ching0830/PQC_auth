# PQ-RBBC issuance native split lowerer checkpoint v1

日期：2026-09-14

## Protocol摘要

本checkpoint仍位於offline issuance relation I3內的`CAP.Commit` child：

```text
(r, c_r) <- CAP.Commit(r || x; rho)
h          = H_RBBC(M, c_r)
beta       = r XOR h
```

它沒有改變ticket statement、witness、`c_r`、parent input或proof bytes。新增的是L3/L4工程
能力：把前一gate已驗證的CAP value-stage bytes接到native relation emitter，將bounded
constraint rows依真正dependency分成五個relation fragments，並核對重新合併後與既有
monolithic emission逐row相同。

本次沒有執行formal I3 replay、589,030,555-row relation、`pi_issue` Prove/Verify或任何
production API。

## Frozen namespace與fragment order

新bounded namespace為：

```text
pq-rbbc/issuance/cap576-native/split-lowerer-4leaf-insecure-test-only/v1
```

Topology仍是production widths／一棵tree／四個leaves／extension degree 3／security bits 0。
Exact fragment order：

1. `input-binding`
2. `tree-pre[0]`
3. `global-tail-phase-a`
4. `tree-post[0]`
5. `global-tail-phase-b`

既有native shard source bytes保持不變。新lowerer在受控test-only sink中截取相同row
emission，依既有連續groups建立fragments：

| Existing group | Fragment |
|---|---|
| `inputs` | `input-binding` |
| `ggm-derive` | `tree-pre[0]` |
| `leaf-commit-and-tape` | `tree-pre[0]` |
| `h1-and-points` | `global-tail-phase-a` |
| `leaf-horner-and-field-aggregation` | `tree-post[0]` |
| `h2-commitment-and-request-binding` | `global-tail-phase-b` |

因此這是bounded sink-level split lowering，不是五個已可獨立執行、持久發布的production
producer。Absolute wire IDs與既有row order均保留；fragments按上列順序合併後，逐row
`label/left/right/output`完全等於同一次existing monolithic emission。

## Row accounting與identities

| Fragment | Rows | Fragment stream SHA-256 |
|---|---:|---|
| `input-binding` | 1,028 | `8070a80460e352168c780e826506fa980b4093e9485a7f7bdd5fffea6ee49faf` |
| `tree-pre[0]` | 40,592 | `316cad3b0e2b4801d71b6ff888766b8e29e3cc9c8f7a396a238ec85766c4a546` |
| `global-tail-phase-a` | 9,555 | `fb1f3b63ef393c77cfeb9b3ca52ca3c3fb55bf6c1380db908d4e63e88b4cfa7a` |
| `tree-post[0]` | 1,656 | `97f93cd769cfd79cf33bec3d05f5294711762946945df862acbc37fbd814a3c6` |
| `global-tail-phase-b` | 20,218 | `d5c0d942b24f603ecbe603206ee3c665f55f83f1118618c9a98d97e0019dfac8` |

合計：

- 73,049 rows；
- 53,032 wires；
- 52,136 nonlinear rows；
- 20,913 linear rows；
- 0 external assertions；
- row archive未materialize；
- assignment未materialize。

Existing monolithic stream identity仍為：

```text
bytes:  46,392,022
sha256: 635c6efaf3aa25d6f2d787450987b08712de5aaacd21f3107a90f5db9599b0cd
```

這個46 MB數字是本tree本次相同emitter的bounded observation；沒有拿其他tree的
`observed stream_bytes`作為本tree結果，也沒有提交row stream。

## Global-A point wire handoff

Global-A輸出的兩個GF(2^193) consistency points固定成386-bit native wire port：

```text
producer: global-tail-phase-a
port:     global.phase-a.consistency-points.native-wires
consumer: tree-post[0]
bits:     386
identity: 6408b990cd7e49a09fd4019178834f5e93df5700289f270fe9f81e38fcbfd421
```

Qualification逐row檢查：

- 386個wire IDs唯一且連續；
- `tree-pre[0]`未引用任何point wire；
- `tree-post[0]`引用全部386個point wires；
- port identity同時綁定producer、consumer、bit length、wire IDs及captured point value digest。

這只固定bounded absolute-wire ABI；production 42-stage plan的fresh wire intervals仍未
materialize。

## Stage snapshot與resume contract

Lowerer先消費前一gate完成的14份append-only artifacts。讀取規則維持：

- caller提供exact final receipt SHA-256；
- 在output lock內先single-open capture final receipt並核對external digest；
- 之後才capture其餘stage/receipt/complete；
- identity、strict JSON、payload、port及receipt-chain validation全部使用同一份
  immutable `Snapshot.raw`；
- closed-world filenames、missing、trailing bytes、payload mutation與stale chain均拒絕。

Fresh lowering另外建立canonical private capsule，包含native lowering所需的bounded XOF call
witness schedule。Capsule SHA-256為：

```text
ddd2535955669e38d90c962d44790598e9430ed1eeb21474d47e6d587bfac3d7
```

Capsule綁定relation/profile/invocation、split plan、final receipt及六個stage payload digests。
Resume必須提供exact capsule SHA-256；digest在JSON parse與lowering前核對。受控regression將
`split.build_stage_computations`與`shard.build_parallel_execution`替換成必定失敗的guard，
resume仍成功且結果與fresh完全一致，證明沒有重新呼叫已完成的upstream value-stage builder。

這不表示native witness computation被消除：relation emitter仍必須展開其constraints；capsule
只是讓value-stage outputs與XOF schedule不必重新由upstream producer取得。Capsule包含private
test fixture material，只能放在operator指定的私有external root，不得提交或嵌入portable
evidence。

## Filesystem與security boundary

Snapshot contract是single-open、single bounded read；metadata僅為best-effort mutation signal，
不證明capture期間完全沒有writer。Trusted producer handoff、writer quiescence、owner/mode/ACL、
既有writable FD、mount namespace及可信filesystem/fsync語義仍是部署前提。

本checkpoint不支持以下claims：

- independently invocable production fragment producers；
- fragment-level durable publisher／crash recovery；
- assignment-backed row replay；
- formal I3 relation satisfaction；
- production 18-tree aggregate identity；
- PQ-SE ZK、formal `pi_issue`或production closure。

## External blockers與資源

五份production external artifacts仍缺：

1. `pq_rbbc_trace_public_key_v1.bin`
2. `pq_rbbc_trace_public_key_certification_v1.json`
3. `pq_rbbc_authenticated_system_initialization_v1.bin`
4. `pq_rbbc_issuance_common_parameters_v1.bin`
5. `pq_rbbc_issuance_production_inputs_independent_review_v1.json`

另缺independent review、trusted handoff、production fragment publisher、fresh 18-tree identities、
PQ-SE backend、resource reservation及large-run authorization。

Historical estimate仍只可用於reservation planning：589,030,555 rows、至少16 GB memory、
64 GB free disk、8,000--12,000秒。沒有新的operator reservation，因此production／large
commands維持`null`。

## Exact commands

Bounded self-check：

```bash
PYTHONPATH=src python -u src/pq_rbbc_issuance_split_lowerer_v1.py --self-check
```

Read-only external inventory：

```bash
PYTHONPATH=src python -u src/pq_rbbc_issuance_split_lowerer_v1.py \
  --artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT
```

Targeted tests：

```bash
PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_split_lowerer_v1 -v
```

## Claim matrix

| 狀態 | Bounded split lowerer | Production |
|---|---:|---:|
| Defined | true | interface only |
| Instantiated | true | false |
| Implemented | sink-level fragments／capsule resume | false |
| Tested | positive、merge、mutation、resume | false |
| Evidence-sealed | bounded metadata | false |
| Proof-closed | false | false |
| Production-closed | false | false |

Tracked outputs：

```text
src/pq_rbbc_issuance_split_lowerer_v1.py
  bytes:   58,756
  sha256:  3ea2787c24aabf66e1ec6b41f4831fba79aad615e35b235d0b1a73e39424051d

manifests/pq_rbbc_issuance_split_lowerer_manifest_v1.json
  bytes:   6,048
  sha256:  ea0b9e889bc0c69643506363c4852518749578d05e60da481798c05676f3c084

artifacts/metadata/issuance_split_lowerer_v1/
  pq_rbbc_issuance_split_lowerer_portable_evidence_v1.json
  bytes:   2,502
  sha256:  1ee9a00a96cd617c2540772e505b90f8d9873804084813ac6f31a694235bc7fc
```

Targeted regression為17 passed、0 failed、0 skipped（64.521秒）。完整baseline共847 tests，
835 passed、12個既有optional external-artifact skips、0 failed、0 errors（1160.994秒）。

## 下一個gate

下一步把五個bounded fragments從sink-level classification提升為independently invocable
fragment producers：每個producer只消費已凍結的import ports，產生canonical fragment receipt，
並以previous gate的append-only publisher做受控中斷／orphan／resume qualification。仍先用
4-leaf test-only topology；沒有external inputs、review與resource reservation前不得啟動
production 18-tree materialization。
