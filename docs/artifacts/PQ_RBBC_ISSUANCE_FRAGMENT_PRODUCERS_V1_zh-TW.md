# PQ-RBBC issuance independent fragment producers checkpoint v1

日期：2026-09-14

## Protocol位置與本次邊界

本checkpoint仍只處理offline issuance relation I3中的`CAP.Commit` child：

```text
(r, c_r) <- CAP.Commit(r || x; rho)
h          = H_RBBC(M, c_r)
beta       = r XOR h
```

它把上一gate的五個sink-level fragments提升成可分別呼叫的bounded producers。Ticket
statement、witness、`c_r`語意、parent input、ticket lifecycle與`pq_sat_auth`均未修改；沒有
產生正式`pi_issue`。

本次namespace為：

```text
pq-rbbc/issuance/cap576-native/fragment-producers-4leaf-insecure-test-only/v1
```

Topology維持production widths／一棵tree／四個leaves／extension degree 3／security bits 0，
不能升格為production profile。

## 五個獨立producer

固定順序與absolute next-wire boundary如下：

| Ordinal | Producer | Rows | Next wire |
|---:|---|---:|---:|
| 0 | `input-binding` | 1,028 | 1,029 |
| 1 | `tree-pre[0]` | 40,592 | 33,141 |
| 2 | `global-tail-phase-a` | 9,555 | 39,372 |
| 3 | `tree-post[0]` | 1,656 | 41,020 |
| 4 | `global-tail-phase-b` | 20,218 | 53,033 |

除第一段外，每個producer只接受同一invocation/capsule所屬的前段canonical export state與
caller明確提供的exact `port_identity_sha256`。Port identity綁定version、relation、profile、
invocation、capsule、producer、consumer、next wire及完整body；wrong identity、wrong
version/domain、unknown field及body mutation均拒絕。

`tree-pre[0]`的external state包含後續lowering所需的4個wire-spool records與tape values；
`global-tail-phase-a`加入H1及386-bit consistency-point native wire port；`tree-post[0]`加入
Horner/aggregate outputs；最後一段只輸出commitment、mask、append base及request hash的wire
ports與value digests。這些state含private test fixture material，只能存在operator指定的私有
external root，不得提交或嵌入portable evidence。

## Row equivalence與frozen identities

五個producer各自從import state的absolute `next_wire`開始呼叫既有native primitives；它們不
呼叫monolithic `build_streaming_shard`。Qualification另以既有monolithic emitter作比較器，確認
五段重新合併後的73,049 rows逐row `label/left/right/output`完全一致，總計53,032 wires、
52,136 nonlinear rows、20,913 linear rows及0 external assertions。

| Fragment | Stream SHA-256 |
|---|---|
| `input-binding` | `8070a80460e352168c780e826506fa980b4093e9485a7f7bdd5fffea6ee49faf` |
| `tree-pre[0]` | `316cad3b0e2b4801d71b6ff888766b8e29e3cc9c8f7a396a238ec85766c4a546` |
| `global-tail-phase-a` | `fb1f3b63ef393c77cfeb9b3ca52ca3c3fb55bf6c1380db908d4e63e88b4cfa7a` |
| `tree-post[0]` | `97f93cd769cfd79cf33bec3d05f5294711762946945df862acbc37fbd814a3c6` |
| `global-tail-phase-b` | `d5c0d942b24f603ecbe603206ee3c665f55f83f1118618c9a98d97e0019dfac8` |

Existing monolithic stream SHA-256仍為
`635c6efaf3aa25d6f2d787450987b08712de5aaacd21f3107a90f5db9599b0cd`；這是同一個bounded
emitter的觀察，不是沿用其他tree的`observed stream_bytes`。Global-A point port identity仍為
`6408b990cd7e49a09fd4019178834f5e93df5700289f270fe9f81e38fcbfd421`。

五個export port identities依序為：

```text
bb492cf59d12f418853b90618104a5a54aa46f948557a0dc1feeb0fd7169f0dd
bebe08a5c019b6464f8f49a628e5da885c3ee25752ebbd25cb368ebe000f989a
1c1a1aa47aaf430e3e79727d2c4988981d7b88ab047dfe36701e6731612465ce
689745ec8cda0f478b9a781eded34ffa0120ff998fdb9d4807c03a6f6013acce
deecf46b9a216ebd65b6425a0c03760a2cc337a485bd22aedd36cff9ae44fe7e
```

## Append-only publication與resume

一個完成的external runtime directory固定12個files：一份genesis receipt、五份fragment
artifacts、五份stage receipts及一份complete。Publication沿用Linux `O_TMPFILE`、file fsync、
exclusive `linkat`及directory fsync，不truncate或replace既有path。

Resume contract為：

- caller必須提供目前latest receipt的exact SHA-256；
- 在directory lock內先single-open capture該receipt並核對digest，之後才parse capsule或讀取其餘
  files；
- identity、strict JSON parsing及validation均只使用同一份immutable `Snapshot.raw`；
- completed artifacts只驗證及還原export state，不重新呼叫已完成producer；
- 最多允許一份恰為next ordinal的orphan fragment；該producer重算一次、raw bytes逐byte相同後
  原位採納，不替換inode，再補receipt；
- unknown、gap、missing、wrong chain、alternate encoding、trailing bytes及mutation均fail
  closed。

受控中斷發生於ordinal 2 artifact link後、receipt前；resume的producer invocation counts為
`[1, 1, 2, 1, 1]`。前兩段未重跑，orphan段恰重算一次，orphan bytes、SHA-256及inode均保持
不變。完成directory的final receipt為1,009 bytes，SHA-256
`044e75a7c835a542ae9162947a1887dab2996a5baddb58efff3a243c81fdbead`。

Snapshot contract只提供single-open、single bounded read。Inode/size/mtime/ctime至多是best-effort
mutation signals，不證明capture期間完全沒有writer。Trusted producer handoff、writer
quiescence、owner/mode/ACL、既有writable FD、mount namespace及可信filesystem/fsync語意仍是
部署前提。Future executor必須消費CandidateSet內已驗證的相同snapshots，不得重新開啟
candidate pathnames後執行。

## Claims、external blockers與資源

本checkpoint只關閉bounded independent-producer與append-only resume工程gate。它沒有
materialize assignment、row archive或BR1CS，沒有執行formal I3 replay、589,030,555-row
relation、18-tree production replay、PQ-SE Prove/Verify或large proving；全部production/security
claims維持false。

五份production external artifacts仍缺：

1. `pq_rbbc_trace_public_key_v1.bin`
2. `pq_rbbc_trace_public_key_certification_v1.json`
3. `pq_rbbc_authenticated_system_initialization_v1.bin`
4. `pq_rbbc_issuance_common_parameters_v1.bin`
5. `pq_rbbc_issuance_production_inputs_independent_review_v1.json`

此外仍缺trusted immutable handoff、independent review、fresh 18-tree interval/stream identities、
production fragment scale qualification、PQ-SE backend、operator resource reservation、execution
authorization及identity-frozen launch manifest。

Historical reservation estimate仍只是589,030,555 rows、至少16 GB memory、64 GB free disk及
8,000--12,000秒；本次沒有新的reservation，因此production execution、large replay與large
proving exact commands均為`null`。

## Exact bounded commands

```bash
PYTHONPATH=src python -u \
  src/pq_rbbc_issuance_fragment_producers_v1.py --self-check

PYTHONPATH=src python -u \
  src/pq_rbbc_issuance_fragment_producers_v1.py \
  --artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT

PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_fragment_producers_v1 -v
```

## Claim matrix

| 狀態 | Bounded producers | Production |
|---|---:|---:|
| Defined | true | interface only |
| Instantiated | true | false |
| Implemented | independent producers／append-only publisher／exact resume | false |
| Tested | positive、negative、mutation、orphan、resume | false |
| Evidence-sealed | bounded metadata | false |
| Proof-closed | false | false |
| Production-closed | false | false |

## Validation與tracked outputs

Targeted regression為14 passed、0 failed、0 skipped（63.926秒）。完整baseline共861 tests，
849 passed、12個既有optional external-artifact skips、0 failed、0 errors（1220.684秒）。
`git diff --check`通過；historical native shard及split lowerer source identity均保持不變。

```text
src/pq_rbbc_issuance_fragment_producers_v1.py
  bytes:   83,785
  sha256:  5695c70364fcbf6f9d04f526e020f81d6a3779e54173642047085ad36f86c6fa

manifests/pq_rbbc_issuance_fragment_producers_manifest_v1.json
  bytes:   7,575
  sha256:  587e5c6ebf78f8c4d0c74363373b4b8ac68f69171dfa6b53a4166019b4288741

artifacts/metadata/issuance_fragment_producers_v1/
  pq_rbbc_issuance_fragment_producers_portable_evidence_v1.json
  bytes:   3,709
  sha256:  0495eab9092e896f59672eb7facf0533bc01f9a7721158649ecc2db04d54ca52
```

## 下一個gate

下一步應建立production 42-stage producer ABI的read-only pre-freeze：把本次五段bounded port schema
scale-neutral化，為18個tree-pre／global-A／18個tree-post／global-B固定fresh namespace、import/
export schema及prospective intervals，但不materialize production rows。External artifacts、review、
resource reservation及execution authorization完整前，large replay與proving必須維持禁止。
