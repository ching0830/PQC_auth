# PQ-RBBC issuance split runner／atomic publisher checkpoint v1

日期：2026-09-13

## 教學摘要

影響的protocol步驟：issuance relation I3內部的`CAP.Commit` child。

使用者可觀察的protocol bytes：沒有改變。正式statement、ticket、proof或parent input均未
產生新production encoding。

這次實際執行：以production width／one-tree／4-leaf insecure test-only topology，把CAP
value computation依真正相依關係拆成`tree-pre → global-A → tree-post → global-B`，再把六個
stage及七個receipt以append-only方式發布到私有臨時external root。Fresh、controlled
interruption、orphan adoption、resume、mutation及two-process race均有測試。

新增能力：future runner已有明確的stage bytes、output identity、receipt chain、exclusive
publication與resume contract。

仍不能做：production constraint-stream split lowering、18-tree replay、完整I3 relation、
`pi_issue` Prove/Verify、security或production closure。

## Protocol相依關係

Formal I3為：

```text
(r, c_r) <- CAP.Commit(r || x; rho)
h          = H_RBBC(M, c_r)
beta       = r XOR h
```

`CAP.Commit`內部不能把每棵tree視為完全獨立的monolithic job。Exact order是：

```text
tree-pre[i]:
    expand roots → leaves
    compute leaf commitments and tapes
    output leaf-commitments, p_plain, mhat_plain

global phase A:
    consume every tree-pre output
    compute delta_p, delta_mhat, h1, consistency points and alpha

tree-post[i]:
    consume tree i polynomial masks and global consistency points
    output xi_masks

global phase B:
    consume every xi_masks output
    compute h2, c_r, derived mask, append base and request hash
```

所以production plan仍是前一gate固定的42 stages；本gate用一棵4-leaf tree縮成六個
stages，驗證ordering、encoding與publication state machine。它沒有把legacy monolithic
tree producer改名成fresh runner，也沒有修改任何historical producer source。

## Bounded split execution

Namespace：

```text
pq-rbbc/issuance/cap576-native/split-runner-4leaf-insecure-test-only/v1
```

Profile維持production widths：576-bit mask、1,472-bit appended signature、2,048-bit witness
及2,450-bit random polynomial；安全topology故意縮為一棵4-leaf tree、extension degree 3、
security bits 0。

Exact stage order：

1. `bind-invocation`
2. `tree-pre[0]`
3. `global-tail-phase-a`
4. `tree-post[0]`
5. `global-tail-phase-b`
6. `final-seal`

`tree-pre[0]`直接使用same `RhoSnapshot.raw`的salt／first root pair執行seed derivation、leaf
commit與tape expansion；其程式路徑不接受global points。Global-A才執行H1與consistency-point
XOF；tree-post之後才執行mask polynomial evaluation；global-B最後執行H2、commitment
serialization與request binding。

Split結果與既有`execute_cap_commit` direct reference逐值比較，commitment與request hash完全
一致。這驗證value-layer decomposition，不是native constraint rows的split lowering；本次
replayed large rows為0，也沒有建立assignment或row archive。

Formal fixture的blind mask仍不等於4-leaf derived mask，因此
`formal_i3_relation_replayed=false`與`full_i3_relation_claimed=false`。

Frozen bounded identities：

- plan：`5655cbb5f751618fa3acf0a7839ebd540103fcfd037f0ae43aec5fc595d442b6`
- complete：`34d1aecd0358b37c57ff11d81eb5422ef3ef73606c6b05f72a8b10e7f6e16c07`
- final receipt：`56fce4aa4606faf155cc66ac4dd8993540fd0a64854fdd39cb490f6fe63db4af`
- tree-pre stage：`fafcdfa05aea090491fa220489cfb2319e9dc166e30d924bb68599006c4d7b3a`
- global-B stage：`42ab676600d7d8a52528be5f4a10f7a9112dd2815d8f0fec9cb2f6c9e0b90ee6`

## Stage artifact contract

每個stage為closed-world canonical JSON object，固定：

- version、test-only mode、relation/profile/plan/invocation及ordinal/stage ID；
- previous receipt SHA-256；
- canonical payload bytes/length/SHA-256；
- relation/profile/plan/invocation/stage-bound `StageOutputIdentityV1`；
- ordered output port IDs、exact bit lengths及value digests；
- rows/wires/row-stream observations皆為0，因本gate沒有lower constraints；
- assignment、external assertions、verification failures皆為0。

Tree-pre payload含bounded private polynomial material；global-A、tree-post與global-B也含private
fixture intermediates。這些runtime files只能存在operator指定的私有external root，不能提交
Git或放進portable evidence。Portable evidence只保存其identities及控制流程結果。

Strict validation拒絕wrong version/domain/profile/plan/invocation/stage、unknown fields、payload
mutation、output mutation、noncanonical JSON及trailing bytes。Consumer不能只因schema parse
成功就接受output，必須提供預期execution domain並逐byte比對deterministic computation。

## Atomic publication與resume

Publisher沿用identity-verified `pq_rbbc_recovery_io_v2_42`：

```text
private external root
└── output/
    ├── receipt-000.json          # genesis
    ├── stage-000.json
    ├── receipt-001.json
    ├── ...
    ├── stage-005.json
    ├── receipt-006.json
    └── complete.json
```

每個stage、receipt與complete檔案分別使用Linux
`O_TMPFILE → write → file fsync → linkat-if-absent → directory fsync`發布；destination存在或為
dangling symlink時不得truncate／replace。Output directory使用cooperative exclusive
`flock`，同一process死亡時lock由OS釋放。

Stage與receipt不是一個跨檔案transaction。若stage已durable、receipt尚未發布，resume只
允許一個exact next-stage orphan：重新計算expected bytes並比對同一captured raw，完全一致
才追加receipt；不替換原inode。Receipt prefix若gap、stage缺少、存在多餘／unknown entries或
bytes變更即fail closed。

Resume caller必須提供latest receipt SHA-256。Runner在持有output lock時先single-open capture
latest receipt並比對外部digest，之後才執行CAP stage recomputation及其餘artifact reads。
每份artifact的identity、strict parse與validation使用同一`Snapshot.raw`，不以第二次pathname
read取代captured bytes。

Bounded qualification觀察：

- complete output固定14 files；
- fresh與stage 3後resume的所有filename/bytes完全一致；
- repeated resume保持bytes及inode不變；
- stage成功發布、receipt前受控中斷時，resume採用exact orphan且inode不變；
- wrong external checkpoint在stage recomputation前拒絕；
- mutation、trailing bytes、unknown、gap、missing及dangling symlink皆拒絕，失敗後不新增output；
- two-process fresh race恰有一個winner；
- production entry point在碰觸output前拒絕。

## Filesystem claim boundary

本gate證明的是bounded cooperative-writer、controlled fault-window contract。它不宣稱：

- `flock`能排除同credential malicious writer；
- stat metadata能證明capture期間沒有writer；
- stage＋receipt是一般filesystem上的單一atomic transaction；
- 已完成實體斷電、kernel crash、remount、network filesystem或production-scale測試。

Trusted producer handoff、writer quiescence、owner/mode/ACL、既有writable FD、mount namespace
與可信filesystem/fsync語義仍是部署前提。若要求對任意concurrent writer提供強不可變性，
必須另有可信immutable handoff或OS/filesystem enforcement，不能靠增加stat、sleep、重讀或
advisory lock宣稱解決。

## External blockers與資源

五份production external artifacts仍未安裝：

1. `pq_rbbc_trace_public_key_v1.bin`
2. `pq_rbbc_trace_public_key_certification_v1.json`
3. `pq_rbbc_authenticated_system_initialization_v1.bin`
4. `pq_rbbc_issuance_common_parameters_v1.bin`
5. `pq_rbbc_issuance_production_inputs_independent_review_v1.json`

此外仍缺production constraint split lowerer、atomic publisher production-scale qualification、
trusted handoff、independent review、PQ-SE backend、resource reservation及large-run
authorization。

Historical reservation baseline仍只可作估算：589,030,555 rows、至少16 GB memory、64 GB
free disk及8,000--12,000秒。未取得新的reservation前不是可執行command。

## Exact commands

Bounded self-check：

```bash
PYTHONPATH=src python -u src/pq_rbbc_issuance_split_runner_v1.py --self-check
```

Read-only external inventory：

```bash
PYTHONPATH=src python -u src/pq_rbbc_issuance_split_runner_v1.py \
  --artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT
```

Targeted tests：

```bash
PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_split_runner_v1 -v
```

Production execution、large replay及large proving commands均為`null`。

## Claim matrix

| 狀態 | Bounded value split/publisher | Production |
|---|---:|---:|
| Defined | true | stage contract only |
| Instantiated | true | false |
| Implemented | true | constraint split runner false |
| Tested | positive/fault/mutation/concurrency true | false |
| Evidence-sealed | bounded metadata true | false |
| Proof-closed | false | false |
| Production-closed | false | false |

Tracked outputs：

```text
src/pq_rbbc_issuance_split_runner_v1.py
  bytes:   59,823
  sha256:  228aa95776d03d2a15b8f71edd5c923b8817f030d8d0244b895c1714295c7e65

manifests/pq_rbbc_issuance_split_runner_manifest_v1.json
  bytes:   8,334
  sha256:  6031d3cc949b0202ba6eb35fcad6688dee864d6a7971d4381c94c5b29a3b0b84

artifacts/metadata/issuance_split_runner_v1/
  pq_rbbc_issuance_split_runner_portable_evidence_v1.json
  bytes:   2,243
  sha256:  6d65c0808a32b6871a8b07559a81911368306c55c238a3040a10857be72abbd5
```

Targeted regression為18 passed、0 failed、0 skipped（204.449秒）。完整baseline共830 tests，
818 passed、12個既有optional external-artifact skips、0 failed、0 errors（1103.658秒）。

## 下一個gate

下一步建立bounded native constraint-stream split lowerer：把tree-pre與tree-post row groups
真正分成獨立relation fragments，固定global-A point import/export wires，逐row比對合併後與
現有monolithic native relation的semantics/accounting，並讓resume從已驗證stage payload開始，
不必重新執行所有已完成value stages。它仍只能使用test-only topology；external artifacts、
review與reservation未完成前不得啟動production 18-tree replay。
