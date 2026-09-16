# Issuance bounded independent tree-post／continuation contract v1

日期：2026-09-14；SRR-01 corrective：2026-09-15。原始基線為
`0e4e2d792716b08be07901e34aa4439bacf469a0`；corrective 基線為
`ca6d4a43d7b2ebf728c660b4df0abaf526714544`，獨立 branch
`codex/pq-rbbc-tree-post-srr01-corrective`。本 gate 不修改 `main`、system
architecture、ticket lifecycle、`pq_sat_auth`、legacy 18-tree profile 或歷史 evidence。

## Protocol 位置與目的

本工作仍位於 offline issuance I3 的 `CAP.Commit` child：

```text
tree-pre ── private spool ──┐
                            ├── global-A points ── tree-post ── xi-mask output
global tail phase A ────────┘
```

上一 gate 已固定 private spool 與 five-snapshot handoff，但 tree-post 仍必須恢復同一個
Python generator；allocator、sink、group counters 與 `hashlib` state 也留在原程序。本 gate
新增真正可獨立呼叫的 bounded tree-post consumer。Consumer 只接受已 capture 的 handoff、
tree-specific private spool、global-A points、ordinal 2／3 receipt snapshots 及 canonical continuation bytes，
不重跑 tree-pre、不重建 CAP，也不重新開啟 pathname。

這沒有改變 protocol message，也不是正式 `Pi_issue.Prove`／`Verify`、parent join、完整 CAP
provider 或 production proof。

## Explicit continuation-state contract

兩份固定名稱的 private metadata continuations 為：

- `tree-0.post-continuation.private.json`
- `tree-1.post-continuation.private.json`

每份最多 16,384 bytes，使用 format
`PQRBBC-ISSUANCE-TREE-POST-CONTINUATION-1` 與 relation namespace
`pq-rbbc/issuance/tree-post-continuation/multitree-4plus4-insecure-test-only/v1`。
Unknown version/domain、欄位增減、trailing bytes、duplicate key、錯誤 tree/cursor/interval、
dependency、verified receipt suffix、group、output layout 或 claim boolean 均拒絕。

Continuation 明確序列化：

- tree index、absolute pre/post intervals 與 owner cursor；
- ordered pre-group rows／bytes／SHA-256；
- native prefix commitment；
- verified ordinal 2／3 receipt snapshot identities；
- handoff、private spool、points、ordinal 2 與 global-A receipt identities；
- spool 內 selected pre-wire/value 與 point snapshot 的 wire/value contract；
- tree-post xi-mask output port layout。

Continuation 明確**不序列化**：

- Python generator frame；
- allocator mutable object；
- full assignment；
- tree／tail sink 的 `hashlib` internal state；
- tail generator、native binding hash internal state；
- global-tail continuation state。

因此 `native_prefix_sha256` 只是對舊 prefix bytes 的 commitment，不是可移植或可恢復的
SHA-256 chaining state。Standalone fragment 使用新的 domain-separated stream header；可驗證
composition boundary 是：

```text
ordered group identities
+ absolute wire interval
+ captured dependency identities
+ captured ordinal 2 raw SHA-256 == ordinal 3 previous_receipt_sha256
```

SRR-01 後的 contract **只宣稱 verified two-entry suffix**。Ordinal 2
(`tree-pre[1]`) 與 ordinal 3 (`global-a`) 皆以同一 capture batch 的 single-open、
single-bounded-read `Snapshot.raw` 驗證 strict JSON、ordinal、stage、invocation、rows、cursor、
relocation 與 canonical encoding，並驗證唯一可證明的 2→3 link。Earlier ordinal 0／1 raw
未被攜帶，因此不再有 `receipt_chain_sha256` 四筆欄位，也不宣稱完整 receipt chain；ordinal 2
的 `previous_receipt_sha256` 僅驗證 canonical digest shape，不宣稱已連到 ordinal 1。

不能把兩段 SHA-256 digest 串接成 legacy monolithic stream digest，也不能宣稱已恢復舊
generator。

## Standalone tree-post consumer

`execute_tree_post_insecure_test_only(...)` 的輸入只有 immutable
`TreePostInvocationInsecureTestOnly` 與兩個 caller-provided exact SHA-256 pins。所有依賴都從
同一 CandidateSet snapshots 解碼；執行函式沒有 pathname，也不呼叫 live session、tree-pre
generator 或 `execute_cap_commit`。

每棵樹只匯入：

| Import | Wires |
| --- | ---: |
| private spool selected wires | 9,736 |
| two global-A field points | 386 |
| total unique imports | 10,122 |

Fresh fragment sink 從該 owner 的 exact post cursor 開始，只允許引用上述 imports 與同一
post interval 內已配置的 wires。每條 native row 都由 captured/imported values 即時檢查；
任何 undeclared、future 或缺值 wire 都 fail closed。

Consumer 回傳 in-memory post-owned values、xi-mask `ProducerPort` 與 private receipt。它確實
在記憶體建立 2,412 個 post fragment assignment values，但沒有 materialize 或發布完整
assignment。Receipt 只供 private handoff；Git 的 portable evidence 不嵌入 continuation、
spool、points、receipt 或 assignment bytes。

## Bounded qualification

Fixture 維持兩棵各 4 leaves、degree 3、security bits 0；production widths 576／1,472 bits
不變。兩個 independently invoked consumers 的結果如下：

| Tree | Post interval | Rows | New wires | Fragment stream SHA-256 |
| ---: | --- | ---: | ---: | --- |
| 0 | `[80699,83111)` | 3,576 | 2,412 | `c650222f753db29f782effef037d47872c218c3871355b676b722130b501f54e` |
| 1 | `[119973,122385)` | 3,576 | 2,412 | `a5797cb75ccb3072f29c7fe1b6e2c9ea619183524600e6c3d5647cc5837a1347` |

每棵的 ordered `tree-post-horner`／`tree-post-output-port` group rows、bytes 與 binary-row
SHA-256，xi output port 及全部 2,412 個 post-owned values，均與 unchanged live native
emitter 相同。合計實際檢查 7,152 rows，0 failures、0 external assertions。第二組 private
fixture 保持相同 row/group contract，但產生不同 output values，確認 consumer 不是固定輸出。

Frozen private identities：

| Object | Bytes | SHA-256 |
| --- | ---: | --- |
| ordinal-2 receipt snapshot | 1,306 | `29a0768e66e15ec989a0b44c98c500688618ec96683b7a171725670d6e14c523` |
| ordinal-3 global-A receipt snapshot | 1,365 | `0573e1b7fb340fcffce9d6cc6f90b3e2c4c2e43e00b6faa59ad528d0f0f427dc` |
| tree-0 continuation | 3,829 | `d68382b393f66e6fcd1374985aa2f70d9d39c7a092756ac9bd954810bbba2bc9` |
| tree-1 continuation | 3,835 | `d2f6bcaad813ae59ebd200512d37fbaae8afcdc604b534009f8d84949c6bdc72` |
| tree-0 post receipt | 2,821 | `1097dee376f9e3a338362e6b74168f3e1e7ac8f772df13408fe0da785b45203c` |
| tree-1 post receipt | 2,824 | `99fd35afa855c184c4dfe482067bb8e77f921cab8a84673ad1b7650ef380a970` |

這些 receipt identities 間接綁定 test-only private assignment digest；receipt bytes 本身不進
Git，也不是 production evidence。

## Snapshot 與部署邊界

Capture 使用固定名稱、single-open、single bounded read。Identity、strict parse、binding 與
consumer 都使用相同 immutable raw。受控 regression 在 capture 後修改 pathname 內容，
consumer 仍只使用已捕捉 bytes；沒有重新開啟 candidate pathname。

這不證明 capture 期間沒有 writer。Metadata 仍只是 best-effort mutation signals；trusted
producer handoff、writer quiescence、owner/mode/ACL、既有 writable FD、mount namespace、
filesystem/fsync semantics 與 confidentiality 都是部署前提。Private spool 與 post assignment
是 plaintext secret state，沒有加密或 zeroization 保證。

## Resources、commands 與驗證

程式仍強制 bounded fixture 的 200,000 wires／300,000 rows 上限；規劃值為 512 MiB memory
與 180 秒。這不是 OS reservation，也不得線性外推 legacy18 或 589,030,555-row proving。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_tree_post_continuation_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_tree_post_continuation_v1.py --self-check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_tree_post_continuation_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

Corrective combined targeted 最終結果：38 passed、0 failures/errors/skips，114.929 秒；其中
continuation 模組 19 tests。完整 baseline 共 940 tests，928 passed、12 個既有 optional
external-artifact skips、0 failures/errors，1,403.316 秒，exit 0。V2.38／v2.39 的 19 份
historical bytes／SHA-256 已逐檔核對不變。

Machine identities：

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| source | 64,057 | `40147e14f1d14db87d4ec2fd223de1037695c3b7a1ed5a0fac3041fc50005bc3` |
| tests | 28,444 | `d96a4fad476e39740b4896b8e056b4a931a89d164274935f6419936432a20aad` |
| manifest | 9,540 | `5de22b1a9cb931b1571e69c4cb2d70a4b99e1efe71f978fcc2ada90e2a566857` |
| portable evidence | 3,635 | `3638c786d90af28e5b286c3da3854823324801cc387bfb57589c7d69bbcb7bbe` |

## Claim boundary 與下一 gate

| 層級 | 本 gate 可宣稱範圍 |
| --- | --- |
| Defined | explicit tree-post continuation 與 fragment composition contract |
| Instantiated | two-tree／four-leaf／degree-3 insecure-test-only fixture |
| Implemented | independently invocable tree-post consumer、strict continuation/receipt validators |
| Tested | positive、alternate private input、negative、mutation、capture/path replacement |
| Evidence-sealed | bounded metadata-only evidence，不含 private payload |
| Proof-closed | false |
| Production-closed | false |

尚未完成 full-session restore、durable resume、private append-only publisher、controlled
process-death recovery、global-tail independent consumer、production degree-12/13、legacy 18-tree／
72 relocations、fresh I1--I5／parent composition、PQ-SE backend、正式 `pi_issue` 或大型 replay。
五份 production external inputs、independent review、resource reservation 與大型 execution
authorization 仍未 provision。

下一 gate：建立 **private append-only continuation/result publication 與 one-tree process
restart／controlled crash recovery qualification**。該 gate 才能證明另一個程序從已發布的
snapshots 執行 tree-post；其後仍須為 global-A/global-B tail 定義可獨立恢復的 state，才能組成
完整 legacy18 provider。
