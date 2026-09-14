# Issuance bounded independent tree-post／continuation contract v1

日期：2026-09-14。基線為 `0e4e2d792716b08be07901e34aa4439bacf469a0`；獨立 branch
`codex/pq-rbbc-issuance-tree-post-continuation-v1`。本 gate 不修改 `main`、system
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
tree-specific private spool、global-A points、global-A receipt 及 canonical continuation bytes，
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
dependency、receipt chain、group、output layout 或 claim boolean 均拒絕。

Continuation 明確序列化：

- tree index、absolute pre/post intervals 與 owner cursor；
- ordered pre-group rows／bytes／SHA-256；
- native prefix commitment；
- receipt-chain commitments；
- handoff、private spool、points 與 global-A receipt identities；
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
+ receipt chain
```

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
| tree-0 continuation | 3,593 | `86ebf3cd87445b105764966859e7255514bd5e5a09ac0e9071435173a2133c09` |
| tree-1 continuation | 3,599 | `210365f8a96ba8b435a05af3e9e2a2f3ffb4731e2d7853f508738e55b5fb48ce` |
| tree-0 post receipt | 2,804 | `7161cbfbe1701ca09b8c9348cfb71b42857acc5011e633312642e1eab5a2457d` |
| tree-1 post receipt | 2,807 | `7b5a3ff16236a8de2f9933c701f76576107c39e668fa1f7f4ec533468f6d2720` |

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

Targeted 最終結果：15 passed、0 failures/errors/skips，54.441 秒。完整 baseline 共 917
tests，905 passed、12 個既有 optional external-artifact skips、0 failures/errors，
1,339.203 秒，exit 0。V2.38／v2.39 的 19 份 historical bytes／SHA-256 已逐檔核對不變。

Machine identities：

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| source | 59,398 | `c604f3c9c0019b6f95ac7faa6c6c21d73cace894602797e1ab08b29cf452f8b0` |
| tests | 19,627 | `1ffc076f4d82b0a2126d3d6dd9a6752fdb5aa4eaf297d092f0ce049b1246d473` |
| manifest | 8,733 | `be861dedf84074d31cfeda3e48ffbab80a270f685c4b3076cbc81ef0cd028a75` |
| portable evidence | 3,249 | `fd2b14ff298d7643d3f7f4c5f90aa6c851decca2f37034cb8baeae6944292541` |

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
