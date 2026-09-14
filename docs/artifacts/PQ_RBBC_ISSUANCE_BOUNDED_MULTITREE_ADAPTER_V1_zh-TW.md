# Issuance bounded multi-tree adapter／per-owner allocator v1

日期：2026-09-14。基線 `47cfd584b4fa1ace9db79a84ccd1be33a3775fd3`，獨立 branch
`codex/pq-rbbc-issuance-bounded-multitree-adapter-v1`。沒有 merge、push、修改 main 或其他
worktree，也沒有改變 system architecture、ticket lifecycle、`pq_sat_auth` 或歷史 evidence。

## Protocol 意義

本 gate 仍在 offline issuance I3 的 CAP child：多棵樹的 leaf commitments、polynomial
plain/mask outputs 必須共同導出 corrections、consistency points、`c_r`、derived mask、
append base 與 `H_RBBC(m,c_r)`。它不是新的 protocol 階段，也不是 `pi_issue` backend。

上一 gate 只定義 42-stage production ABI，本次實際執行 **兩棵各 4 leaves、不同 roots、
degree 3、security bits 0** 的 native adapter。保留 mask 576 bits、append 1,472 bits、witness
2,048 bits、tape 2,450 bits 與共同 386-bit points，但沒有 production 安全性。

原先考慮 4+2 leaves；核對 `pq_rbbc_cap_commit.EXTENSION_MODULI` 後，既有實作只有
degree 3/12/13，沒有 2-leaf 所需 degree 2，因此採 4+4，未改寫或新增 field primitive。
這可測非零跨樹 corrections 與錯樹 binding，**不能**宣稱 mixed degree-12/13 已資格化。

Namespace：`pq-rbbc/issuance/cap576-native/multitree-4plus4-insecure-test-only/v1`。
不同於 production ABI、legacy execution 及 unified-tree profiles；不沿用任一 production tree
的 observed stream bytes、values、assignment 或 portable run evidence。

## 真正暫停與恢復各 owner 的 emitter

新增 private native coroutine source，由未修改的 legacy tree/global-tail generator 在 authoring
時衍生。保留原有 native rows、labels、formulas 與 engine stream encoding；只加入 sink
injection、固定 bounded profile/shape guards、yield boundaries 與 generator type annotations。
Runtime 沒有 AST、exec、monkeypatch 或修改全域 legacy generator。

Tree emitter 在輸出 `p-plain`/`mhat-plain` 後真正 yield。Global-A 等兩棵 pre producers
完成、六個 pre port relocations 成立後才執行；每個 post coroutine 再以其原有局部 state、
private spool 與 **該 tree 自己的 pre-end cursor** 恢復，消費同一 captured point port。
Global-B 等兩個 xi-mask relocations 成立後才執行。

| Stage | 本次檢查的 rows（含該階段額外 binding） |
| --- | ---: |
| bind-inputs | 12,970 |
| tree-pre[0] | 54,070 |
| tree-pre[1] | 54,070 |
| global-a | 19,671 |
| tree-post[0] | 4,734 |
| tree-post[1] | 4,734 |
| global-b | 35,494 |
| bind-child-outputs / final-seal | 0 / 0 |
| 合計 | 185,743 |

Per-owner allocator 固定不重疊 reservations，分別保存 tail、tree[0]、tree[1]、anchors 的
cursor。Wrong owner、global-A end 冒充 tree-post start、重複 allocation、overflow 或未配置
wire 都拒絕。每個 native row 只能引用當前已配置的 local wires 或該階段明確允許的 imports；
pre stage 不允許引用尚未生成的 global points。

## Native binding 與 reference equivalence

Bounded assignment 只保存在記憶體內。每個 native row 在生成時檢查 satisfiability；不是
production archive replay，也沒有把 assignment 寫成 `.f193assign`。

另配置 1,414 個 private anchor input wires，並以 ordinary equality rows 綁定：

- tail salt 與 message；
- 每棵 tree 自己的 salt/root pair；
- 每棵樹的 leaf commitments、p-plain、mhat-plain、xi-masks，共 8 個 relocation ports。

額外 equality rows 共 12,458 條，全部滿足。加上三個 native streams 的 171,871 rows 及
1,414 個 anchor bitness rows，合計 185,743 rows、123,798 allocated wires、0 failures。
Tail input values 可由已知 private fixture 先配置，但 consumer stage 不可在相應 relocations
通過前使用它們；host 值相等或 digest 相等不取代 native equality。

這個 two-tree case 有一組非零 `delta_p = p[0] XOR p[1]` 與
`delta_mhat = mhat[0] XOR mhat[1]`。Mutation tests 改動 tail p/mhat wire，相關 H1 source
constraint 會拒絕；另逐一涵蓋八個 relocation ports 及六組 salt/root/message bindings。

三個 staged native streams 均與另外執行的 unchanged legacy generators 相同，包括 exact
rows、wires、stream bytes 與 canonical stream SHA-256：

| Stream | Rows | Wires | 本次 observed bytes | SHA-256 |
| --- | ---: | ---: | ---: | --- |
| tail | 66,079 | 43,836 | 16,589,734 | `3cc4120442e28ee903f3f251c6727ad97bfdbcf5adcf10d157ab5dfb818b3fa2` |
| tree[0] | 52,896 | 39,274 | 16,764,122 | `e46733ff6019346257cff533bd85a367535c47008db6fc7997032bbfec8bb440` |
| tree[1] | 52,896 | 39,274 | 16,764,127 | `cdf7d394e3cf36e286f54350c34d8241912839adfd5b1e18d82e94ec3c1bf32a` |

Bytes 只是 streaming hash 的計數，未保存 row archive。Table 中每棵樹的 bytes 是其自己的
bounded observation，並未用 tree[0] 的值填入 tree[1]。Engine headers 保持 legacy 格式以
進行 exact comparison；新的 wrapper namespace 和 manifest 明確標示 insecure test-only，
不能把 engine relation 名稱解讀為 production 資格。

## Receipt、snapshot 與暫停邊界

同一個 live session 可在 global-A 後暫停，再傳入 exact previous receipt SHA-256 繼續。
Stage order 必須是連續 prefix；wrong digest、wrong stage 或 wrong point snapshot 在重算／
row emission 前拒絕。Native row 執行中發生錯誤則關閉該 session，不能把部分 state 當作
可恢復 checkpoint。這是 **single-caller、in-process suspension**，不是程序重啟、crash
recovery、concurrent session access、durable publisher 或 production resume。

Receipt 使用 strict canonical JSON，綁定 version、namespace/profile、plan、完整 formal
statement/witness/rho raw、實際 bounded randomness、stage、owner cursors、native stream
prefixes、relocation ports、point snapshot 與 preceding receipt。每條新增 equality 的 label
及三個 exact field forms 亦納入 cumulative digest，不僅記錄 row count。

Point port 的 identity、parse、wire starts、values、invocation/plan binding 全部對應同一份
immutable Snapshot.raw；驗證不重開 pathname。此 gate 的 point/receipt snapshots 是 memory
objects；沒有新增 filesystem publication guarantee。沿用的檔案 capture 仍是 single-open、
single bounded read，metadata 僅為 best-effort signals，不能證明沒有 writer。

Future executor 必須消費同一已驗證 CandidateSet/Invocation snapshots，不得重開候選
pathname。Trusted producer handoff、writer quiescence、owner/mode/ACL、既有 writable FD、
mount namespace 與 filesystem/fsync semantics 仍是 external prerequisites。

Private assignments、point values、live generator state、receipts 與 bounded spool 不進 Git。
Legacy spool helper 使用自動清理的 temporary file；此 gate 未建立持久的 spool artifact、
serialization/resume codec 或 cache。Portable evidence 只有摘要與 digests。

## Resources、tests 與 identities

Bounded planning budget：最多 200,000 wires／300,000 rows（程式強制）、512 MiB memory／
180 秒（規劃，非已保留或強制的 OS quota）。本 gate 不提供 fresh production estimate，
也不把 bounded 耗時外推到 18-tree／589,030,555-row proving。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_bounded_multitree_adapter_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_bounded_multitree_adapter_v1.py --self-check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_bounded_multitree_adapter_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

第一條是唯讀 prerequisite preflight；第二條才執行固定 bounded fixture。Production public
API 和 native helpers 的 production profile branch 均在 fixture construction／output 前
拒絕；production/replay/proving exact commands 仍是 `null`。

Targeted：13 tests，13 passed、0 failures/errors、0 skipped，59.823 秒。
Full baseline：891 tests，879 passed、0 failures/errors、12 skipped，1,282.256 秒。
12 項 skipped 均為未安裝 exact external artifacts 的選用測試；不將 skips 計為通過。
唯讀 CLI exit 0，`read_only_abi_preflight_passed=true`，但 production execution、large
replay／proving authorization 與 commands 仍分別為 false／`null`。

Historical identity：v2.38／v2.39 的 19 份檔案全部通過 exact bytes／SHA-256 核對。
相對基線，既有 source、tests、manifests、artifacts 與 proof 沒有修改；只新增本 gate 的
檔案並追加 PQ-RBBC module handoff，不更新 integration-owned canonical documents。

Plan digest：`729418cf1f9400b729ea02798547d260bf508bb775819456193a4e9270087c84`。
Native binding rows digest：`3b6d9c40756c40aa9e37e49db2e849c313d99790b0bd9dd0b69a2fd435afa3f6`。
Point snapshot SHA-256：`43eceeec2f4b9cda18bc96014bebbaed319e0e7a8a8c04a710a6950828826009`。
Final receipt SHA-256：`e82d57c9edb0b6bf05be5bea5534953e8e91719f2bc049add92635bc50a60801`。
Manifest：6,290 bytes，SHA-256
`aac661c6d32fee9991b8ceb1e28384b9f68df85bfcbdf79e6fa1997feec9db3e`。
Portable evidence：2,511 bytes，SHA-256
`0c795cc9ae502acb9dfc3ebe5048672882f3771e4dec78c41662f55ab938e50b`。

## Claims 與下一 gate

Defined／Instantiated／Implemented／Tested／Evidence-sealed 僅限本 bounded insecure adapter、
allocator、native binding 與 metadata。不同 private fixture 維持相同 topology 並改變 CAP
outputs；variant 1 的 randomness 特意偏離 formal rho，只作 negative isolation fixture。
未宣稱任一 fixture 的完整 formal I1–I5 或 parent join 已成立，也未產生 `pi_issue`。

Production mixed degree-12/13、18 trees／72 relocations、production fragment scale、完整 parent
composition、durable private spool/resume、PQ-SE backend、Proof-closed、Production-closed
與 large replay/proving 全部保持 false。五份 production external inputs 未 provision；trusted
attestations、independent review、operator reservation 與 execution authorization 仍未取得。
Manifest 中保留 predecessor blockers，它們指 production 範圍，不否認本次 bounded 結果。

依 lane ownership，設計理由與測試結果先記錄於本 artifact note，供 integration lane 日後
同步 methodology/experiments/status；本 branch 不回寫 integration-owned canonical docs。

下一 gate：**bounded private-spool canonical codec 與 snapshot-based state handoff**，把目前
live coroutine 所持的必要 private state 移成可明確驗證的 bounded external inputs；之後才做
process restart／durable resume qualification。未取得另外的 production preflight、資源與
授權前，仍不得啟動大型 materialization、replay 或 proving。
