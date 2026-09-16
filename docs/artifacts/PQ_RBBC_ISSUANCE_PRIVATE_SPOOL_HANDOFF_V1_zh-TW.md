# Issuance bounded private-spool codec／snapshot handoff v1

日期：2026-09-14。基線 `c1c2b5d2690643fc136e4c39a867e4376cdb9a97`；獨立 branch
`codex/pq-rbbc-issuance-private-spool-handoff-v1`。不 merge、push、修改 main、v2.43 或其他
worktree；不修改 system architecture、ticket lifecycle、`pq_sat_auth` 或歷史 evidence。

## Protocol 與新增能力

仍在 offline issuance I3 的 `CAP.Commit` child 內。Tree-pre 先產生 leaf tapes／polynomials，
global-A 產生共同 consistency points，tree-post 再完成 Horner evaluation 與 xi-mask outputs。
這是實作 `y = r + H_RBBC(m,c_r)` 所需的內部資料交接，不增加 protocol message，也不是
`Pi_issue.Prove`／`Verify` 或完整 parent join。

上一 gate 的 private spool 只存在 live coroutine／temporary file 中。本次把 **tree-post
確實會使用的 wire records、selected tape bits 與 xi values** 固定成 private binary encoding，
在 global-A 後以五份 immutable snapshots 綁定，並讓 native post stage 消費所接受的 snapshots。
兩棵各 4 leaves、degree 3、security bits 0 的 profile 不變；不是 18-tree production profile，
也不混入 unified-tree namespace 或其他 tree 的 observed bytes。

這只關閉 bounded private-input codec 與 live-session handoff。Allocator、完整 assignment、
global-tail coroutine、tree emitter 的 counters／groups／native prefix hash objects 仍在原程序內。
沒有序列化 Python frames、pickle、hash internal state；沒有 full-session restore、publisher、
checkpoint journal、程序重啟或 crash-safe resume。Memory 中的舊引用也未提供 zeroization 保證。

## 程式介面與檔案權責

- `pq_rbbc_issuance_private_spool_codec_v1.py`：fixed binary codec、bounded scratch spool、
  immutable snapshot reader 與 selected wire/value checks。
- `pq_rbbc_issuance_private_spool_native_v1.py`：由 unchanged bounded tree emitter 衍生；
  改用 bounded memory spool，pre-end 匯出 private raw，post-stage 從 decoded snapshot 取得
  spool／tape witness values／xi masks。Native row formulas、labels 與 stream encoding 不變。
- `pq_rbbc_issuance_private_spool_handoff_v1.py`：`CandidateSet`、唯讀 capture、live-session
  adoption、bounded self-check、manifest 與 metadata builder。

沿用既有 source 的 exact-byte pins，不 monkeypatch 舊 emitter，不以 runtime AST／exec
產生程式。唯一修改的既有檔案是 current module handoff；本 gate 的其他檔案皆為新增。
依 lane ownership，設計理由與實驗結果先記錄於此，供 integration lane 同步 root canonical
documents；此 branch 不自行改寫 methodology、experiments、status 或 system roadmap。

## Versioned canonical private encoding

Wrapper namespace：`pq-rbbc/issuance/private-spool/multitree-4plus4-insecure-test-only/v1`。
Binary magic：`PQRBBC/ISSUANCE/PRIVATE-SPOOL/INSECURE-TEST-ONLY` 加一個 NUL byte。
它不是 production proof、public parameters 或可傳給 issuer 的 public input。

所有 integers 與 packed bit vectors 都是 little-endian；bit index 0 對應最低位。

| 區段 | Exact encoding／大小 |
| --- | --- |
| Magic | 49 bytes |
| Header | `<H32s32s32sBQQHHH`，121 bytes |
| Header fields | version 1；profile、plan、full invocation SHA-256 各 32 bytes；tree index；pre-start、pre-end；leaves 4；record width 2,434；xi bits 1,158 |
| 每個 leaf record 的 wire IDs | 2,434 個 uint64，19,472 bytes |
| 每個 leaf record 的 private bits | 2,434 bits，305 bytes；最後 6 padding bits 必須為 0 |
| Leaf records | 固定四筆，leaf order 0–3，每筆 19,777 bytes |
| Xi masks | 386 個 degree-3 values，合計 1,158 bits／145 bytes；最後 2 padding bits 必須為 0 |
| 整份 spool | 固定 79,423 bytes，不得有 trailing bytes |

Selected tape positions 是 `[0,2048)` 及 `[2064,2450)`：前者提供 Horner witness，後者提供
386-bit mhat tail。中間 16 bits 不被這個 tree-post consumer 使用，故不存入此 codec；不是
把整份 formal witness 或完整 CAP randomness 改成這個格式。Xi values 保持 native algorithm
的輸入形式，最後仍由 ordinary constraints 檢查，不能因 parser 接受就宣稱 relation 成立。

每筆 wire ID 必須在該 tree 自己的 pre interval 內，禁止 0、future／other-owner wires，
同筆及跨 leaf aliases 均拒絕。Header 必須和 caller 提供的 exact immutable `Context` 一致；
bool/int 混淆、unknown version/profile、wrong plan/invocation/tree、length 與 padding mutations
均不能通過適用的 encoder／decoder／handoff checks。

## 五份 snapshots 的交接

固定名稱如下；candidate JSON 不得選擇任意 pathname：

- `handoff.private.json`
- `tree-0.private-spool.bin`
- `tree-1.private-spool.bin`
- `points.private.json`
- `global-a.private-receipt.json`

`capture_candidates(root, expected_handoff_sha256=...)` 先讀 handoff，核對外部提供的 exact
SHA-256，再 strict parse／驗證 closed-world schema，才逐一 capture 四份依賴。它只做
唯讀 identity inventory，不等於 semantic acceptance。Expected digest 必須由可信 producer
handoff 提供；從未信任的同一目錄自行學到 digest，不會建立 authenticity。

`HandoffSessionInsecureTestOnly.accept_handoff(...)` 只在 exact global-A prefix 接受一次。
它要求 handoff 對應此 session 的 full invocation／plan／receipt／point／spool identities，
比對每份 dependency 的 identity 後，以同一 raw 解碼／驗證，再逐一比較 19,472 個 unique
selected wire/value bindings。Wrong or stale input 在 native row emission 前拒絕。

Tree-post 消費 `AcceptedHandoffInsecureTestOnly` 內的同一 spool snapshots；native coroutine
本身另核對 pre-end 保存的 spool digest。Post stage 不重跑 tree-pre／CAP seed expansion，
也不重開 pathname。Global-A point snapshot 與原生 point wires 仍由原有 validation 綁定。
Full native stream equivalence 與其普通 constraints 沒有被 host digest comparison 取代。

錯誤 handoff 不改動 rows、owner cursors 或 accepted state；修正後可在同一 live prefix 重試。
若 native execution 本身失敗，沿用既有 session fail-closed 行為；沒有部分 state 的 durable
recovery 保證。Repeated adoption、wrong stage 及沒有 handoff 的 tree-post 均拒絕。

## Snapshot 與部署邊界

每個 input file 為 single-open、single bounded read。底層 `read_snapshot` 的 read cap 為
1 MiB；上層再對 captured bytes 套用更小的 object limits。Identity、strict JSON／binary
decode、binding 與 consumer 都只使用相同 immutable `Snapshot.raw`。不重讀 pathname
取得第二份內容作為安全保證，不以增加 stat、sleep 或 advisory lock 宣稱強不可變性。

Controlled regression 在舊 spool bytes 完整 capture 後，對同 inode 做同長度原地改寫，並
讓 metadata signals 保持舊值。此時接受已 capture 的舊 bytes 是合法結果；後續檔案內容
不同，不會取代該 snapshot。測試在禁止 pathname reopen／CAP reconstruction 的條件下，
用該 snapshot 完成兩個 tree-post，結果與 fresh native execution 相同。

Metadata 只能作 best-effort mutation signals，不能證明 capture 期間沒有 writer。
Future executor 必須直接消費已驗證 CandidateSet／Invocation snapshots，不得重新打開
candidate pathname。Trusted producer handoff、writer quiescence、owner/mode/ACL、既有
writable FD、mount namespace、filesystem/fsync semantics 與 confidentiality 仍是部署前提。
本 codec 是 plaintext private state，**不是加密、存取控制或安全擦除機制**。

## 本次 bounded evidence

兩棵 spool 各 79,423 bytes；五份 private snapshots 合計 161,908 bytes。Native execution
仍為 185,743 rows、123,798 wires、12,458 binding rows、8 relocation ports、0 failures；
tail／tree[0]／tree[1] 的 rows、wires、stream bytes／SHA-256 各自與 unchanged legacy
generators 相同。這些是本次實際 bounded execution 的檢查，不是新 production observations。

| Identity | SHA-256 |
| --- | --- |
| tree-0 private spool | `3a41227c83fa34c2eb38922f962c7024a80c432a31e93a74994cca45d97169d0` |
| tree-1 private spool | `5212a7c1e6ade7882051d223499fa9083fa1a88889a7745f72fc5b9a19946973` |
| handoff（1,035 bytes） | `ff95140fe4fc0a34ab41360553ae7bdb0f3bb93b2c1537f5742810da572d0c8d` |
| native final receipt（與 predecessor 相同） | `e82d57c9edb0b6bf05be5bea5534953e8e91719f2bc049add92635bc50a60801` |
| manifest（8,521 bytes） | `10ed0e3b1fe25855d44cbfbde6ae125506afcee3c33a2741d34ad88690b196a8` |
| portable evidence（3,497 bytes） | `da285f2958687d8b93381eacf5e80d5e4cbc16407564c9371f08dfa17572e802` |

Git 只存 source、tests、manifest、path-free metadata 與文件；不存上述 private binary／JSON
payloads、完整 assignment、spool、receipt、checkpoint、resume state、pickle、cache、logs、
BR1CS 或 proving output。External-file tests 僅在自動清理的 private temporary directories
建立 fixture files；本 gate 沒有提供持久的 private-output publisher。

## Resources 與驗證

Bounded fixture 不變：最多 200,000 wires／300,000 rows（程式強制）；512 MiB memory／
180 秒（規劃值，不是已保留或強制的 OS quota）。Accepted candidate set 上限 177,278 bytes，
單次 capture 底層上限 1 MiB。不得從本次尺寸／時間線性外推 18-tree 或 589,030,555-row proving。

環境：Linux 6.8.0-138-generic x86_64；AMD Ryzen 5 7600X，6 cores／12 logical CPUs；
30 GiB RAM；Python 3.12.9。檢查當下約 27 GiB available，這不是 operator reservation。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_private_spool_handoff_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_private_spool_handoff_v1.py --self-check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_private_spool_handoff_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

唯讀 preflight exit 0；bounded self-check 通過。Targeted 最終結果為 11 passed、0 failures／
errors／skips，35.783 秒。開發時首次 targeted 的 metadata 比對因尚未生成 manifest 報缺件；
metadata 建立後完整重跑通過，沒有把該初次未完成結果計作通過。
Full baseline：902 tests，890 passed、0 failures/errors、12 skipped，1,309.974 秒，exit 0。
Skips 全部是既有 v2.13–v2.25 optional external artifacts 未安裝，不計入 passed。
Historical identity：v2.38／v2.39 的 19 份 exact bytes／SHA-256 全部不變。

## Claims 與下一 gate

| 層級 | 本次可宣稱範圍 |
| --- | --- |
| Defined | Bounded private spool、five-snapshot handoff 與 trusted-digest interface |
| Instantiated | 兩棵 4-leaf、degree-3 insecure test-only fixture |
| Implemented | Strict codec、memory scratch spool、same-snapshot native post consumer |
| Tested | Positive、mutation、wrong-version/domain/statement、trailing、controlled in-place capture |
| Evidence-sealed | Exact source／manifest 與 bounded path-free metadata，不含 private outputs |
| Proof-closed | false |
| Production-closed | false |

Full-session restore、durable resume、concurrency／power-loss qualification、production mixed
degree-12/13、18-tree／72 relocations、fresh formal I1–I5／parent composition、PQ-SE backend、
正式 `pi_issue` 與 large replay／proving 均未完成。五份 production external inputs 未 provision，
independent review、resource reservation 與大型 execution authorization 仍缺。
Manifest 沿用的 predecessor blockers 指 production 範圍，不能解讀成這次 bounded codec 未實作。

下一 gate：建立 **bounded independently invocable tree-post consumer 與 explicit continuation
state contract**，盤點原程序仍持有的 cursor／groups／prefix-hash 與 tail state，選擇可驗證的
fragment composition 邊界；其後才實作 private append-only publication、process restart 與
controlled crash recovery。不能把這五份 snapshots 當成已完整的 restart checkpoint。
