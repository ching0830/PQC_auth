# Protocol 到工程實作導覽

> 用途：把論文中的 protocol／公式，對應到 canonical bytes、relation、circuit、assignment、tests 與 evidence。
> 本文件是教學與導覽層，不是最新狀態或 production claim 的 canonical source。
> 最新狀態以 `RESEARCH_STATUS_zh-TW.md` 為準；PQ-RBBC 操作進度以 `docs/roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md` 為準；任何散文宣稱都不得超過 manifests、tests 與 proof evidence。

## 1. 先建立正確的心智模型

論文通常把一個密碼學動作寫成一行：

```text
pi_issue <- Prove(crs, x, w)
```

工程實作則必須把這一行展開成：

```text
Protocol semantics
    ↓
Canonical bytes / API
    ↓
Relation R(x, w)
    ↓
Circuit constraints
    ↓
Concrete assignment
    ↓
Full relation replay
    ↓
PQ proof backend Prove / Verify
    ↓
Proof bytes and protocol messages
    ↓
Benchmark and system integration
```

目前經常出現在 RBBC handoff 的 tree、row、assignment、replay、manifest 與
preflight，主要位於中間的 circuit／assignment／replay／evidence 層。它們不是新
protocol 階段，而是把既有 protocol 公式變成可執行、可重現實作所需的工程步驟。

## 2. 五層翻譯法

閱讀任何實作或 checkpoint 時，依序回答以下五個問題。若文件無法回答，代表該
checkpoint 的教學說明仍不完整。

| 層 | 必問問題 | 典型產物 |
| --- | --- | --- |
| L1 Protocol | 哪個角色在何時做什麼？保護哪個安全目標？ | protocol step、公式、security game |
| L2 Data／API | 真正輸入、輸出與傳輸的 exact bytes 是什麼？哪些值公開或隱藏？ | canonical encoding、domain label、API |
| L3 Relation／Circuit | 合法性被拆成哪些關係？每個關係由哪些 constraints 強制？ | relation、rows、wires、constraint generator |
| L4 Execution／Evidence | 給定一組 statement／witness，實際跑了什麼？錯誤資料是否被拒絕？ | assignment、replay、mutation tests、manifest |
| L5 Cryptographic／System closure | 不公開 witness 時能否產生 proof？能否進入真實 protocol？成本多少？ | prover/verifier、proof bytes、benchmark、integration test |

只完成 L4，不代表 L5 完成。特別是 full replay 會取得完整 witness／assignment；真實
zero-knowledge verifier 只能取得 public statement 與 proof bytes。

## 3. 常見工程詞彙

| 詞彙 | 在本專案中的意思 | 不能自動推論 |
| --- | --- | --- |
| Statement `x` | Verifier 可以知道的 public inputs | 不代表 encoding 已 canonical freeze |
| Witness `w` | Prover 必須知道但不應公開的秘密資料 | 不代表 witness 生成安全或 side-channel safe |
| Relation `R(x,w)` | 判定 statement 與 witness 是否一致的規則 | 不等於已存在 ZK proof system |
| Circuit | 把 relation 降成 backend 可處理的簡單代數關係 | 不等於 security reduction |
| Row／constraint | Circuit 中的一項局部等式或檢查 | row 多寡不能直接換算 proof bytes 或秒數 |
| Wire | Circuit 中承載輸入、中間值或輸出的變數位置 | 相同數值不等於相同 wire identity |
| Assignment | 某次具體 statement／witness 對所有 wires 的取值 | 不應放進真實 ZK verifier |
| Materialize | 實際產生 relation、row stream 或 assignment，而非只列公式／估計 | 不代表完整 composition 已完成 |
| Replay | 重新逐 row 檢查 assignment 是否滿足 relation | 不等於 `Verify(statement, proof)` |
| Mutation test | 改動輸入、wire 或 artifact，確認 ordinary constraints 會拒絕 | 不取代 cryptographic proof |
| Aggregate | 將原本分段的 producers／relations 放入共同 namespace 與執行 | 不代表 parent output 已正確接入 |
| Parent join | 把子電路輸出以 exact wires 接入上一層 relation | 不代表 PQ backend 已接入 |
| Profile | 一組完整參數、topology、hash domain、encoding 與安全目標 | 同名高階 primitive 的不同 profile 不可混用 evidence |
| Namespace／fingerprint | 防止不同 profile／版本的 bytes 或 evidence 被混淆 | 不表示該 profile 已實作或安全合格 |
| Preflight | 動工前核對輸入 identity、阻擋條件、資源與允許的下一步 | `preflight_closed` 不等於 production closed |
| Manifest | Machine-readable 的參數、identity、metrics 與 claim boundary | 不取代實際 artifact 或 proof |
| Checksum | 驗證檔案 exact identity | identity 正確不等於 relation 已 replay |
| Portable evidence | 移除本機路徑後保存可核對的執行摘要 | 必須受原始 manifest／artifact／tests 約束 |
| Backend | 將 relation 編譯成真正 `Prove`／`Verify` 的密碼學證明系統 | 有 backend 名稱不等於已 qualification |

## 4. 整個系統的 protocol 與工程模組

| Protocol 階段 | 高階輸入／輸出 | 主要工程位置 | 狀態查詢位置 |
| --- | --- | --- | --- |
| System initialization | FAC、issuer、OA keys、public configuration／parameters | architecture；未來各 primitive adapters | `ARCHITECTURE_zh-TW.md`、`RESEARCH_STATUS_zh-TW.md` |
| Issuer authorization | epoch／policy／quota-bound authorization | 尚待 federation module | `ROADMAP_zh-TW.md` T2 |
| Enrollment／offline issuance | authenticated `rid` → blind response → ticket `T` | `src/pq_rbbc_*.py`、`tests/test_pq_rbbc_*.py`、manifests、proof | RBBC current handoff |
| Satellite access | ticket＋freshness／key shares → session | `src/pq_sat_auth/access.py`、`framing.py` | one-time ticket spec、system tests |
| One-time consumption | `UNSEEN → RESERVED → CONSUMED` | `src/pq_sat_auth/identities.py`、`replay.py` | one-time ticket spec、system tests |
| Handover | existing session → new serving context | 尚待 specification／implementation | `ROADMAP_zh-TW.md` T6 |
| Conditional opening | authorized case＋ticket → threshold shares → identity | core proof abstract interface；production module 未完成 | architecture、status、future opening spec |
| Evaluation | communication、time、memory、storage、latency | instrumentation 與 experiment records | `experiments.md` |

上表的「主要工程位置」是導航，不是完成宣告。精確成熟度只由
`RESEARCH_STATUS_zh-TW.md` 判定。

## 5. Offline issuance：逐行對應

### 5.1 建立 ticket 與 trace ciphertext

Protocol 概念：

```text
C <- TraceEnc(tpk, ctx, holder binding; rid, sn, randomness)
M <- (ctx, sn, holder binding, C)
m <- H_ticket(Encode(M))
```

工程對應：

- `src/pq_rbbc_reference.py`
  - `TicketPayload`：ticket payload 的 reference representation；
  - `IssueStatement`／`IssueWitness`：relation 的 public／private data；
  - `build_honest_instance()`：建立一組可測試的 statement／witness；
  - `verify_relation()`：直接以高階 reference 邏輯檢查 relation；
  - `generate_issue_circuit()`：將同一關係降成 circuit。
- `tests/test_pq_rbbc_reference.py`：positive／negative relation cases。

需要區分：reference object、circuit object 與 production serialized bytes 可以描述
相同語意，但只有 canonical parser／encoder freeze 後才能作為跨模組 wire format。

### 5.2 建立 blind request

Protocol 概念：

```text
c_r <- CAP.Commit(r; rho)
y   <- r + H_RBBC(m, c_r)
```

資料邊界：

- `y` 是給 issuer 的 public blind request；
- `m`、`r`、`rho` 與 `c_r` 留在 issuance proof witness；
- issuer 不應從 request 取得將來可連結 ticket 的隱藏資料。

工程對應：

- `src/pq_rbbc_cap_commit.py`
  - tree／seed／tape expansion；
  - commitment serialization；
  - production accounting 與 profile fingerprint。
- `src/pq_rbbc_blind_uov_abi.py`
  - `BlindUOVRequest`：public request ABI；
  - `CAPBoundRequestState`：CAP 與 request binding；
  - `request_from_production_cap()`：由 CAP output 建立 request。
- `src/pq_rbbc_cap_*`：CAP producer、global tail、relocation 與 composition 的分段工程。

### 5.3 `pi_issue` 合法性證明

Protocol 概念：

```text
pi_issue <- Pi_issue.Prove(crs, x, w)
Pi_issue.Vfy(crs, x, pi_issue) = 1
```

其中 relation 必須同時綁定：

- authenticated identity／session；
- ticket payload 與 digest；
- trace ciphertext 的 plaintext／randomness consistency；
- holder secret binding；
- blind mask／CAP randomness；
- public request `y`。

工程上要依序完成：

1. relation fields 與 exact encoding；
2. ordinary reference evaluator；
3. native circuit generator；
4. producer segments 與 global tail；
5. cross-segment relocation；
6. aggregate replay；
7. CAP-to-`H_RBBC` parent join；
8. PQ simulation-extractable ZK backend；
9. real `Prove`／`Verify`；
10. proof size、time、memory 與 energy benchmark。

若 handoff 只報告 rows replayed、failures 與 mutation rejection，代表第 1–7 項的某個
工程 checkpoint，不表示第 8–10 項完成。

### 5.4 Issuer response 與 holder finalize

Protocol 概念：

```text
z     <- BlindUOV.Respond(bsk, y)
sigma <- BlindUOV.Finalize(m, c_r, y, z; r, rho)
T     <- (M, sigma)
```

這裡容易和 `pi_issue` 混淆：

- `pi_issue` 是 issuer 在發出 `z` 前驗證的 augmented issuance proof；
- CAP／TCitH 的 append、challenge、opening 與 `pi_2` 是完成 Blind-UOV signature 所需的底層 proof；
- 兩者具有不同的 verifier、傳輸時點與 claim boundary。

因此「issuance relation replay 完成」不代表 `pi_issue` backend、Blind-UOV
`Respond`／`Finalize` 或完整 signature 已 production-closed。

## 6. Satellite access：逐行對應

Protocol 概念：

```text
UE  -> FGS: ticket, UE freshness, serving context, UE key share, holder authenticator
FGS -> UE : FGS freshness, FGS key share, key confirmation, access result
```

工程對應：

- `src/pq_sat_auth/framing.py`
  - `FrameV1`、`encode_frame()`、`decode_frame()`；
  - version、type、length 與 trailing bytes 檢查。
- `src/pq_sat_auth/access.py`
  - `ServingContextV1`；
  - `AccessInitV1`、`AccessChallengeV1`、`AccessFinishV1`、`AccessAcceptV1`；
  - transcript／attempt／accept identities。
- `src/pq_sat_auth/identities.py`
  - `derive_use_key()` 與 `TicketUseIdentity`。
- `src/pq_sat_auth/replay.py`
  - process-local `InMemoryLinearizableReplayStore`；
  - reserve、commit、abort、retry 與 collision handling。
- `tests/system/`：encoding、binding、mutation、concurrency 與 replay tests。

目前 reference access code 使用 test-only suite boundary。Codec／state tests 成功只
表示資料與狀態語意可執行；不表示 holder authenticator、PQ AKE 或 distributed
durable replay store 已 production-closed。

## 7. Conditional opening：逐行對應

Protocol 概念：

```text
Q <- (ticket, case_id, evidence_digest, purpose, expiry, authorization)
share_i <- OpenShare(tsk_i, Q)
rid, sn <- Combine(valid shares)
```

工程上至少需要：

1. canonical opening request／authorization bytes；
2. 先執行 `VerifyTicket`；
3. 驗證 case、purpose、evidence、expiry 與 replay state；
4. 產生 authenticated threshold share；
5. 拒絕 malformed、duplicate、stale、revoked 或 equivocated shares；
6. combine 後比較 decrypted serial 與 ticket clear serial；
7. 產生可公開稽核、但不額外洩漏身分的 evidence；
8. security proof 與 opening benchmark。

核心 proof 已提供 abstract boundary，不代表上述 production protocol／implementation
皆存在。Opening 實作可先使用 frozen ticket digest／`VerifyTicket` adapter 建立
schema 與 negative tests，最後才接入 real threshold primitive。

## 8. 如何讀 RBBC checkpoint

不要先從 SHA-256 或 row count 讀起。先依以下順序：

1. **Protocol location：**這次修改 `CAP.Commit`、`H_RBBC` join、`pi_issue` backend，還是 signature finalize？
2. **Reason：**前一版本缺少哪個普通關係、安全假設、artifact 或資源？
3. **Executed：**真的產生／重播／驗證了什麼？有多少 rows、failures、external assertions？
4. **Rejected：**mutation、stale witness、wrong profile 或 corrupted artifact 是否被拒絕？
5. **Not done：**哪些 `false` flags 仍阻止 proof／production claim？
6. **Next gate：**下一步允許寫 spec、做 reduced prototype、跑 pre-freeze，還是接 backend？

狀態欄位的閱讀規則：

- `safe_to_X = true`：允許開始 X，不表示 X 已完成；
- `candidate`：候選格式／profile，不是 production；
- `projected`／`estimated`：規劃數字，不是 observed／frozen；
- `preflight_closed = true`：只有該 preflight checkpoint 封閉；
- `replay failures = 0`：該 assignment 滿足該 relation；
- `production_closed = false`：禁止用 production-ready 措辭。

## 9. Checkpoint 與 protocol 的對照範例

本節只示範如何翻譯版本名稱，不作最新狀態來源。版本是否已整合、當前 exact
identity 與下一步，一律重新查閱 `RESEARCH_STATUS_zh-TW.md` 與 current handoff。

| Checkpoint 類型 | Protocol 對應 | 工程意義 |
| --- | --- | --- |
| tree producer materialization | `CAP.Commit` 內部 seed／tape／polynomial computation | 將一個 logical tree 的計算降成可 replay rows |
| planned-offset replay | 多棵 tree 位於共同 composition 的位置 | 確認相同公式在正確 global namespace 執行 |
| output relocation | producer output 傳給 consumer／global tail | 用 ordinary equality rows 關閉跨 segment wire binding |
| complete aggregate replay | 完整 CAP computation | 同一 assignment 對全部 tree、relocation、tail 零失敗 |
| parent CAP-to-`H_RBBC` join | `y = r + H_RBBC(m,c_r)` | CAP bytes 不經 host assertion，直接進入 issuance relation |
| proof audit／qualification | `CAP.Prove`、`pi_issue` 所需安全假設 | 核對 extractor、ZK、QROM、unforgeability 與 review 缺口 |
| Prove／Verify preflight | 真正 proof API／serialization | 凍結 public statement、proof envelope、acceptance order 與 blockers |
| profile migration preflight | 同一 primitive 的底層 profile 改變 | 保留舊 evidence，為新 topology／namespace 列出重建範圍 |

### 9.1 Worked example：如何翻譯 v2.33

以下只示範閱讀方法；v2.33 是否已 commit／整合以及 exact identities，仍須查 active
RBBC branch 的 current handoff。

| 五層問題 | v2.33 的翻譯 |
| --- | --- |
| 影響哪個 protocol 步驟？ | 直接影響 `CAP.Commit`／CAP `Prove` 的 GGM topology、opening 與 PoW；因 `c_r` 被 `H_RBBC(m,c_r)` 使用，也會間接影響 `pi_issue` parent relation |
| 為什麼需要改？ | Legacy profile 使用 18 個獨立 roots；待採用的 paper-compatible PoW 分析依賴單一 interleaved unified GGM tree，不能直接繼承安全數字 |
| 實際執行什麼？ | 核對來源 identities、保留新 namespace、定義 40,960 個 logical leaves 的 mapping、驗證 mapping bijection、列出 migration impact 並檢查 planning capacity |
| 新增什麼能力？ | 允許撰寫 exact unified-tree specification，並在條件滿足後實作 reduced prototype |
| 仍然不能做什麼？ | 沒有 unified-tree runner／assignment／replay、沒有 CAP accepting proof、沒有正式 `pi_issue`，也沒有 security／production closure |
| 下一個 bounded gate？ | 先寫 exact algorithm specification，再實作 reduced prototype；通過 qualification、resource reservation 與 independent review 後才可進 production pre-freeze |

因此 `v2.33 read-only preflight closed` 的正確白話不是「unified-tree CAP 做完」，而是：

> 已確認為了修補安全 profile，需要建立一個與 legacy 18-tree 隔離的新候選；目前只把
> 遷移規則、禁止沿用的 evidence、所需資源與下一個小型工作固定下來。

## 10. Handoff 應先提供的教學摘要

新 handoff／checkpoint 說明在工程細節之前，應先提供：

```text
影響的 protocol 步驟：
使用者可觀察的輸入／輸出是否改變：
這次實際執行了什麼：
完成後新增了什麼能力：
仍然不能做什麼：
下一個被解除或仍存在的 blocker：
```

大型數字、artifact identity、exact command 與 checksum 仍保留在 handoff 後段，
供重現與稽核使用；不可刪除或以教學摘要取代。

## 11. 文件與證據的權威順序

遇到不同文件說法不一致時：

```text
Machine evidence / tests / proof artifacts
    ↓ 約束能宣稱的內容
RESEARCH_STATUS_zh-TW.md
    ↓ 提供全專案目前成熟度
ARCHITECTURE_zh-TW.md / methodology.md
    ↓ 提供系統語意與決策理由
ROADMAP_zh-TW.md / module handoff
    ↓ 提供下一步與操作細節
本 guide
    ↓ 只負責解釋上述各層如何相連
```

若 guide 的狀態例子與 canonical status 衝突，必須修正 guide 或移除過時例子，不得
反過來修改 evidence 以符合教學文字。
