# PQ-RBBC Issuance fresh parent I1–I5 CandidateSet 唯讀 preflight v1

日期：2026 年 9 月 16 日

## 結論

本 checkpoint 以 finding-free Global-tail completion sealer commit
`12be68c199f108c0141e613b7e70cba251183168` 為直接基準，建立 bounded two-tree／
four-leaf `INSECURE-TEST-ONLY` fresh parent I1–I5 CandidateSet read-only preflight。

它把 completion handoff、既有 36 份 immutable snapshots，以及新的 parent parameters、
statement、witness 組成固定 40-role source inventory。Frozen bounded fixture 以直接 host
reference operations確認 I1–I5 五個 conjunct 使用同一組資料；沒有發出或重播 parent
constraint、native join row、assignment或proof。

## Protocol 位置

論文 issuance relation 是：

```text
x = (pp, ctx, sid, rid, beta)
w = (M, r, rho, k_hold, e)

I1  TicketShape(M, ctx)
I2  m = H_ticket(Encode(M))
I3  CAP.Commit(r; rho) = c_r
    beta = r XOR H_RBBC(m, c_r)
I4  M.h = H_hold(k_hold)
I5  trace ciphertext binds (ctx, rid, M.sn, M.h, e)
```

本 gate 位於已完成的 bounded CAP child 後、fresh parent circuit lowering前：

```text
Global-B result: c_r + H_RBBC(m,c_r)
        + completion CandidateSet
        + fresh pp/statement/witness
                    │
                    ▼
      40-role parent CandidateSet preflight
        host reference I1–I5 = accepted
                    │
                    ▼
 future bounded parent relation consumer（未實作）
```

Host reference acceptance只確認 canonical bytes與高階關係一致，不等於ordinary constraints已
replay，更不等於`Verify(statement, pi_issue)`成功。

## Canonical encoding

Public statement沿用 version 1 section codec，固定欄位順序：

1. `abi_profile_digest`；
2. `public_parameters_digest`；
3. `ctx[32]`；
4. `sid[32]`；
5. `rid[32]`；
6. `beta[72]`。

Private witness使用獨立 magic／version與固定欄位：

1. `abi_profile_digest[32]`；
2. `M[368]`；
3. `r[72]`；
4. bounded two-tree `rho`；
5. `k_hold[32]`；
6. `e[836]`。

所有section以`u16le id || u64le length || payload`編碼；unknown version、section reorder、
length mismatch、truncation與trailing bytes均拒絕。這個 bounded `rho` profile與18-tree production
encoding不同，不可互換，也不可據此宣稱legacy18 provider已完成。

Frozen fixture identities：

| artifact | bytes | SHA-256 |
|---|---:|---|
| CandidateSet handoff | 12,231 | `5e8cc00a9d314c428ff678d563065f2401c3bc9afb853d10a0353ff5849bae37` |
| parent parameters | 330 | `5d5e0f6669538836bd380f78d55e79f10f53967535458b7d3e938dc949bb1d49` |
| parent statement | 321 | `58abad8ca1c79805139bcf02884fb873753bde4aa515188a58d7568dae9af1da` |
| parent witness | 1,676 | `c4a7d22aa6089d1e855262f60371456ff3065bbf58b680d7179e15cc3de75f3a` |

40-role inventory digest為
`589bdebf17c124ec0576ae9f3e733c1a0744a08b0e1757045a9a810778d84d79`。
Portable evidence不包含上述 private raws。

## Host reference binding

Validator從CandidateSet內相同immutable `Snapshot.raw`完成：

- I1：`M.ctx == statement.ctx`；
- I2：`SHAKE256(PQ-RBBC/TICKET || M)`等於predecessor捕捉的ticket message；
- I3：由exact bounded `rho`重算CAP reference，要求511-byte `c_r`、576-bit derived mask、
  `H_RBBC(m,c_r)`與`beta`全部對應同一completion publication；
- I4：`M.h == H_hold(k_hold)`；
- I5：以test-only trace matrix重新建立trace payload，並檢查weight-128 error。

這些是direct host calculations；`parent_constraints_replayed=0`，
`native_join_rows_replayed=0`。Issuer `sid`只檢查fixed-width與非零；freshness、唯一性及
linearizable reservation仍屬外部stateful gate，沒有在本relation中被證明或消費。

## Snapshot contract

固定 role order為：

1. completion handoff；
2. completion sealer既有36-entry `SNAPSHOT_ROLE_ORDER`；
3. parent parameters；
4. parent statement；
5. parent witness。

總數40。External parent handoff digest必須在任何predecessor validation或CAP host computation前
先驗證。Identity、strict parse、closed-schema validation、binding與future execution都必須使用
CandidateSet中的同一份raw；future consumer不得重新開啟pathname後替換。

Single-open、single bounded read只保證後續使用同一份已capture bytes。Inode／size／mtime／ctime
是best-effort mutation signals，不能證明capture期間沒有writer。Trusted producer handoff、writer
quiescence、owner/mode/ACL、既有writable FD、mount namespace與filesystem durability仍是部署前提。

## Wire與join planning contract

Parent-local wire 0保留為constant one。精確input/import reservation為：

| field | visibility | interval `[start,end)` | bits |
|---|---|---:|---:|
| `statement.pp` | public | `[1,257)` | 256 |
| `statement.ctx` | public | `[257,513)` | 256 |
| `statement.sid` | public | `[513,769)` | 256 |
| `statement.rid` | public | `[769,1025)` | 256 |
| `statement.beta` | public | `[1025,1601)` | 576 |
| `witness.M` | secret | `[1601,4545)` | 2,944 |
| `witness.r` | secret | `[4545,5121)` | 576 |
| `witness.rho` | secret | `[5121,6279)` | 1,158 |
| `witness.k_hold` | secret | `[6279,6535)` | 256 |
| `witness.e` | secret | `[6535,13223)` | 6,688 |
| `import.c_r` | private import | `[13223,17311)` | 4,088 |
| `import.request_hash` | private import | `[17311,17887)` | 576 |
| `import.ticket_message` | private import | `[17887,18143)` | 256 |

Public input為1,600 bits，secret witness為11,622 bits；CAP child與parent之間規劃的native
bindings共6,654 bits：message 256、rho 1,158、derived mask 576、c_r 4,088及request hash 576。

`[18143,...)` computed-wire interval與absolute composed interval均故意維持`null`。在fresh lowerer
真正觀測前不得用舊reduced prototype、v2.20 parent或其他profile的wire count填入。3,100,000 rows
僅是下一bounded gate的planning upper bound，不是observed row count。

## Claim boundary

| 狀態 | 本 checkpoint |
|---|---|
| Defined | 40-role inventory、parent ABI、I1–I5 host binding、local input/import intervals、join plan |
| Instantiated | bounded two-tree／four-leaf `INSECURE-TEST-ONLY` fixture |
| Implemented | read-only CandidateSet builder／validator與host reference checks |
| Tested | positive、field mutation、wrong version/order/trailing、inventory swap/re-pin、bool、same-raw、pre-I/O refusal |
| Evidence-sealed | metadata-only portable evidence |
| Proof-closed | false |
| Production-closed | false |

保持false／未完成：

- fresh parent circuit lowerer與relation consumer；
- computed／absolute wire interval observation；
- 6,654 native join rows及I1–I5 constraints replay；
- stateful issuer SID reservation；
- unified filesystem capture與完整線性receipt chain；
- production mixed degree-12/13 legacy18 provider；
- qualified PQ simulation-extractable backend與正式`pi_issue`；
- large replay/proving、physical power-loss、cross-host/failover qualification；
- FAC authentication、system architecture與ticket lifecycle closure。

## Resource estimate與exact commands

本preflight預估上限為180秒、1,024 MiB RSS；實際以bounded in-memory fixture為主，不寫external
artifact。Production estimate仍為`null`。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1.py --bounded-self-check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

Parent replay、production、large replay與proving command均為`null`。

## 驗證結果

- Targeted：14 passed，0 failed/errors/skipped；124.451秒。
- Completion sealer＋本gate：27 passed，0 failed/errors/skipped；164.138秒。
- Full baseline：1,054 tests；1,042 passed、12個既有optional external-artifact skips、
  0 failed/errors；1,711.692秒。
- Independent probe：955/955必要拒絕，`unexpected_acceptances=[]`；包含40-role全部780組
  descriptor pair swaps、120個逐descriptor mutations、40個bool ordinals、15個parameters／
  statement／witness re-pinned mutations。
- 19份v2.38／v2.39 historical identities：19/19 unchanged。

## 下一個 serial gate

本exact commit必須先接受finding-free唯讀technical/security re-review。通過後，下一個serial gate
是 **bounded independently invocable fresh parent I1–I5 relation consumer**：消費同一40-role
CandidateSet，fresh lower I1–I5、觀測computed-wire interval、發出6,654條native joins並進行bounded
replay。該gate仍不得宣稱legacy18、formal`pi_issue`、PQ-SE、Proof-closed或Production-closed。
