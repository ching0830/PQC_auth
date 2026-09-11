# PQ-RBBC formal issuance relation v1 bounded checkpoint

日期：2026-09-11

Relation namespace：`pq-rbbc/issuance/formal-relation/candidate/v1`

## 結論

本 checkpoint 將 core proof 的 issuance relation 明確映射為：

```text
public  x = (pp, ctx, sid, rid, beta)
private w = (M, r, rho, k_hold, e)
```

並建立相同 statement／witness partition 的 bounded structural evaluator、canonical
relation-parameter encoding，以及 issuer-side `sid` 的唯讀候選檢查。本工作沒有建立正式
`pi_issue`、沒有整合 ZK backend，也沒有重播 589,030,555 constraints。

Production relation 仍未 instantiated。原因不是 I1--I5 尚未定義，而是 production I3
必須實際驗證完整 `CAP.Commit(r;rho)` 與 `H_RBBC`，同時 I5 的 trace public key 仍是
deterministic test matrix、不是 certified Goppa key。本 checkpoint 唯一可執行的 I3
adapter 明確命名為：

```text
INSECURE-TEST-ONLY-CAP-HASH-SHAPE-V1
```

它只測試資料流、partition、binding 及 mutation rejection；它不是 CAP commitment，
也不是 `H_RBBC`，不能進入 production configuration。

## 與 protocol 的對應

Holder 在 issuance 階段建立 hidden ticket payload：

```text
M = (ctx, sn, h, C)
h = H_hold(k_hold)
C = Ntr.Enc(tpk, ctx, h; rid, sn, e)
m = H_ticket(Encode(M))
```

接著建立 blind request：

```text
c_r  = CAP.Commit(r; rho)
beta = y = r + H_RBBC(m, c_r)
```

Issuer 只應看到 `(pp,ctx,sid,rid,beta)` 與未來的 `pi_issue`；`M`、`r`、`rho`、
`k_hold`、`e` 必須保持為 proof witness。這就是本 checkpoint 與 legacy relation 的主要
差異：legacy `IssueStatement` 將完整 payload 公開，而新的 backend ABI 將 368-byte
payload 放回 private witness。

### I1：Ticket shape 與 context

```text
TicketShape(M, ctx) = 1
```

Evaluator 嚴格解析 fixed-width 368-byte payload，並檢查 payload 內的 `ctx` 等於 public
statement 的 `ctx`。Payload layout 固定為：

```text
ctx[32] || sn[16] || holder_hash[32] || syndrome[208]
|| masked_identity[48] || tag[32]
```

### I2：Ticket digest

```text
m = SHAKE256("PQ-RBBC/TICKET" || Encode(M), 32 bytes)
```

`m` 是 relation 內部 derived value，不是額外 public input。改變 private `M` 會改變
`m`，並透過 I3 使 unchanged public `beta` 拒絕。

### I3：Exact blind-request relation

Production contract 是：

```text
c_r  = CAP.Commit(r; rho)
beta = r + H_RBBC(m, c_r)
```

現有 v2.29 evidence 已證明其 historical 18-tree fixture 的 CAP-to-H_RBBC parent join，
但它沒有把 formal 1,036-byte `rho` 作為新 private witness 重新接入 relation namespace。
本 checkpoint 不重新使用其他 tree 的 observed stream bytes，也不把 frozen fixture identity
當成一般 relation evaluator。

Executable test-only adapter 對同樣寬度的 `m[32]`、`r[72]` 與 canonical
`rho[1036]` 做 domain-separated deterministic shape binding。此路徑僅供 regression；
manifest 明確記錄：

```text
i3_adapter_is_cap_commit = false
i3_adapter_is_h_rbbc = false
production_i3_cap_h_rbbc_relation_instantiated = false
```

### I4：Holder binding

```text
M.h = SHAKE256("PQ-RBBC/HOLD" || k_hold, 32 bytes)
```

Holder key 仍是 private witness。Mutation 同時破壞 I4 與依賴 `h` 的 trace relation。

### I5：Trace relation

Bounded evaluator 依 canonical `P || K_mac` trace-KDF split，重新計算 syndrome、masked
identity 與 KMAC tag，並要求 `wt(e)=128`。這實作 equation-level trace binding；但使用的
`SystematicParityCheck(TEST_MATRIX_SEED)` 明確是 deterministic test fixture，不是 certified
Goppa public key，因此 production I5 仍未 instantiated。

## `sid` 為什麼不能由 relation 自己證明 fresh

Formal I1--I5 中沒有「查詢全域 session registry」的 NP conjunct。`sid` 的兩個不同責任
必須分開：

1. ZK proof transcript 必須綁定 statement 中 exact `sid` bytes；改變 `sid` 會形成不同
   statement，舊 proof 不應通過。
2. `sid` 是否由 issuer 新產生、是否已使用、是否已為當次 signing response 原子保留，
   是 issuer-side linearizable state 的責任。

本 checkpoint 的 `validate_issuer_sid_candidate` 只接受 caller 提供的 expected issuer SID
與 immutable used-SID snapshot，執行 bounded 唯讀檢查。它不寫入 state，且結果明確固定：

```text
state_reserved = false
freshness_proved_by_relation = false
```

因此 production mode 會直接拒絕。未來 issuer integration 必須在執行 signer response 前
使用 trusted、linearizable、crash-safe reservation／consume interface；不能以 witness
中的 `sn` 衍生 `sid`，也不能把唯讀 snapshot 宣稱成全域 freshness proof。

## Canonical relation parameters

Relation parameters 使用獨立 magic：

```text
PQRBBC-ISSUE-RELATION-PP-V1
```

其 grammar 為 magic、`u16le` version、`u16le` section count，接著依序使用 `u16le`
section ID、`u64le` length 與 payload。固定 sections：

```text
1 relation_id
2 statement_abi_digest[32]
3 target_cap_profile_digest[32]
4 trace_profile_digest[32]
5 trace_public_key_digest[32]
6 mode
7 matrix_seed
```

Unknown/reordered section、wrong version、length mismatch、truncation、trailing bytes、
錯誤 ABI/profile/key digest 均拒絕。Statement 的 `public_parameters_digest` 必須等於
`SHA-256(canonical relation-parameter bytes)`。

未來正式 backend parameters/CRS 必須另外把這個 relation parameter identity 納入
canonical PP payload；目前 test-only relation parameters 不是 production CRS。

## `rho` contract

本 checkpoint 沿用 predecessor 已修正的 production-shaped encoding：

```text
CAPRandomness.serialize(PRODUCTION_PARAMETERS) = 1,036 bytes
```

它包含 64-byte production profile fingerprint、兩個 canonical GF(2^193) salt elements、
18 對 GGM roots；錯誤 profile、tree count、field high bits 或 legacy 32-byte test nonce
均拒絕。使用 production-shaped encoding 不代表 production CAP equation 已執行。

## Claim matrix

| 層級 | 狀態 |
| --- | --- |
| Defined | formal I1--I5 mapping、statement/witness partition、fresh SID external boundary、relation PP encoding |
| Instantiated | 僅 insecure test-only structural profile；production relation=false |
| Implemented | bounded evaluator 與 read-only SID candidate checker；production I3／SID reservation=false |
| Tested | bounded positive、negative、mutation、wrong encoding、SID replay tests |
| Evidence-sealed | bounded formal-contract checkpoint；production relation=false |
| Proof-closed | false |
| Production-closed | false |

尤其不得將下列工作混為一談：

- relation evaluator 通過不是 ZK proof；
- v2.29 large replay 通過不是 formal `pi_issue`；
- production-shaped `rho` 不是 production CAP execution；
- read-only SID candidate check 不是 linearizable reservation；
- test-only I3 adapter 不是 cryptographically secure backend。

## Bounded commands 與資源

Self-check：

```bash
PYTHONPATH=src python -u src/pq_rbbc_issuance_relation_v1.py --self-check
```

Targeted tests：

```bash
PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_relation_v1 -v
```

完整 baseline：

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

本 checkpoint 預估上限為 1 CPU、256 MiB、60 秒；self-check replay rows=0、
cryptographic proofs=0。沒有提供 large replay 或 proving command。

2026-09-11 封存前驗證結果：

- bounded self-check：I1--I5 positive 1/1；4/4 mutation cases rejected；SID candidate
  positive 1/1、replay rejected；production entry points 2/2 refused；replay rows=0、
  cryptographic proofs=0；
- targeted unittest：27 passed、0 failed、0 skipped；
- 完整 baseline：共 741 tests，729 passed、12 個既有 optional-external-artifact
  skips、0 failures/errors，耗時 737.136 秒。

## 下一個 gate

在 reduced ZK backend adapter 前仍須：

1. 固定 production common parameters encoding，包括 certified trace public key、issuer
   verification key、CAP/H_RBBC profile 與 relation identity；
2. 建立可消費 formal `rho` 的 production CAP-to-H_RBBC relation adapter，不能只辨識單一
   frozen fixture；
3. 將 I1--I5 降低到新 relation namespace 的 reduced constraint prototype，證明 topology
   與 public/private wire partition；
4. 定義 issuer-side linearizable SID reservation handoff；此工作屬部署／issuance orchestration
   boundary，不得改變 ticket lifecycle；
5. 完成 mutation evidence與獨立 review後，才可把 reduced relation 接到 Aurora feasibility
   backend；
6. 任何 589M replay或large proving仍需另行 resource estimate、exact command與明確授權。

目前 gate：

```text
production_relation_instantiated = false
qualified_backend_integrated = false
formal_pi_issue_generated = false
safe_to_start_large_replay = false
safe_to_start_large_proving_run = false
Proof-closed = false
Production-closed = false
```
