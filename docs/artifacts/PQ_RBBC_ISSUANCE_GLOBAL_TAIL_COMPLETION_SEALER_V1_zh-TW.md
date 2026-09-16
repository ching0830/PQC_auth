# PQ-RBBC Issuance Global-tail completion sealer／parent-input CandidateSet v1

日期：2026 年 9 月 16 日

## 結論

本 checkpoint 以 finding-free Global-B restart corrective commit
`6b27800a2be000b3dd1c67ce25112a0fbba2e495` 為直接基準，完成 bounded
two-tree／four-leaf `INSECURE-TEST-ONLY` Global-tail completion sealer。它只消費已捕捉、
已驗證的 Global-B CandidateSet、result、fragment receipt 與 terminal complete checkpoint
immutable raws，建立一份 canonical private parent-input snapshot，再封裝成固定 36-role
CandidateSet。

本 sealer 不發出 relation row、不重播 parent constraints、不重新開啟 predecessor pathname，
也不把 receipt branch graph 改稱完整線性 execution chain。它沒有實作 fresh parent I1–I5、
legacy18 production provider、正式 `pi_issue` 或 PQ simulation-extractable proof backend。

## Protocol 位置

以 protocol 資料流表示，本 gate 位於 Global-B 產生 `c_r` 之後、parent relation 消費前：

```text
ticket-request relation fragments
  ├─ Global-A
  ├─ tree-post[0]
  ├─ tree-post[1]
  └─ Global-B → canonical CAP commitment c_r
                    + request-binding hash
                         │
                         ▼
             Global-tail completion sealer
                         │
                         ▼
       immutable 36-role parent-input CandidateSet
                         │
                         ▼
       future fresh parent I1–I5 consumer（未實作）
```

這裡的 `parent input` 是後續 relation 的版本化輸入容器，不是 parent proof；`c_r` 的 identity
binding 也不代表正式 issuance proof `pi_issue` 已產生。

## Frozen input 與 output contract

Predecessor 固定為 finding-free Global-B source、tests、manifest、portable evidence 與 artifact
note。Global-B source publication identities為：

- CandidateSet handoff：5,656 bytes，SHA-256
  `ba284499e8f704840c33ed9b9aaadb86c17e3b4524e02266b4055201ba8b0df3`；
- result：1,039,596 bytes，SHA-256
  `f25145053700d3b651fc78d081a7dc92d099bd521f6df4747a177f90509c4984`；
- fragment receipt：2,969 bytes，SHA-256
  `8d5253ba2c96269de2ead30d085bf005747bf2d7efad56fe32f3c6e938655a4e`；
- complete checkpoint：9,265 bytes，SHA-256
  `fa4e29c19774e39a78aeddfd80203d582eae99f392770edba04e2ff041079525`。

Sealer 的 frozen bounded outputs為：

- completion handoff：9,110 bytes，SHA-256
  `e81c3b3aa5d7ffc60a00fc61ce9a8063ed3a4f88d591f482ca0e8c8836b1a521`；
- private parent input：2,623 bytes，SHA-256
  `97c97f163736965b04fac4636b27ab21245ff51a7bb9d240b55f2cba432eda59`；
- 36-role inventory domain-separated digest：
  `d10c05b6808b447ebe492b50aea0703bb232d28c91524367c582df734c95ce5f`；
- `c_r`：511 bytes，SHA-256
  `778d6dc3526c29b24fd18f0a5e6d24b29ef0f429e3c532d1816f2e4f3815fc4e`；
- request hash：72 bytes，SHA-256
  `1724a62d61710ed6e4ec3bb0664df2192249bbc1472f0f88b916d55b07e5b863`。

Parent input 固定 format／version／mode／relation/domain、profile、plan、invocation、四個 source
digests、`c_r` 與 request hash 的 canonical encoding／byte count／SHA-256。Unknown field、wrong
version/domain、bool-as-int、upper/alternate encoding、length mismatch、wrong source binding、
trailing bytes均 fail closed。

## 36-role immutable Snapshot contract

前 32 roles 精確沿用 Global-B CandidateSet 的固定 `INPUT_ROLE_ORDER`；ordinal 32–35 固定為：

1. `global-b-result`；
2. `global-b-receipt`；
3. `global-b-complete`；
4. `parent-input`。

程式內獨立的 `SNAPSHOT_ROLE_ORDER` 唯一固定 role→ordinal mapping。即使交換完整 descriptors、
重新編號並重算 inventory／handoff digest，也不能建立第二種 canonical layout。所有 identity、
strict JSON parse、closed-schema validation、binding及未來 parent execution都必須使用 CandidateSet
內同一份 `Snapshot.raw`；future consumer不得重新開啟 pathname後用新內容取代已 capture bytes。

Single-open、single bounded read保證的是同一份完整 capture bytes被後續驗證與消費，不是一般
filesystem上的強不可變性證明。Inode／size／mtime／ctime只能作 best-effort mutation signal；
trusted producer handoff、writer quiescence、owner/mode/ACL、既有 writable FD、mount namespace
與 filesystem durability仍是外部部署前提。

## Receipt 與 row accounting

CandidateSet 記錄的 receipt evidence 是：adapter ordinal 0→3 chain、兩個 tree-post branches，
再加上 Global-B terminal receipt。這是 branch graph，不是單一完整線性 execution receipt chain，
所以 `full_execution_receipt_chain_verified=false`。

已由 predecessor consumers實際檢查的 rows合計 70,143：

- Global-A：19,671；
- tree-post：3,576 + 3,576；
- producer→Global-B native relocation equalities：7,826；
- Global-B Phase-B constraints：35,494。

Completion sealer replay 0 rows，parent replay 0 constraints。70,143 是 predecessor bounded
engineering evidence的加總，不是本 gate 新執行的 proof，也不是 589,030,555 constraints replay。

## Claim boundary

| 狀態 | 本 checkpoint |
|---|---|
| Defined | 36-role order、terminal source validation、canonical parent-input encoding |
| Instantiated | bounded two-tree／four-leaf `INSECURE-TEST-ONLY` fixture |
| Implemented | immutable Global-tail completion sealer與parent-input CandidateSet validator |
| Tested | positive、mutation、wrong domain/version/order/binding/bool/trailing、same-raw、pre-I/O refusal |
| Evidence-sealed | metadata-only portable evidence |
| Proof-closed | false |
| Production-closed | false |

保持 false／未完成：

- fresh parent I1–I5 CandidateSet composition與relation consumer；
- parent constraints replay；
- unified cross-root filesystem capture API；
- full linear execution receipt chain；
- production mixed degree-12/13 legacy18 provider；
- qualified PQ simulation-extractable backend與正式 `pi_issue`；
- large replay/proving、physical power-loss、cross-host/failover qualification；
- FAC authentication、system architecture與ticket lifecycle closure。

Portable evidence只包含metadata與identities；不包含private raws、parent input、assignment、BR1CS、
pickle、cache、checkpoint body、resume state、logs或proving output。V2.38／v2.39 historical files
沒有被改寫。

## Exact commands

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_tail_completion_sealer_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_tail_completion_sealer_v1.py --bounded-self-check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_tail_completion_sealer_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

沒有 parent replay、production、large replay或proving command；本 checkpoint 不授權這些執行。

## 下一個 serial gate

本 gate 的 exact commit 必須先接受finding-free唯讀technical/security re-review。通過後，下一個
serial gate是 **fresh parent I1–I5 CandidateSet read-only preflight**：先固定 parent statement、
dependency roles、wire intervals、canonical encoding與resource estimate；在它安全且另經授權前，
不得啟動 parent relation replay、legacy18 production重建或 proving。
