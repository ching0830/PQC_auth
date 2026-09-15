# PQ-RBBC Issuance Global-B bounded consumer／private restart v1

日期：2026 年 9 月 16 日

## 結論

本 checkpoint 在 finding-free CandidateSet corrective commit
`2779e845b53e5bd8c60a4cd45b932c69d0173529` 之後，完成 bounded two-tree／four-leaf
`INSECURE-TEST-ONLY` Global-B consumer。它消費同一份已驗證的 32-role immutable
CandidateSet，先發出並驗證 8 組、合計 7,826 條 native relocation equality rows，再重播
35,494 條 Phase-B constraints。兩者分開計數；本文件不把 equality rows 算進
`global_b_constraints_replayed`。

Global-B 產生的 commitment 與 request hash 和 unchanged bounded monolithic reference
byte-identical。Private result、fragment receipt、append-only journal、externally pinned resume、
exact orphan adoption、completed capture 亦已實作。本 checkpoint 沒有重跑 tree-pre、Global-A
或 tree-post，也沒有重開原 CandidateSet pathnames。

這仍不是 production global-tail、legacy18 provider、正式 `pi_issue` 或 cryptographic proof。

## Protocol 位置

以 protocol 語意表示，本 gate 處理的是 CAP commitment 的後半段：

```text
已驗證 ticket-request witness fragments
  ├─ tree-pre outputs: p_plain, mhat_plain
  ├─ Global-A outputs: H1, consistency points
  └─ tree-post outputs: xi masks
        │
        ▼
  8 組 producer → tail native equalities
        │
        ▼
  shared alpha → H2 → canonical CAP commitment c_r
        │
        └─ ticket message || c_r → request-binding hash
```

`c_r` 是後續 parent relation 的一個輸入，不等於 parent proof，也不等於正式 issuance proof
`pi_issue`。本 gate 證明的是 frozen bounded relation rows 可由相同 CandidateSet 重播；不是
PQ simulation-extractable security proof。

## Frozen contract

- CandidateSet snapshot roles：32。
- Relocation rowsets：8。
- Relocation bits／native equality rows：7,826。
- Phase-B owned wire interval：`[23,094, 43,837)`。
- Phase-B owned wires：20,743。
- Phase-B constraints：35,494。
- 本 gate 總檢查 rows：43,320。
- External assertions：0。
- Frozen profile fingerprint：
  `520980f7518de0c8a22e9fcb66f3d3af1eb4ef50c2df9136b6df873d9f524356`。

Shared salt/message 的 producer-side equality locators 固定為 frozen adapter anchor wires
`123,799` 與 `124,957`；tree-pre／tree-post source locators沿用 CandidateSet 已驗證的 absolute
wire locations。Source values 由同一批 CandidateSet snapshot raws 驗證後建立，target values
來自同一批 relocation raws；任何一側不一致時，native row fail closed。

## Immutable snapshot 與 restart contract

Fresh publication 在建立 output directory 前先完成 CandidateSet 的 identity、strict canonical
JSON、closed schema、receipt graph、invocation/profile/plan、source value與target value驗證。

Validated input publication 使用 32 個固定 role descriptors。程式內獨立的
`INPUT_ROLE_ORDER` 唯一固定 ordinal 0–31 的 role；validator 不從 plan 輸入自行推導順序。
每個 descriptor 同時固定：

- exact ordinal；
- canonical role token；
- private storage filename；
- 原 snapshot 的 filename、bytes 與 SHA-256。

即使同時交換完整 descriptors、重新編號、重新命名input files並重新計算內部checkpoint
digests，也會在CandidateSet reconstruction與Global-B compute前拒絕；合法的role→raw binding
不能取代canonical role→ordinal layout。

Restart 從 private input directory 各做一次 bounded snapshot read，依 plan 驗證 storage
pathname及raw identity，再以原 canonical filename重建同一組 immutable snapshots並完整重跑
CandidateSet validator。它不讀取原 producer pathname，也不以 metadata tuple代替 raw identity。

Journal順序固定為：

1. `0000-publication-plan.private.json`
2. `0001-inputs-committed.private.json`
3. `0002-result-committed.private.json`
4. `complete.private.json`

真正可恢復邊界從 `inputs-committed` 開始。Resume 必須由呼叫者提供 latest checkpoint 的 exact
SHA-256；stale digest、journal gap、unknown file、incomplete inputs及不同 bytes 的 result orphan
一律拒絕。已存在且 byte-identical 的 result orphan可精確採用。Repeated completed resume與
completed capture不改變 result／receipt／complete bytes。

這是 bounded private engineering restart。Writer quiescence、trusted producer handoff、
owner/mode/ACL、既有 writable FD、mount namespace，以及 filesystem/fsync/power-loss assumptions
仍是外部部署前提；`durable_resume=false` 不代表 production power-loss qualification。

## Frozen outputs

- CandidateSet handoff：5,656 bytes，SHA-256
  `ba284499e8f704840c33ed9b9aaadb86c17e3b4524e02266b4055201ba8b0df3`。
- Private Global-B result：1,039,596 bytes，SHA-256
  `f25145053700d3b651fc78d081a7dc92d099bd521f6df4747a177f90509c4984`。
- Fragment receipt：2,969 bytes，SHA-256
  `8d5253ba2c96269de2ead30d085bf005747bf2d7efad56fe32f3c6e938655a4e`。
- Complete checkpoint：9,265 bytes，SHA-256
  `fa4e29c19774e39a78aeddfd80203d582eae99f392770edba04e2ff041079525`。
- Commitment SHA-256：
  `778d6dc3526c29b24fd18f0a5e6d24b29ef0f429e3c532d1816f2e4f3815fc4e`。
- Request hash SHA-256：
  `1724a62d61710ed6e4ec3bb0664df2192249bbc1472f0f88b916d55b07e5b863`。

Portable evidence只記錄metadata；不包含上述private snapshot raws、owned assignment、
checkpoint body或publication directory。

## Claim boundary

| 狀態 | 本 checkpoint |
|---|---|
| Defined | 32-role input inventory、8組equalities、Phase-B、publication/restart contract |
| Instantiated | bounded two-tree／four-leaf `INSECURE-TEST-ONLY` fixture |
| Implemented | independent Global-B consumer、private append-only publication、restart/capture |
| Tested | positive、negative、mutation、canonical-order re-pin、wrong digest、trailing、orphan、resume/capture |
| Evidence-sealed | metadata-only portable evidence |
| Proof-closed | false |
| Production-closed | false |

保持 false／未完成：

- unified cross-root filesystem capture API；
- 單一線性 full execution receipt chain；
- production mixed degree-12/13 Global-B replay；
- production legacy18 provider；
- fresh parent I1–I5 composition；
- qualified PQ simulation-extractable backend與正式 `pi_issue`；
- large replay/proving、physical power-loss、cross-host/failover qualification；
- FAC authentication與system lifecycle closure。

## Exact commands

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python src/pq_rbbc_issuance_global_b_restart_v1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_issuance_global_b_restart_v1 -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

沒有 production、large replay 或 proving command；本 checkpoint 不授權這些執行。

## 下一個 serial gate

本 gate 的初始 commit `4fdb3e3ffb391c3da65f05c98aef8269853c68e6` 的唯讀重審發現
role→ordinal canonicality P3；本 corrective 以固定 `INPUT_ROLE_ORDER` 與完整 re-pin regression
收斂該 finding。本 corrective commit 必須再接受 exact-commit 唯讀 technical/security re-review。
Finding-free 後，才可建立
**bounded global-tail completion sealer／parent-input CandidateSet preflight**，將已reviewed
Global-A、兩個tree-post branches與本Global-B result做同 invocation/profile/plan 的唯讀聚合，
但仍不得把分支 receipt graph宣稱為單一完整chain，也不得直接啟動legacy18或proving。
