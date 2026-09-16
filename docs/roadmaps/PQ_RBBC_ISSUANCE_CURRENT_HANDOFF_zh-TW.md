# PQ-RBBC Issuance 目前交接

> 範圍：離線發行的 `R_issue`、CAP child execution、split／multi-tree execution、
> Global-A／Global-B／Global-tail 與 fresh parent I1–I5。這不是 CAP launch handoff；
> CAP／unified-tree production 狀態仍以
> [`PQ_RBBC_CURRENT_HANDOFF_zh-TW.md`](PQ_RBBC_CURRENT_HANDOFF_zh-TW.md) 為準。

日期：2026 年 9 月 16 日

## 一句話狀態

目前已把完整發行關係拆成可獨立檢查、可中斷恢復的 bounded execution chain，最新
checkpoint 是 `b877189` 的 fresh parent I1–I5 CandidateSet read-only preflight。
所有實際執行仍限 two-tree／four-leaf `INSECURE-TEST-ONLY` fixture；正式
`pi_issue`、合格 PQ simulation-extractable backend、production-scale relation、large
replay／proving、Proof-closed 與 Production-closed 全部尚未完成。

## 它位於 protocol 的哪裡

```text
UE 準備 hidden ticket／holder／trace witness
        ↓
R_issue I1–I5 與 blind request binding
        ↓
CAP child producers → split/multi-tree → Global-A/B/tail
        ↓
fresh parent relation consumer                 ← 下一個實作 gate
        ↓
合格 PQ-SE backend 產生正式 pi_issue          ← 尚未完成
        ↓
Issuer 驗證 pi_issue 後才可回覆 blind issuance
```

## 目前程式位置

| 層次 | 目前路徑 | 說明 |
| --- | --- | --- |
| Relation | `src/pq_rbbc_issuance_relation_v1.py` | I1–I5 reference relation 與 bounded shape |
| Production inputs | `src/pq_rbbc_issuance_production_inputs_v1.py` | source identity 與輸入資格 gate |
| CAP child／lowering | `src/pq_rbbc_issuance_cap*_v1.py`、`src/pq_rbbc_issuance_split_*_v1.py` | bounded child execution 與 native lowering |
| Multi-tree／restart | `src/pq_rbbc_issuance_*restart*_v1.py`、`src/pq_rbbc_issuance_bounded_multitree_*_v1.py` | append-only publication、resume 與 scheduler |
| Parent preflight | `src/pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_v1.py` | 最新 read-only CandidateSet gate |
| Tests | `tests/test_pq_rbbc_issuance_*_v1.py` | positive、negative、mutation、restart tests |
| Evidence | `artifacts/metadata/issuance_*/`、`manifests/pq_rbbc_issuance_*` | path-free evidence 與 claim boundary |

上述長檔名是已存在 checkpoint 的穩定 identity，現階段不搬動。一般閱讀不需要逐一
打開；只有重現某個 checkpoint 或調查 regression 時才進入對應檔案。

## Checkpoint 鏈的閱讀方式

只需先掌握五組：

1. **Relation／input gates**：ZK backend preflight、formal relation、production inputs、
   reduced constraints。
2. **CAP execution**：CAP576 preflight、child executor、split runner／lowerer、fragment
   producers。
3. **Multi-tree execution**：production ABI、bounded adapter、private spool、tree-post、
   scheduler 與 restart。
4. **Global phases**：Global-A、Global-B、Global-tail completion。
5. **Parent composition**：fresh parent I1–I5 CandidateSet；目前只完成 read-only preflight。

各 checkpoint 的 exact rows、digests、mutation coverage 與限制仍保留在
`docs/artifacts/PQ_RBBC_ISSUANCE_*.md`，本文件不複製那些歷史明細。

## 最新 checkpoint 的精確邊界

- CandidateSet 固定 40 個 source roles，並以同一份 captured bytes 執行 identity、parse、
  binding 與 future-consumption validation。
- Bounded fixture 以 direct host checks 核對 I1–I5 的 `M`、`ctx`、ticket message、`rho`、
  `r`、`c_r`、request hash、`beta`、holder 與 trace binding。
- Parent constraints 與 native join rows 都仍為 0；3,100,000 rows 只是 planning upper
  bound，不是 observation。
- `SID` 目前只檢查 canonical／nonzero；freshness 與 linearizable reservation 尚未實作。

最新詳細證據：

- [`PQ_RBBC_ISSUANCE_PARENT_I1_I5_CANDIDATESET_PREFLIGHT_V1_zh-TW.md`](../artifacts/PQ_RBBC_ISSUANCE_PARENT_I1_I5_CANDIDATESET_PREFLIGHT_V1_zh-TW.md)
- `manifests/pq_rbbc_issuance_parent_i1_i5_candidateset_preflight_manifest_v1.json`
- `artifacts/metadata/issuance_parent_i1_i5_candidateset_preflight_v1/`

## 下一個 gate

1. 先對 exact commit `b877189` 完成 finding-free read-only technical／security review。
2. 實作 bounded、可獨立呼叫的 fresh parent I1–I5 relation consumer。
3. 只有 parent constraints／native joins 有實際 replay evidence 後，才評估 production
   relation 與 qualified PQ-SE backend integration。

在上述 gate 完成前，不得把 CandidateSet preflight、host checks 或通過 unit tests描述成
正式 `pi_issue`、cryptographic proof verification 或 production issuance。
