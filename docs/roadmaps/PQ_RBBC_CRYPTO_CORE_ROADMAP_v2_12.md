# PQ-RBBC 密碼學核心 roadmap（v2.12 checkpoint）

日期：2026-08-25

## 本版完成了什麼

v2.12 找回 v2.9 的 21 個 assignment 分片，逐片驗證後重組出原本的
1,004,865,028-byte production archive。接著使用 witness-independent
topology fixture 只重建 row topology，真正的 satisfiability 證據全部取自
frozen assignment。

完整 replay 結果：

- 56,806,711 rows；
- 40,194,596 wires；
- verification failures 0；
- external assertions 0；
- canonical row-stream SHA-256 完全不變；
- H1、兩個 consistency points、commitment、request hash 的 5/5
  exact-wire mutations 全部拒絕。

## Exact production Phase A／B contract

| Segment | Row range | Wire range |
| --- | ---: | ---: |
| Input prelude | `[0, 15939162)` | `[1, 15939163)` |
| Phase A | `[15939162, 56375441)` | `[15939163, 39946062)` |
| Phase B | `[56375441, 56806711)` | `[39946062, 40194597)` |

Phase-A outputs：

- H1：wire 39,943,623 起，386 bits；
- consistency point 0：wire 39,945,673 起，193 bits；
- consistency point 1：wire 39,945,866 起，193 bits。

Phase B 直接使用同一批 H1／point wire IDs，不經複製、序列化或 hash-only
link。

## 現在能宣稱與不能宣稱的事

| Gate | 狀態 | 說明 |
| --- | --- | --- |
| Production global tail | 完成 | v2.9 assignment 完整 replay，零 failures |
| Reduced tree producers | 完成 | v2.10 的兩個 position-sensitive producers |
| Reduced tail Phase A→B identity | 完成 | v2.11 reduced 證據 |
| Production split-tail contract | v2.12 完成 | exact ranges、H1、兩個 point wires 均已封印 |
| Production producer shapes | 未完成 | 尚未生成 producer-only 4,096／13 與 2,048／12 assignments |
| Producer→point wire identity | 未完成 | producer point inputs 尚未 relocation／equality-link |
| 18-tree composition replay | 未完成 | 尚未組合 2 + 16 producers、links 與 shared tail |
| Parent `pi_issue` join | 未完成 | parent BR1CS 仍有 1 個 external assertion |
| 正式安全證明 | 未完成 | fork、CAP、blindness、one-more UF、SE-NIZK/QROM 尚未閉合 |
| Production | 未完成 | `production_closed = false` |

## 下一步：R1b-d production producer materialization

### 1. 生成兩種 production producer shapes

- tree index 0：4,096 leaves、degree 13；
- tree index 2：2,048 leaves、degree 12；
- 不複製 H1、H2、commitment 或 request tail；
- 產生 producer-only fixed-width assignments 並完整 replay。

### 2. 固定兩個 point-input relocations

每個 producer 的兩個 193-bit point inputs 必須 relocation 或 equality-link
到：

- production point 0：wire 39,945,673；
- production point 1：wire 39,945,866。

對 wrong point、point swap、local copy 未連結、錯誤 relocation range 做
mutation tests。

### 3. 固定四類 producer output relocations

對 leaf commitments、`p-plain`、`mhat-plain`、`xi-masks` 記錄：

- producer local source range；
- composition global destination range；
- bit length；
- canonical value digest；
- equality-row count 與 row-stream digest。

### 4. 展開至 18 trees

完成兩種 shape 後，再展開兩個 degree-13 與十六個 degree-12
position-specific producers，最後 replay：

`shared inputs + 18 tree-pre + tail Phase A + 18 tree-post + tail Phase B`

完成條件是完整 assignment、零 verification failures、零 cross-segment
external assertions，以及 tree swap、wrong point、wrong relocation、H1/H2
順序、correction、serialization、request-binding mutations 全部拒絕。

## 後續順序

1. R1b-d：production producers、wire relocation、18-tree replay；
2. R2：CAP commitment wires 接入 parent `H_RBBC(m,c_r)`，移除最後 external assertion；
3. R3：`pi_issue`、Blind-UOV fork、CAP 與 QROM 正式 reductions；
4. R4：Signature-Gated Decryption reduction 與 threshold implementation；
5. R5：抗量子 proof/signature backend、尺寸與效能實測；
6. R6：衛星 AKE、anti-replay、handover、revocation 與 availability integration。

## 下一個具體動作

先以 tree index 0 建立 4,096-leaf／degree-13 producer-only archive，直接
引用 production point wires 39,945,673 與 39,945,866，完整 replay 後再做
tree index 2 的 2,048-leaf／degree-12 shape。
