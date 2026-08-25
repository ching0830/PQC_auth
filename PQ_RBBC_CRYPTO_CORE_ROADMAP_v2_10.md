# PQ-RBBC 密碼學核心 roadmap（v2.10 checkpoint）

日期：2026-08-25

## 本版做了什麼

v2.9 已完成 18-tree 共用的 shared global tail，但 tail 的四類輸入仍只是獨立、bit-constrained consumer ports。v2.10 完成 producer segmentation 的第一個可驗證核心：兩個 reduced profile trees 現在真的從 roots、salt 與 consistency points 計算出 tail 所需的輸出，而不是由測試程式直接塞入正確答案。

資料流變成：

1. `tree-pre[i]`：roots → GGM → leaf commitments／tapes → `p_plain`／`mhat_plain`；
2. global tail phase A：所有 tree commitments 與 corrections → H1 → consistency points；
3. `tree-post[i]`：tapes + consistency points → Horner → `xi_masks`；
4. global tail phase B：H2 → 5,391-byte commitment → request hash。

v2.10 的 producer relation 已實作第 1、3 步，並把 consistency points 設成明確輸入 port。第 2、4 步仍由 v2.9 global tail 提供，但兩邊尚未共用相同 wire IDs。

## Exact reduced evidence

| 項目 | Tree 0 | Tree 1 |
| --- | ---: | ---: |
| Leaves / extension degree | 4 / 3 | 4 / 3 |
| Rows | 34,148 | 34,148 |
| Wires | 23,329 | 23,329 |
| Assignment archive | 583,353 bytes | 583,353 bytes |
| Replay failures | 0 | 0 |
| External assertions | 0 | 0 |
| Mutation probes | 6/6 rejected | 6/6 rejected |

兩棵樹合計產生 8 個 output ports；`leaf-commitments`、`p-plain`、`mhat-plain`、`xi-masks` 的 port ID、bit width 與 value digest 全部和 v2.9 tail consumer 相等。

## 現在能宣稱與不能宣稱的事

| Gate | 狀態 | 說明 |
| --- | --- | --- |
| Shared production global tail | 完成 | 56,806,711 rows、40,194,596 wires、完整 assignment replay、0 failures |
| Reduced producer relation | v2.10 完成 | 兩個 position-sensitive segments、完整 replay、12/12 probes rejected |
| Producer→tail value ABI | 完成 | 8/8 port widths 與 value digests 相等 |
| Producer→tail wire identity | 未完成 | producer 與 tail 仍各自配置 wire namespace |
| Global points wire identity | 未完成 | consistency points 是 producer input，尚未直接重用 tail phase-A output wires |
| Production producer shapes | 未完成 | 尚未跑 4,096/degree-13 與 2,048/degree-12 producer-only assignments |
| 18-tree composition replay | 未完成 | 尚未組合 2 + 16 producers、links 與 shared tail |
| Parent `π_issue` join | 未完成 | parent BR1CS 仍有 1 個 external assertion |
| 正式安全證明 | 未完成 | unique-mask、extraction、blindness、one-more UF、SE-NIZK/QROM 尚未閉合 |
| Production | 未完成 | `production_closed = false` |

Reduced fixture 只證明 segmentation 與 ABI，不是 secure profile，不能外推成 production security。

## 下一步：R1b-b production-shape producers

### 1. 將 global tail 拆成 phase A／phase B port contract

- phase A 輸入 commitments、`p_plain`、`mhat_plain`，輸出 H1 與 consistency-point wire ranges；
- phase B 輸入 phase-A state、18 組 `xi_masks` 與 message，輸出 H2、commitment 與 request hash；
- split 前後的完整 tail row stream、outputs 與 assignment 必須和 v2.9 canonical tail 等價。

### 2. 跑兩個實際 production shapes

- tree index 0：4,096 leaves、degree 13；
- tree index 2：2,048 leaves、degree 12；
- 使用完整 production execution 的真實 tree index、roots、metadata 與 global points；
- 產生 producer-only fixed-width assignments；
- 全 row replay、0 failures；
- 每個 shape 至少保留 GGM、tape、三個 pre ports、xi post port 與 point-link mutation probes。

### 3. 固定 relocation/link ABI

每個 link record 必須包含 source segment、tree index、local wire range、global relocated range、bit length、value digest 與 link-row digest。SHA-256 只能作重現證據，不能取代 native equality constraints或共享 wire identity。

### 4. 展開到完整 18 trees

兩個 production shapes 分別閉合後，再產生 2 個 degree-13 與 16 個 degree-12 position-specific segments，最後 replay：

`shared inputs + 18 tree-pre + tail phase A + 18 tree-post + tail phase B`

完成條件是 exact rows/wires/digest、完整 assignment、零 verification failures、零 cross-segment external assertions，以及 tree swap、wrong point、wrong relocation、correction、H1/H2 order、serialization 與 request-binding mutations全部拒絕。

## 後續順序

1. R1b-b/c：production producers、wire relocation、完整 18-tree replay；
2. R2：CAP commitment wires 接入 parent `H_RBBC(m,c_r)`，移除最後 external assertion；
3. R3：`π_issue`、Blind-UOV fork、CAP 與 QROM 正式 reductions；
4. R4：Signature-Gated Decryption reduction 與 threshold implementation；
5. R5：抗量子 proof/signature backend、尺寸與效能實測；
6. R6：衛星 AKE、anti-replay、handover、revocation 與 availability integration。

## 下一個具體動作

先把 v2.9 global tail 的 consistency-point wires 正式暴露為 phase-A output port，並證明 split-tail 和原始 canonical tail 的 row/output/assignment 等價；接著才跑兩個昂貴的 production-shape producer assignments。
