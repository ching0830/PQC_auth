# PQ-RBBC 密碼學核心 roadmap（v2.11 checkpoint）

日期：2026-08-25

## 本版完成了什麼

v2.10 已能讓兩個 reduced tree producers 算出 tail 所需的四類值，但
producer 的 consistency points 還只是「數值相同的獨立 inputs」。v2.11
先把 global tail 內部切成正式的 Phase A／Phase B wire contract：

1. input prelude 配置 shared 與 tree consumer ports；
2. Phase A 執行 corrections、H1 與 consistency-point derivation；
3. Phase B 使用同一組 H1／point wire IDs 執行 alpha、H2、commitment 與
   request binding。

這是同一條 native relation 裡的邏輯切分，不是把資料序列化後交給另一
條 relation。因此 Phase A→Phase B 已經是 native wire identity。

## Exact reduced evidence

| 項目 | 結果 |
| --- | ---: |
| Rows / wires | 36,801 / 24,992 |
| Assignment archive | 624,928 bytes |
| Canonical／split row stream | 完全相同 |
| Canonical／split assignment body | 完全相同 |
| Replay failures | 0 |
| External assertions | 0 |
| Boundary mutations | 4/4 rejected |

Reduced Phase A 輸出：

- H1：wire 12,255 起、386 bits；
- consistency point：wire 14,305 起、193 bits。

Reduced profile 只有一個 point；production profile 有兩個，因此不能把
這組 reduced wire numbers 外推到 production。

## 現在能宣稱與不能宣稱的事

| Gate | 狀態 | 說明 |
| --- | --- | --- |
| Production global tail | 完成 | v2.9 的 56,806,711 rows 與完整 replay 保持不變 |
| Reduced tree producers | 完成 | v2.10 的兩個 position-sensitive producers |
| Reduced producer→tail value ABI | 完成 | 8/8 ports 的 ID、width、value digest 相等 |
| Reduced tail Phase A→B identity | v2.11 完成 | H1／point 使用相同 native wires |
| Production split-tail contract | 未完成 | 尚未在 production assignment 上取得精確 phase wire ranges |
| Producer→point wire identity | 未完成 | producer point inputs 尚未 relocation／equality-link 到 tail outputs |
| Production producer shapes | 未完成 | 尚未生成 producer-only 4,096／13 與 2,048／12 assignments |
| 18-tree composition replay | 未完成 | 尚未組合 2 + 16 producers、links 與 shared tail |
| Parent `pi_issue` join | 未完成 | parent BR1CS 仍有 1 個 external assertion |
| 正式安全證明 | 未完成 | fork、CAP、blindness、one-more UF、SE-NIZK/QROM 尚未閉合 |
| Production | 未完成 | `production_closed = false` |

## 下一步：R1b-c production split materialization

### 1. 取得 frozen production execution 與 assignment

- 使用 v2.9 已封印的 production execution cache；
- 使用既有 1,004,865,028-byte assignment，若 artifact 不可取得才重跑；
- 在 observer 模式 replay，而不是建立另一份不同 relation；
- 要求 row count、wire count、stream digest、commitment 與 request hash
  仍和 v2.9 完全相同。

### 2. 固定 production Phase A／B ranges

- 記錄 input prelude、Phase A、Phase B 的 half-open row/wire ranges；
- H1 與兩個 193-bit points 必須是 contiguous、bit-constrained outputs；
- H2 與 alpha rows 必須直接引用這些 wire IDs；
- 對兩個 point wires、H1、commitment、request hash 做 exact-wire mutations。

### 3. 跑兩個 production producer shapes

- tree index 0：4,096 leaves、degree 13；
- tree index 2：2,048 leaves、degree 12；
- 使用 production Phase-A 的兩個 point outputs；
- 產生 producer-only fixed-width assignments 並完整 replay；
- 固定 source local range、relocated global range、length、value digest 與
  equality-row digest。

### 4. 展開至 18 trees

完成兩種 shape 後，再展開兩個 degree-13 與十六個 degree-12
position-specific producers，最後 replay：

`shared inputs + 18 tree-pre + tail Phase A + 18 tree-post + tail Phase B`

完成條件是完整 assignment、零 verification failures、零 cross-segment
external assertions，以及 tree swap、wrong point、wrong relocation、H1/H2
順序、correction、serialization 與 request-binding mutations全部拒絕。

## 後續順序

1. R1b-c/d：production split、production producers、wire relocation、18-tree replay；
2. R2：CAP commitment wires 接入 parent `H_RBBC(m,c_r)`，移除最後 external assertion；
3. R3：`pi_issue`、Blind-UOV fork、CAP 與 QROM 正式 reductions；
4. R4：Signature-Gated Decryption reduction 與 threshold implementation；
5. R5：抗量子 proof/signature backend、尺寸與效能實測；
6. R6：衛星 AKE、anti-replay、handover、revocation 與 availability integration。

## 下一個具體動作

優先找回並驗證 v2.9 production execution cache／assignment，以 observer
模式取得 production H1 與兩個 consistency-point 的精確 wire ranges；避免
在已有 artifact 可重用時重新跑一次十幾小時的 production materialization。
