# PQ-RBBC 密碼學核心 roadmap（v2.13 checkpoint）

日期：2026-08-26

## 目前正在做什麼

目前工作仍在 `Blind-UOV -> pi_issue` 的第一個大關：把 CAP 從「參考演算法
跑得動」逐段變成可完整 replay、沒有偷接線的 native relation。

v2.13 完成第一個真實 production tree producer：tree index 0、4,096
leaves、degree 13。它直接讀取 v2.12 已封印的 point wires 39,945,673 與
39,945,866，不複製 points，也不靠 host-language assertion 補洞。

## 本版完成的證據

| 項目 | v2.13 結果 |
| --- | --- |
| Tree position / shape | index 0；4,096 leaves；degree 13 |
| Native relation | 51,325,080 rows；38,953,830 local wires |
| Global wire namespace | local start 40,194,597；max ID 79,148,426 |
| Point inputs | exact global wires 39,945,673、39,945,866 |
| Point copies | 0 |
| Full replay | 0 failures；0 external assertions |
| Mutations | point flip ×2、point swap、producer probes ×6，9/9 拒絕 |
| Outputs | 四類 value 全部與 frozen tail 相等 |
| Resume | GGM level／128-leaf checkpoint；prefix 驗證後續寫 |

## 現在能宣稱與不能宣稱的事

| Gate | 狀態 | 說明 |
| --- | --- | --- |
| Production global tail | 完成 | v2.9 archive replay，零 failures |
| Production split-tail | 完成 | v2.12 exact H1／point wires |
| Index-0 4,096／13 producer | v2.13 完成 | 51,325,080 rows 完整 replay |
| Index-0 point wire identity | v2.13 完成 | 直接引用 global point wires，無 local copy |
| Index-0 output values | v2.13 完成 | 四類 producer／consumer values 相等 |
| Index-2 2,048／12 producer | 未完成 | 下一個實作點 |
| 四類 output relocations | 未完成 | values 已比對，但 wire identity 尚未封印 |
| 18-tree composition replay | 未完成 | 尚未展開 2 + 16 個 position-specific producers |
| Parent `pi_issue` join | 未完成 | parent BR1CS 仍有 1 個 external assertion |
| 正式安全證明 | 未完成 | blindness、one-more UF、SE-NIZK/QROM 等尚未閉合 |
| Production | 未完成 | `production_closed = false` |

## 下一步：index-2 producer-only relation

### 1. 建立 position-sensitive execution cache

- tree index 2；
- 2,048 leaves；extension degree 12；
- 使用 production randomness label 與 canonical position encoding；
- checkpoint 每一 GGM level 及每 128 leaf outputs；
- cache header 綁定 profile fingerprint、tree index 與 source component
  digest，錯一項即拒絕 resume。

### 2. 直接綁定同一組 global points

producer tree-post Horner rows直接引用：

- point 0：wire 39,945,673 起，共 193 bits；
- point 1：wire 39,945,866 起，共 193 bits。

必做 mutations：point 0 flip、point 1 flip、point swap、假 local copy、錯
range 與錯 tree position。

### 3. 生成可續跑 assignment 並完整 replay

- producer-only archive；
- partial prefix 保留、逐 byte 重驗後續寫；
- generation 和 replay 分開 checkpoint；
- 記錄 rows、wire namespace、stream/archive digest、時間、RSS；
- 要求 verification failures 0、external assertions 0。

### 4. 封印兩種 shape 的四類 output relocations

index 0 與 index 2 都完成後，對下列 port 固定 source range、destination
range、bit length、value digest、equality rows 與 row-stream digest：

1. leaf commitments；
2. p-plain；
3. mhat-plain；
4. xi-masks。

只有 exact wire relation 也 replay 通過，才可把
`all_four_output_relocations_closed` 改成 true。

### 5. 展開十八棵樹

固定兩種 shape 後，再展開兩棵 degree-13 與十六棵 degree-12 的
position-specific producers。完整 composition 必須做到：

`shared inputs + 18 tree-pre + tail Phase A + 18 tree-post + tail Phase B`

完成條件：完整 assignment、零 failures、零 cross-segment external
assertions，並拒絕 tree swap、wrong point、wrong relocation、H1/H2 順序、
correction、serialization 與 request-binding mutations。

## 後續總路線

1. R1b-d：完成 index 2、output relocations、18-tree replay；
2. R2：CAP commitment wires 接入 parent `H_RBBC(m,c_r)`，移除最後一個
   external assertion；
3. R3：完成 `pi_issue`、Blind-UOV fork、CAP 與 QROM reductions；
4. R4：完成 Signature-Gated Decryption reduction 與 threshold 實作；
5. R5：選定抗量子 proof/signature backend，實測尺寸、延遲與記憶體；
6. R6：整合衛星 AKE、anti-replay、handover、revocation 與 availability。

## 下一個具體動作

實作 tree index 2 的 2,048-leaf／degree-12 producer-only relation，沿用
v2.13 的 sealed cache、checkpoint/resume、exact point import 與 mutation
框架。這一步完成前，不展開十八棵樹，也不宣稱 output relocation 已閉合。
