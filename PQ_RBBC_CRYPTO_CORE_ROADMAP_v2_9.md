# PQ-RBBC 密碼學核心 roadmap（v2.9 checkpoint）

日期：2026-08-25

## 我們正在做什麼

目標仍是把原先至少約 70 KB、對衛星鏈路太重的 Pilvi 型線上認證資料，改成「離線做重計算，線上只送小型 ticket 與抗量子 credential」。目前研究鏈是：

1. holder 在 `π_issue` 中證明 ticket payload、576-bit mask、CAP randomness、holder key 與 trace witness 一致；
2. public blind request 只有 `y`，而 `y = r + H_RBBC(m,c_r)` 在關係內綁定盲簽訊息；
3. signer 只在 `π_issue` 驗證成功後盲簽；
4. finalized credential 再成為 Signature-Gated Decryption 的授權條件；
5. 衛星端最終仍需把 credential 放入 post-quantum AKE，不能用 credential 取代 AKE。

這個方向容許較大的長期公私鑰、較重的離線 proving 與較大的地面端記憶體，換取較小的線上傳輸。現有 12,012-byte ticket 仍只是 provisional target，不是 production 實測或安全認證數字。

## v2.9 完成的下一塊

v2.8 已凍結 18-tree production reference 與 canonical link schedule，但每個 one-tree fixture 都重複自己的 H1、points、H2、commitment 與 request tail。v2.9-R1a 把真正只能存在一次的 shared global tail 抽成獨立 native relation：

- 18 組 tree input ports 與 shared salt/message ports 全部 bit-constrained；
- 17 組 cross-tree `delta_P`／`delta_Mhat` correction equations；
- H1、兩個 nonzero distinct consistency points、shared `alpha`；
- 18 組 `xi` components 與 H2 field order；
- canonical 5,391-byte commitment serialization；
- 32-byte message 到 576-bit request hash 的 native binding；
- fixed-width assignment archive、完整 row replay、零 external assertions；
- 6 個 stale-witness probes，覆蓋 tree commitment source、correction source、alpha packing、H2 xi source、commitment publication 與 request digest packing。

Canonical production evidence：

- relation：`pq-rbbc/cap/production-global-tail/v1`；
- rows：`56,806,711`；
- wires：`40,194,596`；
- row-stream SHA-256：`c368d41de9e57910803e98284a4ec0a0f45862fa80f3d070a50477f82627c9df`；
- assignment archive bytes：`1,004,865,028`；
- assignment archive SHA-256：`946c1feef78741f0b7e04cfffb237c08b4736d63d8214f8202f822da6e8ec8c1`；
- replay failures：0；
- stale-witness probes：6/6 rejected；
- external assertions：0。

## Claim boundary

| Gate | 狀態 | 本版可以宣稱 | 本版不能宣稱 |
| --- | --- | --- | --- |
| 18-tree reference | 完成 | 2×4,096/degree-13 + 16×2,048/degree-12；40,960 leaves；122,847 CAP XOF calls；17 corrections；5,391-byte commitment | 不等於完整 native composition |
| 2,048-leaf producer shape | 分別閉合 | 完整 assignment、全 row replay、0 failures、5 stale probes | 單樹 fixture 不是 secure profile |
| 4,096-leaf producer shape | 分別閉合 | 完整 assignment、全 row replay、0 failures、5 stale probes | 單樹 fixture 不是 secure profile |
| Shared global tail | v2.9-R1a 完成 | exact native rows/wires/digests、全 assignment replay、6 probes、0 external assertions | port producer 尚未接成同一 wire namespace |
| 18 tree producer segments | 未完成 | 已知兩種 generator 與 canonical tree order | 尚未按每個真實 tree witness 產生 segment archive |
| Cross-segment identity | 未完成 | tail ports 的 exact bit widths/order 已凍結 | 尚未以 exact relocated wire IDs 連接 producer outputs |
| Complete 18-tree replay | 未完成 | shared tail 本身已完整 replay | 尚未 replay producer segments + links + tail 的單一 composition |
| Parent issuance join | 未完成 | parent BR1CS 與 `y = r + h` 可重現 | 仍有 1 個 CAP-to-`H_RBBC` external assertion |
| Fork security proof | 未完成 | threat model與 reduction obligations 已列出 | unique-mask、extraction、blindness、one-more UF、SE-NIZK/QROM 尚未重證 |
| Production backend | 未完成 | relation engineering evidence 可重現 | 無合格 prover/verifier、實測 proof/signature size 或 side-channel review |
| Satellite integration | 未開始 | SGTD 與 credential/AKE 的角色邊界已定義 | 無 AKE、anti-replay、handover、revocation、RF/link-budget 實驗 |

`production_closed` 必須維持 `false`。本版只把 `production_global_tail_native_closed` 設為 `true`；`tree_producer_segments_materialized`、`cross_segment_wire_identity_closed`、`complete_18_tree_assignment_replayed`、`parent_cap_to_h_rbbc_join_closed`、`fork_security_proof_revalidated` 與 `production_closed` 全部維持 `false`。

## 接下來的執行順序

### R1b — 18 個 tree producer segments 與 exact link table

1. 把既有 one-tree generator 拆成 `tree-pre`、Horner／mask producer 與 `tree-post` segments，移除每個 fixture 內重複的 global tail；
2. 對 2 個 4,096-leaf 與 16 個 2,048-leaf 真實 witness 分別輸出 fixed-width segment assignment；
3. 定義不可變 port ABI：tree index、shape、bit length、source segment、local wire range、global relocated wire range、value digest；
4. materialize equality rows或共享 global wire IDs，不以 SHA-256 link 取代 R1CS identity；
5. 對 producer segments、link rows 與 v2.9 shared tail 做一個完整 replay；
6. 加入 tree swap、wrong-shape evidence、port offset、correction、H1 order、H2 xi order、serialization 與 request-binding mutations。

完成條件：canonical 18-tree composition 的 exact rows/wires/digest 可重現；完整 assignment 零 failures；所有 cross-segment links 零 external assertion；任何 stale segment 或 wire relocation 都拒絕。

### R2 — Parent exact wire join

把完整 CAP commitment bytes 的 native wires 直接接入 `H_RBBC(m,c_r)`，再接到 `y = r + h`，移除 parent BR1CS 最後 1 個 external assertion。

完成條件：parent archive external assertions = 0；honest assignment 接受；message、mask、CAP randomness、tree correction、commitment serialization 或 hash output 任一 mutation 都拒絕；archive round-trip 與 witness-independent topology 通過。

### R3 — `π_issue` 與 Blind-UOV fork 正式安全證明

依賴順序為 CAP admissible-domain／unique-mask、mixed degree-12/13 straightline extraction、request binding、fork blindness、one-more unforgeability、proof backend knowledge soundness／zero knowledge／simulation extractability、QROM composition。每項必須列出 adversary interface、assumption、reduction loss、oracle programming、abort event 與 concrete parameter margin，不能直接沿用 Blind-UOV 的 240-row instantiation 結論。

### R4 — Signature-Gated Decryption

Credential verification 必須綁定 `ctx || sid || rid || policy || ciphertext_digest`；threshold shares 使用 domain-separated authenticated encapsulation；decoder 對 duplicate、stale、revoked、equivocated 或 malformed shares fail-closed。需要把 credential unforgeability reduction 到 unauthorized decryption，並測 replay、mix-and-match、CCA、partial compromise 與 rollback。

### R5 — 抗量子 backend qualification 與尺寸實測

選定實際 post-quantum proof/signature backend，量測 keygen、prover、signer、finalize、online verify、peak memory 與能耗；分開報告 PK、SK、blind request、`π_issue`、final signature、ticket、ciphertext 與 threshold share。11,644-byte signature 與 12,012-byte ticket 必須重新 benchmark。

### R6 — 衛星認證整合

完成核心後才進入 post-quantum AKE、timestamp/counter、anti-replay window、handover binding、revocation distribution、clock-loss recovery、fragmentation、packet loss、DoS budget、link simulation 與 field trial。

## 下一個具體動作

下一步不是先刪 parent external assertion，也不是開始寫安全定理。先做 R1b：把 18 個真實 tree producer witnesses 降成不重複 global tail 的 segments，固定 exact port-to-wire relocation，再把 producer + links + v2.9 tail 當成一個 assignment 完整 replay。只有這一步完成，才有資格說 production CAP native composition closed。
