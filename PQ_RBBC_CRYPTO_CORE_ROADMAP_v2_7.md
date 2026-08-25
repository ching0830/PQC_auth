# PQ-RBBC 密碼學核心 roadmap（v2.7 checkpoint）

日期：2026-08-24

## 我們正在做什麼

目標是把原本至少約 70 KB、對衛星鏈路過重的 Pilvi 型線上認證資料，改造成「離線做重計算，線上只送小型 ticket 與抗量子簽章」的架構。核心資料流是：

1. holder 在 `π_issue` 中證明自己知道合法 ticket payload、576-bit mask、CAP randomness、holder key 與 trace witness；
2. `π_issue` 把 Blind-UOV 的 blind request `y` 綁到該 ticket message，而 signer 看不到 message、mask 或 CAP commitment；
3. signer 只在 proof 通過後盲簽 `y`；
4. holder unblind/finalize，得到可公開驗證的 credential；
5. Signature-Gated Decryption 只在 credential、session/context binding 與 threshold policy 都通過時釋放解密材料。

這個方向用較大的長期公私鑰與較重的離線 proving 成本，換取較小的線上 credential。現有 provisional 線上目標是 368-byte payload 加 11,644-byte fork signature，共 12,012 bytes；這不是已量測或已安全認證的 production 數字。

## 目前完成度

| Gate | 狀態 | 目前證據 | 尚不能宣稱 |
| --- | --- | --- | --- |
| Canonical primitives | 完成 | GF(2^193)、Anemoi-193/336、sponge、domain separation、serialization、request binding vectors | 不代表整體 protocol 安全 |
| Blind request ABI | 完成研究型介面 | public request 僅 `y`；message、mask、CAP randomness 留在 `π_issue` witness；`y = r + H_RBBC(m,c_r)` 已內化 | Blind-UOV fork blindness／one-more UF 尚未重證 |
| 2,048-leaf production shard | 完成工程閉合 | degree 12；19,903,324 wires；26,126,283 rows；完整 assignment；0 verifier failures；5/5 stale probes 拒絕 | 單樹 fixture 非 secure profile |
| 4,096-leaf production shard | 本版完成 | degree 13；39,789,564 wires；52,224,501 rows；完整 assignment；0 verifier failures；5/5 stale probes 拒絕 | 單樹 fixture 非 secure profile |
| 18-tree CAP composition | 未完成，下一個主 checkpoint | 已有兩種 constituent tree shapes | 尚未組合 16×2,048 + 2×4,096、cross-tree corrections 與單一 transcript |
| Parent issuance archive | 未完成 | incremental parent BR1CS 可重現，其他關係已 materialize | 仍有 1 個 external assertion；尚未 exact wire join |
| Formal security proof | 部分骨架 | threat model、關係定義與 fail-closed claim boundary 已寫入證明文件 | unique-mask、straightline extraction、blindness、one-more UF、SE-NIZK/QROM reductions 未完成 |
| Proof backend qualification | 未完成 | native R1CS engineering evidence | 尚無 production prover/verifier、proof size、signature size、time、peak-memory benchmark |
| Satellite protocol integration | 未開始 | 線上 payload 方向與 SGTD 介面已定義 | 尚未做 AKE、anti-replay、handover、revocation、availability 與 RF/link-budget 評估 |

## v2.7 新增的精確 checkpoint

4,096-leaf shard 使用 safe extension degree 13。原因是 degree-12 extension field 的 multiplicative group 只有 4,095 個非零元素，無法為 4,096 葉提供互異的非零 evaluation points。

完整 deterministic run 產生：

- 4,096 leaves、2,048 witness bits、11 Horner coefficients、2 consistency points、每葉 2,450 tape bits；
- 12,290 次 XOF（含 request binding）與 38,999 次 Anemoi permutations；
- 39,789,564 wires；
- 38,997,232 nonlinear rows + 13,227,269 linear rows = 52,224,501 rows；
- 37,955,986,032 virtual canonical row-stream bytes；
- 994,739,228-byte fixed-width assignment archive；
- 52,224,501 rows replayed、0 failures；
- GGM source、tape pack、Horner multiply、commitment link、request pack 五個 stale-witness probes 全部拒絕。

這建立的是「完整 deterministic 單樹 assignment 的 satisfiability 與 mutation-sensitive wiring」工程證據，不是 CAP soundness、extractability、zero knowledge 或整個 Blind-UOV/SGTD protocol 的安全證明。

## 接下來的執行順序

### R1 — v2.8：18-tree canonical composition

把 16 個 2,048-leaf/degree-12 trees 與 2 個 4,096-leaf/degree-13 trees 放入一個 production CAP executor：

- 固定 tree ordering、XOF labels、salt/root derivation 與 byte serialization；
- internalize cross-tree correction values；
- 產生一個完整 commitment 與一個 request-binding hash；
- 以 streaming row digest 先鎖 topology；
- completion gate：18-tree vector 可執行、零 callback、零 shard-level external assertion，且所有 constituent counters 與 correction equations 對帳。

資源注意：若直接複製單樹 assignment，18-tree field values 會達約 10.0 GB，row relation 約 5.22 億 rows、虛擬 row stream 約 379 GB。v2.8 應先做 canonical composition topology 與 shared-value schedule，再決定單體 archive、分段 archive或 backend-native witness streaming。

### R2 — v2.9：parent exact wire join

將完整 CAP output bytes 逐 bit/field wire 接到 `H_RBBC(m,c_r)` 與 `y = r + h`，移除 parent BR1CS 最後 1 個 external assertion。

Completion gate：parent archive external assertions = 0；honest assignment 接受；message、mask、CAP randomness、hash image、tree correction、serialization 任一 mutation 都拒絕；archive round-trip 與 witness-independent topology 通過。

### R3：`π_issue` 的 fork-specific formal proof

依賴順序：

1. CAP admissible-domain 與 unique-mask lemma；
2. CAP straightline extractor，明確處理 degree-12/13 mixed trees；
3. `y = r + H_RBBC(m,c_r)` 的 message/commitment binding；
4. Blind-UOV fork blindness；
5. one-more unforgeability；
6. proof backend 的 knowledge soundness、zero knowledge、simulation extractability 與 QROM composition；
7. theorem 將 issuance transcript、blind signature 與 ticket payload 綁成單一 security game。

每一項都需列出 assumption、adversary interface、reduction loss、oracle programming、abort event 與 parameter margin；不能直接繼承 Blind-UOV 論文的 240-row instantiation 結論，因為本 fork 使用 Anemoi-193/336 與不同 native relation。

### R4：Signature-Gated Decryption 證明與實作

- credential verification 綁定 `ctx || sid || rid || policy || ciphertext_digest`；
- threshold shares 使用 domain-separated authenticated encapsulation；
- decoder fail-closed，明確處理 duplicate、stale、revoked 與 equivocated shares；
- 證明 credential unforgeability 到 unauthorized decryption 的 reduction；
- 加入 replay、mix-and-match、chosen-ciphertext、malformed-share 與 partial-compromise 測試。

### R5：backend qualification 與尺寸實測

- 選定抗量子的 proof/signature backend 與 security category；
- 量測 keygen、prover、signer、holder finalize、online verify、峰值記憶體與能源；
- 分別報告 public key、secret key、blind request、`π_issue`、final signature、ticket、ciphertext 與 threshold share 大小；
- 以真實 fork 參數重測 11,644-byte signature provisional target；
- completion gate：可重現 benchmark、參數審查、constant-time/side-channel review 與第三方 cryptographic review。

### R6：衛星認證整合

只在 R1–R5 的核心邊界清楚後進行：把 credential 放入 post-quantum AKE，而不是拿 credential 取代 AKE。加入 timestamp/counter、anti-replay window、handover binding、revocation distribution、clock-loss recovery、packet loss/fragmentation 與 denial-of-service budget；最後才做衛星 link simulation 與 field trial。

## Production 判定規則

下列條件全部成立前，`production_closed` 必須維持 `false`：

1. 18-tree native relation 與 parent exact wire join 均為零 external assertions；
2. `π_issue`、Blind-UOV fork、CAP 與 SGTD 的 formal reductions 完整並經獨立審查；
3. production post-quantum backend、keys 與 parameters 已選定；
4. final signature/proof/ciphertext 尺寸與性能已實測，而不是引用 provisional target；
5. constant-time、fault、side-channel、parser、serialization、rollback 與 key lifecycle 已審查；
6. 衛星 AKE、replay、handover、revocation 與 availability tests 通過。

## 下一個具體動作

下一步是 v2.8 的「18-tree composition topology」，先完成不保留 10 GB Python assignment 的 deterministic streaming composer，凍結 tree ordering、correction schedule、完整 commitment/request-binding vectors 與 row-stream digest；再選擇分段 assignment 或 backend-native witness streaming 來做全體 satisfiability replay。
