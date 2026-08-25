# PQ-RBBC 密碼學核心 roadmap（v2.8 checkpoint）

日期：2026-08-25

## 我們正在做什麼

目標是把原本至少約 70 KB、對衛星鏈路過重的 Pilvi 型線上認證資料，改造成「離線做重計算，線上只送小型 ticket 與抗量子簽章」的架構。核心資料流是：

1. holder 在 `π_issue` 中證明自己知道合法 ticket payload、576-bit mask、CAP randomness、holder key 與 trace witness；
2. `π_issue` 把 blind request `y` 綁到 ticket message，而 signer 看不到 message、mask 或 CAP commitment；
3. signer 只在 proof 通過後盲簽 `y`；
4. holder unblind/finalize，得到可公開驗證的 credential；
5. Signature-Gated Decryption 只在 credential、session/context binding 與 threshold policy 都通過時釋放解密材料。

這個方向用較大的長期公私鑰與較重的離線 proving 成本，換取較小的線上 credential。現有 provisional 線上目標是 368-byte payload 加 11,644-byte fork signature，共 12,012 bytes；這不是已量測或已安全認證的 production 數字。

## 目前完成度

| Gate | 狀態 | 目前證據 | 尚不能宣稱 |
| --- | --- | --- | --- |
| Canonical primitives | 完成 | GF(2^193)、Anemoi-193/336、sponge、domain separation、serialization、request binding vectors | 不代表整體 protocol 安全 |
| Blind request ABI | 完成研究型介面 | public request 僅 `y`；message、mask、CAP randomness 留在 `π_issue` witness；`y = r + H_RBBC(m,c_r)` 已內化 | Blind-UOV fork blindness／one-more UF 尚未重證 |
| 2,048-leaf production shard | 工程閉合 | degree 12；19,903,324 wires；26,126,283 rows；完整 assignment；0 failures；5/5 stale probes 拒絕 | 單樹 fixture 非 secure profile |
| 4,096-leaf production shard | 工程閉合 | degree 13；39,789,564 wires；52,224,501 rows；完整 assignment；0 failures；5/5 stale probes 拒絕 | 單樹 fixture 非 secure profile |
| 18-tree CAP reference composition | 本版完成 | 實跑 2×4,096 + 16×2,048；122,847 CAP XOF calls；17 correction pairs；單一 5,391-byte commitment 與 request hash；canonical linked document | 尚非 monolithic native assignment，也尚未證明 global-tail wire join satisfiable |
| 18-tree native composition | 未完成，下一個 checkpoint | 已有兩種 assignment-verified templates 與唯一 link schedule | 尚未去重 global transcript tail、materialize exact native rows、重播完整 assignment |
| Parent issuance archive | 未完成 | incremental parent BR1CS 可重現，其他關係已 materialize | 仍有 1 個 external assertion；尚未 exact wire join |
| Formal security proof | 部分骨架 | threat model、關係定義與 fail-closed claim boundary 已寫入證明文件 | unique-mask、straightline extraction、blindness、one-more UF、SE-NIZK/QROM reductions 未完成 |
| Proof backend qualification | 未完成 | native R1CS engineering evidence | 尚無 production prover/verifier、proof size、signature size、time、peak-memory benchmark |
| Satellite protocol integration | 未開始 | 線上 payload 方向與 SGTD 介面已定義 | 尚未做 AKE、anti-replay、handover、revocation、availability 與 RF/link-budget 評估 |

## v2.8 新增的精確 checkpoint

Production profile 的唯一 tree order 是先 2 個 4,096-leaf/degree-13 trees，再 16 個 2,048-leaf/degree-12 trees，合計 18 trees、40,960 leaves。平行 executor 先在 reduced profile 與原始直跑 reference 做逐物件相等比對，再執行完整 production profile。

完整 production reference 產生：

- 40,924 次 seed derivation、40,960 次 seed commitment、40,960 次 tape expansion 與 3 次全域 transcript XOF，共 122,847 次 CAP XOF；再加 1 次 request-binding XOF，總計 122,848 次；
- CAP 內 389,974 次 Anemoi permutations（131,031,264 permutation nonlinear rows）；5,391-byte commitment 的 request binding 再用 58 次（19,488 rows），總計 390,032 次與 131,050,752 rows；
- 17 組 `delta_P` 與 `delta_Mhat` cross-tree corrections；
- 1 個 5,391-byte canonical CAP commitment；
- 修正舊版 accounting bug：serializer 對 `alpha` 與每個 correction 分別 byte-align，舊公式只在總 bit count 最後 round-up，少算 13 bytes；
- 1 個綁定 32-byte request message 與 commitment 的 576-bit request hash；
- 18 個位置敏感的 tree-component digests 與一個全序 XOF trace digest；
- 5 個 stale composition probes，分別改動 tree order、shard evidence、correction、commitment 與 request message，全部拒絕。

Frozen vector digests：

- linked document SHA-256：`a7ef7eb4689d84c686074308d0d167e1567ab84578d66b5ad004970940ea0163`；
- commitment SHA-256：`12123e95b1b64d87da7a575dbf803fc53ded9eb9a23b807eeab2cba51dfe5b62`；
- XOF trace SHA-256：`ccfa51ec2aee9501483c65023c4a877316eb6dd0557ccd6c42dfdf5f20f2c4e6`；
- request hash：`3f9ec0aeab100e4ebef8046068851874f08fcda6daa2e42178dd559f55e38a31da28af9ccd0653bb4ca574ec8264cce1f3c024c97e858e2c877bba7968c039dc61f516dfed995ba3`。

## Template envelope 的正確解讀

18 個已驗證 one-tree fixture 的簡單加總是：

- 398,032,312 wires；
- 390,142,528 nonlinear rows；
- 132,327,002 linear rows；
- 合計 522,469,530 rows；
- 377,830,939,120 virtual canonical row-stream bytes；
- 9,950,810,104 assignment archive bytes。

這是保守的工程資源上界，不是精確 production circuit count。每個 one-tree fixture 都含自己的 inputs、H1/points、H2/commitment/request tail，直接相加會重複 18 次全域 transcript。v2.8 的 linked document 只證明 tree ordering、evidence selection、correction schedule 與完整 reference transcript 已被唯一凍結；它沒有用 hash link 取代 native R1CS constraints，也沒有宣稱約 9.95 GB 的單體 assignment 已驗證。

## 接下來的執行順序

### R1 — v2.9：18-tree native global tail 與 segmented assignment

- 把 tree-local GGM、leaf tape、Horner ports 與 shared salt/roots/message ports 分離；
- 只建立一份 production H1/points、17 correction equations、18 組 ξ、H2、commitment serialization 與 request-binding tail；
- 固定 exact wire-ID relocation 與跨 segment link table；
- 以分段 fixed-width archive 或 backend-native witness stream 寫出全 assignment，避免保留 10 GB Python dictionary；
- 對 exact native row generator 重播全部 rows，並加入跨 tree correction、H1 field order、H2 ξ order、commitment bytes 與 request hash stale probes。

Completion gate：exact native rows/wires/digest 可重現；18-tree assignment 全部重播且零 failure；global-tail 與 segment links 零 external assertion；不再用 template envelope 冒充精確 count。

### R2 — v3.0：parent exact wire join

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

每項都需列出 assumption、adversary interface、reduction loss、oracle programming、abort event 與 parameter margin；不能直接繼承 Blind-UOV 論文的 240-row instantiation 結論，因為本 fork 使用 Anemoi-193/336 與不同 native relation。

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

只在 R1-R5 的核心邊界清楚後進行：把 credential 放入 post-quantum AKE，而不是拿 credential 取代 AKE。加入 timestamp/counter、anti-replay window、handover binding、revocation distribution、clock-loss recovery、packet loss/fragmentation 與 denial-of-service budget；最後才做衛星 link simulation 與 field trial。

## Production 判定規則

下列條件全部成立前，`production_closed` 必須維持 `false`：

1. 18-tree native relation 與 parent exact wire join 均為零 external assertions；
2. `π_issue`、Blind-UOV fork、CAP 與 SGTD 的 formal reductions 完整並經獨立審查；
3. production post-quantum backend、keys 與 parameters 已選定；
4. final signature/proof/ciphertext 尺寸與性能已實測，而不是引用 provisional target；
5. constant-time、fault、side-channel、parser、serialization、rollback 與 key lifecycle 已審查；
6. 衛星 AKE、replay、handover、revocation 與 availability tests 通過。

## 下一個具體動作

下一步不是先碰 parent assertion，而是把 v2.8 的 18-tree linked schedule 降成 exact native composition：抽出不重複的 global transcript tail、固定所有跨 segment wire IDs、stream 全 assignment，然後對完整 row generator 做零失敗重播。完成後才有資格把 CAP bytes 接入 parent `H_RBBC`。
