# Satellite Access `R_access` MPC-in-the-Head proof prototype v0.1

> 日期：2026-09-16（Asia/Taipei）
> 狀態：exact relation experimental prototype；Implemented／Tested
> `experimental_reference_only = true`
> `production_ready = false`、`simulation_extractable = false`、
> `proof_closed = false`、`production_closed = false`

## 結論

本 checkpoint 已真正產生並驗證對現行 exact `R_access` 的 proof，不是把
`evaluate_access_relation()` 的布林結果包裝成 proof，也沒有把 `k_hold`、MAC、簽章或
`hash(secret)`當成 proof。Verifier只取得 canonical statement與MPC view openings，會逐個
Boolean AND gate重播兩次完整SHAKE256計算；`k_hold`不傳給verifier。

219-round host benchmark的主要結果為：

| 項目 | Exact measured result |
| --- | ---: |
| Canonical proof bytes | 2,151,727 bytes |
| UE-side prover workload proxy | median 605.938 ms；min 599.648；p95/max 616.392 |
| FGS verification workload proxy | median 337.857 ms；min 336.186；p95/max 343.334 |
| Circuit construction | median 315.837 ms；min 312.818；p95/max 325.777 |
| Proof serialization | median 2.295 ms；min 2.201；p95/max 2.348 |
| Fresh-worker peak RSS | median 39,960 KiB；min 39,880；p95/max 40,068 |
| Success | 5/5 measured proofs；另有1次warm-up，0 failures |

數字是AMD Ryzen 5 7600X／Linux x86_64／CPython 3.12.9上的host-specific結果；proving
只能稱為「UE-side prover workload proxy」，沒有在手機、衛星UE或satellite path實測。

最重要的負面結果是proof比現行`ProofLimitsV2.max_access_nizk_bytes = 262,144`大約
8.21倍，不能直接嵌入目前reference `AccessRequestV2`。本lane沒有修改shared
`src/pq_sat_auth/v2/access.py`或放寬該界線。

## 1. Exact relation與statement adapter

Prototype使用既有`AccessProofStatementV2`的exact 170-byte encoding：

```text
"PQSAT-X2" || u16be(2)
|| access_profile_digest[32]
|| access_pp_digest[32]
|| h[32]
|| request_core_digest[32]
|| holder_binding_tag[32]
```

Witness只有32-byte `k_hold`。Circuit計算：

```text
h' = SHAKE256("PQ-RBBC/HOLD" || k_hold, 256)

tag' = SHAKE256(
    "PQ-SAT/ACCESS-HOLDER-BIND/v2"
    || k_hold
    || request_core_digest,
    256
)
```

接受條件為`h' = h`且`tag' = holder_binding_tag`。兩個輸入都小於SHAKE256的
136-byte rate，因此各執行一個padding／absorb block及一次完整Keccak-f[1600]。

`build_verifier_owned_statement_v01()`要求FGS側提供authenticated
`access_profile_digest`／`access_pp_digest`及從已驗證ticket取得的`h`；
`request_core_digest`與`holder_binding_tag`則由收到的exact request重建。Adapter強制
`access_pp_digest`等於backend parameter digest，拒絕prover另傳statement interpretation。
它仍假設caller已完成`VerifyTicket`及configuration authentication；這個prototype沒有
取代既有FGS pure-check processor。

## 2. Proof construction

本版採3-party ZKBoo-family generalized MPC-in-the-Head：

1. 每個repetition將`k_hold`拆成三份XOR shares；任兩份不決定secret。
2. XOR／NOT gate在share上local計算；NOT的public常數只加入party 0。
3. 每個AND gate使用party-local random tape。對party `i`及`j=(i+1) mod 3`：

   ```text
   z_i = (x_i & y_i) xor (x_i & y_j) xor (x_j & y_i)
         xor r_i xor r_j
   ```

   三份`z_i` XOR後等於明文`x & y`。
4. Prover對三個完整views作SHAKE256 commitment，並把三份output shares及commitments放入
   Fiat–Shamir transcript。
5. 每輪ternary challenge開啟相鄰兩個views。Verifier利用兩個seeds／input shares、其中
   一個neighbour transcript，重新計算被檢查view的每一個AND output與兩個SHAKE outputs。
6. 隱藏view保持commitment-bound；三份output shares必須XOR成statement的`h || tag`。
7. Verifier重建全部commitments／outputs後重新計算challenge；proof只接受唯一canonical
   parameter/version/length，truncation與trailing bytes均拒絕。

Commitment、PRG及Fiat–Shamir使用獨立domain-separated SHAKE256。這提供一個可執行的
hash-based PQ research candidate，不自動推出QROM Fiat–Shamir security或simulation
extractability。

## 3. Parameters與proof encoding

Primary benchmark parameters：

```text
name = PQSAT-R-ACCESS-MPCITH-L1-219-v0.1
proof_suite_id = 0xfffe                # experimental only
parameter_version = 1
repetitions = 219
parameter_digest_sha256 =
  c8aa8fb6a36aa09b5abf9deaec4cbd7561a15f77611c3a7821bf1e79ff3342f3
view seed / commitment = 32 / 32 bytes
one party transcript = 9,600 bytes
round proof = 9,825 bytes
header = 52 bytes
proof = 52 + 219 * 9,825 = 2,151,727 bytes
```

219輪只對應classical interactive `(2/3)^219`、約128.1-bit的analytical accounting。
`claimed_classical_soundness_bits = 128`不是QROM／SE theorem，也不是經審查的concrete
security claim。

Tests另使用7-round、68,827-byte固定parameter set，加速mutation regression。其
deterministic proof SHA-256為
`5d3d7788a0abed28eaeed9d7708cddfbcecc29df9a6c118ccc3358f16309527e`；這個test profile
只有約4-bit classical interactive accounting，不能拿來報安全參數或部署。

## 4. Circuit／constraint size

`circuit.py`重用repository既有FIPS-202 bit ordering及Keccak builder，實際materialize
兩個SHAKE circuits，而非用公式推估：

| Metric | Exact constructed value |
| --- | ---: |
| Canonical statement | 170 bytes |
| Public tuple input bits | 1,280 |
| Secret input bits | 256 |
| Keccak-f[1600] permutations | 2 |
| Boolean AND gates | 76,800 |
| Boolean XOR／NOT definitions | 263,724 |
| Witness bitness constraints | 256 |
| Nonlinear constraints including bitness | 77,056 |
| Public output equality assertions | 512 |
| Value-carrying trace wires | 342,318 |
| Failed／external assertions | 0／0 |

MPC backend本身以64-bit lane平行執行Boolean gates；一個view保存1,200個64-bit nonlinear
outputs，即76,800 bits／9,600 bytes。`access_profile_digest`與`access_pp_digest`屬
statement／Fiat–Shamir／parameter binding；因formal `R_access`兩條等式不使用它們，
不額外捏造hash constraint。

## 5. Benchmark方法與結果分類

重現命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python \
  benchmarks/access_nizk/benchmark_r_access.py \
  --warmups 1 --iterations 5 --timeout-seconds 120
```

每次warm-up／iteration都啟動fresh Python process；worker內用`perf_counter_ns()`分別量測
setup、circuit construction、randomness/share generation、MPC simulation＋commitment、
Fiat–Shamir、serialization及verification。`preprocessing`為not applicable；本construction
沒有可跨proof重用的offline preprocessing。完整JSON在
`benchmarks/access_nizk/results_r_access_mpcith_l1_219_20260916.json`。

### Exact measured

- proof length、proof generation／verification與circuit metrics均為實際執行結果；
- 五個proof使用fresh OS randomness，因此SHA-256不同，但bytes完全相同且5/5接受；
- peak RSS來自fresh Linux worker的`ru_maxrss`，可重現為whole-process peak；它包含
  interpreter、setup、circuit、proof bytes及verification，不能拆成prover-only peak。

### Analytical／extrapolated

- 128-bit值只來自classical `(2/3)^t`公式；
- 完整M1為：

  ```text
  ticket_bytes
  + AccessRequestV2 fixed/framing 354
  + ML-KEM-768 UE public key 1,184
  + measured pi_access 2,151,727
  = ticket_bytes + 2,153,265 bytes
  ```

  `ticket_bytes`未在本proof benchmark量測，保留為unknown且不得當成0。先前5,629-byte
  AKE材料下限也不是完整access通訊量。

### 未量測

- 真實手機／衛星UE proving latency、energy及peak memory；
- satellite-path latency／jitter；
- production ticket bytes；
- production compiler／native backend（本版純Python，compiler flags不適用）。

## 6. Tests與安全邊界

Targeted tests覆蓋：

- exact statement／request adapter及deterministic vector；
- honest proof acceptance與wrong `k_hold` prover rejection；
- mutated `h`、`request_core_digest`、`holder_binding_tag`、profile／parameter digest；
- proof bit／byte mutation、truncation、trailing bytes；
- cross-parameter／cross-version proof；
- proof中不出現exact 32-byte `k_hold` plaintext sequence；
- exact circuit output、gate counts及zero external assertions。

Final validation：

```text
Targeted: 13 passed, 0 skipped, 0 failures/errors (0.396 seconds)
Full repository: 1,039 total; 1,027 passed; 12 existing optional-artifact
                 skips; 0 failures/errors (777.581 seconds)
```

Full command為`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover
-s tests -q`。12個skip是既有、需repository外部artifact的測試；本lane沒有新增skip。

本版仍有下列未關閉限制：

- construction／serialization沒有formal proof或independent cryptographic review；
- 沒有QROM Fiat–Shamir reduction、simulation-extractability或access composition theorem；
- Python實作不是constant-time，沒有secure erasure、side-channel或fault analysis；
- 只檢查proof不含完整32-byte secret序列，不等於一般資訊洩漏proof；
- proof超過現行M1 parser limit，沒有接入production FGS path；
- 沒有跨語言vectors、fuzzing、native backend或第二套獨立implementation；
- test／benchmark success不構成Proof-closed或Production-closed。

## 7. 下一個最小checkpoint

建立同一exact SHAKE circuit的compressed successor（優先ZKB++／Picnic3-style seed-tree與
view compression），第一個gate是：

1. 保留現行170-byte statement及兩條SHAKE等式不變；
2. 加入challenge-fork／三-view consistency與special-soundness regression；
3. 經獨立construction review；
4. 只有實測canonical proof不超過262,144 bytes後，才提出新的shared proof registry／
   `AccessRequestV2` integration request。

在此gate以前，不應修改現有production／reference proof limit，也不應把本prototype註冊成
production access suite。
