# PQ-RBBC Issuance ZK backend interface-only preflight

日期：2026-09-11
Checkpoint namespace：`pq-rbbc/issuance-zk-backend/preflight/v1`

## 結論

本 checkpoint 完成從既有 issuance relation inventory 到未來正式
`π_issue` backend 的介面層與 fail-closed gate；它沒有選定、下載、整合或宣稱任何
cryptographically secure production backend，也沒有執行 589,030,555 constraints
的大型 proving。

最重要的 preflight finding 是：核心 proof 與既有 replayed relation 的 public／private
partition 不同。這個差異必須先以新 relation namespace 處置，不能把 v2.29 replay
直接交給 proof backend 後稱為正式 `π_issue`。

目前狀態：

| 層級 | 狀態 |
| --- | --- |
| Defined | backend security requirements、`Setup`／`ProveIssue`／`VerifyIssue`、canonical encodings 已定義 |
| Instantiated | 僅有明確命名的 insecure test-only backend；production backend 未 instantiated |
| Implemented | interface codec、binding checks 與 production refusal 已實作；secure prover／verifier 未實作 |
| Tested | bounded interface positive／negative／mutation tests 已建立；大型 proving 未測試 |
| Evidence-sealed | 本 preflight contract 可形成 portable evidence；production backend 未 evidence-sealed |
| Proof-closed | false |
| Production-closed | false |

## 範圍與不變項

本工作從 local `main` commit
`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb` 建立獨立 branch
`codex/pq-rbbc-issuance-zk-backend-preflight`。不延續或修改 v2.43
reservation-binding worktree。

本 checkpoint：

- 不修改 system architecture、ticket lifecycle 或 `pq_sat_auth`；
- 不修改 v2.25、v2.29、v2.37 historical files；
- 不沿用其他 tree 的 observed `stream_bytes`；
- 不建立或提交 assignment、BR1CS、pickle、cache、checkpoint、resume state、logs 或
  proving output；
- 不執行 constraint replay 或 cryptographic proving；
- 不把 relation replay 說成 `π_issue` 已產生；
- 不把 test backend 說成 PQ、ZK、extractable 或 cryptographically secure。

## 實際 relation 與程式位置

| 項目 | 實際位置 | 已有 claim |
| --- | --- | --- |
| Reference statement／witness／relation | `src/pq_rbbc_reference.py` 的 `IssueStatement`、`IssueWitness`、`verify_relation` | executable research relation |
| Incremental production-shape circuit | `src/pq_rbbc_reference.py:generate_issue_circuit` | 2,971,580 rows；1 external assertion 的歷史 parent archive |
| Binary R1CS lowering | `src/pq_rbbc_br1cs.py` | streaming F2 R1CS；無 proof backend |
| Blind-UOV request ABI | `src/pq_rbbc_blind_uov_abi.py` | `y` 為 72 bytes；test adapter 不可 deployment |
| CAP-to-H_RBBC parent join | `src/pq_rbbc_parent_join_replay.py` | v2.29 replay closed；不是 ZK proof |
| v2.37 unified statement codec | `src/pq_rbbc_cap_unified_statement_parent_abi.py` | 314-byte statement codec；production relation 未 qualified |
| v2.25 reference manifest | `manifests/pq_rbbc_reference_manifest_v2_25.json` | 4,032 public bits、8,224 secret bits |
| v2.25 BR1CS manifest | `manifests/pq_rbbc_br1cs_manifest_v2_25.json` | parent 2,971,580 rows；無 proof backend |
| v2.29 replay evidence | `artifacts/metadata/parent_join_recovery_v2_29/` | combined 589,030,555 rows、0 failures、0 external assertions |

v2.29 證明 complete replay 中的 rows、assignments 與 bindings 在該 historical
relation 下相符。它不證明：

- witness privacy；
- zero knowledge；
- knowledge extraction 或 simulation extraction；
- proof system transcript correctness；
- `π_issue` proof serialization；
- production proof size、prover time 或 verifier time。

## Formal relation 與現有 partition 差異

核心 proof 定義：

```text
public x  = (pp, ctx, sid, rid, beta)
private w = (M, r, rho, k_hold, e)
```

其中 relation 必須同時驗證：

1. I1 `TicketShape(M,ctx)`；
2. I2 canonical ticket digest；
3. I3 exact Blind-UOV request relation；
4. I4 holder-key binding；
5. I5 identity／serial／trace-encryption binding。

目前 `src/pq_rbbc_reference.py` 則使用：

```text
public  = (common_ctx, rid, payload, blind_request)
private = (sn, holder_key, error, blind_mask,
           blind_randomness, blind_hash_image)
```

差異如下：

- formal private `M`／payload 在 legacy circuit 是 public；
- legacy statement 缺少 `pp` 與 `sid`；
- `blind_hash_image` 在 legacy witness 中顯式提供，formal relation 則由完整 request
  relation 約束；
- v2.37 雖有 `(common_parameters_digest,ctx,sid,rid,y)`，其 `sid` fixture 是由
  witness serial 衍生，而 formal protocol 要求 fresh issuer-side `sid`；
- v2.37 statement codec 尚未與 589,030,555-row relation 接合。

所以新的 backend 不能直接把 historical v2.29 relation identity 宣稱成 formal
`R_issue`。後續需要新 relation/profile namespace；v2.29 evidence 只能作 predecessor
與 equation-level engineering evidence，必須保持原 bytes 與 claims。

## `π_issue` 在 protocol 中的位置

`π_issue` 是 holder 在 issuer 執行 `Blind-UOV.Respond` 前提交的 augmented
well-built-request proof。它把 exact public request `beta=y` 綁定到 hidden ticket、holder
secret、trace ciphertext 與 authenticated `rid`／`sid`。

它不是完成 ticket 後 CAP protocol 的最終 `π_2`，也不是另外放在 native request proof
旁邊的第二份 proof；核心 proof 將它定義為 native well-built-request proof 的 strengthened
replacement。

## Backend 必須滿足的安全性質

### Post-quantum security

完整 soundness、knowledge extraction、zero knowledge、Fiat–Shamir/non-interactive
transformation 與 transcript hash 都必須在 quantum adversary model 下成立。只使用
hash-based commitment、lattice assumption 或「transparent」名稱，不足以自動得到整個
composition 的 PQ security。

### Zero knowledge

Issuer 已知 `ctx`、`sid`、`rid`、`beta`，但 proof 不得額外洩漏 hidden `M`、blind mask、
randomness、holder key 或 trace error。Relation evaluator 通過與 test backend binding
通過都不是 ZK 證據。

### Knowledge soundness／extractability

每個 accepted issuance proof 必須對應滿足 I1–I5 的 witness。這個 extractor property
用來排除 request/message substitution，並保證只讓 certified-language ciphertext 進入
後續 opening path。

### Simulation extractability

若只考慮 simple stand-alone decoder safety，核心 proof 表示 knowledge soundness 足夠。
但目前 protocol 同時主張 concurrent issuance 與 gated-CCA/GCCA hybrid：reduction 在看過
simulated proofs 後，仍須從 adversarial accepted proofs 擷取 witness。因此保留完整現有
claim 時，simulation extractability 是必要條件。

本 checkpoint 不授權把 protocol 降格成 stand-alone profile，也不因候選名稱包含
`SNARK`、`argument of knowledge`、`Fiat–Shamir` 或 `post-quantum` 就宣稱 SE。

### Non-interactive／Fiat–Shamir 條件

候選若由 public-coin IOP/argument 經 Fiat–Shamir 或 BCS 類 transformation 變成
non-interactive proof，至少必須另外固定：

- 適用於 exact protocol 的 QROM theorem 與 assumptions；
- hash function、security parameters、query bounds 與 challenge sampling；
- 每一 round 的 transcript grammar、message ordering 與 length encoding；
- protocol、backend、backend version、security profile、relation identity、PP identity、
  statement及 proof role 的 domain separation；
- verifier 重建 challenge 的 exact byte sequence；
- simulated-transcript extraction theorem，而非只引用一般 soundness。

### Setup assumptions

Transparent setup 可以避免 toxic waste，但仍需凍結 hash／field／code／query parameters。
若候選使用 structured CRS，則 setup ceremony、participant model、contribution verification、
trapdoor disposal 與 public parameter identity 都是 production blocker。核心 proof 中的
simulation/extraction trapdoors 只存在於 security experiment，不得讓真實 protocol
participant 取得。

## 候選方案

本比較只使用原始論文、正式發表頁或官方 implementation documentation；成本數據不得
外推成目前 589,030,555 rows 的實測。

### Aurora／libiop

- 原始論文／官方 implementation：
  <https://eprint.iacr.org/2018/828>、<https://github.com/scipr-lab/libiop>
- Transparent、hash/random-oracle；官方 implementation 說明 BCS transform 的 QROM/PQ、
  ZK 與 proof-of-knowledge preservation。
- R1CS；官方 implementation 列出 smooth prime fields 與 binary extension fields。
- Asymptotic：`O(n log n)` prover、`O(n)` verifier、`O(log^2 n)` proof；論文在數百萬
  constraints 的特定參數下報告小於 250 KB，不能外推至本 relation。
- MIT。
- Academic proof-of-concept，未經充分 code review，不可 production。
- 沒有找到符合本 concurrent/GCCA composition 的 simulation-extractability 證明。

Disposition：作為後續 reduced engineering baseline 的首選，但不是 production selection。

### Brakedown／Shockwave

- 原始論文／reference branch：
  <https://eprint.iacr.org/2021/1043>、<https://github.com/conroi/Spartan/tree/brakedown>
- Transparent hash/random-oracle；Brakedown field-agnostic、linear-time prover、sublinear
  proof/verifier；Shockwave 需 FFT-friendly field。
- 論文明確說現有兩份 implementation 都不是 zero knowledge。
- 未建立本 protocol 需要的 simulation extractability。
- Reference branch 沿用 MIT；整合前仍須 pin exact commit 與 license bytes。

Disposition：只作 performance／field-compatibility comparator。

### STARK／Winterfell

- 原始論文／官方 implementation：
  <https://eprint.iacr.org/2018/046>、<https://github.com/facebook/winterfell>
- Transparent、hash-based、PQ-oriented family。
- 現有 relation 必須另做 AIR translation；不是直接 streamed R1CS consumer。
- 官方 README 明確說目前 implementation 不提供 perfect zero knowledge，且為 unaudited
  research project、not production ready。
- 沒有本 relation 的 knowledge／SE qualification。
- MIT。

Disposition：不作本 checkpoint 的 integration target。

### LaBRADOR／lattirust

- 原始論文／官方研究頁／implementation：
  <https://eprint.iacr.org/2022/1341>、
  <https://research.ibm.com/publications/labrador-compact-proofs-for-r1cs-from-module-sis>、
  <https://github.com/lattirust/labrador>
- Module-SIS、quantum-safe knowledge proof。
- 論文對 `2^20` constraints、模 `2^64+1`、128-bit security 報告 58 KB；與
  GF(2^193)/589M relation 不同，不可轉用。
- Rust implementation 為 `0.0.1-alpha`，binary/ring R1CS reductions 仍標示進行中；
  research use、未 audit。
- MIT OR Apache-2.0。
- 未建立本 protocol 的 ZK/SE qualification。

Disposition：研究候選，不作近期 backend。

### Binius64

- 官方 repository／documentation：
  <https://github.com/binius-zk/binius64>、<https://www.binius.xyz/>
- Transparent、hash-based、binary-oriented；MIT OR Apache-2.0。
- 使用 64-bit-word constraint system，不是目前 GF(2^193) streamed R1CS 的直接 consumer。
- 專案與 ZK 功能說明快速演進；整合前須 pin exact commit、protocol blueprint 與 security
  claim，並解決官方頁面在不同時間留下的狀態差異。
- 未建立本 protocol 的 simulation extractability。

Disposition：watchlist，不作本 checkpoint 的 integration target。

## 推薦與風險

目前不選 production backend。若下一階段授權 reduced prototype，優先評估
Aurora/libiop，因為它同時具直接 R1CS 介面、明確 PQ/QROM、ZK、AoK 文件與 permissive
license；Brakedown 只作 field-agnostic performance comparator。

Aurora 的主要風險：

- 沒有符合本 protocol 的 simulation-extractability qualification；
- implementation 是 C++ academic prototype，未 production review；
- exact GF(2^193) parameter、FFT/code domain 與 589M streaming/memory 相容性未驗證；
- public-parameter/proof encoding 不是本 repository 已凍結的 production grammar；
- paper benchmark 不代表本 relation；
- dependency、compiler、hash、parameter及 source commit identity 均未凍結。

所以後續 reduced prototype 即使成功，也只能提升到「candidate backend integrated and
tested on reduced relation」，不能提升 `Proof-closed` 或 `Production-closed`。

## Canonical backend interface

實作位置：`src/pq_rbbc_issuance_zk_backend_preflight.py`。

介面為：

```text
Setup(backend, security_profile_id, relation_manifest_sha256,
      production=True) -> canonical public-parameter bytes

ProveIssue(backend, pp_bytes, statement_bytes, witness_bytes,
           production=True) -> canonical proof bytes

VerifyIssue(backend, pp_bytes, statement_bytes, proof_bytes,
            production=True) -> bool
```

每種物件使用不同 magic、`u16le` codec version、fixed section count、依序 `u16le`
section ID、`u64le` payload length 與 payload。Unknown、reordered、duplicate、wrong-length、
truncated、wrong-version 與 trailing bytes 均拒絕。

### Public parameters

固定欄位：

```text
backend_id
backend_version
security_profile_id
abi_profile_digest[32]
relation_manifest_sha256[32]
setup_kind
backend_payload
```

未來 backend-specific payload 的內部 grammar 仍須由選定 backend checkpoint 凍結；目前
只有 test-only payload。

### Statement

新的 interface ABI 使用：

```text
abi_profile_digest[32]
public_parameters_digest[32]
ctx[32]
sid[32]
rid[32]
beta[72]
```

`public_parameters_digest = SHA-256(canonical pp bytes)`，使 formal `pp` 透過 exact
canonical identity 進入 statement。這是新的 interface namespace，不表示已重建
formal relation。

### Witness

Private encoding 為：

```text
abi_profile_digest[32]
ticket_payload_M[368]
blind_mask_r[72]
canonical_cap_randomness_rho[1036]
holder_key[32]
error_vector_e[836]
```

`rho` 不是 historical test adapter 的 32-byte `blind_randomness` nonce。依 core proof
與既有 production CAP profile，它固定使用 `CAPRandomness.serialize(PRODUCTION_PARAMETERS)`：
`PQRBBC-CAP-RANDOM-V1` magic、64-byte profile fingerprint、兩個 canonical
GF(2^193) salt elements、`tree_count = 18`，以及 18 對 canonical root elements，合計
1,036 bytes。錯誤 profile、tree count、field high bits 或 32-byte nonce 均拒絕。

Witness bytes 只能在 prover process 內使用，不得寫入 manifest、portable evidence、log、
cache 或 checkpoint。本 checkpoint 只使用 deterministic synthetic fixture。

### Proof

Envelope 為：

```text
abi_profile_digest[32]
backend_id
backend_version
public_parameters_digest[32]
statement_digest[32]
transcript_domain
backend_payload
```

固定 transcript domain：`PQ-RBBC/ISSUE-PROOF/V1`。這個 envelope 只固定外層 binding；
backend-specific proof payload、Fiat–Shamir transcript 與 parameter grammar 仍未 production
freeze。

## Production fail-closed 與 test backend

`PRODUCTION_BACKEND_ALLOWLIST` 初始為空。Production `Setup`、`ProveIssue`、
`VerifyIssue` 在 parse 或建立 output 前即丟出 `ProductionBackendUnavailable`。

唯一替身名稱為：

```text
InsecureTestOnlyIssueBackend
backend_id = INSECURE-TEST-ONLY-PQ-RBBC-ISSUE
```

它不檢查 relation、不隱藏 witness、不提供 knowledge soundness，也沒有 PQ／ZK／SE
security。其 proof payload 只是 deterministic statement/PP binding digest，用於測試
wrong statement、wrong domain、mutation及 codec rejection。它只有在呼叫者明確傳入
`production=False` 時才能使用，且不在 production allowlist。

## Bounded tests 與資源

Targeted command：

```bash
PYTHONPATH=src python -m unittest \
  tests.test_pq_rbbc_issuance_zk_backend_preflight -v
```

Bounded self-check：

```bash
PYTHONPATH=src python -u \
  src/pq_rbbc_issuance_zk_backend_preflight.py --self-check
```

完整 regression：

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Preflight 上限估算：1 CPU、256 MiB、60 秒；實際大型 replay rows 與 cryptographic
proofs 都是 0。589M proving command 故意未提供。

2026-09-11 實際驗證結果：

- bounded self-check：positive 1/1、negative 5/5 rejected、production entry points
  3/3 refused；
- targeted unittest：26 passed、0 failed、0 skipped；
- 完整 baseline：共 714 tests，702 passed、12 個既有 optional-external-artifact
  skips、0 failed／errors，耗時 737.706 秒。

## 下一個 gate

在任何 major backend integration 前，必須先完成：

1. 將 formal statement/witness partition 接到完整 relation 的新 namespace；
2. 固定 fresh issuer-side `sid` 的產生、驗證與 replay 語義；
3. 對選定 backend pin 原始 security proof、official source commit、license、build 與
   dependency identities；
4. 取得 exact transformation/transcript 的 PQ simulation-extractability theorem 或另行
   授權縮限 protocol claim；
5. 凍結 field、code、query、hash、security profile、PP/proof serialization及 concrete
   security bound；
6. 只在 reduced relation 建立 adapter、positive／negative／mutation evidence；
7. 完成獨立 cryptographic review；
8. 大型 proving 另行提供 operator-approved resources、exact command 與明確授權。

以上條件未完成前：

```text
qualified_production_backend = false
formal_pi_issue_generated = false
safe_to_integrate_major_backend = false
safe_to_start_large_replay = false
safe_to_start_large_proving_run = false
Proof-closed = false
Production-closed = false
```
