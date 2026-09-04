# PQ-RBBC v2.32 CAP Prove/Verify 唯讀 preflight

日期：2026 年 9 月 4 日

## 結果

V2.32已建立fail-closed、唯讀的CAP Prove／Verify、production proof
serialization與PoW／security-profile disposition preflight：

- `v2_32_cap_prove_verify_preflight_closed = true`
- `cap_prove_verify_interface_requirements_frozen = true`
- `production_proof_envelope_requirements_frozen = true`
- `pow_security_profile_disposition_requirements_frozen = true`
- `complete_statement_serialization_frozen = false`
- `production_proof_serialization_frozen = false`
- `cap_prove_implemented = false`
- `cap_verify_implemented = false`
- `fork_pow_implemented = false`
- `complete_concrete_security_bound_available = false`
- `cap_security_qualified = false`
- `production_closed = false`

這個checkpoint只凍結後續候選artifact的interface、schema、acceptance requirements與
claim boundary。它沒有實作prover／verifier、沒有選定PoW disposition、沒有產生
proof，也沒有重新執行589,030,555-row relation。

## Frozen inputs

Preflight逐byte綁定v2.31 contract evidence、proof-artifact evidence、frozen
manifest、qualification checker、candidate extractor及Blind-UOV ABI。來源relation
維持：

- rows：589,030,555；
- verification failures：0；
- external assertions：0；
- v2.29 input identity：
  `b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a`；
- ordered transcript：
  `1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514`；
- CAP profile fingerprint：
  `2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`。

沒有使用其他tree的observed `stream_bytes`。

## Prove／Verify requirements

`Prove`的輸入固定為canonical public statement、滿足既有relation的private
witness及fresh cryptographic randomness；輸出為canonical production proof
bytes。Deterministic frozen randomness只能用於測試，不構成security evidence。

`Verify`只可取得canonical public statement與proof bytes，不可取得private
witness、prover randomness或oracle secret state。Acceptance order必須先完成strict
parse與statement/profile binding，再重建Fiat–Shamir challenges、檢查PoW、驗證
`c_r`／`c_x`／`pi_2`、openings及degree-2 relation，所有檢查均成功才可接受。

Public statement的logical inputs固定為common parameters、`ctx`、`sid`、`rid`、
`y`；`y`為72 bytes。完整statement canonical encoding仍是必須補齊的external
design item，因此目前不宣稱serialization已封閉。

Contract identities：

| Contract | SHA-256 |
| --- | --- |
| Statement | `2905f91c975eda731db5172922a13ce9c467f9fd48404fbb7d9616a232ebc70a` |
| Prove／Verify | `96135823d10b216c4d8e0a3a46e8ddbc3ec24bd0c399c0c8fba1e924a0b1be7a` |
| Proof serialization | `ff8f6dc6b730f81df12ea4e32e3abdf40a0cb0b7537b5d05b813d53c5fd38950` |
| PoW／security profile | `57523a716ae9980a29304ce07ac869d5549d2c45f6dd4084275221c9358dd7f1` |

## Production proof envelope requirements

Preflight固定outer envelope grammar：

```text
magic || u16le(version) || profile_fingerprint[32] ||
u16le(section_count) ||
repeated(u16le(section_id) || u64le(payload_bytes) || payload)
```

- magic：`PQRBBC-CAP-PROOF-V1`；
- version：1；
- canonical section order：`c_r`、`c_x`、`pow_nonce`、`pi_2`；
- `c_r`固定5,391 bytes；
- `c_x`、`pow_nonce`與`pi_2`的production payload grammar及byte lengths尚未凍結；
- duplicate、unknown、reordered、truncated、oversized、trailing bytes與
  noncanonical unused high bits一律拒絕；
- statement不重複嵌入proof，而由Fiat–Shamir transcript綁定exact statement bytes。

V2.31的252-byte `PQRBBC-CAP-APPEND-CANDIDATE-V1`只供extractor candidate vector
使用，不是production `c_x`，不得直接升格。

## PoW 與 security-profile disposition

目前mixed-tree raw degree security在`q_H = 1`時只有182 bits，低於192-bit
target。Paper NIST III Shorter profile列出9 explicit PoW bits及約13.9 total PoW
bits，但fork尚未實作，也不能把13.9直接加到182就視為完整bound。

Disposition artifact必須明確選擇並review以下其中一種路徑：

1. 實作並驗證paper-compatible PoW；
2. 改變tree／degree profile並重建relation；
3. 只有取得明確project authorization時才可改變security target。

完整bound必須包含degree test、hidden leaves、oracle collision／guessing、constraint
sampling、PoW grinding／challenge sampling、multi-target／adaptive-session、concrete
Anemoi ROM及QROM measurement／programming loss，並至少列出`q_H`為`2^0`、`2^32`、
`2^64`及`2^128`的disposition。此preflight沒有選擇任何路徑；改變tree/profile會
使目前production shape失效並需要新namespace與replay，且未由本checkpoint授權。

## External requirements

Initial preflight執行時，下列五份artifact均缺少且identity未凍結：

1. `pq_rbbc_cap_prove_verify_spec_v2_32.pdf`；
2. `pq_rbbc_cap_proof_serialization_v2_32.json`；
3. `pq_rbbc_cap_pow_security_profile_disposition_v2_32.json`；
4. `pq_rbbc_cap_prove_verify_implementation_evidence_v2_32.json`；
5. `pq_rbbc_cap_prove_verify_independent_review_v2_32.json`。

即使候選檔schema-valid，在exact bytes、SHA-256與獨立review凍結前仍只有
`identity_not_frozen`，不能啟動implementation或擴張claim。

## V2.32 implementation start

依既有contract直接開始後，已完成以下bounded工作：

- candidate statement codec：固定
  `common_parameters_digest[32]／ctx[32]／sid[32]／rid[32]／y[72]`，包含magic、
  version、profile fingerprint、ordered field IDs及lengths；
- frozen outer proof envelope codec：strict parse `c_r／c_x／pow_nonce／pi_2`，拒絕
  wrong magic/version/profile、reordered/duplicate/unknown sections、length錯誤、
  noncanonical `c_r`與trailing bytes；
- `c_x`候選payload為raw 1,472-bit delta（184 bytes），明確拒絕v2.31的252-byte
  extractor wrapper；
- `pow_nonce`候選payload為`u64le`；`pi_2`只有bounded opaque payload，內部grammar
  尚未凍結；
- `prove()`明確回報production backend unavailable，`verify()`在strict parse後仍
  fail closed，沒有任何candidate envelope會被當成accepting proof；
- 已產生Prove／Verify specification PDF、serialization candidate、PoW disposition及
  partial implementation evidence；獨立review沒有自行補造。

PoW source cross-check確認paper-compatible規則不是單獨測試nonce前導零。ePrint
2024/490的optimized BAVC把18個vector commitments交錯映射到單一GGM tree，counter
同時驅動hidden indices，且必須讓explicit 9 challenge bits為零並使opening nodes
不超過`T_open=174`。目前fork的`CAP.Commit`是18個獨立roots，因此不能在不改變
CAP profile／namespace並重播relation的情況下直接繼承該13.9-bit PoW。V2.32沒有
做這項architecture/profile變更，也沒有以generic leading-zero PoW代替。

目前external candidate identities：

| Artifact | Bytes | SHA-256 | 狀態 |
| --- | ---: | --- | --- |
| Prove／Verify specification PDF | 71,327 | `79dd7a5d9c1a33d6f3a5f247f2143890ff6761d1971f83439f85e0ada84615af` | schema-valid candidate |
| proof serialization JSON | 3,722 | `b771ebc306937c2c72a419b976c2724e80e839a60e91d58051e253bf916c257e` | schema-valid candidate |
| PoW disposition JSON | 2,906 | `034279dd0214eb94d9385d6a81fa4b5f5b50748df4842bb80a24a803973c7552` | schema-valid, selected but blocked |
| partial implementation evidence | 5,519 | `93f4eea2e120e181846d70cffb7340e205a16efdfd13a70db75464a3036b8c75` | schema-valid, explicitly incomplete |
| independent review | — | — | missing；不得self-attest |

未調整既有preflight checker的identity table，因此candidate inventory仍正確回報前
四份為`identity_not_frozen`、review為`not_provided`，且所有large-run與security
flags維持false。Post-start report位於external directory的
`pq_rbbc_cap_prove_verify_environment_after_start_v2_32.json`。

本次bounded authoring使用1 CPU core、peak memory低於256 MiB、秒級完成，重播0
relation rows且產生0 accepting proofs。可重現的exact command為：

```bash
PYTHONPATH=src python -m pq_rbbc_cap_prove_verify_artifacts \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify \
  --blind-uov-paper /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/blind_uov_eprint_2025_895_revision_2025_10_31.pdf \
  --bavc-paper /tmp/eprint_2024_490.pdf \
  --dsd-paper /tmp/eprint_2024_541.pdf \
  --specification /tmp/pq_rbbc_v232_pdf/pq_rbbc_cap_prove_verify_spec_v2_32.pdf
```

## Resource estimate 與 exact command

唯讀preflight估算為1 CPU core、peak memory不超過256 MiB、60秒內完成、0
relation rows replayed、0 proofs generated。已實際完成的exact inventory command：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_prove_verify_preflight.py \
  --report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_prove_verify_environment_v2_32.json \
  --prove-verify-specification /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_prove_verify_spec_v2_32.pdf \
  --production-proof-serialization /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_proof_serialization_v2_32.json \
  --pow-security-profile-disposition /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_pow_security_profile_disposition_v2_32.json \
  --implementation-evidence /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_prove_verify_implementation_evidence_v2_32.json \
  --independent-review-attestation /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_prove_verify_independent_review_v2_32.json
```

結果為：

- `safe_to_run_read_only_preflight = true`；
- `safe_to_author_v2_32_candidate_artifacts = true`；
- `safe_to_implement_cap_prove_verify = false`；
- `safe_to_start_large_relation_replay = false`；
- `safe_to_start_large_proving_run = false`；
- `safe_to_claim_cap_security_qualified = false`；
- `exact_implementation_command = null`。

## Evidence identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `pq_rbbc_cap_prove_verify_preflight.py` | 30,829 | `83a79443c52fdaa6435e9c0ded7b3db0fed724b6a4af8d80134af0445b8976dd` |
| `pq_rbbc_cap_prove_verify_preflight_manifest_v2_32.json` | 11,021 | `d132dd0953a81af2f54d285d6162139880828927a659e95fb1cfbbdd927717aa` |
| external environment report | 3,340 | `94ad30300b83b517745e317ed027daffef8fc2c1de1b2f83cd92a9d1485fac86` |
| portable evidence | 5,445 | `0fcba15c45dda36df82606a49a197eb85aa20e8ac38f1c31c557eba639258657` |

Portable evidence位於
`artifacts/metadata/cap_prove_verify_preflight_v2_32/pq_rbbc_cap_prove_verify_preflight_evidence_v2_32.json`。
External environment report不加入Git。

Evidence verification command：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_prove_verify_preflight_evidence.py \
  --environment-report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_32_cap_prove_verify/pq_rbbc_cap_prove_verify_environment_v2_32.json
```

## Claim 與 artifact boundary

本checkpoint沒有修改system architecture、ticket lifecycle或`pq_sat_auth`。沒有
重新使用或提交assignment、BR1CS、pickle/cache、checkpoint/resume state或logs，
也沒有自行建立獨立review attestation。新增codec與candidate artifacts不代表
CAP.Prove／Verify或PoW已完成；large replay與large proving run均未啟動。
