# Satellite Access holder authentication D4：ML-DSA handshake prototype v0.1

日期：2026-09-16

狀態：D4 ML-DSA baseline Implemented／Tested／Measured；experimental only

```text
production_ready = false
proof_closed = false
production_closed = false
```

## 1. 結論

本checkpoint把D1–D3的ML-DSA-65候選降成隔離、可執行的完整握手prototype。它實際：

- 產生每票獨立ML-DSA-65 holder key及3,309-byte holder signature；
- 以ticket中的48-byte `q`重新綁定1,952-byte holder public key；
- 執行ML-KEM-768 keygen／encapsulation／decapsulation並取得相同32-byte shared secret；
- 由另一把ML-DSA-65 FGS key簽署response transcript；
- 經HKDF／HMAC-SHA384候選產生server及client Finished；
- 序列化完整M1、M2、顯式M3及包含M3的第一筆application record；
- 由兩套獨立ML-DSA實作雙向驗證同一種public key／signature bytes。

在11,644-byte issuer signature仍成立的**provisional fixture**下，實測wire bytes為：

| 物件 | Exact serialized bytes | 證據分類 |
| --- | ---: | --- |
| Candidate ticket | 12,126 | payload／envelope實際序列化；issuer signature只是固定長度fixture |
| Holder public key | 1,952 | 真實ML-DSA-65 output |
| Holder authenticator | 3,309 | 真實ML-DSA-65 signature |
| M1 `AccessRequest` | 18,897 | 實際序列化 |
| M2 `AccessAccept` | 4,755 | 真實KEM ciphertext、FGS signature與Finished |
| M3 `SessionActivate` | 198 | 實際序列化 |
| M1＋M2＋M3 | **23,850** | 實際序列化；距50,000尚有26,150 bytes |
| First application record | 377 | 17-byte ciphertext是條件式尺寸fixture |
| M1＋M2＋first record | **24,029** | AEAD尚未實例化；距50,000尚有25,971 bytes |

因此D1的算術已由真實ML-DSA／ML-KEM wire object重播確認；但尚不能說production
handshake已低於50,000 bytes，因為PQ-RBBC issuer signature、`R_issue,new`、`R_key`
circuit及production AEAD仍未完成。

## 2. Protocol位置與版本隔離

本prototype對應：

```text
offline issuance candidate:
    ticket authenticates D_H=(holder suite, parameter digest, q)

online access candidate:
    M1 = ticket + UE KEM epk + pk_H + Sign_skH(HolderAuthCoreV3)
    M2 = ML-KEM ciphertext + Sign_skFGS(transcript) + server Finished
    M3 = client Finished
```

程式只位於：

- `src/pq_sat_auth/v2/prototypes/holder_auth_v3/`；
- `tests/prototypes/holder_auth_v3/`；
- `benchmarks/access_holder_auth/`。

它使用不同的`PQSAT-A3` magic、version 3、`0xff10／0xff11` experimental suite IDs
與獨立Python types。沒有修改或註冊到shared v0.2 parser、suite registry、production
processor、`VerifyTicket`或one-time store。

## 3. Frozen bytes

### 3.1 Candidate ticket

Candidate payload為420 bytes：

```text
profile_version[2] || ctx[32] || sn[16]
|| holder_suite_id[2] || holder_parameter_digest[32] || q[48]
|| syndrome[208] || masked_identity[48] || trace_tag[32]
```

Transport envelope為62 bytes，issuer signature fixture為11,644 bytes，因此總長12,126。
Deterministic size fixture SHA-256：

```text
b992111734a6e2c1016c4ebcad1c79ff3534c30e282357a7cb81d63ba88d5264
```

這個fixture中的11,644 bytes明確不是PQ-RBBC signature，也不會通過現行
`Core.VerifyTicket`。D4 holder verifier刻意只驗holder binding／signature；issuer ticket
authentication仍是未實作的`VerifyTicketNew`邊界。

### 3.2 `HolderAuthCoreV3`

M1 fixed prefix保持294 bytes，第二個u16欄位由舊`proof_suite_id`改為
`holder_suite_id`，後接三個canonical `Opaque`：exact ticket、UE KEM epk及holder pk。
Holder簽署：

```text
"PQ-SAT/HOLDER-AUTH/v3"
|| u32be(len(holder_auth_core))
|| holder_auth_core
```

Deterministic frozen identities：

| Object | Bytes | SHA-256 |
| --- | ---: | --- |
| `holder_auth_core` | 15,568 | `aedf84ae8af060c5d513995dc5f24fff851a5b79b6cdab3b3eb06e9a87baa0ae` |
| holder signing input | 15,593 | `3ef57a174275143ccc67fcb959ff4c0aa055006030411e047681994bd5ff8f6b` |
| deterministic M1 fixture | 18,897 | `514bed0b29fc472f708c59c956162ecfe5bcdd9d4e3abc780ecced8e83271e86` |

採「protocol domain放入message、ML-DSA native context為空」是為了讓兩個provider使用
同一API語意。這是D1原先`ctx_H`建議的具體修訂；parameter descriptor及digest已明確標示
這項選擇，不得與非空native-context profile混用。

## 4. Providers、ACVP與interop

隔離環境：

```text
pqcrypto==0.3.3
dilithium-py==1.4.0
cffi==1.17.1
```

- `pqcrypto.sign.ml_dsa_65`提供PQClean-derived native provider；
- `dilithium_py.ml_dsa.ML_DSA_65`提供獨立pure-Python provider；其上游明確標示為
  教學／實驗用途且不是constant-time；
- `pqcrypto.kem.ml_kem_768`提供本次ML-KEM-768實測。

Interop結果四項皆通過：兩套provider各自產生的key/signature，皆可由自己及另一套
provider驗證；message或signature bit mutation均拒絕。

另以NIST ACVP Server `ML-DSA-sigVer-FIPS204`資料的ML-DSA-65、external／pure、
`tgId=3`、`tcId=33` positive vector驗證`dilithium-py`，結果接受。下載檔案：

```text
bytes = 4,533,178
SHA-256 = 47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437
```

`pqcrypto 0.3.3`高階API沒有暴露該向量使用的非空FIPS context，因此本次沒有聲稱它通過
該exact positive vector；chosen empty-native-context profile的雙向interop則已通過。

## 5. Host benchmark

命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  /tmp/pqc_auth_d4_venv/bin/python \
  benchmarks/access_holder_auth/benchmark_ml_dsa_handshake.py \
  --warmups 3 --iterations 30 \
  --acvp-sigver-json /tmp/ML-DSA-sigVer-FIPS204-internalProjection.json \
  --output benchmarks/access_holder_auth/results_ml_dsa_65_handshake_d4_20260916.json
```

環境：AMD Ryzen 5 7600X、12 logical CPUs、Linux 6.8.0-138-generic、CPython 3.12.9。
30次結果：

| Operation | Median | Min | p95 nearest-rank | Max |
| --- | ---: | ---: | ---: | ---: |
| UE holder sign，pqcrypto | 0.473 ms | 0.205 | 0.907 | 0.941 |
| FGS holder verify，pqcrypto | 0.143 ms | 0.142 | 0.147 | 0.158 |
| Holder sign，dilithium-py | 21.932 ms | 11.788 | 91.329 | 93.786 |
| Holder verify，dilithium-py | 5.766 ms | 5.746 | 5.836 | 5.842 |
| Full handshake，pqcrypto | 1.851 ms | 1.309 | 3.190 | 3.478 |

Full handshake包含兩次ML-DSA keygen、兩次signature、ML-KEM keygen／encap／decap、
canonical codecs、KDF及Finished。這是單機host wall-clock，不是衛星UE、手機、能耗、
backhaul或network latency量測。Whole-process peak RSS為38,496 KiB，不能解讀成單一
crypto operation的增量記憶體。

完整machine-readable結果：
`benchmarks/access_holder_auth/results_ml_dsa_65_handshake_d4_20260916.json`。

## 6. Tests與拒絕案例

定向tests覆蓋：

- candidate ticket／holder core／M1／M2／M3／first record frozen bytes；
- strict magic、version、length、truncation、trailing bytes及embedded activation binding；
- holder key／parameter digest對48-byte `q`的binding；
- wrong ticket `q`即使由真holder重新簽M1仍拒絕；
- wrong FGS、authorization、UE KEM epk、holder pk、message及signature mutation；
- 兩套ML-DSA provider雙向interop；
- official positive ACVP vector；
- 真實ML-KEM shared-secret equality、FGS signature及雙向Finished；
- 明確確認D4 holder verifier不會把provisional issuer bytes誤稱為已驗證ticket。

## 7. Security／claim boundary

本checkpoint支持：

```text
holder_signature_profile_implemented = true
real_ml_dsa_signature_generated = true
real_ml_kem_shared_secret_established = true
two_provider_mldsa_interop_tested = true
50k_wire_target_met_for_provisional_fixture = true
```

本checkpoint不支持：

```text
old_exact_R_access_preserved = false
generic_signature_is_SE_NIZK = false
new_R_issue_implemented = false
R_key_circuit_implemented = false
production_PQ_RBBC_ticket_measured = false
production_AEAD_instantiated = false
access_composition_proof_closed = false
production_ready = false
production_closed = false
```

另外，`dilithium-py`不是production／constant-time實作，`pqcrypto` wheel亦未經本專案
production qualification。通過ACVP sample、interop及mutation tests不等於FIPS module
validation、安全歸約或side-channel closure。

## 8. 下一個checkpoint

建議下一個bounded checkpoint為 **D4b FAEST-192s counterpart**：沿用完全相同的
`HolderAuthCoreV3`、ticket fixture、M1/M2/M3、benchmark方法與mutation matrix，只替換
holder suite／`R_key`候選，實測9,410-byte signature及provider時間。完成同尺度比較後，
再進D5的issuance `R_key` circuit cost prototype；在D5以前不修改shared ticket parser或
production registry。
