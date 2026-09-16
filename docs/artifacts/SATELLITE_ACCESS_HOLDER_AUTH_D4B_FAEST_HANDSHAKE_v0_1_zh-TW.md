# Satellite Access holder authentication D4b：FAEST-192s handshake prototype v0.1

日期：2026-09-16

狀態：D4b FAEST-192s v3 counterpart Implemented／Tested／Measured；experimental only

```text
production_ready = false
proof_closed = false
production_closed = false
```

## 1. 結論

本checkpoint在D4相同的`HolderAuthCoreV3`、candidate ticket、M1／M2／M3、ML-KEM-768、
ML-DSA-65 FGS authentication及HKDF／Finished流程中，把holder suite換成真實
FAEST-192s v3。結果確認：

- 真實產生48-byte FAEST public key、40-byte private key及9,410-byte randomized signature；
- 使用官方`faest-ref` v3 reference implementation完成keygen／sign／verify；
- ticket中的48-byte `q`綁定FAEST suite、parameter digest與public key；
- 完整M1、M2、顯式M3及first application record均實際序列化；
- 相同core重新簽章時，wire request digest不同，但logical `attempt_id`維持相同；
- ML-DSA D4 frozen bytes與tests保持不變。

在11,644-byte issuer signature仍為**provisional fixture**時：

| 物件 | FAEST D4b exact bytes | ML-DSA D4 | 差異 |
| --- | ---: | ---: | ---: |
| Candidate ticket | 12,126 | 12,126 | 0 |
| Holder public key | 48 | 1,952 | -1,904 |
| Holder authenticator | 9,410 | 3,309 | +6,101 |
| M1 `AccessRequest` | 23,094 | 18,897 | +4,197 |
| M2 `AccessAccept` | 4,755 | 4,755 | 0 |
| M3 `SessionActivate` | 198 | 198 | 0 |
| M1＋M2＋M3 | **28,047** | **23,850** | **+4,197** |
| First application record | 377 | 377 | 0 |
| M1＋M2＋first record | **28,226** | **24,029** | **+4,197** |

因此FAEST路線在此fixture下仍低於50,000-byte application-layer gate：顯式M3保留
21,953 bytes，first-record形式保留21,774 bytes。這只完成D4b的wire與host benchmark，
不能宣稱production ticket或完整production handshake已低於50,000 bytes。

## 2. Exact FAEST revision

### 2.1 版本陷阱

D1／D3指定的是FAEST v3。實際核對顯示：

| Source | FAEST-192s signature | pk | sk |
| --- | ---: | ---: | ---: |
| `faest-ref v2.0.4@5113c66...` | 11,260 | 48 | 40 |
| v3 specification／本checkpoint | **9,410** | **48** | **40** |

所以不能用v2.0.4 release binary驗證D1的9,410-byte帳目。本次改為pin官方repository中
明定`project version 3.0.0`的exact commit：

```text
repository = https://github.com/faest-sign/faest-ref
commit = 9236611c42d1a761a58a44cabef7aeedd40d85bb
commit date = 2026-09-15
release tag = none
```

該commit的`meson.build`固定FAEST-192s：`beta=2`、`ell=1728`、`tau=16`、
`w_grind=12`、`T_open=162`、pk=48、sk=40、signature=9,410。

本專案候選parameter descriptor為：

```text
FAEST-SPEC:3.0/FAEST-192s/AES-192/beta=2/ell=1728/
tau=16/w-grind=12/t-open=162/pk=48/sk=40/sig=9410
```

SHA-256：

```text
b07b2bd53c05fa9a42a76aaadf40e5ec2ca62ea9d66fb5f38a00fd1a7bc55fb5
```

這是本prototype的suite identity，不是NIST指定的canonical identifier。

### 2.2 External build identity

建置採GCC 11.4.0、Meson 1.9.0、Ninja 1.13.0、release／O3／LTO／
`march-native=true`，偵測AES-NI與AVX2，SHA3使用opt64。外部輸入沒有進Git：

| External object | Bytes | SHA-256 |
| --- | ---: | --- |
| `libfaest.so.2.0.0` | 699,624 | `08c53ec7b217c39ab7041020849b8655b02b2a4925808fd82270c122ddac47a6` |
| `faest_192s_api_test` | 627,128 | `fc4b6a68c7e18144bad0bb706e769d6e65b091ae952c602411ba43721cfe0707` |
| generated `config.h` | — | `03b6fd8f956a9bc195cac3994a7e9be508280bd19a57b06c86b1e2064424cbbe` |
| generated `faest_192s.h` | — | `b1989b530709ac88603382e05e3c8591e181ce45c6c191eb0b02b738abfae74e` |

官方API self-test輸出`Sign/Verify test passed`。這是官方source的自我測試，不是獨立
provider interop，也不是KAT／ACVP、module validation或production qualification。

官方另提供`faest-arch-opt`，但其目前README要求GCC >=16.2.1或Clang >=22.1.8；本機只有
GCC 11.4.0，因此本checkpoint沒有產生optimized-provider實測，也不拿官方網站發布的
optimized數字冒充本機結果。

## 3. Protocol與retry identity

本prototype仍使用：

```text
M1 = ticket || UE ML-KEM epk || pk_H || FAEST.Sign(sk_H, HolderAuthCoreV3)
M2 = ML-KEM ciphertext || ML-DSA FGS authenticator || server Finished
M3 = client Finished
```

FAEST使用新的experimental holder suite ID `0xff12`；shared v0.2 parser、production
registry、`VerifyTicket`與one-time store均未修改。

因FAEST signature具隨機性，本checkpoint把logical attempt identity固定為：

```text
attempt_id = SHAKE256(
    "PQ-SAT/ACCESS-ATTEMPT/v3"
    || use_key
    || HolderAuthSigningInput
)
```

而M2中的`request_digest`仍包含完整M1 wire bytes。因此：

- 同core重新簽章不會建立第二個logical attempt；
- M2／FGS transcript仍綁定實際收到的signature bytes；
- bitwise retry及durable response recovery仍由未整合的one-time store負責；
- 本checkpoint沒有宣稱完成race、crash recovery或distributed linearizability。

## 4. Frozen bytes

| Object | Bytes | SHA-256 |
| --- | ---: | --- |
| Candidate ticket fixture | 12,126 | `66b1bbf3cdcf5e5bc4b7b107d1353249dc5ac21f39406b5c156a561dd0c2ab33` |
| `HolderAuthCoreV3` | 13,664 | `a2ead75a23180afc2ec14d8e6716a531a30d77a6695c76742cdc469eab2dbc93` |
| Holder signing input | 13,689 | `88ab20b8dc6f3a3d53ba9e6fdecb8e27bdd1dafd64b4444533ce39abfb96e882` |
| Deterministic M1 fixture | 23,094 | `8754824d3e3388ca7917684f428fd771ef6facd96784ffd4a06b43c5239cc795` |
| Deterministic M2 fixture | 4,755 | `98b1339beba817fb5926ccb02a07f5a904a9d737a0d5cba07bae119ea27d11ce` |
| Deterministic M3 fixture | 198 | `14c78614fd8681efce596852ca2d052923886d393e5c0eccee739c9e55fe8e20` |
| First-record fixture | 377 | `d5561794625fd52c44b5cbc1977ec4c6777a73d64354f59b64116982a2797c8f` |

Ticket中的11,644-byte issuer bytes與first record的17-byte ciphertext仍只是尺寸fixture。

## 5. Host benchmark

命令：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  /tmp/pqc_auth_d4b_venv/bin/python \
  benchmarks/access_holder_auth/benchmark_faest_192s_handshake.py \
  --warmups 3 --iterations 30 \
  --faest-library /tmp/faest-ref-v3-build/libfaest.so.2.0.0 \
  --faest-library-sha256 08c53ec7b217c39ab7041020849b8655b02b2a4925808fd82270c122ddac47a6 \
  --faest-source-dir /tmp/faest-ref-v2.0.4 \
  --faest-api-test /tmp/faest-ref-v3-build/faest_192s/faest_192s_api_test \
  --faest-api-test-sha256 fc4b6a68c7e18144bad0bb706e769d6e65b091ae952c602411ba43721cfe0707 \
  --output benchmarks/access_holder_auth/results_faest_192s_handshake_d4b_20260916.json
```

環境：AMD Ryzen 5 7600X、12 logical CPUs、Linux 6.8.0-138-generic、CPython 3.12.9。

| Operation | Median | Min | p95 nearest-rank | Max |
| --- | ---: | ---: | ---: | ---: |
| FAEST keygen，reference | 0.0015 ms | 0.0014 | 0.0021 | 0.0024 |
| UE holder sign，FAEST reference | 120.980 ms | 116.231 | 139.229 | 143.798 |
| FGS holder verify，FAEST reference | 75.260 ms | 74.810 | 76.431 | 77.492 |
| Full handshake，FAEST reference | 197.239 ms | 192.321 | 215.378 | 217.184 |

Whole-process peak RSS為33,680 KiB；不是單一operation的增量記憶體。完整握手包括FAEST
holder keygen／sign／verify、ML-DSA FGS keygen／sign／verify、ML-KEM
keygen／encap／decap、codec、KDF及Finished。

D4 ML-DSA frozen baseline的median為sign 0.473 ms、verify 0.143 ms、完整握手1.851 ms。
兩者來自同一host但不同時間與不同成熟度provider，故只能作descriptive comparison；
可直接比較的結論是FAEST多4,197 wire bytes，不能據此reference timing直接淘汰FAEST。

## 6. Tests與拒絕案例

D4b定向tests覆蓋：

- exact FAEST v3 suite、parameter digest、pk／sk／signature lengths；
- ticket／M1／M2／M3／first record frozen bytes與strict round-trip；
- truncated、trailing、9,409／9,411-byte signature rejection；
- wrong message、signature、public key、FGS、authorization、serving context與UE KEM epk；
- wrong ticket `q`、holder parameter digest、holder suite，即使由真正holder重新簽仍拒絕；
- randomized same-core re-sign產生相同logical attempt identity；
- external library digest mismatch fail closed；
- official source commit／parameter literals／API self-test identity；
- D4 ML-DSA frozen vectors與provider tests維持通過。

Mutation tests只證明implementation wiring，並不等於EUF-CMA、AKE或composition proof。

## 7. Decision與claim boundary

本checkpoint支持：

```text
real_FAEST_192s_v3_signature_generated = true
real_ML_KEM_shared_secret_established = true
FAEST_official_API_self_test_passed = true
same_core_attempt_identity_stable = true
50k_wire_target_met_for_provisional_fixture = true
```

本checkpoint不支持：

```text
FAEST_official_KAT_checked = false
FAEST_second_provider_interop_tested = false
optimized_FAEST_provider_benchmarked = false
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

目前兩條路線都通過provisional 50 kB gate。ML-DSA有標準化、wire較小及目前provider明顯
較快的優勢；FAEST多4,197 bytes、標準成熟度較低，但其AES-192 OWF key relation預期較適合
issuance circuit。真正決策不能只看access signature，下一個checkpoint必須量`R_key`。

## 8. 下一個checkpoint

建議進入 **D5 issuance `R_key` circuit cost prototype**：先實作FAEST-192s v3的
`k[192], x[128] -> pk_H[48]` AES-192 OWF relation，固定key-domain rule、bit order、
`x xor LE128(1)`、兩次AES evaluation與canonical key encoding，量constraints／wires／
assignment bytes／construction time。再建立ML-DSA `R_key,consistency`的可比較下界；D5以前
仍不修改shared ticket parser或production registry。

## 9. 來源

- [FAEST官方網站與v3 size／optimized benchmark](https://faest.info/)
- [FAEST v3 specification](https://faest.info/faest-spec-v3.0.pdf)
- [FAEST reference implementation](https://github.com/faest-sign/faest-ref)
- [FAEST architecture-optimized implementation](https://github.com/faest-sign/faest-arch-opt)
- [NIST additional signature Round 3](https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures)
