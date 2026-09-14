# Satellite Access concrete PQ AKE／NIZK suite review

> 日期：2026-09-15（Asia/Taipei）
>
> 狀態：候選研究；不關閉 D-002，不建立 production suite ID
>
> 對象：`AccessRequestV2 -> AccessAcceptV2` 一趟往返 profile

## 結論

目前沒有找到一個現成 backend 同時具備以下全部條件：

- 精確支援現行`R_access`中的SHAKE-based holder relation；
- post-quantum安全目標；
- 對本論文所需組合game具有明確simulation-extractability證明；
- proof足夠小，適合衛星鏈路；
- 可直接接入的成熟reference implementation；
- 已完成production等級的審計與qualification。

因此不應現在就把D-002標成已決定。建議採兩層路線：

1. **近期executable reference候選：**保留Access V2 bytes，使用
   ML-KEM-768、ML-DSA-65、HKDF-SHA384及HMAC-SHA384建立AKE外框；`pi_access`
   先以generalized MPC-in-the-Head prototype驗證精確`R_access`並取得實測成本。
2. **長期research候選：**若MPCitH proof不符合衛星budget，另開protocol version研究
   KEM authentication及lattice-native holder relation；不得在V2欄位中靜默替換。

近期候選只表示各KEM／signature primitive已標準化，不表示本專案自訂的signed-KEM
composition、access NIZK或完整AKE已標準化、Proof-closed或Production-closed。

## 1. 標準化與實作基線

### 1.1 ML-KEM／ML-DSA

NIST FIPS 203定義ML-KEM，並建議ML-KEM-768作為一般default parameter set。其Category
3參數大小為：encapsulation key 1,184 bytes、ciphertext 1,088 bytes、shared secret
32 bytes。[FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)

NIST FIPS 204的ML-DSA-65 public key為1,952 bytes、signature為3,309 bytes。
[FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)

NIST SP 800-227明確把KEM key confirmation建模為由KEM shared secret導出的獨立KC key
與MAC；bilateral confirmation使用不同data string及相反provider／recipient roles。
這與V2把server Finished放在M2、client Finished放在第一個protected packet的分層一致，
但標準也提醒單向範例可能不足以自動取得所有安全性質。
[NIST SP 800-227](https://doi.org/10.6028/NIST.SP.800-227)

OpenSSL 3.5的default／FIPS providers已有ML-KEM與ML-DSA介面，可作近期interop與KAT
候選；本機現行OpenSSL 3.0不能直接滿足這個gate。
[OpenSSL ML-KEM](https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/)；
[OpenSSL ML-DSA](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/)

### 1.2 TLS／KEM authentication參考

RFC 10024已定義TLS 1.3的`X25519MLKEM768`等PQ／traditional hybrid key-agreement
groups，可作互通與transition baseline；它沒有定義本專案的ticket、`pi_access`或
one-time consumption composition。[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html)

ML-DSA用於TLS 1.3截至本次核對仍是Internet-Draft，不能寫成已發布RFC。
[IETF ML-DSA in TLS draft](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/)

KEMTLS與AuthKEM研究以KEM取代handshake signature，可降低某些PQ握手的server成本與
傳輸量；但AuthKEM仍是work in progress，且兩者都不是Access V2的drop-in security
proof。[KEMTLS](https://kemtls.org/publication/kemtls/)；
[AuthKEM draft](https://datatracker.ietf.org/doc/draft-celi-wiggers-tls-authkem/)

## 2. Access NIZK候選比較

| 候選 | 與現行`R_access`相容性 | 優點 | 主要阻礙 |
| --- | --- | --- | --- |
| generalized ZKB++／MPCitH | 可把SHAKE與tag relation降成Boolean circuit | 不需改ticket或holder relation；PQ研究基礎成熟 | proof可能數十至數百KB；需自行建立精確circuit、transform及安全mapping |
| Picnic-derived design | 具成熟C reference與MPCitH工程經驗 | 可借用constant-time、Fiat–Shamir與serialization經驗 | Picnic證明的是LowMC key relation，不是現行`R_access`的直接backend |
| STARK-style general proof | 可表達一般計算，通常以hash assumptions作PQ候選 | transparent setup | proof／implementation複雜且大；未找到符合本composition的現成SE mapping |
| LaZer／LaBRADOR family | lattice relation與sublinear proof研究具吸引力 | 若holder relation改成lattice-native可能較自然 | 不能直接證明現行SHAKE relation；目前公開code明列research-only、未production review |

ZKBoo／ZKB++的MPC-in-the-Head方法能證明一般Boolean／arithmetic circuit中的witness
knowledge，故可作「保持精確`R_access`」的第一個prototype方向。
[ZKBoo](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/giacomelli)；
[ZKB++／Picnic](https://eprint.iacr.org/2017/279)

不能由「使用Fiat–Shamir」直接推論post-quantum simulation-extractability。QROM下的
knowledge extraction需要逐項核對interactive protocol、commitment、challenge space、
transform及adversary oracle model。[Fiat–Shamir in the QROM](https://arxiv.org/abs/1902.07556)

2026年的Faonio–Tong工作提出non-malleable reductions of knowledge框架，並聲稱對
LaBRADOR給出第一個simulation-extractability分析及新的ZK variant；這是很新的研究
結果，不能把現有LaBRADOR／LaZer code直接等同該SE-ZK construction。
[Faonio–Tong 2026](https://www.eurecom.fr/publication/8939)；
[LaBRADOR research repository](https://github.com/lazer-crypto/labrador)

是否真的需要SE應由end-to-end access composition game決定：若reduction需要在向
adversary提供simulated access proofs後，仍從新accepting proof抽取holder witness，SE是
實質要求；若game沒有simulation oracle，knowledge soundness加上exact transcript binding
可能已足夠。未完成game mapping前，manifest不得標示`simulation_extractable = true`。

## 3. 近期reference suite候選

暫用研究名稱，不配置正式數字ID：

```text
PQSAT-A2-REF-MLKEM768-MLDSA65-MPCITH
status = experimental_reference_only
```

候選組成：

- KEM：ML-KEM-768；
- FGS authentication：ML-DSA-65簽署完整domain-separated transcript；
- KDF：HKDF-SHA384；
- server／client Finished：不同key及label的HMAC-SHA384，48-byte tag；
- access proof：對exact `R_access`建立generalized MPCitH prototype；
- runtime：Python只負責orchestration，primitive預期使用OpenSSL 3.5+或獨立C／Rust
  backend，不自行撰寫production cryptography。

不含ticket、NIZK、fixed fields與Opaque length的密碼材料下限：

| 方向 | 材料 | Bytes |
| --- | --- | ---: |
| M1 | ML-KEM-768 ephemeral encapsulation key | 1,184 |
| M2 | ML-KEM-768 ciphertext | 1,088 |
| M2 | ML-DSA-65 signature | 3,309 |
| M2 | HMAC-SHA384 server Finished | 48 |
| 合計 | 不含ticket／NIZK／framing | 5,629 |

1,952-byte FGS verification key可放在authenticated configuration，不需每次傳送。
真正最大的未知數是`pi_access`。因此在proof prototype量測前，不能把5,629 bytes當成
完整access通訊量。

### 建議凍結的suite欄位

```text
suite_id / suite_version / suite_status / security_category_target
kem_id / standard_revision / ek_bytes / ct_bytes / ss_bytes
fgs_auth_mode / fgs_auth_id / key_encoding_id / key_id / signature_bytes
kdf_id / transcript_hash_id / finished_mac_id / finished_tag_bytes
proof_suite_id / relation_id / transform_id / parameters_digest
holder_commitment_profile_id / channel_binding_policy
provider / provider_version / provider_build_identity
每個wire field的exact或maximum length
```

建議增加的domain labels：

```text
PQ-SAT/ACCESS-NIZK-CHALLENGE/v2
PQ-SAT/FGS-AUTH-MSG/v2
PQ-SAT/KDF-SALT/v2
PQ-SAT/KDF/server-finished/v2
PQ-SAT/KDF/client-finished/v2
PQ-SAT/KDF/application/v2
PQ-SAT/KDF/exporter/v2
```

ML-DSA authentication至少綁定suite、access profile、完整`transcript_digest`及FGS key
identity。KDF context至少綁定role、algorithm suite、`ctx`、epoch、FGS、serving context、
channel binding及transcript；所有variable-length input必須先作canonical length
separation。

## 4. 長期research profile

若signature成本成為瓶頸，可另開V3研究雙KEM authentication：UE在M1同時encapsulate
至FGS長期authentication key，FGS在M2再encapsulate至UE ephemeral key，並把兩份shared
secret用versioned、length-separated combiner導入KDF。粗略密碼材料約為：

```text
M1: FGS auth ciphertext 1,088 + UE ephemeral ek 1,184
M2: ephemeral ciphertext 1,088 + Finished 48
合計: 3,408 bytes，不含ticket／NIZK／framing
```

這需要新增M1欄位、system-init FGS KEM-auth key role及新的security proof，不能偷塞入
既有`ue_kem_epk`。KEMTLS／AuthKEM只能作設計參考，不能自動證明本profile安全。

另一個可能方向是把ticket中的holder commitment版本化為one-time lattice public key
commitment，讓access proof只證明知道對應short secret，並在proof外綁定request。這可能
較適合LaBRADOR family，但會改動issuance relation、ticket schema、linkability與
composition proof，因此只能是新profile研究，不能修改V2既有語意。

## 5. 落地gates

1. 先完成access composition game，判定SE是否必要及其精確oracle model。
2. 只配置experimental suite ID；凍結primitive revision、exact encoding及length拒絕規則。
3. 以OpenSSL 3.5+及第二個獨立implementation跑ML-KEM／ML-DSA KAT與interop。
4. 對exact `R_access`量測proof bytes、prove／verify時間、peak RAM及UE energy。
5. 把proof theorem、parameters digest、implementation commit及compiler flags寫入manifest。
6. 測試algorithm／role／key／epoch／FGS／channel substitution、invalid KEM input、proof／
   signature mutation、cross-version replay與exact-M1 retry。
7. 檢查constant-time、RNG、secret erasure、parser robustness及key rotation／revocation。
8. 接上durable distributed consume store與wallet recovery後，才做satellite-path benchmark。
9. 經獨立cryptographic review後，才考慮提升Instantiated／Proof-closed／Production claims。

## Claim boundary

本文件支持將ML-KEM-768＋ML-DSA-65外框及generalized MPCitH列為第一個**實驗候選**，
並把KEM-auth／lattice relation列為長期研究比較。它不支持任何正式suite註冊、完整AKE
security、access-NIZK SE、Category 3端到端安全、production backend或performance claim。
