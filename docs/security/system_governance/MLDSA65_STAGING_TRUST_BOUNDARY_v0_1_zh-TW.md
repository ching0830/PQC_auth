# ML-DSA-65 non-threshold staging trust boundary v0.1

- 對應實作：`src/pq_rbbc/governance/authentication/`
- profile：`PQRBBC-OPENSSL-ML-DSA-65-NON-THRESHOLD-STAGING-V1`
- 狀態：S2 engineering security boundary；非 canonical FAC／production approval

## 1. Security objective

S2 要排除的主要繞過是：request caller 自帶一把 key、自簽一份結構合法 bundle，再把該 key
當作 trust anchor；或 caller 傳入任意 verifier／`verified=true` 讓 quota consume。可信起點
只能在 service startup 由 operator-owned registry 建立，並須解析到實際 public-key DER bytes，
不能只比較 metadata 字串。

本輪提供 authenticity／integrity 的範圍是普通 FIPS 204 ML-DSA-65 signatures。單一
configuration private key holder 或單一 grant private key holder 可以獨立簽署，因此它沒有
達成 core proof 所需 FAC threshold control。

## 2. Trust chain

```text
operator-provisioned absolute directory
  -> exact canonical registry bytes
  -> role + key_id + profile + key filename + declared SHA-256
  -> safely captured SPKI DER bytes
  -> recomputed SHA-256 == KeyReference.public_key_digest
  -> canonical ML-DSA-65 key parser
  -> full bundle/grant domain verification
  -> existing binding/time validation
  -> S1 atomic quota/SID consume
```

Attacker-controlled bundle 內的 reference 不會成為 trust root。Service 先以固定 role-1
reference 驗 bundle signature，再要求 role-2 reference 也解析到 startup registry。Grant
verifier 每次依完整 `(role,key_id,digest)` 查同一 captured registry。

## 3. Fail-closed controls

- Registry JSON exact schema/order/version/profile；duplicate keys、unknown fields、trailing bytes、
  uppercase/noncanonical hex 與 alternate serialization 拒絕。
- Registry directory/file/public key 以 `O_NOFOLLOW` 開啟；只接受 regular files，拒絕
  group/world writable；所有 identity/hash/parse 使用同一 captured bytes。
- Role 1/2 key IDs、digests 與 actual bytes 均須互異；不能共用一把 key 冒充 role separation。
- OpenSSL path 是 absolute；每次呼叫重開並 hash 同一 executable FD，再透過該 FD 執行；
  exact version 與 ML-DSA-65 availability 在 startup 檢查。
- DER 必須是固定 1,974-byte ML-DSA-65 SubjectPublicKeyInfo，且 OpenSSL parse/re-encode bytes
  完全一致；signature 必須恰為 3,309 bytes。
- 簽署和驗證使用固定 application context；protocol domain 仍在 message bytes 內，形成兩層
  domain separation。錯誤 context 或任一 message mutation 拒絕。
- Signer private key 每次從 `O_NOFOLLOW`、regular、exact `0600` FD 導出 public key並與
  captured trust key constant-time 比對；key pathname 被替換不能悄悄改簽署身分。
- Backend exception 或 non-true verify result 均沿既有 API fail closed；authentication 失敗
  不觸碰 quota。Quota backend error 也不回報 authorization success。

## 4. Why this is not threshold authentication

本 adapter 的 key generation 是標準 OpenSSL `genpkey -algorithm ML-DSA-65`，會建立一份
完整 private key；sign operation 由持有該完整 key 的單一程序完成。沒有 share、participant、
quorum transcript、dealer distribution、DKG、complaint、abort identification 或 refresh。

未來 Mithril/Quorus/TALUS/Hermine 或多個獨立 signatures 都可能改變 signer/trust/security
model。即使 threshold candidate 的最後 signature 可被同一 FIPS ML-DSA verifier接受，
key-origin、ceremony、profile identity、corruption/availability claim 與 signing-state
requirements 仍必須另外版本化、測試與審查。

## 5. Residual risks／OPEN

| 風險／決策 | 狀態 |
|---|---|
| 單一 role private key compromise | staging inherent；未由 threshold 緩解 |
| `n/t/f/u`、membership、committee separation | OPEN |
| dealer／a-posteriori sharing／DKG | OPEN |
| abort、identifiable abort、robustness、availability | OPEN |
| operator registry ceremony、rotation、revocation、historical verification | OPEN |
| HSM/KMS、encrypted keys、audit log、dual control | 未實作 |
| key-origin evidence for B/T inputs | 未實作；owner dependency |
| OpenSSL build reproducibility/SBOM/FIPS 140 validation | 未封閉／未主張 |
| Linux procfs、ACL/MAC、mount、host compromise | deployment assumption／未 qualification |
| side channel、fault injection、physical power loss | 未測 |
| authorization-to-signer-response idempotency | B／主整合線 versioned protocol dependency |

因此本輪適合作為「真實 cryptographic positive path 與 trust plumbing」的 staging gate；不能
以單元測試數、FIPS 204 名稱或 official vector 通過取代 threshold security proof、組織
authorization 或 production closure。
