# PQ-RBBC issuance production inputs v1 preflight

## 結論

本 checkpoint 將 formal issuance relation 的下一個 gate 限定為 production input
qualification，建立：

1. certified trace public key 的 canonical binary encoding；
2. production issuance common parameters 的版本化 encoding；
3. 由同一組 immutable snapshots 驗證 external candidate identities 的唯讀 checker；
4. 可處理一般 canonical `rho`、直接呼叫既有 `CAP.Commit` 與 `H_RBBC` 的 adapter；
5. 明確標示 insecure/test-only 的 bounded adapter qualification。

目前環境沒有真實的 trace key ceremony／certification、authenticated system
initialization 或 independent review。因此本 gate 是 Defined、Implemented、Tested 與
Evidence-sealed，但不是 Instantiated、Proof-closed 或 Production-closed。

```text
production_common_parameters_instantiated = false
certified_trace_public_key_instantiated = false
production_cap_h_rbbc_adapter_qualified = false
production_relation_instantiated = false
formal_pi_issue_generated = false
safe_to_start_large_replay = false
safe_to_start_large_proving_run = false
```

## Protocol 位置

上一個 checkpoint 已把 public statement
`(pp, ctx, sid, rid, beta)` 與 private witness `(M, r, rho, k_hold, e)` 映射到
I1--I5。本 gate 處理其中兩個尚未實例化的邊界：

```text
authenticated system initialization
              │
              ├── issuer verification key
              └── SHA-256(canonical common parameters)
                                │
certified trace public key ─────┤
CAP profile + H_RBBC profile ───┤
formal relation identity ───────┘
                                │
                      IssueStatement.pp digest

(M, r, rho) ── CAP.Commit(r; rho) ── c_r
                          │
                          └── H_RBBC(m, c_r) ── h

                         beta = r XOR h
```

Common parameters 不是只放一個自由選擇的名稱；其 exact bytes 同時綁定 formal
relation manifest、statement ABI、CAP relation/profile、`H_RBBC` relation/profile、
trace profile、trace public-key identity、trace certification identity，以及 issuer
verification public-key digest。Authenticated system-initialization bundle 再反向綁定
`SHA-256(common_parameters_bytes)`。

此安排避免循環 hash：common parameters 不包含 initialization envelope 的 digest；
initialization envelope 單向承諾 common parameters，而 independent review 再綁定兩者的
exact identities。

## Trace public-key contract

新 binary container 使用 magic `PQRBBC-TRACE-PUBLIC-KEY-V1`、u16le version `1`，
以及依 section ID 遞增的 u64le length-prefixed fields。固定 profile 為：

| Field | Value |
| --- | --- |
| scheme | `PQ-RBBC-BINARY-GOPPA-6688128-CANDIDATE-V1` |
| encoding | `SYSTEMATIC-H-I-THEN-T-ROW-MAJOR-LSB0-V1` |
| `n` | 6,688 |
| `k` | 5,024 |
| `r=n-k` | 1,664 |
| `t` | 128 |
| matrix | `H=(I_R\|T)` |
| `T` row bytes | 628 |
| `T` body bytes | 1,044,992 |
| complete container bytes | 1,045,216 |

每列以 byte 內 LSB-first 打包。Wrong magic/version/section order/length/profile、
truncation 與 trailing bytes 均拒絕。這個 parser 只能確認 encoding、dimensions 與 exact
bytes；不能從任意矩陣的 shape 推論它是由合格 binary Goppa key generator 產生。

所以 production 仍必須取得與該 exact key identity 綁定的 producer certification、
ceremony transcript 及 authenticated attestation。Repository 內既有
`SystematicParityCheck` 是 deterministic test fixture，不可升格或轉碼成 production key。

## Common parameters contract

Common parameters 使用 magic `PQRBBC-ISSUE-COMMON-PARAMETERS-V1`、u16le version
`1` 與 closed ordered sections，固定：

- formal relation：`pq-rbbc/issuance/formal-relation/candidate/v1`；
- statement ABI digest：
  `a230a789344220e653bec2e39402f850d566fe6899c5550d9ce1e00e949ce2dc`；
- CAP relation：`pq-rbbc/cap/tcith-iii/anemoi-193-336/v1`；
- CAP profile fingerprint：
  `2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`；
- `H_RBBC` relation：`pq-rbbc/anemoi-193-336/sponge/v1`；
- `H_RBBC` fingerprint：
  `4fa0eb276ebba70a9f6c2f38f3f55d197c094121a2b614cc6ef9b7e8522cac87`；
- trace profile digest：
  `697bc86a6de34a8ba026177ec6abe0fea78275a1127382e15bdca8f8ecd53260`。

另外三個 32-byte digest 由實際部署輸入決定：trace public key、trace certification與
issuer verification public key；formal relation manifest digest則由本 checkpoint 固定。
Statement 必須滿足：

```text
statement.public_parameters_digest = SHA-256(exact common_parameters_bytes)
```

## CAP-to-H_RBBC adapter

`CAPToHRBBCAdapterV1` 不再用固定 SHAKE shape stub。它會：

1. strict decode 任意明確提供的 `CAPParameters` 所對應的 salt/root `rho`；
2. 呼叫現有 `execute_cap_commit`；
3. 要求 formal witness 的 576-bit `r` 等於 CAP execution 導出的 mask；
4. 將 canonical commitment bytes 直接交給既有 `hash_request_binding`；
5. 計算 `beta = r XOR H_RBBC(m,c_r)`；
6. 後續若另行授權 production activation，仍必須再與既有
   `request_from_production_cap` strict ABI 比對。

Bounded qualification 使用相同 witness width、commitment serializer 與 `H_RBBC` code
path，但 tree topology 被刻意縮成 insecure/test-only profile。兩組不同 `rho` 產生不同
request，證明 adapter 不只辨識單一 frozen fixture。此結果不提供 CAP security、Goppa
security 或 production relation qualification。

Production profile 在本 checkpoint 中無條件於呼叫 18-tree executor之前拒絕，不能以
caller boolean 開啟。後續 activation 至少仍需：

- exact production inputs 經 trusted qualification；
- 另行明確授權 large execution；
- CAP/fork security qualification 仍為 false。

## External artifacts

目前環境缺少以下五份 external inputs：

| Filename | Purpose |
| --- | --- |
| `pq_rbbc_trace_public_key_v1.bin` | exact systematic trace public key bytes |
| `pq_rbbc_trace_public_key_certification_v1.json` | generator、ceremony、producer attestation與key identity |
| `pq_rbbc_authenticated_system_initialization_v1.bin` | federation-authenticated initialization bundle |
| `pq_rbbc_issuance_common_parameters_v1.bin` | exact canonical common parameters |
| `pq_rbbc_issuance_production_inputs_independent_review_v1.json` | independent review bound to the four preceding identities |

現有 `/tmp/pq_rbbc_external_artifacts_rebuilt` 內的 v2.29 replay、v2.32 CAP candidate、
v2.33--v2.39 unified-tree qualification及其他歷史 artifacts，都不能取代上述輸入。
特別是 v2.29 frozen commitment 只是一個歷史 execution observation，不是 issuer common
parameters 或 trace public key。

## Snapshot 與部署邊界

Checker 沿用 single-open、single bounded-read contract。Identity、strict parse、cross-file
binding 與後續 validation 全部只使用同一個 immutable `Snapshot.raw`。Inode、size、
mtime、ctime 只屬 best-effort mutation signals，不能證明 capture 期間完全沒有 writer。

Future executor 必須消費已驗證 `CandidateSet` 的同一 snapshots，不得在 qualification
後重開 pathname。Trusted producer handoff、writer quiescence、owner/mode/ACL、既有
writable FD 與 mount namespace 仍是部署前提。

即使五份文件在 schema 與 identity 上完全一致，本 checkpoint 仍不把 schema 中的
`accepted=true` 當成 authentication。正式啟用還需要：

- out-of-band federation configuration trust anchor；
- qualified federation-authentication verifier；
- trace-key producer attestation verifier；
- independent-review attestation verifier或等價可信 handoff；
- 已封閉的 CAP/fork security disposition。

## Read-only preflight

Exact command：

```bash
PYTHONPATH=src python -u src/pq_rbbc_issuance_production_inputs_v1.py \
  --artifact-root /ABSOLUTE/PRIVATE/ARTIFACT/ROOT
```

空的私有 external root 已實際執行。結果列出五份 missing artifacts，且：

```text
structural_candidate_complete = false
trusted_handoff_complete = false
safe_to_instantiate_production_relation = false
safe_to_start_large_replay = false
safe_to_start_large_proving_run = false
output files created = 0
```

Preflight 預估為 1 CPU、256 MiB 以下及 60 秒內；不 replay constraints、不產生 proof。

Validation結果：targeted 19 passed；完整baseline共760 tests，748 passed、12個既有
optional external-artifact skips、0 failures/errors，耗時779.954秒。

Frozen manifest為5,728 bytes、SHA-256
`76272df2d70e2a42d4a7acaf18eea54160f7bb3fb272ffe21d296c7d4bb4e752`；portable evidence
為1,528 bytes、SHA-256
`fe7cffbb0037b6bbbea6a262711bb0d803b625771ae3c23b9e19ef6672371721`。

## Claim boundary

| Maturity | Status | Meaning |
| --- | --- | --- |
| Defined | true | canonical trace-key/common-parameter encoding及external requirements固定 |
| Instantiated | false | 沒有真實 key、ceremony、initialization或review |
| Implemented | true | codecs、snapshot checker與general direct adapter存在 |
| Tested | true | positive structural、negative、mutation與production refusal已測 |
| Evidence-sealed | true | manifest與path-free portable evidence存在 |
| Proof-closed | false | CAP/fork、Goppa generation與issuance ZK proof均未封閉 |
| Production-closed | false | trusted handoff、backend與完整 relation尚未完成 |

沒有修改 system architecture、ticket lifecycle 或 `pq_sat_auth`；沒有沿用其他 tree 的
observed `stream_bytes`；沒有建立或提交 assignment、BR1CS、pickle、cache、checkpoint、
resume state、log 或 proving output。

## 下一個 gate

在沒有真實 external inputs 的情況下，下一個安全實作步驟是把 I1--I5 與本次 general
CAP/H_RBBC adapter 降成新的 reduced constraint prototype，固定 public/private wire
partition及trace-key input ABI。該 prototype 必須繼續使用 test-only trace matrix並拒絕
production configuration；它不能把本次 structural codec qualification升格為 certified
Goppa key或正式 `pi_issue`。
