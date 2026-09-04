# PQ-RBBC v2.30 fork-security proof-audit evidence

日期：2026 年 9 月 4 日

## 結果

V2.30已完成可由本專案安全完成的bounded internal proof audit，並產生供獨立
cryptographic reviewer使用的digest-bound packet。結果是**負向且fail-closed**：

- `v2_30_internal_proof_audit_closed = true`
- `v2_30_independent_review_packet_sealed = true`
- `v2_30_independent_review_ready = true`
- `fork_security_proof_revalidated = false`
- `production_closed = false`

這不是把paper theorem直接套到fork。審計確認ePrint 2025/895的one-more reduction
需要CAP straight-line extraction與request NIZK extraction；blindness reduction需要
NIZK／CAP zero knowledge及mask pseudorandomness。現有v2.29 evidence已固定exact
functional semantics與serialization，但不證明上述cryptographic properties。

## Authoritative source

官方IACR ePrint頁面及PDF已核對為：

- report：IACR ePrint 2025/895
- title：*Blinding Post-Quantum Hash-and-Sign Signatures*
- revision：2025-10-31 major revision
- pages：47
- external PDF bytes：1,595,999
- external PDF SHA-256：
  `7ba2c040fd04823fb0d2aaad5e58348b5ef374726657ff1c0d87d000b4beff95`

PDF保留在
`/tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/`，不加入Git。

## Proof-audit packet

Tracked reviewable source：
`docs/proof/source/pq_rbbc_fork_security_audit_v2_30.html`

- bytes：13,144
- SHA-256：`d8d5f2acb5fac80cc4e6ae358da55d89593f889be7bbbf5fbe4e23264c85ff56`

External PDF：`pq_rbbc_buov_336_fork_security_argument_v2_30.pdf`

- bytes：123,065
- SHA-256：`b855dd450f9672bfb4540599078d76a2331a6aa26d50c880c59b0a7f5a72691b`

Packet將paper Protocols 3–4、Definition 10、Theorems 1–3與Blind-UOV-III
instantiation對映到v2.29 final semantics，並逐項列出不能由functional replay
取代的assumptions、extractors、simulators、oracle accounting及review gates。

## Machine-readable reviews

以下檔案為**internal fail-closed gap analysis**，不是independent attestation：

| External artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `pq_rbbc_cap_unique_mask_straightline_extraction_review_v2_30.json` | 3,514 | `cdb613e07397ed70a12aca2a507550243fa39dc3123b8b1a527d7b0edc631185` |
| `pq_rbbc_qrom_request_binding_review_v2_30.json` | 3,479 | `e2c6009b0c03331c2606fbf26cec5cab48527692f206dc9dad2ca0b51108054f` |
| `pq_rbbc_blindness_one_more_review_v2_30.json` | 3,908 | `e85753e45abaeed27da5107c7a2a98b538d1b35fb7d2fd706504211e765ee9fc` |
| `pq_rbbc_fork_security_independent_review_request_v2_30.json` | 3,223 | `0a982958a2904068b5464381b374a139483c5893a20fb09259a987a6dde8d6b3` |
| `pq_rbbc_fork_security_audit_manifest_v2_30.json` | 3,054 | `6db7e6ea5230855b62a69116c4a93d3b11159641088ee716c420afc70f784162` |

`pq_rbbc_fork_security_audit.py`會核對authoritative PDF、proof packet、tracked
proof source、v2.29 evidence與v2.30 frozen preflight manifest的exact identities，
再canonicalize上述documents。Exact generation command：

```bash
PYTHONPATH=src python -u src/pq_rbbc_fork_security_audit.py \
  --external-root /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security
```

## Portable evidence

Path-free evidence：
`artifacts/metadata/fork_security_audit_v2_30/pq_rbbc_fork_security_audit_evidence_v2_30.json`

- bytes：4,491
- SHA-256：`ab82fe91e2e71cbfdf90bc171b0e62f6be6021365f0870e5878edd8a8496de60`

Fail-closed sealer重新核對paper、proof packet、generator與全部internal review
documents；任何bytes、SHA-256、canonical content或claim promotion變更都拒絕。
Evidence不含absolute path，且明記未使用其他tree的observed `stream_bytes`。

Exact seal verification command：

```bash
PYTHONPATH=src python -u src/pq_rbbc_fork_security_audit_evidence.py
```

## Blocking findings

目前仍有八項blocking findings：

1. fork CAP unique committed mask尚未revalidate；
2. fork CAP straight-line extractor尚未建立或review；
3. concrete Anemoi-to-ideal-QROM boundary及`q_H` budget尚未接受；
4. fork blindness尚未revalidate；
5. fork one-more unforgeability尚未revalidate；
6. qualified PQ ZK／simulation-與straight-line-extractable backend尚未選定；
7. independent-review attestation不存在；
8. fork signature size尚未fresh rebenchmark。

下一個gate是由合格且獨立的cryptographic reviewer對全部frozen digests出具
`pq_rbbc_fork_security_independent_review_v2_30.json`。此步沒有可誠實提供的
automated exact command：reviewer identity、trust basis、signed findings與accepted
dispositions尚不存在，專案不能自我簽署。

## Claim boundary 與 artifact policy

本checkpoint沒有啟動large replay，也沒有修改system architecture、ticket
lifecycle或`pq_sat_auth`。Paper PDF、generated PDF與machine-readable working
reviews留在external directory；Git只保存source、tests、documentation、checksums
與path-free evidence。Assignment、BR1CS、pickle/cache、checkpoint/resume state及
logs均不得加入Git。
