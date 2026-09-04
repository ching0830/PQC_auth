# PQ-RBBC v2.30 fork-security 唯讀 preflight

日期：2026 年 9 月 4 日

## 結果

V2.30 preflight 已將 fork-security audit 綁定至 v2.29 final execution
semantics：589,030,555 rows、0 failures、0 external assertions，input identity
`b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a`，
ordered transcript
`1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514`。

Frozen manifest：
`manifests/pq_rbbc_fork_security_preflight_manifest_v2_30.json`

- bytes：6,677
- SHA-256：`a57610c347491b47e70b73f991d5af7f30b7d317fd096860b770b532d4c8aac7`

它也核對既有v2.25 native-profile／Blind-UOV ABI與v2.13 conditional proof
baseline的exact identities。這些baseline明確聲明：本fork不是bit-exact
Blind-UOV，不能自動繼承paper security reduction或signature-size claims，且仍需
依v2.29 semantics更新。

## Proof obligations

Preflight 將以下七項維持為 open：

1. CAP unique committed mask；
2. CAP straight-line extraction；
3. QROM cross-message request binding；
4. fork honest-protocol signer blindness；
5. fork one-more unforgeability；
6. augmented issuance composition；
7. 綁定全部proof與semantics digests的independent review。

目標 request relation 固定為
`c_r = CAP.Commit(r; rho)`及`y = r + H_RBBC(m, c_r)`；public request只有576-bit
`y`，`m`、`r`、`rho`與`c_r`保持hidden。QROM audit必須保留
`Adv_xmsg <= Adv_CAP_uw + Adv_CAP_ext + O(q^3 / 2^576)`的assumption、query與
bad-event accounting，不得把functional replay當作security evidence。

## External artifacts 與 blockers

Environment report：
`/tmp/pq_rbbc_fork_security_environment_preflight_v2_30.json`

- bytes：3,005
- SHA-256：`d71ecda87473039acd4a5e774da5601186c56e9042da2cc6ca800a17a2b8751c`
- `safe_to_continue_read_only_gap_analysis = true`
- `safe_to_start_fork_security_revalidation = false`
- `safe_to_claim_fork_security_revalidated = false`
- `safe_to_start_large_replay = false`

目前缺少六份外部 artifacts：

| Artifact | 用途 |
| --- | --- |
| `blind_uov_eprint_2025_895_revision_2025_10_31.pdf` | source framework、games、oracle model與protocol transcript |
| `pq_rbbc_buov_336_fork_security_argument_v2_30.pdf` | fork-specific blindness與one-more reductions |
| `pq_rbbc_cap_unique_mask_straightline_extraction_review_v2_30.json` | CAP unique-mask／extractor review |
| `pq_rbbc_qrom_request_binding_review_v2_30.json` | QROM theorem、query accounting與concrete-to-ideal boundary review |
| `pq_rbbc_blindness_one_more_review_v2_30.json` | fork games的independent review |
| `pq_rbbc_fork_security_independent_review_v2_30.json` | reviewer scope、findings及全部artifact digests |

即使提供candidate檔案，preflight也只記錄bytes／SHA-256並回報
`identity_not_frozen`；在人工核對並凍結identity以前不會接受。

## Exact candidate inventory command

```bash
PYTHONPATH=src python -u src/pq_rbbc_fork_security_preflight.py \
  --report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/pq_rbbc_fork_security_environment_preflight_v2_30.json \
  --blind-uov-reference /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/blind_uov_eprint_2025_895_revision_2025_10_31.pdf \
  --fork-proof-packet /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/pq_rbbc_buov_336_fork_security_argument_v2_30.pdf \
  --cap-extraction-review /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/pq_rbbc_cap_unique_mask_straightline_extraction_review_v2_30.json \
  --qrom-request-binding-review /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/pq_rbbc_qrom_request_binding_review_v2_30.json \
  --blindness-one-more-review /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/pq_rbbc_blindness_one_more_review_v2_30.json \
  --independent-review-attestation /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/pq_rbbc_fork_security_independent_review_v2_30.json
```

這是candidate inventory命令，不是proof revalidation或claim-promotion命令。
真正的exact revalidation command在所有外部inputs完成identity freeze與review前維持
`null`。

## Claim boundary

本 checkpoint 只關閉 preflight contract、v2.29 prerequisite與read-only gap
analysis。`cap_unique_witness_reviewed`、`cap_straightline_extraction_reviewed`、
`qrom_request_binding_reviewed`、`fork_blindness_revalidated`、
`fork_one_more_unforgeability_revalidated`、`fork_security_proof_revalidated`、
`qualified_pq_se_nizk_backend_selected`、`signature_size_rebenchmarked`及
`production_closed`全部維持false。

System architecture、ticket lifecycle與`pq_sat_auth`均未修改。
