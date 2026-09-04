# PQ-RBBC v2.31 CAP-security qualification checkpoint

日期：2026 年 9 月 4 日

## 結果

V2.31已建立fail-closed、唯讀的CAP-security qualification contract，並綁定
v2.30 audit與v2.29 final execution semantics。這個checkpoint關閉的是後續proof
artifact的輸入、schema與claim boundary，不是CAP security theorem：

- `v2_31_cap_security_qualification_contract_closed = true`
- `cap_oracle_contract_frozen = true`
- `cap_admissible_commitment_contract_frozen = true`
- `cap_extractor_interface_frozen = true`
- `cap_unique_mask_game_frozen = true`
- `v2_31_cap_proof_candidate_artifacts_authored = true`
- `proof_candidate_artifacts_verified = true`
- `safe_to_request_independent_review = true`
- `cap_straightline_extractor_implemented = false`
- `cap_security_qualified = false`
- `fork_security_proof_revalidated = false`
- `production_closed = false`

候選extractor、reduction及full-transcript evidence已撰寫、凍結identity並通過
checker；`cap_straightline_extractor_implemented`仍保留給完整production CAP
Prove／Verify與review後的實作。現在可安全送交獨立cryptographic review，但尚不可
開始qualification或提升security claim。這一步不需要、也沒有啟動large replay。

## Frozen source semantics

Checkpoint逐byte與SHA-256核對v2.30 fork-security audit evidence、v2.29 parent
join evidence、v2.28 aggregate evidence及CAP／composer／global-tail／Anemoi source。
綁定的v2.29 execution identity為：

- input identity：
  `b92aa6b78d123173574ad00cb337e12877a9615f56605bddfd66236ca263d11a`
- ordered transcript：
  `1f0113f965a03351b6d62c4801a9d15d0255640282b90215397170b87ad6a514`
- combined rows：589,030,555
- verification failures：0
- external assertions：0

沒有沿用任何其他tree的observed `stream_bytes`。

## Frozen CAP profile

Profile fingerprint：
`2ac471f8d7c6cb4e6352bbc5a2eb7f9394b807ff132aec8cadebd696f7b1fa38`

| Item | Frozen value |
| --- | ---: |
| Field | GF(2^193) |
| Mask `r` | 576 bits |
| Appended witness `x` | 1,472 bits |
| Witness | 2,048 bits |
| Consistency values | 386 bits |
| Random tape | 2,450 bits |
| Tree profile A | 2 × 4,096 leaves, degree 13 |
| Tree profile B | 16 × 2,048 leaves, degree 12 |
| Total leaves | 40,960 |
| Canonical commitment | 5,391 bytes |
| XOF calls | 122,847 |

Mixed degree-12／13 trees均為proof與negative-vector的必要coverage，不可用單一
tree profile推廣。

## Frozen security contracts

Oracle contract固定CAP的六個獨立domain：`seed_derive`、`seed_commit`、
`tape_expand`、`h1`、`consistency_points`與`h2`，以及canonical frame、tuple
encoding、output width與ordered full-value query/response record。Digest-only
transcript不構成extractor input；request-binding oracle不屬於此CAP transcript。

Extractor contract依paper Definition 10固定ROM straight-line interface：

- `Ext_1(Q_CAP, c_1)`輸出576-bit `r`；
- `Ext_2(Q_CAP, c_1, c_2)`輸出`(r, x)`；
- 不得把statement、final CAP proof或secret randomness交給extractor；
- 不允許rewinding；
- 必須對missing query、ambiguity／collision、mixed-tree interpolation與
  noncanonical commitment提供數值化的`epsilon_ext` accounting。

這不包含quantum-query measurement或QROM lift。Repository也尚無完整
`CAP.Prove`／`CAP.Verify`與paper NIST III Shorter profile使用的proof-of-work，
所以functional assignment satisfaction不能證明admissible commitment或完整
knowledge soundness。

Contract identities：

| Contract | SHA-256 |
| --- | --- |
| Oracle | `d5b200abba58a4e5f8c7ec02c76d404b4dc04179205ffc7a69038975d73267de` |
| Admissible commitment | `677773f1c0ad3863d7bceaea9f3e4d14724204a63050d3f2bc98101cc0b6faec` |
| Extractor | `3183f143027c89e001c13110ca1411cad4753e2aa91660b1355a711cd201ebe2` |
| Unique-mask game | `321caf34885e2ac0a24a535bf00c230f02ed103b33a7f05dbb7912ba531dce7b` |

## Proof artifacts 與 external blocker

前三份候選proof artifacts已存在於獨立external directory，且exact identity已凍結：

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `pq_rbbc_cap_straightline_extractor_spec_v2_31.pdf` | 114,907 | `b588f351600161a6c87623b66a39c5f7bfb0e96580a0adff96f8298f1d7baa15` |
| `pq_rbbc_cap_unique_committed_mask_reduction_v2_31.pdf` | 100,724 | `fa94bd262e58cbd5c1218d07d4839a242177537109847e5d63737932e781e370` |
| `pq_rbbc_cap_security_qualification_evidence_v2_31.json` | 78,898,232 | `2009503887da006dd4492baf27c48cc85387fc13a909ef0a75c0bab12418a47d` |

Candidate evidence包含122,847筆ordered full-value oracle records；records的
canonical JSON為78,878,128 bytes，SHA-256為
`226d6f43ed95616c636bc9f91894070830214432134f59aa6f0086f9fccc6b92`。
六個domain counts為40,924次`seed_derive`、40,960次`seed_commit`、40,960次
`tape_expand`及各一次`h1`、`consistency_points`、`h2`。兩種mixed tree shape均
覆蓋，10／10 required negative vectors均被拒絕；沒有使用其他tree的observed
`stream_bytes`。

唯一尚未提供、也未凍結的inventory artifact是
`pq_rbbc_cap_security_independent_review_v2_31.json`。它必須由合格且獨立的
reviewer綁定全部digests與findings；專案不得自行補造或自我簽署。

## Numeric finding 與 claim boundary

候選reduction的mixed-tree accounting為
`2*12 + 16*11 = 200`，degree-2 relation在未加入PoW時的raw acceptance上界為
`2^-182`。這在`q_H = 1`時已低於192-bit target；在純診斷性的`q_H = 2^64`
budget下，列出的dominant term為`2^-118`。Paper NIST III Shorter profile另列約
13.9-bit PoW，但目前fork未實作，故不得把該增益加入bound。

完整CAP Prove／Verify acceptance、PoW與challenge sampling、candidate `c_2`
production serialization、constraint-sampling soundness、multi-target loss、concrete
Anemoi ROM／QROM justification仍未封閉。因此即使inventory只剩獨立review，
`cap_security_qualified`仍必須是false；review還必須對這些profile findings做出
disposition，不能只確認檔案存在。

候選evidence的exact authoring command（只重用並重新驗證既有trusted local cache，
不啟動replay）為：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_security_artifacts.py \
  --allow-trusted-local-pickle \
  --trusted-execution-cache /tmp/pq_rbbc_external_artifacts_rebuilt/v2_19_composer_recovery/pq_rbbc_cap_composition_execution_v2_8.pkl \
  --paper /tmp/pq_rbbc_external_artifacts_rebuilt/v2_30_fork_security/blind_uov_eprint_2025_895_revision_2025_10_31.pdf \
  --extractor-pdf /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_straightline_extractor_spec_v2_31.pdf \
  --unique-mask-pdf /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_unique_committed_mask_reduction_v2_31.pdf \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_security_qualification_evidence_v2_31.json
```

候選檔案放入獨立external directory後，exact inventory command為：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_security_qualification.py \
  --report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_security_environment_with_candidates_v2_31.json \
  --extractor-specification /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_straightline_extractor_spec_v2_31.pdf \
  --unique-mask-reduction /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_unique_committed_mask_reduction_v2_31.pdf \
  --qualification-evidence /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_security_qualification_evidence_v2_31.json \
  --independent-review-attestation /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_security_independent_review_v2_31.json
```

目前`exact_qualification_command = null`，原因是獨立review不存在，且
Prove／Verify／PoW findings仍是blocker。Checker已將前三份候選artifact的
`identity_frozen`、`schema_valid`與`verified`設為true，但不因此提升security
claim。

## Portable evidence

Frozen manifest：
`manifests/pq_rbbc_cap_security_qualification_manifest_v2_31.json`

- bytes：11,778
- SHA-256：`dc143238d9c22d94ace03ee37b1f4ead0b6f0b2f876c7a790fc0b644495326db`

Initial external environment report：
`pq_rbbc_cap_security_environment_v2_31.json`

- bytes：2,703
- SHA-256：`96a3038b8e05ca277fd37d5f7b78df139172eaaa5ce21ee9b37d0a64c3d428b5`
- `safe_to_author_cap_proof_artifacts = true`
- `safe_to_start_cap_security_qualification = false`
- `safe_to_claim_cap_security_qualified = false`
- `safe_to_start_large_replay = false`

Initial report留在external directory，不加入Git。Path-free evidence位於
`artifacts/metadata/cap_security_qualification_v2_31/pq_rbbc_cap_security_qualification_evidence_v2_31.json`：

- bytes：5,606
- SHA-256：`6a447112809ae999d72a4c6886f353ffa1f38720870364009dc7e8155c29edfd`

Exact seal verification command：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_security_qualification_evidence.py \
  --environment-report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_security_environment_v2_31.json
```

Candidate inventory report仍留在external directory：

- bytes：2,907
- SHA-256：`8b80a6bce2a6022d6f7ea499a2314ddda56fb83ec908a3b26681399404a941cd`
- `proof_candidate_artifacts_verified = true`
- `safe_to_request_independent_review = true`
- `safe_to_start_cap_security_qualification = false`
- `safe_to_claim_cap_security_qualified = false`
- `safe_to_start_large_replay = false`

候選authoring的第二份path-free seal位於
`artifacts/metadata/cap_security_qualification_v2_31/pq_rbbc_cap_security_artifact_evidence_v2_31.json`：

- bytes：4,720
- SHA-256：`eb5b1c901b7fd55d2092e71caadf797f8ac510ad857c8199c9f77cd5b6c544e8`

Exact verification command：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_security_artifact_evidence.py \
  --external-root /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security \
  --environment-report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_31_cap_security/pq_rbbc_cap_security_environment_with_candidates_v2_31.json
```

## Claim boundary 與 artifact policy

本checkpoint沒有修改system architecture、ticket lifecycle或`pq_sat_auth`，也沒有
擴張v2.30 findings。Git只保存checker、sealer、tests、frozen manifest、文件、
checksums與path-free evidence。Proof PDFs、full-transcript candidate、inventory
reports及independent attestation留在external directory；assignment、BR1CS、
pickle/cache、checkpoint／resume state與logs均不得加入Git。
