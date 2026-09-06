# PQ-RBBC v2.34 unified-tree production pre-freeze checkpoint

## 結論

V2.34已建立唯讀、fail-closed的production pre-freeze checker與operator resource
reservation schema。Checker逐byte綁定v2.33 reduced portable seal及其四份external
outputs，並凍結production descriptor fingerprint、pre-freeze contract、future command
digest、resource minimums與independent-review contract。

本次environment report結果為：

- `safe_to_run_read_only_checker = true`；
- `safe_to_request_independent_review = true`；
- `safe_to_start_production_prefreeze = false`；
- `safe_to_start_large_replay = false`；
- `safe_to_start_large_proving_run = false`。

本checkpoint沒有展開production leaves、沒有建立assignment或BR1CS、沒有replay
relation rows，也沒有產生proof。

## Protocol位置

V2.33只證明reduced profile的單root tree、position-major mapping、canonical opening、
counter grinding與mutation rejection能一致運作。Production pre-freeze則是第一次讓
40,960-leaf candidate進入完整CAP producer/relation pipeline，以觀察並凍結新的
`c_r` bytes、row stream、wire identity、assignment identity與resource measurements。

因unified root會改變`c_r`與後續`h3` transcript，舊18-tree profile的observed
`stream_bytes`、digests、assignments及v2.29 transcript都不能作為新profile observation。
Pre-freeze成立後仍只得到可供freeze的functional observation；它不自動授權第二次
frozen replay、Prove／Verify、CAP security、fork security或production closure。

## Frozen production descriptor

- profile：`PQ-RBBC-CAP-TCitH-III/Anemoi-193-336-Unified-GGM-CANDIDATE-v1`；
- fingerprint：
  `c270e4681f23955667a6c0640317e7beccc666d60a0cffb40bfdccfcee811b7a`；
- domain prefix：`PQ-RBBC/v2.33/CAP-UGGM/`；
- logical leaves：`(4096,4096,2048×16)`，total 40,960；
- internal nodes／seed derivations：40,959；
- challenge index bits：200；explicit bits：9；`T_open=174`；
- pre-freeze contract SHA-256：
  `a419513cc6bac1022c9b3ff270f655382336d5370face67dffd28869f0e9fe19`。

Rows仍只有保守lower bound：combined至少589,054,075 rows，兩個完整passes至少
1,178,108,150 row checks。這些不是observed或frozen execution counts。

## Resource-reservation schema

Schema位於
`schemas/pq_rbbc_cap_unified_tree_resource_reservation_v2_34.schema.json`，SHA-256
`87db532e70dfedf1c79aea828fab24f898a5b6286eff94a2b7706c04a4446d91`。
它使用closed-world object grammar（所有object皆`additionalProperties=false`）並要求：

- 綁定production profile fingerprint、v2.34 pre-freeze contract與v2.33 portable seal；
- operator identifier、role、canonical UTC approval time與`approved=true`；
- scope只限`production-prefreeze`及指定external root；
- `fresh_cache_required=true`、existing output不得覆寫、legacy evidence唯讀；
- `other_tree_observed_stream_bytes_reusable=false`；
- 至少4 CPU cores、16 GiB available memory、80 GiB free disk；
- operator提供正整數wall-clock reservation，並明確接受目前沒有frozen runtime
  estimate；
- 只授權pre-freeze，不授權frozen replay、large proving或任何security claim。

`--print-resource-template`輸出的template故意保持`approved=false`、wall-clock為0，
因此不能通過schema，也不能被誤認為operator attestation。有效reservation必須由
operator在repo外提供；schema-valid candidate也不會自行凍結identity。

## Current blockers

Initial report精確列出五個blockers：

1. resource reservation尚未提供／凍結；
2. independent design/cryptographic review尚未提供／凍結；
3. v2.33 runner目前只支援`--phase reduced`，production runner尚未實作；
4. production relation contract尚未由pre-freeze observation凍結；
5. 使用者只授權本次checker/schema，沒有授權production pre-freeze execution。

即使把schema-valid reservation與review candidate傳給本checker，兩者仍會回報
`identity_not_frozen`，而implementation／authorization gates仍保持false。後續必須
在新的bounded checkpoint內實作並驗證production runner、凍結兩份external identity，
再重新產生launch preflight；不得直接切換本檔案中的常數。

## Exact commands

唯讀checker：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_production_prefreeze.py \
  --report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_34_unified_tree_prefreeze/pq_rbbc_cap_unified_tree_production_prefreeze_environment_v2_34.json \
  --specification-pdf /tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration/pq_rbbc_cap_unified_tree_spec_v2_33.pdf \
  --reduced-evidence /tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration/reduced/pq_rbbc_cap_unified_tree_reduced_evidence_v2_33.json \
  --runner-qualification /tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration/reduced/pq_rbbc_cap_unified_tree_runner_qualification_v2_33.json \
  --post-reduced-report /tmp/pq_rbbc_external_artifacts_rebuilt/v2_33_unified_tree_migration/pq_rbbc_cap_unified_tree_environment_after_reduced_v2_33.json
```

未核准resource template：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_production_prefreeze.py \
  --print-resource-template
```

Prospective production command已凍結供review，但目前不可執行：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_runner.py \
  --profile-manifest manifests/pq_rbbc_cap_unified_tree_production_prefreeze_manifest_v2_34.json \
  --phase production-prefreeze \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_34_unified_tree_prefreeze/production-prefreeze \
  --fresh-cache --allow-large
```

Command SHA-256為
`0e12867248331aeeb32deb5830bc1e96b500fbfdf1b7b808a987ee1e4ff0f9b9`；
`executable_now=false`且`authorized_now=false`。

## Evidence identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| checker | 41,709 | `b09eb31b716535560c5f36ecd2dd865222927e52476bb15c84dbbe774c747450` |
| resource schema | 3,280 | `87db532e70dfedf1c79aea828fab24f898a5b6286eff94a2b7706c04a4446d91` |
| frozen manifest | 8,777 | `5bef89840171011c9072bdea44b28a632b2b21df604b382f33cc6de572397829` |
| checker tests | 11,767 | `805795a6ab6f8dde276f3829ad17fb81d6f5db84a6dbae22d38d3c6356389169` |
| external environment report | 5,200 | `7201c56ee8f04c9095c85ce7cf0c57879011b30704ca1c77f2d2a9ea2c21595f` |
| portable evidence | 3,816 | `7778bdad550baa31e530c739e916e14d5e5ce4738846c64f2c0729b663a9e341` |

Portable evidence位於
`artifacts/metadata/cap_unified_tree_production_prefreeze_v2_34/pq_rbbc_cap_unified_tree_production_prefreeze_evidence_v2_34.json`。
External environment report不加入Git。

## Claim boundary

V2.34只關閉read-only checker、resource schema、v2.33 seal binding與production
descriptor fingerprint。以下全部維持false：production runner implemented、production
relation frozen、operator reservation frozen、independent review frozen、pre-freeze
authorized/started、large replay/proving started、CAP/fork security與production closure。
System architecture、ticket lifecycle及`pq_sat_auth`均未修改。
