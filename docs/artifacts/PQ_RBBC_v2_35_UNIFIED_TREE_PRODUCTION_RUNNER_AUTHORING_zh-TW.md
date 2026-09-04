# PQ-RBBC v2.35 unified-tree production runner authoring checkpoint

## 結論

V2.35已建立獨立的unified-tree production runner skeleton、relation-stage contract、
18-vector production-shaped qualification fixture與portable evidence。Fresh run、
plan後中斷／resume、deterministic identity、existing-output refusal及production branch
在建立output前拒絕等control flow均已驗證。

這不是production runner qualification。唯一可執行phase只展開40個test-only leaves，
production profile、relation rows、assignment、BR1CS與proof均未執行或建立：

- `runner_skeleton_qualified = true`；
- `production_runner_qualified = false`；
- `safe_to_start_production_prefreeze = false`；
- `safe_to_start_large_replay = false`；
- `safe_to_start_large_proving_run = false`。

## Protocol位置

在protocol中，unified CAP producer必須先用單一root seed展開40,960個leaves，依
position-major mapping分配給18個logical vectors，再形成18個vector hashes及1個
unified root。新的`c_r`隨後必須一路綁定ticket relation、output relocation、
aggregate relation、parent-bound global tail、CAP-to-H-RBBC parent join及完整relation
identity。

V2.35只把這條路徑的順序、輸入邊界、state machine及resume規則寫成machine-readable
contract，並用縮小但保留18-vector形狀的fixture驗證producer控制流程。它沒有觀察
production的row stream、wire count、assignment或resource cost，因此不能把舊18-tree
的observed `stream_bytes`、digests、assignments或v2.29 transcript移植成新profile
evidence。

## Authored relation contract

Production descriptor fingerprint維持
`c270e4681f23955667a6c0640317e7beccc666d60a0cffb40bfdccfcee811b7a`；v2.35
relation contract SHA-256為
`650bd7715f1158e948db0fa5f8ce547410653bbc6b405c6ec37f8fadd85570a7`。

Ordered stages為：

1. 40,959次seed derivation；
2. 40,960個leaf commitment與tape expansion；
3. 18個logical-vector hashes；
4. 1個unified-root hash；
5. 重建CAP relation與parent binding；
6. 產生pre-freeze evidence。

所有production observations仍為`null`。589,054,075 combined rows與兩個passes的
1,178,108,150 row checks只是planning lower bounds，不是observed或frozen counts。
Production checkpoint payload與relation generator仍標為未實作；final unified-profile
statement bytes也仍待後續checkpoint凍結。

## Bounded qualification observation

Test-only profile fingerprint為
`72a4b1a09805c6af324f1176709ebde51435bee7235082ea86d3099bcf75a4f5`，使用
`(4,4,2×16)`共40個leaves、18個logical vectors、39個internal nodes、64-bit tape、
`T_open=18`與2個explicit bits。它保留production的兩大／十六小向量比例及
position-major mapping，但`secure_profile=false`且不能被當成production profile。

Fresh evidence的deterministic result identity為
`5075ebcbabb7cfa95a459f27a21bf2a0db11b7ef0f7ec69e30a4414f0c3a2a0f`：

- 138次XOF calls，commitment 158 bytes；
- grinding counter 4，共5 trials；
- minimal frontier 12 nodes，opening 1,456 bytes；
- verifier接受，22個opened leaves、18個hidden leaves；
- 本次fresh run elapsed 52.392秒、peak RSS 21,364,736 bytes；
- production leaves、relation rows及proofs均為0。

這個runtime只描述40-leaf Python fixture，不能外推40,960-leaf production relation或
589M-row replay。Production資源規劃仍使用v2.34最低reservation：4 cores、16 GiB
available memory、80 GiB free disk，以及operator明確填寫的wall-clock reservation。

## Launch blockers

Production branch目前固定在建立output前fail closed，精確列出：

1. production checkpoint payload尚未實作；
2. production relation generator尚未實作；
3. operator resource reservation identity尚未凍結；
4. independent review identity尚未凍結；
5. production pre-freeze尚未獲明確execution authorization；
6. 尚缺後續identity-frozen launch manifest。

專案不能自行替operator或independent reviewer製造attestation，也不能靠修改manifest
booleans開啟production branch。

## Exact commands

已執行的bounded qualification：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_production_runner.py \
  --profile-manifest manifests/pq_rbbc_cap_unified_tree_production_runner_manifest_v2_35.json \
  --phase qualification \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_35_unified_tree_runner/qualification \
  --fresh-cache
```

Portable sealer：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_production_runner_evidence.py \
  --run-evidence /tmp/pq_rbbc_external_artifacts_rebuilt/v2_35_unified_tree_runner/qualification/pq_rbbc_cap_unified_tree_production_shaped_evidence_v2_35.json \
  --runner-qualification /tmp/pq_rbbc_external_artifacts_rebuilt/v2_35_unified_tree_runner/qualification/pq_rbbc_cap_unified_tree_production_runner_qualification_v2_35.json \
  --output artifacts/metadata/cap_unified_tree_production_runner_v2_35/pq_rbbc_cap_unified_tree_production_runner_evidence_v2_35.json
```

Prospective production command已凍結供review，但目前不可執行：

```bash
PYTHONPATH=src python -u src/pq_rbbc_cap_unified_tree_production_runner.py \
  --profile-manifest manifests/pq_rbbc_cap_unified_tree_production_runner_manifest_v2_35.json \
  --phase production-prefreeze \
  --authorization-manifest /tmp/pq_rbbc_external_artifacts_rebuilt/v2_35_unified_tree_runner/pq_rbbc_cap_unified_tree_launch_authorization_v2_35.json \
  --output /tmp/pq_rbbc_external_artifacts_rebuilt/v2_35_unified_tree_runner/production-prefreeze \
  --fresh-cache --allow-large
```

Command SHA-256為
`df3fe53ac3c2720c63f9c3b493def3bdb558d87c14ecd7f52faf68e68cbc8f07`；
`executable_now=false`且`authorized_now=false`。

## Evidence identities

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| production runner skeleton | 25,541 | `05328e30a6a17283c2329867c00601aea5894c18b6e9a0d49e98c48e5e8ffeee` |
| frozen runner manifest | 7,000 | `e995d3e2db48008550ee15de89ce58ca2b574a8142a9cc39f96010d2a44c9bf0` |
| runner tests | 8,236 | `c3f02e03e36da623fad03b9ee26a33000d93decd7a235a6babb231b8bbbe4a4b` |
| sealer tests | 3,385 | `dff43a57fea95a45c0a7f084589372016a32614a2f8675ac7f656aa46046d839` |
| external run evidence | 5,506 | `f17a82f67785612b040301893852eb72ee46eabe21e93dd017fc69d8599e3659` |
| external runner qualification | 1,867 | `f124f9b27d5c6b6a82ff717ddf148ef683c43a0cc4e16ff47961cc7ba6e59329` |
| portable evidence | 4,836 | `5284654b909158c18c3f3df50b9de190e50bf06469b1d1f1036bfeb860cf292e` |

Portable evidence位於
`artifacts/metadata/cap_unified_tree_production_runner_v2_35/pq_rbbc_cap_unified_tree_production_runner_evidence_v2_35.json`。
Runtime evidence與JSON state均留在external directory，不加入Git。

## Claim boundary

V2.35只關閉relation contract authoring、runner skeleton及bounded fixture control-flow
qualification。Production profile implementation、checkpoint payload、relation generator、
production runner qualification、observed relation freeze、pre-freeze/replay/proving、CAP／
fork security及production closure全部維持false。System architecture、ticket lifecycle、
`pq_sat_auth`與既有18-tree evidence均未修改。
