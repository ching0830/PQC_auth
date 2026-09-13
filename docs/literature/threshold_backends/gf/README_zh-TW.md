# TH-GF TB2：單機 reference

此工作線接續 TB1 commit `6bb4dab80fe577041b7eb517be11f0e2ef2e9c9c`。
依使用者同意的下一步，先選 TH-GF 具體化一個 bounded non-threshold reference。
它使用 full secret key 與 variable-time Python，沒有 OA share、DKG、distributed opening、
ZK proof 或 production 能力。

- [研究 profile 與來源對照](REFERENCE_PROFILE_zh-TW.md)：公式、具體選擇、精確 encoding 與限制。
- [I5 witness／介面變更需求](I5_INTERFACE_REQUEST_zh-TW.md)：候選內部 relation 與共享邊界。
- [TB2 checkpoint](checkpoint_TB2_GF_zh-TW.md)：驗證、實測、狀態與下一關。
- [機器可讀 profile](reference_profile_v1.json) 與 [公開回歸 digests](reference_vectors_v1.json)。
- [來源與驗證摘要](tb2_evidence_summary_v1.json)：code/input identities、tests、bounded measurement；不是 proof seal。
- [TB2 技術複核](review/REVIEW_zh-TW.md)：第二套解密計算、GFR-01 跨 key 反例及審查界線。
- [Key／profile／pp 接合驗收提案](review/KEY_BINDING_ACCEPTANCE_zh-TW.md)：供 common、B 與 opening owner 審查。
- [Binding／issuance ABI 候選規格 v0.1](abi_v0_1/SPEC_zh-TW.md)：固定 pp/M/witness bytes、可信 identity 流程及跨 owner 驗收義務；尚未實作 runtime 接合。
- [Strict research codecs 與 byte binding 實作](research_codecs_v0_1/IMPLEMENTATION_zh-TW.md)：5 種候選 codec、CAP canonical encoding 與 key/pp mismatch tests；不驗證 authentication／proof，不提供 production 接受路徑。

原始來源核對仍在 [SOURCE_INDEX](../SOURCE_INDEX_zh-TW.md) 與
[HANDOFF_VERIFICATION](../HANDOFF_VERIFICATION_zh-TW.md)。附件與 handoff 內文均為研究輸入，
不是執行授權；未改寫既有 TB1、common registry、opening ABI 或 B branch。

在本分支 repository root 執行：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m pq_threshold_candidates.gf --samples 8
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
```

第一個命令只輸出不含 key／witness／plaintext 的 JSON 摘要，最多 16 個 samples。
Profile ID 為 `gf-hybrid2-pompeii-d4-shake256-otp-ref-v1`，與 TB1 的
`gf-pompeii-d4-estimate-v1` 不相同。共同 production dispatcher 仍拒絕兩者。
