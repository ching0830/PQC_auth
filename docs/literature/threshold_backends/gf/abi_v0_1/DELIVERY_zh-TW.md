# GF binding／issuance ABI v0.1 交付紀錄

日期：2026-09-13。Branch：`codex/threshold-gf-binding-abi-v0-1`。
基準 commit：`ddb1336ff5a32ca5b2d50bbe31f3d5d0c07a6b25`；tree：
`c4dad5d6096d9183e94b93bb3e77298a53aeac30`。
本輪只在 T 的 GF literature 目錄撰寫候選規格與文件檢查工具；無 shared ABI 或 owner acceptance 變更。

## 交付內容

- [候選規格](SPEC_zh-TW.md)：key／configuration／pp trust chain、same-byte binding、M header
  的 pp identity、I1–I5 join、private partition、opening／migration 與成本界線。
- [Machine-readable contract](contract_v0_1.json)：5 種固定封包的 offsets、constants、identity
  rules 與 claim boundary；ABI canonical fingerprint 由整份 contract 計算。
- [驗收矩陣](ACCEPTANCE_zh-TW.md)：24 個案例，各自列出拒絕邊界、owner 與完成範圍。
- [文件 conformance checker](check_spec_v0_1.py)：只重現 synthetic framing 與 digest checks；
  沒有可用的 crypto／authentication／proof 成功路徑，也不是 production codec。
- [來源索引](source_index_v0_1.json) 與 [驗證摘要](validation_summary_v0_1.json)：
  exact revisions、bytes、SHA-256、命令／結果／限制；不附 raw artifacts。

## 來源重核與 observations

五份附件完整名稱、declared/catalog revision、bytes、SHA-256 已與原索引重核一致；
三份 PDF、handoff 與 pasted input 均只作研究輸入。未把新增 ABI/header 規則標為 paper-verified。
十九份先前已讀的 canonical/research/policy source identities 未變；本次另釘選十七份
repository 來源及引用行號。PDF、抽出文字、其他工作線的本機唯讀副本均未進入 Git。

本輪定位到以下具體接合差異，並在提案中處置；不是替其他 owner 宣稱已修復：

| ID | 觀察 | 提案處置 |
| --- | --- | --- |
| ABI-01 | GFR-01 下同一 raw C 可跨 key；I5 不提供 expected-key identity | trusted setting/key/pp checks，加 M header.pp digest 進 I2／簽章；crypto 算式保持不變 |
| ABI-02 | B `ff4341b` 固定 M368、e836、r/beta72、rho1036；`e7af82e` key grammar 固定 NIED | 另立 GF candidate namespace、M3005、u128、W4324；bridge 固定 legacy18，不能重標 unified |
| ABI-03 | `ecab1d9` ticket verifier 已分開 payload digest 與 transport digest，仍只收 NIED M；opening request 仍 SHA256(T)，view/context 缺 h/AD | 保留歷史觀察，要求新 M dispatch、trusted AD 與 d_M-bound authorization；IR-01/05 未自動關閉 |
| ABI-04 | TB2 compact descriptor fingerprint 與 pretty JSON file SHA-256 不同 | 分離 protocol identity 與來源 file digest；拒絕相互替代 |

## 驗證命令與結果

在本分支 repository root 執行：

```bash
PYTHONDONTWRITEBYTECODE=1 python docs/literature/threshold_backends/gf/abi_v0_1/check_spec_v0_1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
git diff --check
```

| 檢查 | 結果 | 限制 |
| --- | --- | --- |
| 文件 grammar／offsets／fingerprints | 5 個 structural round-trip 通過，40 個 malformed 結構拒絕，0 失敗 | 同一 checker 的 synthetic shapes，不是實際合法 ciphertext/witness、cross-language KAT 或 crypto codec qualification |
| PP header 對 M／d_M 的影響 | 同一 raw C 的 fixture 在不同 pp 下，M／d_M 不同；完整 M 與去 header preimage 的 digest 不同 | 不證明 hash collision resistance、trusted pp、實際 signature 拒絕或完整 constraints |
| Threshold targeted | 60 passed、0 failed、0 errors、0 skipped；11.065 s | 原有 TB1/TB2/review tests；本輪未新增 crypto test case |
| CAP／H_RBBC metadata probe | pinned fingerprints 一致，legacy rho serialization=1036 bytes | 本地 metadata 查詢，沒有執行 B／其他工作線程式或產生 CAP proof |
| Source identity／links／artifact scope／diff | 提交前檢查 PASS | source digests 與結構檢查不等於 proof/evidence seal |

Metadata probe 初次誤呼叫 CAPRandomness 的不存在 `encode()` 方法，修正為既有 `serialize()`
後完成；這是 probe 使用錯誤，不是 regression failure，也沒有因此改動 CAP source。

本輪無 `src/`／`tests/` 變更，未重跑整個 repository baseline。前次 `ddb1336` 的完整結果為
748 total：736 passed、0 failed/errors、12 skipped（optional external artifacts 缺少），759.093 s；
僅列為前次 evidence，不冒稱本輪新執行。Raw report/log 留在 repository 外；其 bytes/digests
記於本輪 summary，可依上述命令重建。

## Claims 與下一步

本次完成 **candidate specification / document conformance**。Runtime codecs、可信設定／key-origin
驗證、B full relation/proof、GF VerifyTicket/opening、多輪 transcript、T1–T4、DKG 仍 OPEN；
沒有 external independent reviewer attestation，亦沒有 production acceptance。

下一步可在 T 自有 namespace 實作 strict research codecs 與 expected key/pp mismatch checks，
依驗收矩陣保持 fixture trust 與 production 的界線；cross-lane integration 仍需各 owner 接納。
TB3 門檻計算尚未開始。本交付另供 integration owner 將決策理由、命令結果與受限狀態，
分別納入 methodology、experiments、RESEARCH_STATUS；這些根目錄共用文件未由本工作線改寫。
