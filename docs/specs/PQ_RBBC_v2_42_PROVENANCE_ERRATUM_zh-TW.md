# PQ-RBBC v2.42 provenance erratum／successor specification

日期：2026-09-10。修正 CR-02（P3），適用於 v2.42 effective tree 的來源解讀。

本 erratum 修正 sealed v2.33 specification §1 的引用歸屬。原檔
`docs/proof/source/pq_rbbc_cap_unified_tree_spec_v2_33.html` 與其 PDF、seal、checksums
保留原始 bytes；新機器契約為
[`pq_rbbc_cap_unified_tree_provenance_v2_42.json`](../../manifests/pq_rbbc_cap_unified_tree_provenance_v2_42.json)。
參數數值、unified-tree mapping、domains、profile 與 CAP 算法均未改變。

| 用途 | 正確來源與位置 | 支持範圍 |
| --- | --- | --- |
| BAVC construction | [ePrint 2024/490](https://eprint.iacr.org/2024/490)，2025-03-31 revision，§3.1、§4 | 單一 interleaved GGM tree、frontier compression 與 grinding 的構造來源 |
| Generic TCitH comparison | [ePrint 2024/541](https://eprint.iacr.org/2024/541.pdf)，2024-11-08 revision，Table 7，印刷頁 29 | RSD support-decomposition signatures 的參數與尺寸；共用 symmetric tree 數值的比較來源 |
| Blind-UOV CAP parameters | [ePrint 2025/895](https://eprint.iacr.org/2025/895)，2025-10-31 revision，Table 2，印刷頁 20 | degree-2 CAP system 的 NIST III／Shorter／TCitH 參數 |
| Blind-UOV performance | [同一份 2025/895](https://eprint.iacr.org/2025/895)，Table 4，印刷頁 25 | Blind-UOV／Blind-MAYO public-key 與 signature sizes；不是本 fork 的實測 benchmark |

2024/541 的 Table 4 屬 MinRank，Table 7 屬 RSD；兩者都不能稱為 Blind-UOV
參數表。Table 7 的 NIST III／**Short** row 與 2025/895 Table 2 的
NIST III／**Shorter** row 共用 tree 數值，名稱及使用問題仍須分開。
2025/895 Table 7 則是 Blind-Wave performance，不能替代 Table 4 的用途。

選定 CAP row 仍為 `tau=18`、`(tau_1,N_1)=(2,4096)`、
`(tau_2,N_2)=(16,2048)`、`T_open=174`、explicit `w=9`、paper `w_tot=13.9`。
最後一項在 integer-only provenance JSON 中以 decimal string `"13.9"` 保存。
Paper 的參數與 work factor 並不自動建立本 fork 的安全 bound。

| PDF revision | Exact filename | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| 2024/490，2025-03-31 | `eprint_2024_490.pdf` | 1,500,374 | `b41c874ea925a65f33984e0789951144dd012380c6e99e53859af53aa9ffe7a4` |
| 2024/541，2024-11-08 | `eprint_2024_541.pdf` | 859,797 | `ce30ff1d9a49b13211340f4c20d05a4ee76a9f9db1745d3f853102aad0b9837f` |
| 2025/895，2025-10-31 | `blind_uov_eprint_2025_895_revision_2025_10_31.pdf` | 1,595,999 | `7ba2c040fd04823fb0d2aaad5e58348b5ef374726657ff1c0d87d000b4beff95` |

以上三個 identities 與 sealed v2.33 manifest 的 `source_requirements` 相符。
2026-09-10 核對官方 landing pages 的 revision dates，並檢查 exact local PDF
metadata 與上表指定頁面。`pdf_url` 是取得入口，會隨網站更新；**日期、bytes 與
SHA-256 合在一起才是本 checkpoint 的 revision selector**。即使 URL 或檔名相同，
不同 bytes 必須拒絕；不接受自動改用最新 revision。各來源的 history URL 也保存在
manifest；本次未宣稱已下載或驗證 archive-version endpoint（該 endpoint 未能讀取）。

PDFs 保持 external。將上述 exact copies 放入事先建立、可信且不可由群組／其他使用者
寫入的 artifact root 後，可執行唯讀核對：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python \
  src/pq_rbbc_cap_provenance_v2_42.py --artifact-root /trusted/external/papers
```

工具對每份 PDF single-open、bounded capture（最多 2 MiB），只由同一 raw bytes
計算 length／SHA-256；不執行 PDF code 或下載替代檔。Tracked provenance 的 identity
與語意同樣來自一份 snapshot。來源身分的核對不代表完成 cryptographic review。

本次未建立完整 CAP acceptance／extractor／unique-mask proof、concrete Anemoi
ROM／QROM justification、完整 PoW/query-loss bound、production relation／parent join
或 scale qualification。`cap_security_qualified`、`fork_security_proof_revalidated`、
`qrom_qualified`、`production_closed` 全部維持 false。
