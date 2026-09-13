# Threshold backend 來源索引 v1

核對日期：2026-09-13，Asia/Taipei。範圍：使用者提供的四份研究附件，以及另附的工作草案。
完整身分以 [source_inventory_v1.json](source_inventory_v1.json) 為準。

## 精確檔案身分

以下 bytes 與 SHA-256 均由附件的原始 bytes 計算；沒有正規化換行、重新輸出 PDF 或使用抽出的文字代替原檔。

| Source ID | 完整檔名 | bytes | SHA-256 |
| --- | --- | ---: | --- |
| SRC-HANDOFF | `threshold_backend_codex_handoff_zh-TW.md` | 35,930 | `7888b2c4253a11e3225f9e9895eaff0b4ba9fa6a983a70103efdddf255366cc3` |
| SRC-GF | `2021-096.pdf` | 695,683 | `b730d4640218b5ea86b019a52501be2e4682b562e61a468abd08658ee393678e` |
| SRC-UT | `2017-956.pdf` | 655,125 | `8123d5e1ae1d67f054f6f55d4026bb6d3248356cde1a261c66137fd46bcc45b5` |
| SRC-NIED | `2025-757.pdf` | 971,854 | `5e6135b80cac690d95beb73914d89b77280c6ea739ff7a1f7add0da39663ffb6` |
| SRC-PASTED | `pasted-text.txt` | 8,859 | `e737e3e7966287ac4c653e81b4031b24959c3af3af7c203d8d90a297e23c5652` |

## 名稱與 revision 的證據層級

**Catalog revision 與附件身分分開。** 可取得官方頁面的 history，但直接擷取三份 ePrint PDF 與
FIPS 203 PDF 的請求均收到 HTTP 403。未取得可比較的 publisher PDF bytes，因此
`remote_pdf_identity_verified=false`。下表的日期歸屬是 catalog 與附件 metadata 一致的判讀，
不是「附件 SHA-256 已獲出版者認證」。Metadata 也不是簽章或可信 timestamp。
所有原文頁碼均綁定上表的附件 digest，不套用至另一 revision 或出版排版。

| Source | 完整名稱／作者 | revision 紀錄 | 附件證據與限制 |
| --- | --- | --- | --- |
| SRC-HANDOFF | **Codex 交接：PQ-RBBC 門檻後端接入、實作與最終選型** | 首段自述 `handoff v1`，整理日期 `2026-09-10` | 自述版本；沒有獨立修訂歷史或簽章 |
| SRC-GF | **Gladius: LWR based efficient hybrid public key encryption with distributed decryption**；Kelong Cong、Daniele Cozzo、Varun Maram、Nigel P. Smart | [ePrint history](https://eprint.iacr.org/2021/096)：2021-01-27 received；2021-08-31 last of 5 revisions | 57 頁；CreationDate／ModDate 同為 `D:20210831115837+02'00'`；與 catalog 最後修訂日期一致，revision byte match 未確認 |
| SRC-UT | **Threshold Cryptosystems From Threshold Fully Homomorphic Encryption**；Dan Boneh、Rosario Gennaro、Steven Goldfeder、Aayush Jain、Sam Kim、Peter M. R. Rasmussen、Amit Sahai | [ePrint history](https://eprint.iacr.org/2017/956)：2017-09-29 received；標示 Preprint／MINOR revision，沒有可確認的 revision 序號 | 61 頁；CreationDate／ModDate 同為 `D:20170927094725-07'00'`；製作日期早於收件日，不把 2017-09-27 當成正式 revision 日期 |
| SRC-NIED | **Threshold Niederreiter: Chosen-Ciphertext Security and Improved Distributed Decoding**；Pascal Giorgi、Fabien Laguillaumie、Lucas Ottow、Damien Vergnaud | [ePrint history](https://eprint.iacr.org/2025/757)：2025-04-28 received；2025-04-30 revised | 49 頁；CreationDate／ModDate 同為 `D:20250430142228+02'00'`；與 catalog 修訂日期一致，revision byte match 未確認 |
| SRC-PASTED | **Threshold Backend Coordinator T 角色與 TB0／TB1 工作草案**（依首行辨識；原文未提供正式標題） | 無日期、無 revision；`declared_revision=null` | 以 digest 識別；不採用其中的啟動、授權、分工與提交要求 |

UT 的 [CRYPTO 2018 出版頁](https://link.springer.com/chapter/10.1007/978-3-319-96884-1_19)
標示 2018-07-25 first online、pp. 565–596。這是出版資訊；本次核對的 Construction 7.7／8.29
與 Definition A.7 均實際存在於 61 頁的 ePrint 附件，無須推定是另一版本的編號。

Niederreiter 的 [DCC 出版頁](https://link.springer.com/article/10.1007/s10623-025-01795-6)
標示 2026-02-28 version of record、volume 94 article 64，稿件修訂日為 2025-12-04。
因此 `2025-757.pdf` 不可直接標成 DCC 最終稿；本次未完成 ePrint 與 version of record 的全文差異核對。

## 原文定位索引

三份附件的以下 PDF 頁序與印刷頁碼相同，均從 1 起算。表中的項目表示實際查閱範圍，
不表示整篇 proof 已審查。易受文字抽取影響的 GF Fig. 5／Table 2、UT p. 35／E.4 p. 55、
NIED Table 1 已另行渲染頁面作目視核對。

| Source | 位置 | 核對用途 |
| --- | --- | --- |
| SRC-GF | p. 7 family table；§3.2／Theorem 3.2 pp. 23–24；Fig. 5 p. 24 | Fulham＝Hybrid2＋Module-LWR；完整四分量與洩漏模型 |
| SRC-GF | pp. 9–10；§6 pp. 41–42；§7 pp. 44–45／Fig. 14 p. 45；Table 2 p. 46 | 取整規則、message space、無 LVP 分支的限制、底層參數與大小推導 |
| SRC-GF | §3.3 p. 35；§9 pp. 48–52、Fig. 15 p. 48 | 互動解密、DKG 描述、4.99 秒原型的範圍 |
| SRC-UT | Definitions 7.1–7.6 pp. 24–26；Construction 7.7 pp. 26–27 | UT／TFHE／PZK／commitment 及公開份額驗證 |
| SRC-UT | Definitions 8.23–8.28 pp. 34–35；Construction 8.29 pp. 35–36；Theorems 8.30–8.34 p. 36 | 完整 PKE 解密電路、setup、CCA 查詢及 robustness |
| SRC-UT | Definition A.7 p. 44；Appendix E.4 pp. 55–56；E.5 pp. 56–57；G pp. 59–61 | 完美正確性、commitment hybrid、TPKE 歸約文字核對 |
| SRC-NIED | Definitions 1–3 pp. 7–8；Algorithm 1 p. 12；Fig. 1 p. 13 | 互動解密、Patterson decoding、weight／syndrome 檢查 |
| SRC-NIED | Definition 7／Fig. 2 p. 14；Definition 8／Fig. 3 p. 15；Fig. 4 p. 16；§4 p. 17 | 原文 NIZK 轉換、IND-CCA2+、加密 randomness 的可見性 |
| SRC-NIED | Theorems 3–5 pp. 23–24；Fig. 7 p. 24；§5 pp. 25–30、Fig. 8／Theorem 8 p. 30 | NIZK 與 distributed decoding 接合；未重證量子組合安全 |
| SRC-NIED | §6／Eq. (5) p. 31；Table 1 p. 32 | 6688128 syndrome 與 proof 大小；文獻值和本專案預算分離 |
| SRC-HANDOFF | §§3–4.2、§5、§6、§9、§12 | 共同關係、三候選公式、介面差異、預算與次級引用；詳細矩陣見核對報告 |

## 補充網頁來源

這些不是使用者提供的檔案。只保存網址、查閱範圍與 metadata；沒有取得原檔 bytes 時，
inventory 的 `bytes`／`sha256` 均保留 `null`，不能稱為 exact-source identity verification。

| 來源 | 已核對範圍 | 仍未核對 |
| --- | --- | --- |
| [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)，2024-08-13 final | 線上原文 §3.2／Table 1（印刷 p. 15）、§3.3（p. 16）、Algorithm 18（p. 34）、Tables 2–3（p. 39） | 原檔 digest；本次不選定實作或認證合規 |
| [Efficient Schemes for Committing Authenticated Encryption](https://eprint.iacr.org/2022/268)，catalog 最新 2024-07-24 | 標題、history、abstract；支持 CAE 是研究方向 | 未選 construction／參數，未核對量子承諾性 theorem |
| [Post-Quantum Multi-Party Computation](https://eprint.iacr.org/2020/1395)，received 2020-11-10 | 標題與 abstract | 未核對具體 MPC、UT 替換或組合定理；不宣稱函式庫資格 |
| [Threshold Public-Key Encryption: Definitions, Relations, and CPA-to-CCA Transforms](https://eprint.iacr.org/2025/1665)，catalog 最新 2026-07-17 | metadata／abstract，PKC 2026 出版資訊 | 未重證腐敗集合或 challenge-share-query 擴充 |
| [Quasipolynomial Cryptanalysis of the McEliece Cryptosystem (or: PIR Meets McEliece)](https://eprint.iacr.org/2026/1630)，catalog 最新 2026-08-27 | metadata／abstract | 未核對 6688128 的具體成本與假設影響；不得宣稱已實際破解或仍安全合格 |
| [Keeping Up with the KEMs](https://dl.acm.org/doi/10.1145/3658644.3670283)（handoff 標籤） | 網頁擷取失敗 | 標題、revision、定義與 theorem 全部 OPEN |

## 保存與重現

原始 PDF、handoff、pasted attachment、抽出的全文與渲染頁面都留在 repository 外。
本目錄只保存來源索引、摘要、引用位置、digest 與驗證紀錄。沒有提交完整原文、download cache 或圖片。

對自行提供的外部 attachment directory，可重算清單；`source_inventory_v1.json` 是固定的預期值，
不能以重新取得的同名檔案直接覆蓋它。以下命令在本 literature 目錄執行，兩個參數分別指向
四份主要附件與 `pasted-text.txt` 所在目錄：

```bash
python - /path/to/research-attachments /path/to/pasted-attachment <<'PY'
import hashlib, json, sys
from pathlib import Path
inventory = json.loads(Path('source_inventory_v1.json').read_text())
for item in inventory['inputs']:
    directory = Path(sys.argv[2] if item['source_id'] == 'SRC-PASTED' else sys.argv[1])
    raw = (directory / item['filename']).read_bytes()
    assert len(raw) == item['bytes'], item['filename']
    assert hashlib.sha256(raw).hexdigest() == item['sha256'], item['filename']
    print(item['source_id'], 'identity PASS')
PY
```

閱讀工具：Poppler `pdftotext`／`pdfinfo`／`pdftoppm` 22.02.0。
文字抽取用 `pdftotext -layout INPUT.pdf EXTERNAL_OUTPUT.txt`；日期用 `pdfinfo -rawdates INPUT.pdf`。
對每個 PDF 先計算原始 bytes／SHA-256，再抽取閱讀；提交前另與 inventory 重算比較。
沒有反序列化 pickle，沒有執行附件中的 shell／Python 指令。
