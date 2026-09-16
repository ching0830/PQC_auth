# TB1 checkpoint：共同研究契約與比較工具

日期：2026-09-13。使用者在來源稽核完成後同意開始 TB0／TB1。
附件文字一直維持研究輸入身分；沒有依文件內的啟動指令建立其他工作、執行 TB2 或啟用 crypto。

## Base 與範圍

- Canonical local main：`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`。
- 直接 parent／來源稽核：`853cf2f20f914704ed9b001d0be87d57f04e2e8a`，相對 main 僅四份來源文件。
- 本輪 branch：`codex/threshold-backend-tb0-tb1`；使用獨立 worktree。
- 唯讀 B 分支 tip：`fc59ff0c7a8fba8bc443c488e37f9a148f238753`，沒有引入 B 的程式或測試。
- 寫入範圍：`src/pq_threshold_candidates/`、`tests/threshold_candidates/`、本 literature 目錄及 `docs/security/threshold_backend_obligations_zh-TW.md`。

本文件隨結果 commit 提交；其 exact commit/tree 由交付時 Git 回報，避免自我引用 hash。
沒有 merge、push、修改其他 worktree 或啟動 production。原始 PDF、handoff、pasted text、
下載內容與測試 log 均未納入 Git。

## 已完成能力

TB0 的 [介面盤點](TB0_INTERFACE_INVENTORY_zh-TW.md) 記錄現有 gate／combiner 的真實能力，
以及 AD 缺失、多輪 replay、份額數學驗證、KDF metadata drift、ticket digest 語意差異、
B 的 I5／witness ABI 與 root 文件更新等七個 integration requests。

TB1 實作 [共同研究契約 v1](COMMON_CONTRACT_v1_zh-TW.md)：closed-world candidate/profile
registry、固定 48/80-byte trace codec、嚴格 versioned ciphertext envelope、保留 unknown 的
component accounting、JSON comparison CLI、研究與 production dispatch 的明確拒絕。
四個 profile 是 estimate IDs；沒有 reference encryption/decryption、share、combine 或
interactive transcript 的成功路徑。三份 fit 文件與安全義務表提供後續具體化的條件。

| 候選 | 共同契約／算術 | Reference crypto | Threshold execution | Security fit | Production |
| --- | --- | --- | --- | --- | --- |
| TH-GF（d4/d9 estimate） | PASS | Unsupported | 未實作 | OPEN | 未封閉 |
| TH-UT（ML-KEM-768 estimate） | PASS | Unsupported | 未實作 | OPEN | 未封閉 |
| TH-NIED（6688128 estimate） | PASS | Unsupported | 未實作 | OPEN | 未封閉 |

## 大小資料及 claim boundary

| 草案 | 已知 B_C | 完整 B_C | sigma=11644、extra=0 的條件式 B_ticket | Research envelope overhead |
| --- | --- | --- | --- | --- |
| TH-GF d4 | 2816 | 2816+g | 14540+g | 71 |
| TH-GF d9 | 6752 | 6752+g | 18476+g | 71 |
| TH-UT | 1136 | 1136+Δ | 12860+Δ | 69 |
| TH-NIED | 288 | 288 | 12012 | 72 |

大小單位 bytes；B_C／B_ticket 全是 estimated，sigma provisional。表中 extra=0 是明示假設，
不是測得的 framing；若採用研究 envelope，需另計相應 overhead。預設 CLI 的 extra 為 null，
所以四列完整 ticket 大小都是 null。GF 的 g、UT 的 Δ 預設也為 null。
Observed ciphertext、ticket、rounds、opening time、satellite online bytes 全為 null。
論文的不同 profile 實驗值只留在 fit 文件，不填入 observed。

## 驗證紀錄

環境為 Python 3.12.9 stdlib、`PYTHONDONTWRITEBYTECODE=1`、`PYTHONPATH=src`；使用無 ignored
external-artifact provision 的獨立 worktree。執行目錄為本 branch 的 repository root。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/system_modules/opening -t tests -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest tests.test_pq_rbbc_reference.RelationTests.test_trace_kdf_canonical_split_and_frozen_vector tests.test_pq_rbbc_reference.RelationTests.test_trace_kdf_split_rejects_noncanonical_boundaries tests.test_pq_rbbc_reference.RelationTests.test_trace_kdf_wrong_order_rejected_by_direct_relation tests.test_pq_rbbc_trace_kdf_source_transition -v
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests -v
git diff --check
```

| 檢查 | Passed | Failed/errors | Skipped | unittest elapsed |
| --- | --- | --- | --- | --- |
| 新共同契約 tests | 28 | 0 | 0 | 0.132 s |
| 既有 opening regression | 29 | 0 | 0 | 0.020 s |
| KDF reference／source-transition | 10 | 0 | 0 | 0.805 s |
| Full regression（716 total） | 704 | 0 | 12 | 733.100 s |

Targeted 合計 67 項，67 passed、0 failed、0 skipped。初次新測試 run 的手工 wire vector
把 24-byte profile 長度誤寫成 23，產生一項 test failure；已改正 expected literal，28 項重跑
全通過，沒有放寬 decoder。覆蓋 round trip、獨立 wire vector、所有截斷點、未知版本／profile、
大小／trailing／type／bool／overflow、serial mismatch、unknown propagation、拒絕 estimate
提升為 observation，以及所有 candidate 的 production／crypto 拒絕。

Full regression exit code 0，包含新 28 項測試。12 項 skip 全因獨立 worktree 未安裝指定的
外部 artifacts：v2.13 tree-0 assignment/cache、v2.14 replay/tree-2、v2.15 relocation、
v2.19 recovery、v2.20 global-tail、v2.21 tree-2、v2.22 tree-1、v2.23 tree-3、v2.24 tree-4、
v2.25 batch。沒有複製大型 artifacts、略過新增測試，或把 skip 計為 pass。

此外重核 5 份附件、19 份 source-audit repository entries、20 份 TB0 補充來源的 bytes／SHA-256，
全部相符。原始 SOURCE_INDEX、HANDOFF_VERIFICATION、source_inventory 均未改寫。
精確附件 hash 已有記錄，但與 publisher 所託管 PDF 的 byte identity 仍未確認（來源稽核 F-01）。
提交前 `git diff --check`／staged diff 檢查通過；16 個變更檔案皆在限定範圍、各小於 64 KiB，
Markdown 相對連結均可解析。所有新增內容為 `.py`／`.md`／`.json`，無禁止提交的 artifacts。

## 留給整合與下一階段

Root 文件由 integration lane 擁有。本 checkpoint 的設計理由、命令／結果與受限 claim 狀態
作為 IR-07 的可審查輸入，待 owner 登錄 methodology、experiments、RESEARCH_STATUS。
此工作線未自行改動 canonical 文件、opening ABI、KDF source/manifest 或 B branch。

接續工作可依 [安全義務表](../../security/threshold_backend_obligations_zh-TW.md) 選定一個
non-threshold reference 的 bounded scope，先具體化參數與 I5 witness descriptor。
共同 v1 變更須經明確 change request；多輪 opening、OA setup／DKG、proof closure、
production qualification 及大型 proving／replay 仍不在本輪完成範圍。
