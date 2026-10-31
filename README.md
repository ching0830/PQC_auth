# PQ-SAT 論文程式 v0.1

這是 2026-10-31、82 頁 Hχ⁺ BUOV／CAP 論文閱讀版的乾淨程式基準。
主方案實作 **UE 真實 π_iss Prove → HNCC 自有敘述 Verify → 接受後 Inv → 原 CAP 狀態 Append → π₂ Prove → 獨立 VerifyTicket**。
論文版本、來源 commits 與逐檔 SHA-256 見 [provenance](provenance/baseline.json)。

目前仍是研究原型：`Backend=null`、`qualified2PC=false`、`gate=BLOCKED`、
`wholeSystemProofClosed=false`、`issuerUnlinkabilityClosed=false`。
128 僅是 FRI query target；actual fork／PQ 安全與正式參數未資格化。
通過程式測試不等於密碼學證明或 production closure。

## 最短入口

Python 3.12、Linux x86_64。以下指令在 repository 根目錄執行，無需舊工作樹：

```bash
python3 -B release.py --help
python3 -B release.py test
python3 -B release.py compare
```

`test` 檢查數學、canonical codec、角色邊界、公開設定、I/O、資源限制與發布閉包；
缺外部 native inputs 的選用測試會明列 skip。`compare` 只重算既有公開資料，不產生新樣本。

完整主方案須先安裝 [外部輸入](docs/REPRODUCE_zh-TW.md)：

```bash
cp runtime.example.json runtime.local.json
# 編輯 artifacts 絕對路徑與新的 run_root；兩者不得混用
python3 -B release.py doctor --config runtime.local.json
python3 -B release.py run --config runtime.local.json --label thesis-replay-001
```

`doctor` 只驗 size／SHA-256，不載入 CS、不執行 Prove。
缺輸入時回傳 exit 2，明列缺件；不會使用舊 `/tmp` 輸入或降級為 fake proof。
正式 `run` 保留原共享重型工作鎖、單核、資源准入與原 cryptographic gates。
安裝清單目前 164 檔、約 1.35 GB；包含完整必要 compiler runtime、94 個 rlibs、公開 T、
setup binary／receipt 與 688,968,080 B 唯讀公開 CS cache。這些 binary 不進 Git。
尚無公開 artifact 下載，跨機 bit-identical 重建未驗證，因此本版不宣稱一鍵完整可重現。

## 程式與結果分組

| 位置 | 用途 |
| --- | --- |
| `release.py`、`publication/` | 單一入口、集中路徑設定、artifact 校驗、純 I/O helpers、結果重算 |
| `src/pq_rbbc/blind_uov_hplus*` | Hχ⁺ CAP 與 native prover；閉合 source overlay 重用 pinned 舊 CAP 算法 |
| `src/pq_sat_auth/prototypes/buov_cap_hplus_research_v0_1/` | 主方案敘述、見證、Append 與獨立驗票 |
| `benchmarks/buov_cap_hplus_research_v0_1/` | UE／HNCC／consumer 真實角色程序 |
| `native/`、`dependencies/binius/` | C／Rust source、必要共用核心、完整 Cargo adapter／lock／研究 patches |
| `tests/`、`manifests/` | 精簡正負向測試與 frozen identities |
| `comparisons/old30/` | 舊 profile 的 30 票公開逐票資料及統計重算程式 |
| `comparisons/opening/` | 獨立 OA 元件的 warm-up 1＋10 次公開結果 |
| `evidence/`、`provenance/` | 主體 n=1／來源／依賴及 claim 邊界 |

主方案 n=1 的終點是獨立驗票接受。舊 30 票採另一個一致性雜湊、優化關係及 UE 四核，
終點為同票 access ACTIVE；OA 是另一個 dealer-assisted、單主機 2-of-3 開啟元件。
本版僅保留這兩組比較資料及離線分析，不附它們的完整舊 cryptographic runtime，
也不將其接入／開啟成本當成 Hχ⁺ 同票完整生命週期。詳見 [分組範圍](comparisons/README_zh-TW.md)。

部分長路徑保留是因 source／CS／profile identity 耦合。未選取舊論文、研究卡、
logs、cache、assignments、wallet／私鑰、未採用 mask 候選及無關祖先 history。
後續直接在 `codex/pqsat-buov-thesis-code-v0-1` 依 [工作規則](CONTRIBUTING.md) 提交。
