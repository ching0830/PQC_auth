# 從這裡開始

這是本 repository 的人類入口。若你只是要了解「目前有哪些成果、程式放哪裡、下一步
要改哪個機制」，先讀本頁，不需要先打開 `docs/artifacts/` 裡的長檔名。

## 目前的整理原則

1. **按 protocol 機制理解，而不是按歷史版本理解。**入口在
   [`modules/README_zh-TW.md`](modules/README_zh-TW.md)。
2. **既有程式暫不搬家。**許多 `pq_rbbc_*.py` 長檔名已被 tests、manifests、checksums
   與 sealed evidence 引用；現在搬動會破壞可重現性。
3. **新機制使用新版本／新 namespace。**不在同一 codec 或 relation 版本中靜默改義。
4. **歷史文件保留，但不作日常入口。**`docs/artifacts/`、`docs/releases/`、
   `docs/reviews/` 與大部分 `docs/roadmaps/` 只在重現 checkpoint 時閱讀。

## 七個容易理解的區塊

| 機制 | 你要回答的問題 | 短入口 |
| --- | --- | --- |
| System | 誰設定系統、誰可發票、quota 如何消耗？ | [`modules/system/`](modules/system/README_zh-TW.md) |
| Issuance | UE 如何離線取得匿名且可追責的 ticket？ | [`modules/issuance/`](modules/issuance/README_zh-TW.md) |
| Access | UE 如何用 ticket 與 FGS 建立 session？ | [`modules/access/`](modules/access/README_zh-TW.md) |
| Lifecycle | ticket 如何 one-time consume、retry、revocation、handover？ | [`modules/lifecycle/`](modules/lifecycle/README_zh-TW.md) |
| Opening | 什麼情況可開啟身分，誰能產生 share？ | [`modules/opening/`](modules/opening/README_zh-TW.md) |
| Threshold research | 哪些 threshold backend 只是研究候選？ | [`modules/threshold/`](modules/threshold/README_zh-TW.md) |
| Evaluation | proof size、時間、通訊量如何量測？ | [`modules/evaluation/`](modules/evaluation/README_zh-TW.md) |

## 程式入口

- [`src/README_zh-TW.md`](src/README_zh-TW.md)：程式資料夾與舊長檔名的分類。
- [`tests/README_zh-TW.md`](tests/README_zh-TW.md)：測試如何對應各機制。
- [`manifests/project_module_registry_v0_1.json`](manifests/project_module_registry_v0_1.json)：
  機器可檢查的模組 registry。

## 文件只分四層

| 層級 | 主要入口 | 用途 |
| --- | --- | --- |
| 導覽 | 本頁、`modules/`、`src/README_zh-TW.md` | 快速了解與找程式 |
| Canonical | `ARCHITECTURE_zh-TW.md`、`RESEARCH_STATUS_zh-TW.md`、`ROADMAP_zh-TW.md` | 正式語意、狀態、下一步 |
| 研究工作台 | `research-notes.md`、`methodology.md`、`experiments.md`、`thesis-outline.md` | 跨任務恢復論文脈絡 |
| 歷史／證據 | `docs/artifacts/`、`docs/releases/`、`docs/reviews/`、`artifacts/metadata/` | 重現或審查特定 checkpoint |

更完整規則見 [`docs/README_zh-TW.md`](docs/README_zh-TW.md) 與
[`docs/DOCUMENTATION_POLICY_zh-TW.md`](docs/DOCUMENTATION_POLICY_zh-TW.md)。

## Access 機制目前有三條線

| 線 | 用途 | 是否正式 |
| --- | --- | --- |
| V1 四訊息 | 歷史 baseline，保留相容性與比較 | 否 |
| V2 exact `R_access` NIZK | 已有完整 reference processors／state stores；真實 NIZK／PQ suite 未封閉 | 否 |
| V3 holder signature | D4 ML-DSA 與 D4b FAEST 隔離 prototype；尚未改 shared ticket／parser | 否 |

你提供的 `ctx` 統一公式文件屬於下一版候選設計輸入，目前沒有被當作已採納規格或已
實作程式。本次整理完成後，再以這三條線為單位判斷哪些沿用、哪些收進歷史區。

