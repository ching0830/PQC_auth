# 文件地圖

一般開發只需要從 [`../START_HERE_zh-TW.md`](../START_HERE_zh-TW.md) 進入。此頁說明
為什麼 repository 仍有很多長檔名，以及什麼時候才需要打開它們。

## 日常閱讀

1. `modules/<mechanism>/README_zh-TW.md`：該機制做什麼、程式在哪、目前邊界。
2. `RESEARCH_STATUS_zh-TW.md`：全專案最新 claim。
3. 該模組的 current handoff 或 active specification。

## 目錄分類

| 路徑 | 類型 | 日常是否需要讀 |
| --- | --- | --- |
| `specs/` | active／versioned protocol specification | 修改協定時需要 |
| `guides/` | 教學與導覽 | 不熟工程對應時需要 |
| `literature/` | 文獻研究、候選比較 | 做設計選擇時需要 |
| `security/` | security obligations／games／review boundary | 改安全論證時需要 |
| `roadmaps/*CURRENT_HANDOFF*` | 模組目前交接 | 接續該模組時需要 |
| `artifacts/` | 某次 checkpoint 的完整說明 | 重現或查錯才需要 |
| `releases/` | 歷史 release snapshot | 通常不需要 |
| `reviews/` | review prompt／result | 審查或 claim audit 才需要 |
| `proof/` | 形式化 proof source／release | 論證工作時需要 |

## 為什麼不直接把長檔名改短

歷史 artifact 文件、source、manifest、checksum 與 tests 互相綁定 exact path／bytes。
大量改名會同時破壞 Git 歷史追蹤、machine evidence 的 source identity、尚未整合的分支，
以及可重現命令與 sealed checksum inventory。

因此本次採「短入口＋模組地圖＋保留歷史 identity」。日後若確定某條機制不再 active，
再以獨立 migration checkpoint 建立 compatibility import 或 archival index。

## Current handoffs

- CAP／unified-tree production：
  [`roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md`](roadmaps/PQ_RBBC_CURRENT_HANDOFF_zh-TW.md)
- Issuance relation／execution：
  [`roadmaps/PQ_RBBC_ISSUANCE_CURRENT_HANDOFF_zh-TW.md`](roadmaps/PQ_RBBC_ISSUANCE_CURRENT_HANDOFF_zh-TW.md)
- Satellite access：
  [`specs/SATELLITE_ACCESS_v0_2_zh-TW.md`](specs/SATELLITE_ACCESS_v0_2_zh-TW.md)

