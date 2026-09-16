# 第二十四堂：Repository 地圖——規格、程式、測試與證據放在哪裡

日期：2026-09-16。所屬階段：5／程式閱讀工具。
接續[第二十三堂](23_THREAT_MODEL_AND_SECURITY_BOUNDARIES_zh-TW.md)，本堂第一次把前面的協定概念
接到實際檔案。目標不是立刻讀懂所有 Python，而是看到一項功能時，知道應該去哪裡找它的定義、
實作、測試與目前限制。

## 1. Repository 是什麼

Repository（常簡稱 repo）是由 Git 管理的一整個專案工作區。它不只包含程式碼；本專案還包含：

- 論文研究問題與設計理由；
- 正式架構、狀態與工作路線；
- Python 原始碼；
- 單元測試與整合測試；
- machine-readable manifests、checksums 與 proof／artifact evidence；
- 個人學習教材。

目前 repository root 是：

```text
/home/ucheng0830/Documents/PQC_auth
```

Root 是最外層資料夾。像 `src/pq_sat_auth/framing.py` 是相對於 root 的 relative path；完整寫出來的
`/home/ucheng0830/Documents/PQC_auth/src/pq_sat_auth/framing.py` 則是 absolute path。

## 2. 先把專案分成五個區域

### A. 研究與設計工作台

| 路徑 | 唯一責任 |
| --- | --- |
| `research-notes.md` | 文獻、理論、研究問題與研究缺口 |
| `methodology.md` | 設計決策、理由、替代方案與評估方法 |
| `experiments.md` | 實驗環境、commit、命令、輸入、結果與限制 |
| `thesis-outline.md` | 論文章節安排、寫作進度與所需材料 |

這些文件回答「為什麼研究、為什麼這樣設計、做過什麼實驗」。它們不單獨決定最新實作成熟度。

### B. 正式全專案定義

| 路徑 | 回答的問題 |
| --- | --- |
| `ARCHITECTURE_zh-TW.md` | 系統有哪些角色、模組、流程與信任邊界？ |
| `RESEARCH_STATUS_zh-TW.md` | 哪些只 Defined，哪些已 Implemented／Tested，還缺什麼？ |
| `ROADMAP_zh-TW.md` | 接下來的工程工作、相依關係與 integration gate 是什麼？ |

其中 `RESEARCH_STATUS_zh-TW.md` 是判斷目前完成程度的主要入口。看到某個 Python 檔存在，不應直接
推論整個功能已 production-ready。

### C. 可執行實作

| 路徑 | 目前內容 |
| --- | --- |
| `src/pq_sat_auth/` | 衛星接入 framing、message binding、ticket-use identity 與 process-local replay reference |
| `src/pq_rbbc/` | 新的 system-level contracts、governance 與 opening package |
| `src/pq_rbbc_*.py` | 既有 PQ-RBBC reference、relation、circuit、producer、replay 與 evidence 工具 |

`src` 是 source 的縮寫。這裡保存會被 Python 執行或匯入的原始碼。現在仍保留許多根據既有
artifact identity 使用的 `pq_rbbc_*.py` 路徑，不能因為檔名較長或版本看似舊就任意搬動。

### D. 驗證與機器證據

| 路徑 | 用途 |
| --- | --- |
| `tests/system/` | access、framing、replay 等 system reference tests |
| `tests/system_modules/` | governance、opening 等模組測試 |
| `tests/test_pq_rbbc_*.py` | PQ-RBBC core、circuit、replay 與 evidence tests |
| `manifests/` | 固定參數、identity、metrics 與 claim boundary 的 JSON 資料 |
| `checksums/` | 檔案 exact identity 的 checksum inventories |
| `artifacts/metadata/` | 可攜、不包含大型 binary 的 artifact metadata |
| `docs/proof/` | 形式化證明來源與 release snapshots |

Test 是可執行的有限檢查；manifest 是機器可讀的紀錄。兩者都重要，但單一 test 或 manifest 都不能
自動取代密碼學 proof、完整 integration 或 production qualification。

### E. 導覽與學習

| 路徑 | 用途 |
| --- | --- |
| `modules/` | 模組 registry 與遷移期間的入口 |
| `docs/guides/` | 把 protocol、資料、relation、實作與證據連起來的導覽 |
| `learning/` | 依你的程度建立的課程、術語與進度 |

這些文件幫助導航。若其中的狀態敘述和 machine evidence 或 `RESEARCH_STATUS_zh-TW.md` 衝突，應先
視為需要調查的 claim drift，不能讓教材覆蓋正式狀態。

## 3. 不要從檔名猜完成度

本次 checkout 約有 100 個 `src/**/*.py`、90 個 `test_*.py` 與 126 個 manifests。這只表示專案已經
累積很多工程產物，不表示有 126 個 production-ready 功能。

判讀一項功能時，依序問：

1. **Protocol**：角色應該做什麼，安全目標是什麼？
2. **Data／API**：輸入輸出與傳輸的 exact bytes 是什麼？
3. **Relation／implementation**：程式強制哪些合法性條件？
4. **Execution／evidence**：哪些正常、錯誤與 mutation cases 實際跑過？
5. **Closure**：真正 proof backend、整合、benchmark 與部署條件是否完成？

只看到第 3 或第 4 層，不能跳到第 5 層的結論。

## 4. 一條實際閱讀路徑：接入訊息 framing

我們先追蹤一個很小的問題：

> FGS 收到一串 bytes 時，程式如何確認它是唯一格式，並拒絕錯誤 version、length 或 trailing bytes？

### 第一步：確認系統語意和狀態

- `ARCHITECTURE_zh-TW.md` 告訴我們 satellite access 屬於 M6 系統接入層。
- `RESEARCH_STATUS_zh-TW.md` 說 canonical frame／opaque parser 已 Implemented／Tested，但 PQ AKE、
  holder authenticator 與 production distributed replay store 尚未完成。

所以本次能檢查的是「外層 frame encoding」，不能宣稱整個衛星認證已完成。

### 第二步：找到原始碼

`src/pq_sat_auth/framing.py` 定義：

- `FRAME_MAGIC`：辨認這是哪一種 protocol frame；
- `FRAME_VERSION`：目前接受的格式版本；
- `FrameType`：允許的四種 access message type；
- `encode_frame(...)`：把 type 與 body 組成 canonical bytes；
- `decode_frame(...)`：解析並拒絕錯誤 magic、version、type、length、過大 body 或 trailing bytes。

這裡的 parser 只回答「格式是否正確」。它沒有驗證 ticket signature、NIZK、holder secret 或
Replay backend state。

### 第三步：找同名測試

對應測試位於 `tests/system/test_pq_sat_auth_framing.py`。它包含：

- 固定的 empty `ACCESS_INIT` test vector；
- 四種 message type 的 encode／decode round trip；
- wrong magic、wrong version、unknown type、錯誤 length、trailing byte 與 truncated header；
- 非 `bytes` 輸入、opaque truncation 與 size limit。

`test_` 開頭是 Python `unittest` 的測試命名慣例。讀 source 時搜尋相同模組名稱，通常能很快找到
使用範例及預期拒絕條件。

### 第四步：執行精確測試

本堂由助教執行：

```bash
PYTHONPATH=src python -m unittest tests.system.test_pq_sat_auth_framing -v
```

結果是 `Ran 6 tests`、`OK`。這支持目前 checkout 的六組 framing 測試通過；它不支持 NIZK、PQ AKE、
匿名性、安全 reduction 或 production deployment 已完成。

## 5. 這行命令每一段是什麼

| 部分 | 意思 |
| --- | --- |
| `PYTHONPATH=src` | 告訴 Python 可從 `src/` 尋找 project packages |
| `python -m unittest` | 讓 Python 執行標準函式庫中的 `unittest` test runner |
| `tests.system.test_pq_sat_auth_framing` | 用點號表示要載入的測試 module path |
| `-v` | verbose，列出每個 test method 與結果 |

這個命令不會修改 protocol，也不會產生 production artifact；它只執行指定測試。你的第一次親自操作
會在後續課堂進行，因此這次結果只記為助教驗證。

## 6. 三個安全的閱讀指令

下面都是查找或顯示內容，不會修改檔案：

| 指令 | 用途 |
| --- | --- |
| `rg --files src tests` | 列出 `src/`、`tests/` 裡的檔案 |
| `rg -n "decode_frame" src tests` | 尋找名稱出現在哪些檔案和行號 |
| `sed -n '1,160p' FILE` | 顯示指定檔案的第 1 到 160 行 |

`rg` 是 ripgrep；`-n` 表示顯示 line number。知道名稱時先搜尋，再開小段內容，比從第一個檔案一路
翻完整個 repository 更容易建立脈絡。

## 7. 現在先避開的陷阱

- `__pycache__/` 和 `*.pyc` 是 Python 執行時產生的 cache，不是要閱讀或提交的 source。
- `external_artifacts/` 可能含大型外部輸入；使用前要依 manifest／checksum 核對，不能反序列化
  不可信 pickle。
- 檔名帶 `production`、`evidence` 或較大的版本號，不代表它已 `Production-closed`。
- README 和 guide 適合找入口；最新成熟度仍要回到 canonical status 與實際 evidence。
- Test 通過只支持它真正檢查的條件，不能把六個 framing tests 寫成「衛星認證已證明安全」。

## 8. 本堂後你應建立的閱讀習慣

遇到任何功能，固定沿這條路找：

```text
研究問題／設計理由
        ↓
Architecture／spec／status
        ↓
src 中的實作
        ↓
tests 中的正常與拒絕案例
        ↓
manifest／artifact／proof／experiment（若該層存在）
        ↓
只寫證據實際支持的 claim
```

不是每項功能目前都有完整 manifest 或 proof。找不到時應記成缺口，而不是推定它存在。

下一堂會從 `src/pq_sat_auth/framing.py` 開始學 Python package、module、`import` 與 `__init__.py`，
再追蹤一次 `encode_frame` 從測試被呼叫到回傳 bytes 的完整路徑。
