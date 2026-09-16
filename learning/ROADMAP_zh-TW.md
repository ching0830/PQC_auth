# 從基礎 Python 到獨立接手論文的學習路線

建立日期：2026-09-12。學習者已確認會基礎 Python，但部分 library 與工程用語需要說明。
目前位置以 [學習進度](PROGRESS_zh-TW.md) 為準。

## 全程路線

```text
研究問題 → 必要概念 → 系統流程 → 設計取捨
    → 程式閱讀工具 → 各模組實作 → 證據與限制 → 獨立修改
```

| 階段 | 學習內容 | 安排理由 | 完成時能做到 |
| --- | --- | --- | --- |
| 1．研究問題 | 衛星接入情境、使用者與提供者需求、隱私與追責的衝突 | 先知道研究目的，才能理解功能為何存在 | 用自己的話解釋論文替誰解決什麼問題 |
| 2．必要安全概念 | 身分、認證、授權、秘密金鑰、隨機數、雜湊、加密、簽章、後量子；盲簽章、零知識與門檻機制先理解用途 | 建立閱讀協定需要的詞彙，細部數學留待相應單元 | 說明各種工具的用途與限制，辨認認證和加密的差別 |
| 3．完整系統流程 | 角色責任；初始化、發行、接入、連線建立、身分開啟、撤銷與換手 | 先追蹤一張票券的生命週期，定位所有模組 | 畫出流程並指出每一步誰知道哪些資料 |
| 4．設計取捨 | 離線發行、盲簽章、一次性使用、權限分離、地面與衛星分工、信任假設 | 理解流程後才能比較替代方案及代價 | 回答為什麼選這個設計，以及換一種會影響什麼 |
| 5．程式閱讀工具 | repository 目錄、Python 模組與 import、bytes、資料類別、型別提示、例外、測試、Git 基礎 | 將概念接到實際資料表示與工作流程 | 找到功能入口、讀懂輸入輸出、執行一個測試 |
| 6．逐層實作 | 資料格式、系統模組、票券關係、密碼學計算、電路、分段組合與恢復 | 每一層建立在前一層的理解上 | 追蹤資料流，解釋主要函式、拒絕條件與依賴 |
| 7．證據與限制 | 單元測試、安全證明、實驗、manifest、版本與尚未完成的整合 | 確認各類結果到底支持什麼結論 | 對一項研究宣稱找到證據，說清楚其適用範圍 |
| 8．獨立修改 | 影響分析、預測、修改、測試、記錄、口頭說明 | 將理解轉成自己能完成的工作 | 完成一個有理由、有驗證、有清楚限制的小型修改 |

每個階段可以拆成多堂課。階段 1–4 以理解與口頭說明為主；階段 5 起逐步加入程式操作。
階段 7 集中整理證據判讀方法，但從第一堂開始就區分研究目標與已完成成果。

2026-09-14 需求澄清：階段 3–4 必須將減少衛星接入往返與 backhaul 等待納入設計比較，
不能把現有四訊息草稿當成必要下界。先評估首則附 NIZK、單往返接入的條件與代價；
參見 [接入延遲補充](notes/ACCESS_LATENCY_AND_NIZK_zh-TW.md)，此處未選定新正式協定。

## 階段 6 的實作閱讀順序

下表是完整閱讀清單的分類入口，不表示各項功能都已完成。進入每個單元時，按當時
checkout 補出「概念 → 檔案 → 函式 → 測試 → 目前限制」的具體對照。

| 單元 | 範圍／程式入口 | 核心問題 |
| --- | --- | --- |
| 6-1 | `src/pq_sat_auth/framing.py`、`identities.py` 與相關 codecs | 資料如何變成唯一 bytes？如何拒絕錯誤格式？ |
| 6-2 | `src/pq_rbbc/contracts/`、`governance/` | 系統設定如何綁定？誰能在哪段期間、依哪些規則發票？ |
| 6-3 | `src/pq_rbbc_reference.py` | 票券欄位是什麼？reference model 如何檢查發行資料一致性？ |
| 6-4 | `src/pq_sat_auth/access.py`、`replay.py` | 接入訊息如何綁定？同時使用、失敗與重送如何處理？ |
| 6-5 | `src/pq_rbbc/opening/` | 授權檢查、開啟份額與合併之間有什麼限制？ |
| 6-6 | `src/pq_rbbc_anemoi_*`、`pq_rbbc_horner_native.py`、`pq_rbbc_blind_uov_*`、`pq_rbbc_cap_commit.py` | 雜湊、有限體、Blind-UOV 與 CAP 各自完成什麼計算？ |
| 6-7 | `src/pq_rbbc_native_profile.py`、`pq_rbbc_br1cs.py`、native circuits、assignment 與 shard modules | 如何把規則轉成電路限制，為變數填值並逐條檢查？ |
| 6-8 | tree producers、composer、split tail、global tail、relocation、aggregate replay、parent join | 每段算對之後，如何確認跨段接線與整體關係一致？ |
| 6-9 | `src/pq_rbbc_cap_unified_tree*`、`pq_rbbc_cap_unified_statement_parent_abi*`、`pq_rbbc_launch_io_v2_41.py`、`pq_rbbc_recovery_io_v2_42.py` | 為何遷移 profile？資料如何串流、固定身分、檢查啟動條件並中斷恢復？ |
| 6-10 | CAP Prove／Verify、extractor、security qualification、fork audit、trace-KDF／provenance、`docs/proof/` 與各 evidence modules | 資料介面、參數來源、安全假設與真正可接受的密碼學證明之間，還缺什麼？ |

閱讀每個主模組時，一起找出其 `tests/`、`manifests/` 與適用的 `artifacts/metadata/`。
歷史 producer、recovery 與 evidence 檔案在對應單元比較其版本差異，不以版本號作為課程順序。
尚未實作的功能以需求與介面學習，並明確標註缺口。

## Python 與數學的補充時機

| 使用時機 | 補充內容 |
| --- | --- |
| 資料物件 | `dataclasses`、`frozen=True`、型別提示、欄位與方法 |
| bytes 與編解碼 | bytes／str／int 的差別、位元組順序、長度、`struct`（實際用到時） |
| 摘要與測試向量 | `hashlib`、輸入輸出、固定範例與 domain label 的用途 |
| 錯誤與測試 | exceptions、`unittest`、assertion、正常與拒絕案例 |
| 並行狀態 | 程序、執行緒、`threading`、鎖、原子操作、持久保存的差別 |
| 檔案與大型計算 | `pathlib`、`json`、串流、檔案系統、checkpoint、恢復 |
| 有限體與密碼學核心 | 位元與 XOR、模運算、多項式、有限體；先做小例子再接目前參數 |
| 關係與電路 | 公開資料與秘密資料、變數、限制式、代入檢查；再學證明系統 |

這些是補課清單；是否已學會以實際回答與操作確認。Library 用法以當時程式與適用版本為準。

## 獨立修改的練習安排

由小範圍開始，每次先寫下「想改什麼、為什麼、哪些結果應改變、哪些規則必須保留」。

1. 改變範例輸入，預測格式檢查與輸出，再執行核對。
2. 在教學練習中改變競爭請求數，核對唯一使用等必要條件。
3. 為一個合理的小功能或實際缺陷設計修改，選擇能檢查其行為的測試。
4. 辨認介面變更是否需要新版本，以及會影響哪些呼叫端、測試與文件。
5. 解釋修改後得到的證據與仍然存在的限制，練習口試式說明。

第一次實作練習前會教 task branch／worktree 與 repository 的 artifact 規則。
正式原始碼修改、實驗與設計決策依 [專案指引](../AGENTS.md) 及
[文件權責規則](../docs/DOCUMENTATION_POLICY_zh-TW.md) 管理。

## 已建立的課程入口

| 課程 | 所屬階段與完成條件 |
| --- | --- |
| [第一堂：論文要解決什麼問題](lessons/01_RESEARCH_PROBLEM_zh-TW.md) | 階段 1；能用自己的話說明使用情境、認證需求、隱私問題與受控追責的基本邊界，並辨認這是研究目標 |
| [第二堂：票券有效，為什麼還要驗證持票者](lessons/02_TICKET_AND_HOLDER_AUTH_zh-TW.md) | 階段 2 的起點；能區分格式、票券有效性、持票者證明與授權，解釋複製有效票券的風險 |
| [第三堂：簽署金鑰、驗證金鑰與票券簽章](lessons/03_SIGNATURE_KEYS_zh-TW.md) | 階段 2；理解簽署私鑰與驗證公鑰的用途、驗票資料流，以及使用者秘密的不同責任 |
| [第四堂：盲發行如何兼顧隱私與合法性](lessons/04_BLIND_ISSUANCE_zh-TW.md) | 階段 2；能沿發行流程說明誰看到哪些資料，以及盲簽章、發行 NIZK 與最終簽章各自的用途 |
| [第五堂：持票者摘要與追責密文](lessons/05_HASH_AND_TRACE_ENCRYPTION_zh-TW.md) | 階段 2；能說明摘要與密文的輸入、用途及恢復能力，分辨持票者認證與身分開啟 |
| [第六堂：一張票券為什麼需要多種隨機資料](lessons/06_RANDOMNESS_zh-TW.md) | 階段 2；能區分難猜、避免重複與保密需求，理解三項取樣用途及固定測試資料的界線 |
| [第七堂：後量子要求如何影響整套協定](lessons/07_POST_QUANTUM_zh-TW.md) | 階段 2；能說明後量子目標、各元件的安全依賴，以及條件式分析與完成實作的差別 |
| [第八堂：一張票券的完整生命週期](lessons/08_TICKET_LIFECYCLE_zh-TW.md) | 階段 3 起點；能沿完整流程指出角色、資料可見性與必要檢查，區分發行、初始接入、連線及開啟 |
| [第九堂：共同設定與發行授權](lessons/09_CONFIGURATION_AND_ISSUER_AUTH_zh-TW.md) | 階段 3；能說明公鑰信任來源、設定認證與發行權限的分工，辨認額度狀態不等於票券接入消耗 |
| [第十堂：一次發行中的公開輸入、秘密與 NIZK](lessons/10_ISSUANCE_DATA_FLOW_zh-TW.md) | 階段 3；能沿申請指出 HNCC 已知與裝置保留的資料，解釋證明如何綁定同一份票券及已認證身分 |
| [第十一堂：持票透過衛星接入地面站](lessons/11_SATELLITE_ACCESS_FLOW_zh-TW.md) | 階段 3；能沿四訊息草稿說明衛星中繼、持票者認證、接入綁定與連線建立，辨認格式與認證的差別 |
| [第十二堂：一次性票券的狀態、並行與失敗恢復](lessons/12_ONE_TIME_TICKET_STATE_zh-TW.md) | 階段 3；能說明三個使用狀態、不同 attempt 的唯一 winner、同 attempt 重試，以及 commit 前後中斷的恢復差異 |
| [第十三堂：過期、撤銷、已消耗與換手](lessons/13_EXPIRY_REVOCATION_HANDOVER_zh-TW.md) | 階段 3；能區分時間條件、撤銷政策與使用狀態，說明撤銷／消耗競爭及以原 session 授權換手的邊界 |
| [第十四堂：受控身分開啟為什麼需要兩道門](lessons/14_CONDITIONAL_OPENING_zh-TW.md) | 階段 3；能分開說明案件授權與門檻解密，沿 OA gate 與 combiner 指出綁定、replay、份額一致性及最終序號檢查 |
| [第十五堂：完整生命週期與資料可見性總整理](lessons/15_END_TO_END_AND_DATA_VISIBILITY_zh-TW.md) | 階段 3 總整理；能沿完整案例指出每一階段的角色、資料、狀態與分支，並說清楚匿名／不可連結性的觀察者與時間範圍 |
| [第十六堂：後量子計算前移——離線發行、在線驗證](lessons/16_OFFLINE_ISSUANCE_ONLINE_VERIFICATION_zh-TW.md) | 階段 4 起點；能說明哪些高成本 PQ issuance work 可提前完成、哪些 access work 必須依賴當下資料，並區分 Replay、issuance NIZK 與 access NIZK |
| [第十七堂：流程不同，怎麼公平比較衛星認證論文](lessons/17_FAIR_SATELLITE_AUTH_COMPARISON_zh-TW.md) | 階段 4；能區分 related work、comparison paper 與 baseline，依相同事件、在線邊界和證據等級比較異構協定，不把原作者數值冒充同環境 benchmark |
| [第十八堂：One-use ticket 與 reusable anonymous Show](lessons/18_ONE_USE_VS_REUSABLE_SHOW_zh-TW.md) | 階段 4；能說明固定票券重用不等於匿名 Show，並比較 one-use 與 multi-show 在不可連結性、quota、計算位置、狀態、庫存和失竊風險上的取捨 |
| [第十九堂：Blind issuance 與普通 signed ticket](lessons/19_BLIND_VS_ORDINARY_ISSUANCE_zh-TW.md) | 階段 4；能說明 issuer unlinkability 保護的配對、NIZK 對 hidden ticket 的檢查責任，以及 honest-protocol、共同 metadata、opening threshold 與 traffic analysis 的限制 |
| [第二十堂：組織拓撲、角色分離與跨域關聯風險](lessons/20_ROLE_SEPARATION_AND_COLLUSION_zh-TW.md) | 階段 4；能分開行政隸屬、protocol role 與 key role，說明 FAC／OA 同組織、各 NCC 所屬地面站、satellite operator 合作關係，以及跨域資料共享／門檻失陷的邊界 |
| [第二十一堂：地面站與衛星的工作分配](lessons/21_GROUND_SATELLITE_WORK_PLACEMENT_zh-TW.md) | 階段 4；能說明驗證位置與 RTT 是不同設計軸，區分 satellite path、state backhaul 與 home lookup，並解釋首則 access NIZK 為何不取代權威 one-use state |
| [第二十二堂：短效票券的有效期、庫存與補發策略](lessons/22_TICKET_LIFETIME_AND_INVENTORY_zh-TW.md) | 階段 4；能區分 configuration／grant／challenge／session expiry，說明共同 bucket、batch 容量、提前補發、wallet crash state 及短長有效期的取捨 |
| [第二十三堂：Threat Model 與安全邊界](lessons/23_THREAT_MODEL_AND_SECURITY_BOUNDARIES_zh-TW.md) | 階段 4 總整理；能按角色列出 adversary view／capability、誠實假設與成功事件，並判斷 issuer unlinkability、one-use、opening privacy 與 availability 各自在哪些條件下成立 |
| [第二十四堂：Repository 地圖與證據路徑](lessons/24_REPOSITORY_MAP_AND_EVIDENCE_PATH_zh-TW.md) | 階段 5 起點；能區分 repository root、研究工作台、canonical definitions、source、tests、manifests／artifacts 與導覽文件，沿 framing 功能說明測試真正支持的範圍 |

目前單元與理解狀態只在 [學習進度](PROGRESS_zh-TW.md) 更新。第二至七堂已提供必要概念的
入門說明；第八至十五堂已完成階段 3 的教材範圍，涵蓋共同設定、發行、接入、使用狀態、
換手／撤銷、受控身分開啟及資料可見性總整理。第十六堂已分析高成本 PQ 運算的前移邊界，
第十七堂建立異構衛星認證論文的公平比較方法，第十八堂比較 one-use ticket 與 reusable anonymous
`Show`，第十九堂分析 blind issuance 與普通 signed ticket，第二十堂已依作者更正建立組織拓撲，
第二十一堂分析 HGS、FGS 與 LEO／FLEO 的工作分配，以及 2 RTT 草稿和 1 RTT 候選；第二十二堂
分析 short-lived ticket 的有效期、庫存和補發策略；第二十三堂整理 threat model 與安全主張邊界。
第二十四堂已進入階段 5，建立 repository 地圖並沿 framing 走過規格、source、tests 與 claim
boundary；下一堂學 Python package、module、`import` 與 `__init__.py`。仍於應用時補課，不以教材
建立視為已掌握，尚未進入階段 6 的逐模組實作閱讀。
