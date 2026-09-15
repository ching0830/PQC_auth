# 論文學習工作區

起點是會基礎 Python；終點是能解釋設計取捨、讀懂目前實作，並獨立修改與驗證。
不預設熟悉 Python libraries、工程術語或密碼學；在概念首次需要時補充說明。

## 從這裡開始

| 文件 | 用途 |
| --- | --- |
| [學習路線圖](ROADMAP_zh-TW.md) | 全程順序、每階段的理由與完成條件 |
| [學習進度](PROGRESS_zh-TW.md) | 目前位置、實際回答、待釐清問題與下一步 |
| [術語表](GLOSSARY_zh-TW.md) | 只隨課程加入已介紹的詞彙 |
| [第一堂：論文要解決什麼問題](lessons/01_RESEARCH_PROBLEM_zh-TW.md) | 從使用情境理解認證、隱私與追責需求 |
| [第二堂：票券有效，為什麼還要驗證持票者](lessons/02_TICKET_AND_HOLDER_AUTH_zh-TW.md) | 區分格式、票券有效性、持票者證明與服務授權 |
| [第三堂：簽署金鑰、驗證金鑰與票券簽章](lessons/03_SIGNATURE_KEYS_zh-TW.md) | 用完整例子理解私鑰、公鑰與驗票流程，對照核心定義 |
| [第四堂：盲發行如何兼顧隱私與合法性](lessons/04_BLIND_ISSUANCE_zh-TW.md) | 沿著小明申請票券，理解盲簽章、發行 NIZK 與最終簽章的分工 |
| [第五堂：持票者摘要與追責密文](lessons/05_HASH_AND_TRACE_ENCRYPTION_zh-TW.md) | 理解雜湊與加密的不同用途，連結一般認證與受控身分開啟 |
| [第六堂：一張票券為什麼需要多種隨機資料](lessons/06_RANDOMNESS_zh-TW.md) | 用兩張票券區分秘密、序號與加密亂數，附 Python secrets 入門示範 |
| [第七堂：後量子要求如何影響整套協定](lessons/07_POST_QUANTUM_zh-TW.md) | 理解量子攻擊能力，以及簽章、加密與 NIZK 各自需要的安全條件 |
| [第八堂：一張票券的完整生命週期](lessons/08_TICKET_LIFECYCLE_zh-TW.md) | 階段 3 起點；串起設定、發行、衛星接入、連線、換手與受控開啟 |
| [第九堂：共同設定與發行授權](lessons/09_CONFIGURATION_AND_ISSUER_AUTH_zh-TW.md) | 理解信任起點、共同設定、發行授權與兩種使用額度的不同責任 |
| [第十堂：一次發行中的公開輸入、秘密與 NIZK](lessons/10_ISSUANCE_DATA_FLOW_zh-TW.md) | 沿一次申請對照資料可見性、I1–I5、簽署回應與本機關係檢查 |
| [第十一堂：持票透過衛星接入地面站](lessons/11_SATELLITE_ACCESS_FLOW_zh-TW.md) | 沿四種接入訊息理解驗票、持票者認證、新鮮值、金鑰確認與接受時點 |
| [第十一堂補充：NIZK 與接入延遲](notes/ACCESS_LATENCY_AND_NIZK_zh-TW.md) | 更正四訊息並非必然；記錄低延遲動機，評估首則認證、防重放與預先金鑰的取捨 |
| [第十二堂：一次性票券的狀態、並行與失敗恢復](lessons/12_ONE_TIME_TICKET_STATE_zh-TW.md) | 理解 `UNSEEN`、`RESERVED`、`CONSUMED`，以及競爭、重試、回應遺失與中斷恢復 |
| [第十三堂：過期、撤銷、已消耗與換手](lessons/13_EXPIRY_REVOCATION_HANDOVER_zh-TW.md) | 區分三種拒絕原因、撤銷競爭與保存期限，理解 handover 不能重用已消耗票券 |
| [第十四堂：受控身分開啟為什麼需要兩道門](lessons/14_CONDITIONAL_OPENING_zh-TW.md) | 理解案件授權與門檻解密的分工、OA share gate、opening replay 及合併終點檢查 |
| [第十五堂：完整生命週期與資料可見性總整理](lessons/15_END_TO_END_AND_DATA_VISIBILITY_zh-TW.md) | 串起設定、發行、接入、session、換手與開啟，逐角色核對 `rid`、`k_hold`、`sn` 與 `C` 的可見性 |
| [第十六堂：後量子計算前移——離線發行、在線驗證](lessons/16_OFFLINE_ISSUANCE_ONLINE_VERIFICATION_zh-TW.md) | 階段 4 起點；區分可前移的重型 issuance work 與依賴當下資料的 access work，並解釋 Replay |
| [第十七堂：流程不同，怎麼公平比較衛星認證論文](lessons/17_FAIR_SATELLITE_AUTH_COMPARISON_zh-TW.md) | 保留各篇真實機制，依相同事件、成本邊界與證據等級比較 AnFRA、PkT-SIN、N3PA-STIN、QPCASIN 與本研究 |
| [第十八堂：One-use ticket 與 reusable anonymous Show](lessons/18_ONE_USE_VS_REUSABLE_SHOW_zh-TW.md) | 比較一次性票券批次與多次匿名出示，說明不可連結性、quota、Replay、在線成本、共享狀態及 v0.1 的選擇理由 |
| [第十九堂：Blind issuance 與普通 signed ticket](lessons/19_BLIND_VS_ORDINARY_ISSUANCE_zh-TW.md) | 解釋發行端知道註冊身分時，blindness 與 NIZK 如何共同切斷 issuance session 到最終票券的直接連結，並限定共謀與 metadata 邊界 |

課程按概念相依順序進行。第一堂從研究問題開始；角色名稱與新術語先解釋用途，再進入公式、程式與測試。
先前對話曾提前介紹 replay；該次介紹不代表學習者已理解或完成相應單元。

## 每堂課的做法

1. 先說明本堂要解決的問題，以及它在整篇論文中的位置。
2. 用情境、圖或小例子解釋；新術語附白話定義。
3. 適用時才進入公式、少量程式與必要 library 用法。
4. 先完整示範一次，再於適合時安排有明確目的的小練習；不把每段講解都變成追問或猜測助教想要的答案。
5. 記錄實際回答、尚未理解之處及下一步；未回答的問題可留待自然的應用情境，不作逐題過關的必要門檻。

2026-09-14 教學調整：學習者明確表示不清楚助教在問什麼。暫停連續更換 `k`／`h` 的
問答，先用同一個人物與完整情境，清楚標示正在解釋的檢查、給定條件與結論。
每段先說明它在學習路線中的用途；目前以完整示範、白話說明和適量檔案對照接續。

2026-09-14 圖表偏好：學習者要求「之後給的流程圖可以直接畫出來 不用給程式碼」。
後續對話直接呈現可見流程圖，不貼 Mermaid、HTML 或其他圖表原始碼。這項偏好針對流程圖，
不視為禁止有教學目的的 Python 片段。既有課程不因這項偏好自動全部重製。

前三類能力分別記錄：「能解釋」「能讀程式」「能修改並驗證」。教材建立、助教執行測試、
或學習者表示願意繼續，都不能直接當成已掌握的證據。

未來新增課程使用 `lessons/NN_TOPIC_zh-TW.md`，並更新本入口與進度。
若教學涉及練習程式，先說明修改目的、影響範圍與驗證方法，再依 repository 工作規則執行。

## 教材與正式文件的關係

建立日期：2026-09-12，Asia/Taipei。
初始內容對照的程式／文件基線：`6f6d8c832c0f90d69d96ffe3abd0dcc8b8c562bb`，
當時整合狀態為 v2.42。這是教學參考基線，不是要求未來教材永遠停留在此版本。

`learning/` 是教學與個人學習紀錄。學習路線圖規劃的是學習順序；根目錄
[ROADMAP_zh-TW.md](../ROADMAP_zh-TW.md) 規劃的是研究與工程工作。
教材對既有設計的解釋與情境例子，須受下列正式來源約束：

- [ARCHITECTURE_zh-TW.md](../ARCHITECTURE_zh-TW.md)：系統角色、語意與信任假設。
- [methodology.md](../methodology.md)：既有設計理由與取捨。
- [RESEARCH_STATUS_zh-TW.md](../RESEARCH_STATUS_zh-TW.md)：目前實作、測試、證明與限制。
- [文件權責規則](../docs/DOCUMENTATION_POLICY_zh-TW.md)：正式文件與教學資料的分工。
- [Protocol 到工程實作導覽](../docs/guides/PROTOCOL_TO_IMPLEMENTATION_GUIDE_zh-TW.md)：後續深入閱讀的對照材料。

接續教學時先讀本文件及學習進度，核對相關來源是否變更，再延續目前單元。
學習完成不表示研究、實作、安全證明或部署條件已完成；新的研究決策與正式實驗仍按
repository 規則記錄於其各自負責的文件。
