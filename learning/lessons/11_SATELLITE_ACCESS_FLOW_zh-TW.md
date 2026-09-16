# 第十一堂：持票透過衛星接入地面站

日期：2026-09-14。所屬階段：3／完整系統流程。
接續 [第十堂](10_ISSUANCE_DATA_FLOW_zh-TW.md)：小明已完成發行，裝置保存票券 `T`
與另行保護的持票者秘密。現在學它們如何用來建立一次接入連線。

2026-09-14 補充更正：使用者明確說明採 NIZK 是為減少衛星接入往返與 backhaul delay。
本堂四訊息僅描述現有草稿，**不是所有安全接入都必須先向 FGS 索取 nonce**。
應優先評估首則申請附接入 NIZK 的單往返候選，並補足防重放、金鑰確認及後端狀態條件；
詳見 [NIZK 與接入延遲補充](../notes/ACCESS_LATENCY_AND_NIZK_zh-TW.md)。
本堂保留四訊息作現況對照，尚未選定新的正式協定。

## 本堂要接上的能力

這堂將驗票、持票者認證、此次連線的新鮮性與連線金鑰分開，再串成接入流程。
最後希望能說明四種訊息各自補上哪一項需求；目前不要求選定或實作密碼學演算法。

流程依 [one-time access v0.1 草稿](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md)
第 5–6 節與現有四種 `Access*V1` 資料物件。這是已有資料格式的草稿，不是完整可部署協定。
[Protocol 導覽](../../docs/guides/PROTOCOL_TO_IMPLEMENTATION_GUIDE_zh-TW.md) §6 的兩列
概念通訊摘要與四訊息草稿仍需細部對照；本堂不把兩列摘要當成已完成的兩訊息協定，
也不透過流程圖凍結尚未選定的 PQ AKE。

## 1. 誰參與這次接入

| 角色 | 本堂的工作與資料 |
| --- | --- |
| UE，小明的裝置 | 持有票券及秘密，產生接入認證與金鑰協議資料，核驗地面站回應 |
| LEO／FLEO，衛星 | 中繼兩端訊息；本圖採中繼情境，不安排衛星持有發行／開啟金鑰或權威票券消耗狀態 |
| FGS，地面站 | 驗證票券、服務條件、持票者與此次接入，管理使用狀態，作為連線金鑰的另一端 |

HNCC 的發行工作已在前一階段完成，這條接入路徑不要求每次再向 HNCC 詢問小明身分。
FGS 取得 `T=(M,sigma)`，可看見序號、持票者摘要與追責密文；不取得額外的註冊身分明文、
發行證明 `pi_issue` 或持票者秘密。中繼本身不提供機密性，不能因衛星只轉送便宣稱
它看不到沿途未受保護的票券或其他欄位。

## 2. 第一種訊息：AccessInitV1，提出接入

小明的裝置經衛星送出接入申請。重要內容包括：

- 票券 `T` 與共同設定 `ctx`。
- 本次的 serving context 摘要，指定地面站、營運端、中繼／服務範圍、期間與政策等環境。
- 新產生的 `ue_nonce`、`attempt_nonce`，辨認這次接入嘗試；不同於發行的 `sid`。
- `ue_key_share`，使用者端為金鑰協議送出的資料。

Nonce 是本次新產生、用來支持新鮮性與綁定的值，不是密碼，也不靠保密來認證持票者。
Key share 這裡譯作「金鑰協議資料」，避免誤認為把最終連線金鑰或 OA 開啟秘密份額送出。
實際內容由未來選定的 PQ AKE 決定，目前只是預留欄位。

FGS 收到後可執行初步檢查、準備回應。**收到 AccessInit 不能預留或消耗票券。**
否則旁觀者只要抄到票券便可能先把它占住，卻沒有證明掌握持票者秘密。

## 3. 第二種訊息：AccessChallengeV1，提供地面站的新資料

FGS 經衛星回傳自己的 `fgs_nonce`、金鑰協議資料、此次 challenge 的期限，以及
`challenge_cookie`，並帶回必要的共同欄位。

Cookie 在這裡是供 FGS 後續核對的憑據，用來確認 challenge 的來源、期限與原申請的
綁定。草稿容許使用受認證的 cookie 或獨立的待處理 challenge 紀錄；它不是票券已消耗
的紀錄，也不是瀏覽器 cookie 的教學。

例如小華保存了小明上次接入的認證資料，這次 FGS 給出的 nonce 與其他接入內容已不同。
新的認證必須綁定這次資料，讓舊認證不能直接搬來回答新的申請。

這不是發行 NIZK 內部的 Fiat–Shamir 挑戰。NIZK 的「非互動式」說明證明本身如何產生；
AccessChallenge 的新鮮值則服務於整段接入。實際持票者認證方法仍待選定，不能先宣稱
它必然採 NIZK 或某種互動式證明。收到 nonce 或 cookie，也不等於 UE 已認證地面站。

## 4. 第三種訊息：AccessFinishV1，完成持票者認證與金鑰確認

裝置使用本機持票者秘密，依選定協定產生 `holder_authenticator`，回傳給 FGS；
不把秘密本身傳出去。它要支持 FGS 確認：「這次請求者掌握票券摘要 `h` 所綁定的秘密」。
這個驗證還必須和此次接入內容綁定，不能只證明曾經知道某個秘密。

另一個欄位 `ue_key_confirmation` 是使用者端的金鑰確認資料，供 FGS 確認 UE 掌握
這次協議的金鑰。持票者認證與金鑰確認責任不同：前者關聯票券秘密，後者關聯
這次連線使用的金鑰。具體計算與認證方式仍由 PQ AKE／suite 設計補足。

兩端需要對照的接入內容稱為 transcript，本堂譯作「交握紀錄」。例如小明原本要連到
FGS 甲，若有人把認證資料搬去 FGS 乙，或替換金鑰協議資料，原認證就不能直接沿用。
因此必須綁定票券、共同設定、serving context、雙方新鮮值及金鑰協議資料等內容。

目前 `access_transcript_digest()` 彙整 Init、Challenge 與 Finish 的核心欄位。
Finish 的持票者認證資料和 UE 金鑰確認不納入這個核心摘要；它們要依規定認證該摘要，
不是把自己的輸出又包含回自己的輸入。算出摘要不等於已完成認證或金鑰協議。

## 5. 第四種訊息：AccessAcceptV1，確認此次接入結果

FGS 在收到 Finish 後，必須完成格式、可信設定、服務範圍、期限、票券簽章、撤銷、
challenge／transcript、持票者認證、金鑰確認與服務准入等必要檢查。失敗不能建立
票券消耗紀錄。通過後，還需透過一致的狀態管理，確保同一張票券只建立一份初始連線。

依草稿，FGS 必須把 session、接受回應的識別／恢復資料與票券已消耗的狀態一起可靠提交，
之後才送出接受回應。原子提交表示這些相關結果不能各自留下互相矛盾的成功／失敗狀態；
詳細競爭、重試與中斷恢復留待下一堂。

Accept 包含這次嘗試與連線的識別值、服務環境、連線期限及 FGS 的金鑰確認資料。
回應必須依選定協定受保護。UE 核驗後才接受連線結果；系統還需要認證 FGS 這個對端，
不能只因有人回傳一個「成功」字串就信任。FGS 的具體認證、AKE 與回應保護仍待完成。

連線金鑰用於保護後續通訊，與持票者秘密不同。一張票券成功建立的 session 可以承載
多筆資料；FGS 仍可辨認同一 session 的活動，不把不可連結性擴張成每個封包都無法關聯。
若 FGS 已提交成功但 Accept 遺失，票券不因此恢復未使用；同次合法重試如何取回原結果，
也是下一堂的內容。

## 程式入口與目前界線

| 檔案 | 本堂對應內容 | 可以與不能得出的結論 |
| --- | --- | --- |
| [access.py](../../src/pq_sat_auth/access.py) | `ServingContextV1`、四種 `Access*V1`、編解碼、`access_transcript_digest()` | 已表示欄位與檢查部分一致性；沒有 holder authenticator、金鑰產生／協議或完整接入服務 |
| [framing.py](../../src/pq_sat_auth/framing.py) | 訊息外框、種類、長度與格式檢查 | 能拒絕錯誤外框不代表內部票券或認證有效 |
| [identities.py](../../src/pq_sat_auth/identities.py) | `TicketUseIdentity` 與 `derive_use_key()` | 建立使用狀態的識別，不能取代票券或持票者驗證 |
| [replay.py](../../src/pq_sat_auth/replay.py) | `InMemoryLinearizableReplayStore` | 單程序記憶體參考模型；`production_ready = False`，不是跨 FGS 耐故障儲存 |
| [接入資料測試](../../tests/system/test_pq_sat_auth_access.py) | 編解碼、欄位綁定、摘要與變造案例 | 測試中的 ticket、key share、authenticator 使用佔位 bytes，不是真實發票與登入測試 |

「編解碼」是把欄位轉成依規定排列的 bytes，再依同一規定讀回。
現有 `holder_authenticator` 等欄位是 opaque bytes：外層先保留資料位置與長度邊界，
內部密碼學意義需由選定協定驗證。通過這層格式檢查不等於其中的認證成立。
目前只有 `suite_id = 0xffff` 的 test-only profile，不能用於正式部署。

## 來源與下一堂

- [One-time access 草稿](../../docs/specs/ONE_TIME_TICKET_STATE_v0_1_zh-TW.md)：§2、§5–7、§13。
- [架構](../../ARCHITECTURE_zh-TW.md)：角色、M5／M6 與 mutual authentication 目標。
- [研究狀態](../../RESEARCH_STATUS_zh-TW.md)：access codecs、test-only state 與未完成的認證／AKE。
- [第二堂](02_TICKET_AND_HOLDER_AUTH_zh-TW.md)：持票者秘密、接入新鮮值與 NIZK 的不同用途。

本堂只核對來源並更新教材，沒有執行接入協定或新密碼學測試，也沒有提升安全宣稱。
下一堂沿兩個申請同時抵達、回應遺失與程序中斷，學習一次性使用狀態如何避免重複建立連線。
