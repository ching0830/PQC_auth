# Hχ⁺ 同狀態完整研究發行與票券 consumer 實測

> 發布副本只修正相對連結；原量測數值與原來源 pin 保留於 provenance/source_inventory.json。

日期：2026-10-21。來源：乾淨 `be00fada` 加本次差異，沿用隔離 Hχ⁺ 工作線。
完整公開設定仍是前輪已固定的
[actual setup](SETUP_REPORT_zh-TW.md)，沒有修改其 compiler、圖、mask 或安全參數。
本輪來源、binary、結果身分與數值見
[lifecycle.json](../manifests/buov_cap_hplus_research_v0_1/lifecycle.json)。
這是同一新 profile 的 single sample，沒有把舊 ff32 成果接成新 ff33 證據。

本輪實際跑通：

```text
一次 Hχ⁺ CAP.Init
→ UE 對完整既定研究關係呼叫原生 Prove
→ NCC 從 own records 重建 statement，以公開 proof／圖真 Verify
→ 接受後才用自己 RAM 裡的 issuer key 反演 beta，回傳 z
→ UE 將 z Append 至原 CAP state，呼叫原生 pi₂ prover
→ 獨立 consumer 從自身配置及收到的 M／CR 重建 Scope／u，真 CAP Verify
```

研究關係為 Hχ⁺ profile 下的 `F1–F5 ∧ R_PC2 ∧ F7–F8`。
指定 repetition `s=2` 的全部2048 parties、2322位置／12 planes 來源與合併計算均在同一份證明內。
full Init、共同 root image、其餘17組來源、holder KeyGen image仍未納入。
pi₂在發行 Verify／反演之後產生，是另一份證明。

## 角色、資料與版本邊界

- [full_statement.py](../src/pq_sat_auth/prototypes/buov_cap_hplus_research_v0_1/full_statement.py)
  使用 HPLUS NIFS domain，frame **1037B**、public slots846B。NCC只從request取beta，
  其餘欄位與request-core digest從自己的snapshot重建；compiler／setup／T三個ID必須符合自有checkpoint。
- [full_witness.py](../src/pq_sat_auth/prototypes/buov_cap_hplus_research_v0_1/full_witness.py)
  的private semantic body2030206B，HPLUS NIFW frame2030298B。只經UE至native prover的RAM stdin，
  不寫檔、不傳給NCC、不輸出其值或雜湊。資料來自同一次Init與同一份內容witness。
- [proof_main.rs](../native/buov_cap_hplus_research_v0_1/src/proof_main.rs)
  在UE重建唯一CS及private values，完整constraint replay後呼叫`prove_sig`；
  NCC程序以EOF stdin載入自己pin的公開cache，核canonical CS／actual setup，
  `verify_sig`與transcript `finalize`均成功才回傳接受。
- [issuer.py](../benchmarks/buov_cap_hplus_research_v0_1/issuer.py)
  自持key和snapshot；真native接受才反演。NCC等UE完成Prove才載大圖，不在UE峰值時持有第二份CS。
  封存FD確保native驗證的是NCC剛重建／收到的確切公開bytes。
- [continuation.py](../src/pq_sat_auth/prototypes/buov_cap_hplus_research_v0_1/continuation.py)
  重查原state／r／CR／witness／beta及request-proof digest、`Q_I(z)=beta`，才Append原state。
  這些host same-state檢查不是對惡意UE的密碼學binding證明。
- [ticket_consumer_verify.py](../benchmarks/buov_cap_hplus_research_v0_1/ticket_consumer_verify.py)
  接收M／CR／CZ／pi₂，配置另由實驗操作者供給的sealed FD取得；不接受caller u、
  issuer SK、UE witness、CAP state或發行session records。配置來源仍是研究fixture，沒有完成正式配置認證。

CAP profile為ff33、新FP／relation／binding IDs；Scope suite仍0001，CAP wire version仍1。
新傳輸`NIH1/v1`固定1037B statement；舊`NIC1/v1`固定1031B，兩者拒絕混用。
原生pi₂ API／kernel使用隔離的Hχ⁺型別與loader namespace，保留新profile gate，
共享的C relation／q數學核心未改算法。沒有停用舊gate，也沒有改正式production入口或另一條效能工作線。

## 新實測成本

所有bytes為精確編碼長度；時間為本輪單次實測，UE／NCC／CAP均固定**1個physical core**。
這是新relation整合樣本，不能拿舊4核數字宣稱跨版本加速或退化。

| 項目 | 本輪值 | 計量範圍 |
| --- | ---: | --- |
| pi_iss proof body | **995632 B** | 真Prove產生的公開proof，不含statement／圖 |
| pi_iss statement | **1037 B** | 完整NIFS；內含846B compiler public slots |
| pi₂ canonical object | **5592 B** | 含50B CAP物件header；不是pi_iss的一部分 |
| CR／CZ／M | 5074／234／388 B | final consumer收到的其他欄位 |
| consumer ticket frame | 11318 B | 30B header＋M＋CR＋CZ＋pi₂；非發行request |
| 可重用公開CS cache | **688968080 B** | 前輪新profile圖／設定，另計、不逐次傳輸 |
| canonical CS encoding | 2718916370 B | 串流hash，不落地；不是proof或RAM大小 |
| UE CAP.Init＋內容準備 | 1.851282 s | 同一次Init及準備 |
| pi_iss核心Prove | **58.328783 s** | native prove_sig／finalize，不含建圖setup |
| UE native整體 | 80.860037 s | 含建圖10.940695s、replay0.743112s、CS hash、setup5.450157s及Prove |
| pi_iss核心Verify | **8.501734 s** | NCC verify_sig／finalize |
| NCC native整體 | 17.453197 s | 含cache載入／重核CS、setup1.418695s及Verify |
| NCC反演 | 1.379235 s | 接受之後的一次反演，SK只在NCC RAM |
| Append | 0.025440 s | 原state |
| pi₂ hybrid native Prove | **0.487527 s** | 含Python transcript／opening及native q，不稱全C核心 |
| consumer核心CAP Verify | **0.150947 s** | 不含worker啟動／配置重建 |
| consumer worker整體 | 1.474867 s | UE觀察的verify callback含IPC／啟動為2.013550s |
| 完整成功flow | **105.733544 s** | 從Init前至consumer接受，含各次冷setup／IPC；不含獨立controls |
| 整輪worker | **163.158141 s** | 含公開admission、NCC啟動、獨立controls與收尾核對 |
| guard整體 | 163.822008 s | supervisor窗口 |

新proof長度恰與某舊profile樣本相同；這裡的995632B來自新Prove及新Verify，並非借用歷史數字。
分項窗口不同，不能要求全部加總剛好等於flow。warm service延遲、網路開銷與完整production
雙向通訊仍未知；300MB只作完整雙向issuance的軟參考。

| 本輪實際NIH1傳輸 | Bytes |
| --- | ---: |
| NCC→UE初始公開setup | 190602 |
| UE→NCC request | 996688 |
| NCC→UE回覆 | 227 |
| 一次發行雙向、不含初始setup | **996915** |
| 含初始setup | **1187517** |

兩端獨立wire counters一致。Issuer telemetry、consumer IPC、可重用圖不算入這個codec。
回覆227B中含私密z184B，只走RAM pipe；未持久化其bytes或hash。

## 資源、失敗與驗證

| 資源 | 本輪實測 |
| --- | ---: |
| UE native OS RSS HWM | 3859927040 B |
| NCC native OS RSS HWM | 1329926144 B |
| consumer OS RSS HWM | 62492672 B |
| 程序樹RSS最大抽樣 | **3971100672 B** |
| 最大程序AS抽樣 | 3897135104 B |
| MemAvailable開始／最低 | 29007065088／25110622208 B |
| guard account bytes | 778008744 B |

准入用當次公開setup RSS與新counts／oracles重算component formula，含192MiB heuristic margin及
resident NCC allowance後為4195438328B，低於4GiB停止門檻；這不是正式RSS上界。
實際guard `exit=0／stop=null／no_residual_group=true`。維持共享鎖、最多一個重型工作、
4GiB sampled tree-RSS停止、8GiB每程序AS、MemAvailable16→8GiB、30分鐘、單檔1GiB、account10GiB。
Parent、native／NCC／consumer子程序均繼承finite limits與單核affinity；沒有全尺寸無界配置或OOM探測。

- Python **40 passed／0 failed／0 errors／0 skipped**，含Hχ⁺12、公開setup9、新lifecycle13、resource6。
- Native **38 passed／0 failed／0 ignored**，含新NIFS格式／profile與既有cache／hash／lowering控制。
- 另在完成flow後執行15個consumer控制：good-before／good-after接受；M-SN、M-q、CR-salt、
  CZ、pi₂ commitment、自有configuration generation與issuer map惡改，均在真CAP Verify拒絕；
  另6項格式／配置注入在入口拒絕。合計9次真CAP Verify；不另Init、不反演、不存presentation。
- 同一新發行proof的公開bytes惡改後，fresh NCC式native Verify實際拒絕。
  這項控制不載issuer SK，不能稱帶SK拒絕後反演次數的動態測試。
- own-record ctx變更在重建時拒絕。原主flow各1次Init／issuance P／issuance V／反演／Append／pi₂ P／consumer V。
- Full repository suite未重跑。內部唯讀review不是外部獨立安全審查。
- 量測後僅移除`nonhash_census.py`最後一個多餘空行，Python AST比較完全相同；
  原量測source snapshot保持不改，before／after pins另列manifest，不為此重跑完整flow。

歷史不刪：`lifecycle-v1-build`的Rust錯誤型別接合失敗已修正；v2／v3 build及最終v4 build都38項通過。
`lifecycle-v1／v2`在Init與Prove前被缺少advisory role marker的既有入口拒絕；新worker在核
實際lock／limits／session之後設定marker，未略過admission。審查另發現舊codec的1031B限制，
已改為隔離的1037B新codec；沒有等到產生proof才觸發該錯誤。
初版Python控制11過／1error是測試誤用不存在的context manager，改成explicit close後完成最終40過。
原始失敗與成功receipt留在外部目錄，不把探索失敗刪除或改寫為成功。

## 完整本機重跑

需保有tracked manifests列出的精確本機readonly Rust rlibs、public T與上一輪公開cache／build。
這是有身分核對的本機重跑，不是已封裝的跨機release。新native build固定在`lifecycle-v4-build`；
若未安裝，入口於同一guard下建立並跑38項native控制；已有則先核source／binary，沒有慢版fallback。

```bash
cd /tmp/PQC_auth_buov_cap_hplus_research_v0_1
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m benchmarks.buov_cap_hplus_research_v0_1.run \
  --label lifecycle-replay-01 --wait-seconds 120
```

label必須未用過；主入口自動接NCC與獨立consumer，成功後跑獨立controls。
全部產物在`/tmp/pqsat-buov-cap-hplus-exploration-v0-1/<label>`。
本次最終實測label為`lifecycle-v3`，對應guard `lifecycle-v3.json`。
只存公開proof／statement、公開build/result metadata；不存witness、隨機幣、秘密state、z或final payload。

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
BUOV_HPLUS_TEST_BUILD=/tmp/pqsat-buov-cap-hplus-exploration-v0-1/regression-v7 \
BUOV_HPLUS_SETUP_EXTERNAL=1 BUOV_HPLUS_LIFECYCLE_EXTERNAL=1 \
  python3 -m unittest tests.test_buov_cap_hplus_research_v0_1 \
  tests.test_buov_cap_hplus_setup_v0_1 tests.test_buov_cap_hplus_lifecycle_v0_1 \
  tests.test_buov_cap_runner_v0_1 -v
```

## 論文主張與下一步

這份Hχ⁺既定完整研究關係與同state角色流程達Defined／Instantiated／Implemented／Tested／Measured。
可報告「能由NCC公開資料驗證、接原state完成票券的Hχ⁺發行研究原型」，
不能因此宣稱對任意惡意UE的prefix／masked-image／origin binding或BUOV安全化約已完成。
Evidence-sealed、Proof-closed、Production-closed與backend qualification均false。
128僅FRI query-target，不等於整體128-bit或後量子安全資格。

下一個交付是Hχ⁺的條件式binding論證：核對新consistency family的定理前提，分開處理固定資料差值、
adaptive／delayed-preimage選擇、terminal接受到有效候選的bridge，以及NCC實際回覆目標的接合。
不以這次誠實same-state執行替代該引理，也不恢復full Init／其餘17組來源或新增公開隱藏資料。
效能工作線若要接新profile，需先固定本輪語意與ID邊界；本輪不替另一工作線合併或更新設定。
