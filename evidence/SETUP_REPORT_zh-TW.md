# Hχ⁺ 完整公開 setup 與新 cache 實測

> 發布副本只修正相對連結；原量測數值與原來源 pin 保留於 provenance/source_inventory.json。

日期：2026-10-21。來源為 `97d72914` 加本次diff，沿用同一隔離工作線。
完整原始記錄在 `/tmp/pqsat-buov-cap-hplus-exploration-v0-1/actual-setup-v1*`；
portable結果與source／artifact pins見
[actual_setup.json](../manifests/buov_cap_hplus_research_v0_1/actual_setup.json)。
先前首個里程碑 `RESULT_zh-TW.md`（歷史checkpoint未收錄）保留當時count-only／未知setup的狀態。

本輪真的建立完整 Hχ⁺ public CS、執行原生 `ZKVerifier::setup_research_unmerged`，
寫出新公開cache，另一程序重新載入、驗SHA／canonical CS並再次setup。
兩次CS／compiler／setup身分及全部actual參數相同。沒有提供private ValueVec，
沒有檢查完整assignment滿足性、呼叫Prove或驗證任何proof；不能稱新版發行已完成。

## 確認的身分與形狀

| 項目 | 本輪結果 |
| --- | --- |
| canonical CS SHA-256 | `92216254586814f128d68c91cc5842b8d5bc61d13bcdc76a51405afabfa74c5f` |
| compiler ID | `0b375652a1823a9fafd3bbf88495a95d3b6d9f07aca4188137f8688266798e2b` |
| setup ID | `6a4b28686792da14efd04dc59f4f3123e43bb5a1df2d850570b5f6ac0e2cdb6a` |
| public cache SHA-256 | `25ccf947e09c3e894aea78b58b79b298b7958f6694f4a903bd405e87defe6864` |
| public cache實際長度 | **688,968,080 bytes**，唯讀，與上一輪格式推導相同 |
| canonical CS編碼 | **2,718,916,370 bytes**，64KiB buffer串流雜湊，未寫巨檔 |
| 完整CS | AND16,361,386／ZERO3,263,533／private words19,866,173／public words106／constants8,487 |

Compiler ID使用新的HPLUS domain、FP、relation ID及真CS SHA；setup ID再綁compiler與
完整actual setup JSON。沒有沿用舊cache／CS／compiler／setup ID。
新 cache magic為`BCSHPL01`；header同時綁exact shape、CS／source／T SHA，bounded decoder
核版本、index／shift、template budgets、長度及EOF，載入後重算canonical CS。
這些cache身份核對不等於新relation replay或cryptographic soundness proof。

| actual oracle順序 | len | log_msg_len | is_zk |
| --- | ---: | ---: | --- |
| outer precommit | 863 | 10 | true |
| inner packed private trace | 9,933,087 | 24 | true |
| outer private | 98,715 | 17 | true |
| mask | 512 | 9 | true |

實際source constant／FRI query-target=128、rate=1/2、q=309；dummy wires310、每segment
兩條dummy constraints，padding316。Outer新symbolic compile得到precommit547／private98399，
padded multiplication constraints1,048,576；mask dims=(7,2)，FRI arities=[4,4,3,3]，
max_log_domain_size=25。現在這些數值有新setup實例化依據。

原生格式函式得到 **FRI component 984,832 bytes**。這是特定component的精確格式計量，
不是新proof body實測；整份新proof、實際issuance statement frame與雙向發行成本仍未知。
846B是compiler的public input slots；完整NIFS與角色流程尚未移植。
Hχ⁺對χ的多項式次數32，與此Binius masked-composition degree2分開處理，未錯改mask次數。

## Single sample成本

| 階段 | 冷建圖／寫cache／setup | cache重載／setup |
| --- | ---: | ---: |
| 真完整CS建構 | 10.275956 s | 未重新建圖 |
| canonical CS hash | 5.155701 s | 5.312655 s |
| cache寫入／載入 | 1.785588 s | 2.214179 s |
| 原生ZK verifier setup核心 | 1.390887 s | 1.460760 s |
| native整體 | **18.610379 s** | **8.989554 s** |
| Python worker整體 | 18.785202 s | 9.160372 s |
| guard整體 | 18.836688 s | 9.279449 s |
| native OS HWM | 1,293,533,184 B | 1,281,081,344 B |
| 程序樹RSS最大抽樣 | 1,308,266,496 B | 1,208,111,104 B |

分項在不同窗口量測，不強求相加等於whole。RSS抽樣可能錯過HWM，兩種數字分列，
不是formal RSS上界。這不是完整proof時間或發行延遲；也不是跨版本加速實驗。
公開cache屬可重用公開圖成本，單獨計量。

三個guard（建置、cold、reload）均exit0／stop=null／無殘留；1個physical core。
建置可用至多8個compiler helper threads，native setup固定1個research worker。
保持4GiB tree-RSS停止、8GiB每程序AS、MemAvailable16→8GiB、30分鐘、單檔1GiB、
新account合計10GiB的界線。新的實際setup量測供後續Prove准入使用，不能把setup RSS
直接當成Prove RSS；後者尚未量測。未修改其他worktree、舊guard、歷史累計額度或系統全域設定。

## 驗證與NCC使用邊界

- 新原生setup/cache測試 **38 passed／0 failed／0 ignored**，含原hash／lift helpers、
  cache codec roundtrip、unknown／unused／alias／shift、allocation caps、舊magic及T／profile拒絕。
- Python **27 passed／0 failed／0 errors／0 skipped**：含12個Hχ⁺回歸、9個setup／runtime
  控制、6個既有resource-policy檢查。收緊trace／cache／phase metadata後，另補跑該9項全過；
  重複測試不相加。Full repository suite未重跑。
- NCC用的 [public_setup.py](../src/pq_sat_auth/prototypes/buov_cap_hplus_research_v0_1/public_setup.py)
  只從tracked checkpoint取expected CS/cache/compiler/setup；拒絕舊profile、舊inner length、
  query／mask／FRI惡改與bool/int混用。另核exact build/binary、shared native sources及其
  local build-input manifest，公開cache先核160B header及readonly／大小，再stream-hash。
- `validate_public_setup_result`只做metadata核對，不驗proof、不產生proof-accepted旗標。
  Native public-setup binary對`full-prove/full-verify`在讀T／大型配置前拒絕；測試也確認此界線。
  將來的proof consumer須自行重建statement並呼叫真正Verify。

## 重跑

```bash
cd /tmp/PQC_auth_buov_cap_hplus_research_v0_1
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
  python3 -m benchmarks.buov_cap_hplus_research_v0_1.setup_run \
  --label actual-setup-replay-01 --wait-seconds 120
```

使用未用過label；入口按順序建置／測試、cold生成cache及setup、獨立reload/setup並比對身份。
全部輸出在新exploration account。它不自動改寫tracked checkpoint。
NCC runtime預設仍固定本次`actual-setup-v1` build與cache；新輸出不得由UE宣告為新可信設定。

可另重跑Python檢查（本機需已安裝本次精確公開依賴）：

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. \
BUOV_HPLUS_TEST_BUILD=/tmp/pqsat-buov-cap-hplus-exploration-v0-1/regression-v7 \
BUOV_HPLUS_SETUP_EXTERNAL=1 python3 -m unittest \
  tests.test_buov_cap_hplus_research_v0_1 tests.test_buov_cap_hplus_setup_v0_1 \
  tests.test_buov_cap_runner_v0_1 -v
```

## 完成度與下一個整合交付

新完整public CS與ZK verifier setup達Instantiated／Implemented／Tested／Measured。
新完整assignment滿足性、UE Prove、NCC無witness Verify、原CAP狀態續接pi₂及consumer仍未完成。
本輪無新完整proof、安全定理或formal／production提升；Evidence-sealed、Proof-closed、
Production-closed皆false。前輪條件式binding分析及backend／ZK資格仍待各自論證。

下一個交付是同一新profile下的完整角色流程：移植X18／statement／private frame及same-state
準備／continuation；新增Hχ⁺ native pi₂ wrapper的profile gate；NCC從自身records重建輸入，
以本次新setup／cache做真Verify，通過才反演，再由原CAP state Append／pi₂及獨立consumer驗證。
所有元件使用同一份受約束秘密；不拼接獨立成功案例，不新增R1／full Init／其餘17組來源。
