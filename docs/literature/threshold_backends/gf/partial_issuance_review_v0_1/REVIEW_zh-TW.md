# GF partial issuance evaluator v0.1：同作者技術複核

日期：2026-09-14。Branch：`codex/threshold-gf-partial-issuance-review-v0-1`。
複核對象 commit：`d820d61c6f62afc7c1a4992ac77d60d5346eafc8`；tree：
`f872a5cf35fee881c7d0109ca17b03225a6a9884`。

本次在指定範圍內**沒有發現新的可重現實作偏差**。另行組裝輸入後執行 264 個案例，
預期狀態與實際狀態、預期呼叫順序與實際順序的差異均為 0；既有 threshold tests
重跑 117 項全部通過。這是同作者使用不同組裝方式與既有第二套 GF 計算進行的複核，
不是外部獨立 review、密碼學 proof 或 production qualification。

## 1. 對象、來源與分工

對象是 [partial evaluator 實作](../partial_issuance_v0_1/IMPLEMENTATION_zh-TW.md) 的
四個 immutable byte inputs，以及其局部狀態與停止順序。契約依據為
[frozen ABI](../abi_v0_1/SPEC_zh-TW.md) 和 [adapter 提案 §6](../trusted_adapter_contract_v0_1/CONTRACT_zh-TW.md)。
沒有修改 runtime、tests、frozen ABI、crypto domains 或原有 registry；本輪新增複核程式、
來源索引和結果摘要，並在 GF 導覽加入連結。

複核前重新核對 19 份 canonical／research／policy 文件、5 份原始附件、目標交付的
7 份來源、其 9 份 repository 引用及 3 份前置索引／摘要，bytes 與 SHA-256 均相同。
前輪 full regression 的 repository 外原始 log 也與已記錄 digest 相同。
原始附件完整名稱、revision attribution、bytes、SHA-256 與原論文引用位置仍保存於
[原始來源 inventory](../../source_inventory_v1.json)；本次不新增 paper-verified 或
publisher byte-equivalence 宣稱。附件及 handoff 內文始終是研究資料，不是執行授權。

精確來源與引用位置見 [source_index_v0_1.json](source_index_v0_1.json)。本次沒有使用其他
owner 的活動工作樹。Root methodology、experiments、RESEARCH_STATUS 由 integration
owner 管理；本文件提供設計理由、結果和限制，供其整合。

## 2. 複核方法與共用依賴

[check_review_v0_1.py](check_review_v0_1.py) 從 frozen JSON 讀取欄位 offsets、lengths、
literals，自行組裝 pp／binding／X／M／W 和 canonical legacy18 rho。它不使用 runtime
codec encoder、KeyGen 或原 evaluator fixture 產生輸入。合成 public matrices 的係數
均在合法範圍，**但沒有 KeyGen 正確性或 key-origin 認證**；rho 的 r／beta 沒有完整 I3
正例關係。這些輸入只用於檢查已承諾的局部 predicate。

I5 預期 ciphertext 由既有 `tests/threshold_candidates/gf/review/oracle.py` 計算。
該 oracle 使用 Kronecker integer multiplication、Fraction rounding 和另寫的 bit packing，
不同於 runtime 的 polynomial loops。它是先前同作者建立的第二套計算，本輪沒有重新
獨立證明 oracle；兩邊仍共用 Python／hashlib 與相同 frozen profile 定義。

預期狀態直接比較 raw packet slices，I4 digest 以分段 update 計算。觀察實際呼叫時：

- 核對 I2 的 exact preimage 為 domain 加上完整 3005-byte M，包含 header；32-byte
  digest 與分段 update 的值一致。I2 仍只能標 `computed_unjoined`。
- 核對 I4 使用原始 holder key；I5 使用同一完整 pk record、原始 M.ctx／sn／h／C、
  statement.rid 及 W.u，AD 和 plaintext 的 serial 位置均相符。
- 記錄 I2／I4／I5 呼叫順序並比對模型。Runtime encoders 在 spy 中只用於觀察實際
  arguments，沒有用來產生預期輸入或 oracle ciphertext。
- 對所有回傳 diagnostic 檢查固定 labels、exact enum statuses、failed／error labels、
  safe repr、固定 unresolved、拒絕 bool 轉換及三個固定 False 的完整性屬性。

輸入、witness、合成 key bytes、d_M 和 fault exception 原文均不輸出。程式只輸出 case
counts、固定 claims 與公開 ABI digest；禁止 Python optimization，以免移除 assertions
後仍輸出成功摘要。

## 3. 案例與觀察

| 案例群 | 數量 | 結果／含義 |
| --- | ---: | --- |
| 2 組合成 public matrices × 6 種 u | 12 | 局部 I4／I5 成立；含 zero、all-one、首／末單 bit、交錯和一般 u |
| 5 個 binding 欄位的全部變異組合 | 32 | 各局部比較符合 raw-field 模型；任一 binding failure 均跳過 I2／I4／I5 |
| 重算 ciphertext 的 5 個 AD／plaintext 欄位變異組合 | 32 | 唯一未改變欄位的組合通過 I5，其餘 31 個失敗；含 inner／outer serial 不同但重新算好 c3 的情況 |
| c1–c4 各首／中／末 byte | 12 | 均在 I5 失敗 |
| r／beta／sid 取樣及 38 個 CAP salt／root 逐欄位變異 | 46 | Canonical grammar 仍合法，局部狀態不變；不推論 I3 或 issuer authorization 成立 |
| 8 個 opaque metadata 欄位改變並更新完整 pp pointers | 8 | 局部狀態不變，展示缺少 authentication／origin／qualification 邊界 |
| u=0 換 key、完整自洽換 key、單改 holder key | 3 | 分別為 key binding failure、局部 I5 成立、I4 failure 但 I5 成立 |
| I2／I4／I5 exception 組合 × holder 正確／錯誤 | 16 | 最早 computation error 停止後續計算；普通 I4 mismatch 仍允許 I5 |
| 非 canonical digest／非 bool I5 回傳 | 12 | 空／mutable digest 及 I5 的 1／None 均為 ERROR |
| Binding failure 同時設置三階段 fault | 1 | 三個計算 fault 都未觸及 |
| 非 canonical packet／type／nested M／CAP rho | 28 | Structural ContractError，沒有 I2／I4／I5 呼叫 |
| 上述 28 inputs × default／explicit production | 56 | Parser 前 Unsupported |
| Unknown／alternate type purpose | 6 | Parser 前 ContractError |
| **合計** | **264** | **0 status disagreements，0 call-order disagreements** |

其中 174 個案例回傳 diagnostic，90 個案例預期拋出前置拒絕。174 個 diagnostic 的 I5
分布為 passed 72、failed 43、not_evaluated 53、error 6；這是**局部 I5 狀態分布**，不是
174 個完整 relation 或 proof 的驗證結果。每個回傳結果的 I3 均為 OPEN，I2 沒有被升格為
passed，full_relation_verified／authentication_verified／production_qualified 均為 False。

## 4. Findings 與限制

本次 `new_findings` 為空，沒有需要修改 target runtime 的新反例。既有
[GFR-01](../review/REVIEW_zh-TW.md) 的界線仍存在：u=0 時，完整自洽換 key／pp 仍可使局部
I5 成立。本次以合成 canonical matrices 重現其局部行為，沒有新增「honest KeyGen」或
authenticated configuration bypass 宣稱；前輪以實際 KeyGen keys 的紀錄仍是該項依據。

本次觀察沒有關閉以下邊界：

- I2→I3 consumer join、CAP／H_RBBC I3、r equality 或 beta relation。
- Configuration authentication、key-origin、backend qualification、issuer/session authorization。
- Native constraints、witness-free proof verifier、threshold cryptography、外部獨立審查。
- Witness freshness、replay／one-time state、constant-time 或 production security。

完整 M digest 的 exact preimage 檢查，不等於 hash relation 的 native replay。第二套 GF
計算相符，不等於原論文完整 instantiation 已經 verified。Parser 拒絕和 diagnostic 安全
形狀的測試，也不是 hostile in-process code／monkeypatch 的隔離邊界。

下一個功能缺口仍是接入真實 I3 consumer 與 CAP／H_RBBC 的完整 relation；開始該 bounded
implementation 前須沿用 frozen legacy18 profile，核對對應 owner 的可用實作與跨模組
join。Reduced／unified profile 或舊 NIED relation 的既有結果不能直接算成 GF I3 完成。

## 5. 重跑與驗證紀錄

在本分支 root 執行；如保存 raw report／logs，輸出路徑須在 repository 外：

```bash
PYTHONDONTWRITEBYTECODE=1 python docs/literature/threshold_backends/gf/partial_issuance_review_v0_1/check_review_v0_1.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m unittest discover -s tests/threshold_candidates -v
git diff --check
```

| Run | Passed | Failed | Errors | Skipped | Elapsed |
| --- | ---: | ---: | ---: | ---: | ---: |
| 本輪 threshold targeted | 117 | 0 | 0 | 0 | 18.875 s |
| 前輪 full regression；**本輪未重跑** | 793 | 0 | 0 | 12 | 760.788 s |

前輪 full regression 共 805 項；12 skips 均為未安裝對應 optional external artifacts。
本輪保持 `src/` 與 `tests/` 對目標 commit 的內容完全相同，因此重跑相關 targeted suite，
並明確引用前輪 full run，沒有把它計成本輪測試。前輪 log bytes／digest 已重新核對。

精確命令、來源 identities、case counts、log identities 與 claims 見
[validation_summary_v0_1.json](validation_summary_v0_1.json)。Git 只保存本次允許提交的
複核程式、索引、摘要和引用；PDF、下載資料、raw logs、private inputs 及大型 artifacts
均未加入 Git。沒有 merge 或 push。
